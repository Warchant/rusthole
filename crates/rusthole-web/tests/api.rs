//! Integration tests of the admin API over loopback HTTPS (docs/API.md, docs/SECURITY.md).

// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right
// result. Short names (h, s, r) keep the request chains readable.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::single_match_else
)]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{Creds, Options, PASSWORD, fill, harness, method_of, password_hash};
use reqwest::{Method, StatusCode};
use rusthole_web::assets::MemoryAssets;
use rusthole_web::router::{Access, ROUTES};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_route_needs_auth_except_the_public_ones() {
    let h = harness(Options::default()).await;
    let none = Creds::default();
    for r in ROUTES {
        let path = format!("/api/v1{}", fill(r.path));
        let method = method_of(r.method);
        let body = (method != Method::GET && method != Method::DELETE).then(|| json!({}));
        let resp = h.req(method.clone(), &path, body, &none).await;
        match (r.access, r.path) {
            (Access::Public, "/auth/login") => {
                // The body has no password: the request fails before any check.
                assert_eq!(
                    resp.status,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{method} {path}"
                );
            }
            _ => {
                assert_eq!(
                    resp.status,
                    StatusCode::UNAUTHORIZED,
                    "{method} {path}: {}",
                    resp.text
                );
                assert_eq!(resp.code(), "unauthorized");
            }
        }
        assert_eq!(resp.headers["cache-control"], "no-store", "{path}");
    }
    // A path that is not in the table gives 404 JSON, not the UI.
    let resp = h.get("/api/v1/nothing", &none).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(resp.code(), "not_found");
    let resp = h.get("/api/v2/lists", &none).await;
    assert_eq!(resp.code(), "not_found");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_logout_and_session() {
    let h = harness(Options::default()).await;
    let none = Creds::default();
    let bad = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": "wrong password"})),
            &none,
        )
        .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad.code(), "invalid_credentials");
    assert!(bad.headers.get("set-cookie").is_none());

    let s = h.login().await;
    let probe = h
        .get(
            "/api/v1/auth/session",
            &Creds {
                csrf: None,
                ..s.clone()
            },
        )
        .await;
    assert_eq!(probe.status, StatusCode::OK);
    assert_eq!(probe.body["csrf_token"], s.csrf.clone().unwrap().as_str());
    assert_eq!(probe.body["totp_enabled"], false);
    assert!(probe.body["expires_at"].as_str().unwrap().ends_with('Z'));

    let out = h.req(Method::POST, "/api/v1/auth/logout", None, &s).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(
        out.headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    // Logout works at once.
    let after = h.get("/api/v1/auth/session", &s).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.get("/api/v1/lists", &s).await.status,
        StatusCode::UNAUTHORIZED
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookie_has_the_host_prefix_and_flags() {
    let h = harness(Options::default()).await;
    let r = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": PASSWORD})),
            &Creds::default(),
        )
        .await;
    let c = r.headers["set-cookie"].to_str().unwrap();
    assert!(c.starts_with("__Host-rusthole_session="), "{c}");
    for part in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
        assert!(c.contains(part), "{c}");
    }
    assert!(!c.contains("Domain"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_password_set_fails_every_login() {
    let h = harness(Options {
        with_password: false,
        ..Options::default()
    })
    .await;
    let r = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": PASSWORD})),
            &Creds::default(),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.code(), "password_not_set");
    // `rusthole passwd` writes the file; the next login reads it.
    let text = h.config_text().replace(
        "[admin]\n",
        &format!("[admin]\npassword_hash = \"{}\"\n", password_hash()),
    );
    std::fs::write(&h.config_path, text).unwrap();
    // A login reads a changed file at most once in 2 s.
    h.clock.advance(Duration::from_secs(3));
    h.login().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ban_after_five_failures_with_retry_after() {
    let h = harness(Options::default()).await;
    let none = Creds::default();
    let wrong = json!({"password": "wrong password"});
    for _ in 0..5 {
        let r = h
            .req(
                Method::POST,
                "/api/v1/auth/login",
                Some(wrong.clone()),
                &none,
            )
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    // Even the right password is refused during the ban, with no check.
    let r = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": PASSWORD})),
            &none,
        )
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.code(), "rate_limited");
    assert_eq!(r.headers["retry-after"], "60");
    assert_eq!(r.body["retry_after_seconds"], 60);
    // A bad token counts in the same ban and is refused too.
    let t = h
        .get(
            "/api/v1/lists",
            &Creds {
                bearer: Some("rh_nothing".into()),
                ..Creds::default()
            },
        )
        .await;
    assert_eq!(t.status, StatusCode::TOO_MANY_REQUESTS);
    // After the lock time, the login works (the injected clock moves).
    h.clock.advance(Duration::from_secs(61));
    h.login().await;
    // The audit log has the failures and the ban.
    let s = h.login().await;
    let audit = h.get("/api/v1/audit?action=auth.", &s).await;
    let actions: Vec<&str> = audit.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"auth.ban"), "{actions:?}");
    assert_eq!(
        actions
            .iter()
            .filter(|a| **a == "auth.login_failed")
            .count(),
        5
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn totp_required_reused_code_and_disable() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let setup = h
        .req(
            Method::POST,
            "/api/v1/auth/totp/setup",
            Some(json!({"password": PASSWORD})),
            &s,
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.text);
    let uri = setup.body["otpauth_uri"].as_str().unwrap();
    let secret = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let key = rusthole_web::totp::base32_decode(&secret).unwrap();
    let code_at = |wall: i64| {
        format!(
            "{:06}",
            rusthole_web::totp::code_at(&key, rusthole_web::totp::step_of(wall))
        )
    };
    let state = h.get("/api/v1/auth/totp", &s).await;
    assert_eq!(state.body, json!({"enabled": false, "pending": true}));

    let wall = common::WALL;
    let confirm = h
        .req(
            Method::POST,
            "/api/v1/auth/totp/confirm",
            Some(json!({"code": code_at(wall)})),
            &s,
        )
        .await;
    assert_eq!(
        confirm.body,
        json!({"enabled": true, "pending": false}),
        "{}",
        confirm.text
    );
    assert!(
        h.config_text()
            .contains(&format!("totp_secret = \"{secret}\""))
    );

    // No code: totp_required, and it does not count in the ban.
    for _ in 0..6 {
        let r = h
            .req(
                Method::POST,
                "/api/v1/auth/login",
                Some(json!({"password": PASSWORD})),
                &Creds::default(),
            )
            .await;
        assert_eq!(r.code(), "totp_required");
    }
    // The code of the confirm step was used: refused.
    let reuse = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": PASSWORD, "totp": code_at(wall)})),
            &Creds::default(),
        )
        .await;
    assert_eq!(reuse.code(), "invalid_credentials");
    // The next step works once, then not again.
    h.clock.advance(Duration::from_secs(30));
    let body = json!({"password": PASSWORD, "totp": code_at(wall + 30)});
    let s2 = h.login_with(body.clone()).await;
    let again = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(body),
            &Creds::default(),
        )
        .await;
    assert_eq!(again.code(), "invalid_credentials");
    // Wrong password with a good code: same error, no hint.
    h.clock.advance(Duration::from_secs(30));
    let wp = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": "wrong password", "totp": code_at(wall + 60)})),
            &Creds::default(),
        )
        .await;
    assert_eq!(wp.code(), "invalid_credentials");

    // A token cannot change TOTP.
    let tok = h
        .req(
            Method::POST,
            "/api/v1/tokens",
            Some(json!({"name": "t", "password": PASSWORD})),
            &s2,
        )
        .await;
    let secret_tok = tok.body["secret"].as_str().unwrap().to_owned();
    let bearer = Creds {
        bearer: Some(secret_tok),
        ..Creds::default()
    };
    let forbidden = h.get("/api/v1/auth/totp", &bearer).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);

    h.clock.advance(Duration::from_secs(30));
    let off = h
        .req(
            Method::POST,
            "/api/v1/auth/totp/disable",
            Some(json!({"password": PASSWORD, "code": code_at(wall + 90)})),
            &s2,
        )
        .await;
    assert_eq!(
        off.body,
        json!({"enabled": false, "pending": false}),
        "{}",
        off.text
    );
    assert!(!h.config_text().contains("totp_secret"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_is_checked_on_writes_with_a_session() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let body = json!({"enabled": false, "duration_seconds": 60});
    let missing = h
        .req(
            Method::PUT,
            "/api/v1/blocking",
            Some(body.clone()),
            &Creds {
                csrf: None,
                ..s.clone()
            },
        )
        .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    assert_eq!(missing.code(), "csrf_failed");
    let wrong = h
        .req(
            Method::PUT,
            "/api/v1/blocking",
            Some(body.clone()),
            &Creds {
                csrf: Some("x".repeat(43)),
                ..s.clone()
            },
        )
        .await;
    assert_eq!(wrong.code(), "csrf_failed");
    // GET needs no CSRF token.
    assert_eq!(
        h.get(
            "/api/v1/blocking",
            &Creds {
                csrf: None,
                ..s.clone()
            }
        )
        .await
        .status,
        StatusCode::OK
    );
    let ok = h.req(Method::PUT, "/api/v1/blocking", Some(body), &s).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text);
    assert_eq!(ok.body["enabled"], false);
    assert_eq!(ok.body["remaining_seconds"], 60);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bearer_token_works_without_csrf_and_fails_after_revoke() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let wrong_pw = h
        .req(
            Method::POST,
            "/api/v1/tokens",
            Some(json!({"name": "script", "password": "nope nope nope"})),
            &s,
        )
        .await;
    assert_eq!(wrong_pw.code(), "invalid_credentials");
    let created = h
        .req(
            Method::POST,
            "/api/v1/tokens",
            Some(json!({"name": "script", "password": PASSWORD})),
            &s,
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let secret = created.body["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("rh_") && secret.len() == 46, "{secret}");
    let id = created.body["token"]["id"].as_u64().unwrap();
    assert_eq!(created.body["token"]["prefix"], secret.get(..7).unwrap());
    // The config keeps the hash only.
    let text = h.config_text();
    assert!(!text.contains(&secret));
    assert!(text.contains("hash = \"sha256:"));

    let bearer = Creds {
        bearer: Some(secret.clone()),
        ..Creds::default()
    };
    // A write with the token and no CSRF header works.
    let w = h
        .req(
            Method::POST,
            "/api/v1/groups",
            Some(json!({"name": "kids"})),
            &bearer,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.text);
    // A token cannot make tokens.
    let t2 = h
        .req(
            Method::POST,
            "/api/v1/tokens",
            Some(json!({"name": "x", "password": PASSWORD})),
            &bearer,
        )
        .await;
    assert_eq!(t2.status, StatusCode::FORBIDDEN);
    let list = h.get("/api/v1/tokens", &s).await;
    let item = &list.body["items"][0];
    assert_eq!(item["last_used_ip"], "127.0.0.1");
    assert!(item.get("hash").is_none());

    let del = h
        .req(Method::DELETE, &format!("/api/v1/tokens/{id}"), None, &s)
        .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
    let after = h.get("/api/v1/lists", &bearer).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_header_check_gives_421() {
    let h = harness(Options::default()).await;
    let none = Creds::default();
    let port = h.addr.port();
    for host in [
        "evil.example".to_owned(),
        format!("evil.example:{port}"),
        format!("127.0.0.1:{}", port + 1),
    ] {
        let r = h
            .req_with(
                Method::GET,
                "/api/v1/lists",
                None,
                &none,
                &[("host", &host)],
            )
            .await;
        assert_eq!(r.status, StatusCode::MISDIRECTED_REQUEST, "{host}");
        assert_eq!(r.code(), "misdirected_request");
        assert!(r.headers.contains_key("content-security-policy"));
        let ui = h
            .req_with(Method::GET, "/", None, &none, &[("host", &host)])
            .await;
        assert_eq!(ui.status, StatusCode::MISDIRECTED_REQUEST);
    }
    for host in [format!("localhost:{port}"), format!("rusthole.lan:{port}")] {
        let r = h
            .req_with(
                Method::GET,
                "/api/v1/lists",
                None,
                &none,
                &[("host", &host)],
            )
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{host}");
    }
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_headers_on_every_response() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    for (path, creds) in [
        ("/", Creds::default()),
        ("/api/v1/lists", Creds::default()),
        ("/api/v1/lists", s.clone()),
        ("/api/v1/nothing", s.clone()),
    ] {
        let r = h.get(path, &creds).await;
        let hd = &r.headers;
        assert_eq!(
            hd["content-security-policy"],
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            "{path}"
        );
        assert_eq!(hd["strict-transport-security"], "max-age=31536000");
        assert_eq!(hd["x-content-type-options"], "nosniff");
        assert_eq!(hd["referrer-policy"], "no-referrer");
        assert_eq!(hd["cross-origin-opener-policy"], "same-origin");
        assert!(
            hd["permissions-policy"]
                .to_str()
                .unwrap()
                .contains("camera=()")
        );
        if path.starts_with("/api/") {
            assert_eq!(hd["cache-control"], "no-store");
        }
    }
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_idle_expiry() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    h.clock.advance(Duration::from_secs(3599));
    assert_eq!(h.get("/api/v1/lists", &s).await.status, StatusCode::OK);
    // The request above moved the idle limit.
    h.clock.advance(Duration::from_secs(3599));
    assert_eq!(h.get("/api/v1/lists", &s).await.status, StatusCode::OK);
    h.clock.advance(Duration::from_secs(3601));
    let r = h.get("/api/v1/lists", &s).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // A stale cookie does not count in the ban.
    for _ in 0..10 {
        h.get("/api/v1/lists", &s).await;
    }
    h.login().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_write_round_trip_keeps_comments() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let g = h
        .req(
            Method::POST,
            "/api/v1/groups",
            Some(json!({"name": "kids", "comment": "Tablets"})),
            &s,
        )
        .await;
    assert_eq!(g.status, StatusCode::CREATED, "{}", g.text);
    let gid = g.body["id"].as_u64().unwrap();
    assert_eq!(gid, 1);
    let l = h
        .req(
            Method::POST,
            "/api/v1/lists",
            Some(json!({"url": "https://lists.example/hosts.txt", "groups": [0, gid], "comment": "Main"})),
            &s,
        )
        .await;
    assert_eq!(l.status, StatusCode::CREATED, "{}", l.text);
    assert_eq!(l.body["groups"], json!([0, 1]));
    assert!(l.body["status"]["state"].as_str().is_some());
    let r = h
        .req(
            Method::POST,
            "/api/v1/rules",
            Some(json!({"kind": "regex", "action": "deny", "pattern": "^ads\\.", "groups": [gid]})),
            &s,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    assert_eq!(r.body["created_at"], "2026-11-17T08:10:00Z");
    let dup = h
        .req(
            Method::POST,
            "/api/v1/rules",
            Some(json!({"kind": "regex", "action": "deny", "pattern": "^ads\\."})),
            &s,
        )
        .await;
    assert_eq!(dup.code(), "conflict");
    let unknown = h
        .req(
            Method::POST,
            "/api/v1/rules",
            Some(json!({"kind": "exact", "action": "deny", "pattern": "a.example", "id": 9})),
            &s,
        )
        .await;
    assert_eq!(unknown.status, StatusCode::UNPROCESSABLE_ENTITY);
    let bad_json = h
        .req_with(
            Method::POST,
            "/api/v1/groups",
            None,
            &s,
            &[("content-type", "application/json")],
        )
        .await;
    assert_eq!(bad_json.code(), "bad_request");

    let text = h.config_text();
    assert!(
        text.starts_with("# Test config: keep this comment.\n"),
        "{text}"
    );
    assert!(text.contains("name = \"kids\""));
    assert!(text.contains("comment = \"Tablets\""));
    assert!(
        text.contains("value = '^ads\\.'") || text.contains("value = \"^ads\\\\.\""),
        "{text}"
    );
    let reparsed = rusthole_core::Config::from_toml_str(&text).unwrap();
    assert!(reparsed.has_all_ids());
    assert_eq!(*h.config(), {
        let mut c = reparsed.clone();
        c.assign_ids();
        c
    });

    // Patch and delete through the API; the group delete removes its references.
    let p = h
        .req(
            Method::PATCH,
            &format!("/api/v1/groups/{gid}"),
            Some(json!({"enabled": false})),
            &s,
        )
        .await;
    assert_eq!(p.body["enabled"], false);
    assert_eq!(p.body["lists"], 1);
    assert_eq!(p.body["rules"], 1);
    let d = h
        .req(Method::DELETE, &format!("/api/v1/groups/{gid}"), None, &s)
        .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    let lists = h.get("/api/v1/lists", &s).await;
    assert_eq!(lists.body["items"][0]["groups"], json!([0]));
    assert_eq!(
        h.req(Method::DELETE, "/api/v1/groups/0", None, &s)
            .await
            .code(),
        "conflict"
    );

    // Every write has an audit line.
    let audit = h.get("/api/v1/audit", &s).await;
    let actions: Vec<&str> = audit.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    for want in [
        "group.create",
        "list.create",
        "rule.create",
        "group.update",
        "group.delete",
    ] {
        assert!(actions.contains(&want), "{want}: {actions:?}");
    }
    let first = &audit.body["items"][0];
    assert_eq!(first["actor"], "session");
    assert_eq!(first["client_ip"], "127.0.0.1");
    assert_eq!(first["result"], "ok");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hand_edit_gives_409_and_reload() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let text = h
        .config_text()
        .replace("[stats]\n", "[cache]\nmax_entries = 1234\n\n[stats]\n");
    std::fs::write(&h.config_path, text).unwrap();
    let r = h
        .req(
            Method::POST,
            "/api/v1/groups",
            Some(json!({"name": "kids"})),
            &s,
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.code(), "config_conflict");
    // The server read the file again.
    let settings = h.get("/api/v1/settings", &s).await;
    assert_eq!(settings.body["cache"]["max_entries"], 1234);
    assert!(!h.config_text().contains("kids"));
    // The retry works.
    let r = h
        .req(
            Method::POST,
            "/api/v1/groups",
            Some(json!({"name": "kids"})),
            &s,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert!(h.config_text().contains("max_entries = 1234"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secrets_never_in_any_get_response() {
    let totp = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let token_hash = format!("sha256:{}", "ab".repeat(32));
    let h = harness(Options {
        extra_toml: format!(
            "\n[[admin.api_tokens]]\nname = \"monitoring\"\nhash = \"{token_hash}\"\n"
        ),
        ..Options::default()
    })
    .await;
    let s = h.login().await;
    // Turn TOTP on by a hand edit (the next write or login reads the file).
    let text = h
        .config_text()
        .replace("[admin]\n", &format!("[admin]\ntotp_secret = \"{totp}\"\n"));
    std::fs::write(&h.config_path, text).unwrap();
    let _ = h
        .req(
            Method::POST,
            "/api/v1/groups",
            Some(json!({"name": "kids"})),
            &s,
        )
        .await;
    assert_eq!(h.config().admin.totp_secret, totp);
    let secrets = [
        password_hash().to_owned(),
        totp.to_owned(),
        token_hash.clone(),
        "ab".repeat(32),
    ];
    for r in ROUTES.iter().filter(|r| r.method == "get") {
        let resp = h.get(&format!("/api/v1{}", fill(r.path)), &s).await;
        // The secret filter changes a leaking response into 500 `internal`, so a 500 is a
        // leak too.
        assert_ne!(
            resp.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{}: {}",
            r.path,
            resp.text
        );
        for secret in &secrets {
            assert!(
                !resp.text.contains(secret.as_str()),
                "{} has a secret",
                r.path
            );
        }
    }
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_assets_and_spa_fallback() {
    let mut files = HashMap::new();
    files.insert(
        "index.html".to_owned(),
        b"<!doctype html><title>ui</title>".to_vec(),
    );
    files.insert(
        "assets/app-abc123.js".to_owned(),
        b"console.log(1)".to_vec(),
    );
    files.insert("favicon.svg".to_owned(), b"<svg/>".to_vec());
    let h = harness(Options {
        assets: Arc::new(MemoryAssets(files)),
        ..Options::default()
    })
    .await;
    let none = Creds::default();
    let index = h.get("/", &none).await;
    assert_eq!(index.status, StatusCode::OK);
    assert_eq!(index.headers["cache-control"], "no-cache");
    assert!(
        index.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let js = h.get("/assets/app-abc123.js", &none).await;
    assert_eq!(
        js.headers["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert!(
        js.headers["content-type"]
            .to_str()
            .unwrap()
            .contains("javascript")
    );
    let spa = h.get("/clients/02:00:00:00:00:01", &none).await;
    assert_eq!(spa.status, StatusCode::OK);
    assert_eq!(spa.text, index.text);
    let missing = h.get("/assets/missing.js", &none).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let post = h.req(Method::POST, "/", None, &none).await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn placeholder_page_without_a_built_ui() {
    let h = harness(Options::default()).await;
    let r = h.get("/", &Creds::default()).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.text.contains("bun run build"), "{}", r.text);
    let css = h.get("/placeholder.css", &Creds::default()).await;
    assert_eq!(css.status, StatusCode::OK);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_body_gives_413() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let big = json!({"name": "x".repeat(70 * 1024)});
    let r = h.req(Method::POST, "/api/v1/groups", Some(big), &s).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.code(), "payload_too_large");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpoints_answer_with_the_contract_shapes() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    for path in [
        "/api/v1/stats/summary",
        "/api/v1/stats/timeline",
        "/api/v1/stats/hours?utc_offset_minutes=120",
        "/api/v1/stats/top/domains",
        "/api/v1/stats/top/blocked",
        "/api/v1/stats/top/clients",
        "/api/v1/stats/query-types",
        "/api/v1/stats/upstreams",
        "/api/v1/stats/clients",
        "/api/v1/stats/domains?q=example",
        "/api/v1/queries/recent",
        "/api/v1/clients/seen",
        "/api/v1/settings",
        "/api/v1/system",
        "/api/v1/system/tls",
        "/api/v1/search/domain?name=use-application-dns.net",
        "/api/v1/audit",
        "/api/v1/blocking",
    ] {
        let r = h.get(path, &s).await;
        assert_eq!(r.status, StatusCode::OK, "{path}: {}", r.text);
    }
    let t = h.get("/api/v1/stats/timeline?range=24h", &s).await;
    assert_eq!(t.body["bucket_seconds"], 600);
    assert_eq!(t.body["queries"].as_array().unwrap().len(), 144);
    let hours = h
        .get("/api/v1/stats/hours?range=7d&utc_offset_minutes=330", &s)
        .await;
    assert_eq!(hours.body["utc_offset_minutes"], 300);
    assert_eq!(hours.body["queries"].as_array().unwrap().len(), 24);
    assert_eq!(
        h.get("/api/v1/stats/summary?range=1y", &s).await.code(),
        "bad_request"
    );
    assert_eq!(
        h.get("/api/v1/stats/hours?domain=a.example&base=example", &s)
            .await
            .code(),
        "bad_request"
    );
    let search = h
        .get("/api/v1/search/domain?name=use-application-dns.net", &s)
        .await;
    assert_eq!(search.body["matches"][0]["source"], "special");
    assert_eq!(search.body["verdicts"][0]["verdict"], "blocked");
    let settings = h.get("/api/v1/settings", &s).await;
    assert_eq!(settings.body["blocking"]["mode"], "null");
    assert!(settings.body.get("admin").is_none());
    let tls = h.get("/api/v1/system/tls", &s).await;
    assert_eq!(tls.body["mode"], "local-ca");
    let ca = h.get("/api/v1/system/tls/ca.pem", &s).await;
    assert_eq!(ca.status, StatusCode::OK);
    assert!(ca.text.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(ca.text.as_bytes(), h.ca_pem.as_slice());
    let test = h
        .req(
            Method::POST,
            "/api/v1/rules/test",
            Some(json!({"kind": "regex", "pattern": "(", "domain": "a.example"})),
            &s,
        )
        .await;
    assert_eq!(test.body["valid"], false);
    // Settings round trip: PATCH changes the file and answers the full settings.
    let p = h
        .req(
            Method::PATCH,
            "/api/v1/settings",
            Some(json!({"cache": {"enabled": true, "max_entries": 20000, "min_ttl": 0, "max_ttl": 86400, "negative_ttl": 300}})),
            &s,
        )
        .await;
    assert_eq!(p.status, StatusCode::OK, "{}", p.text);
    assert_eq!(p.body["cache"]["max_entries"], 20000);
    assert_eq!(p.body["restart_required"], false);
    let ro = h
        .req(
            Method::PATCH,
            "/api/v1/settings",
            Some(json!({"acl": {"extra_cidrs": [], "local_subnets": []}})),
            &s,
        )
        .await;
    assert_eq!(ro.status, StatusCode::UNPROCESSABLE_ENTITY);
    let st = h
        .req(
            Method::PATCH,
            "/api/v1/settings",
            Some(json!({"stats": {"flush_interval_seconds": 30, "retention_days": 7, "recent_queries_size": 500}})),
            &s,
        )
        .await;
    assert_eq!(st.body["restart_required"], true, "{}", st.text);
    let v: Value = h.get("/api/v1/settings", &s).await.body;
    assert_eq!(v["restart_required"], true);
    h.stop().await;
}

/// A test case of an idle connection: name, ALPN protocols, bytes to send.
type IdleCase<'a> = (&'a str, &'a [&'a [u8]], &'a [u8]);

/// A raw TLS connection to the admin listener (no HTTP client).
async fn raw_tls(
    h: &common::Harness,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use rustls_pki_types::pem::PemObject;
    let ca = rustls_pki_types::CertificateDer::from_pem_slice(&h.ca_pem).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(rusthole_tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    connector.connect(name, tcp).await.unwrap()
}

/// Reads until the server closes the connection. A read error counts as closed. Returns
/// the time to the close; panics when the connection stays open for `limit`.
async fn time_to_close(
    tls: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    limit: Duration,
) -> Duration {
    use tokio::io::AsyncReadExt;
    let started = std::time::Instant::now();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + limit;
    // At most one step for each read; each read waits until the deadline at most.
    for _ in 0..10_000 {
        match tokio::time::timeout_at(deadline, tls.read(&mut buf)).await {
            Err(e) => panic!("the server did not close the connection in {limit:?}: {e}"),
            Ok(Ok(0) | Err(_)) => return started.elapsed(),
            Ok(Ok(_)) => {}
        }
    }
    panic!("the server sent too much data")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_connections_close_after_the_idle_limit() {
    use tokio::io::AsyncWriteExt;
    let h = harness(Options {
        header_timeout: Duration::from_millis(500),
        stall_timeout: Duration::from_secs(2),
        ..Options::default()
    })
    .await;
    // The HTTP/2 preface and an empty SETTINGS frame.
    let mut h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    h2.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    // The HTTP/2 preface, SETTINGS with INITIAL_WINDOW_SIZE = 0 (the server cannot send a
    // response body), and one GET request (HPACK: GET, https, /). The client never reads.
    let mut stalled = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    stalled.extend_from_slice(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0]);
    stalled.extend_from_slice(&[0, 0, 3, 1, 5, 0, 0, 0, 1, 0x82, 0x87, 0x84]);
    let cases: [IdleCase<'_>; 5] = [
        ("nothing after TLS", &[], b""),
        ("start of the h2 preface", &[], b"PRI"),
        ("h2 preface and SETTINGS", &[b"h2"], &h2),
        ("h2 preface, no ALPN", &[], &h2),
        ("h2 request with a zero send window", &[b"h2"], &stalled),
    ];
    for (name, alpn, bytes) in cases {
        let mut tls = raw_tls(&h, alpn).await;
        if !bytes.is_empty() {
            tls.write_all(bytes).await.unwrap();
            tls.flush().await.unwrap();
        }
        // The idle limit (0.5 s) or the stall limit (2 s), and the grace time (1 s), with
        // a wide margin.
        let took = time_to_close(&mut tls, Duration::from_secs(10)).await;
        assert!(
            took < Duration::from_secs(7),
            "{name}: closed after {took:?}"
        );
    }
    // The connection slots are free again: a normal request works (no login: an Argon2
    // check in a debug build can take longer than the short stall limit of this test).
    let r = h.get("/api/v1/auth/session", &Creds::default()).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_token_uses_no_ban_try_and_resets_no_failure() {
    let argon_token = "rh_argon_token_for_the_ban_test_0000000000000";
    let argon_hash = rusthole_web::password::hash_password(argon_token).unwrap();
    let h = harness(Options {
        extra_toml: format!("\n[[admin.api_tokens]]\nname = \"argon\"\nhash = \"{argon_hash}\"\n"),
        ..Options::default()
    })
    .await;
    let s = h.login().await;
    let created = h
        .req(
            Method::POST,
            "/api/v1/tokens",
            Some(json!({"name": "script", "password": PASSWORD})),
            &s,
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let sha_token = created.body["secret"].as_str().unwrap().to_owned();
    let none = Creds::default();
    let bad_login = || async {
        h.req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": "wrong password"})),
            &none,
        )
        .await
    };
    for _ in 0..4 {
        assert_eq!(bad_login().await.status, StatusCode::UNAUTHORIZED);
    }
    // Parallel requests with a valid token all pass: they use no ban try.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let client = h.client.clone();
        let url = format!("{}/api/v1/lists", h.base);
        let token = sha_token.clone();
        tasks.push(tokio::spawn(async move {
            client
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::OK);
    }
    // A valid Argon2id token passes too, and gives its ban try back.
    let argon = Creds {
        bearer: Some(argon_token.to_owned()),
        ..Creds::default()
    };
    let r = h.get("/api/v1/lists", &argon).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    // The valid tokens did not reset the 4 failures: the 5th failure locks the address.
    assert_eq!(bad_login().await.status, StatusCode::UNAUTHORIZED);
    let r = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": PASSWORD})),
            &none,
        )
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.headers["retry-after"], "60");
    // During the lock, a valid token is refused too.
    let sha = Creds {
        bearer: Some(sha_token),
        ..Creds::default()
    };
    let r = h.get("/api/v1/lists", &sha).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.headers["retry-after"], "60");
    // After the lock, the token works again.
    h.clock.advance(Duration::from_secs(61));
    assert_eq!(h.get("/api/v1/lists", &sha).await.status, StatusCode::OK);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_header_connection_closes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let h = harness(Options {
        header_timeout: Duration::from_millis(500),
        ..Options::default()
    })
    .await;
    let mut tls = raw_tls(&h, &[]).await;
    // Half a header, then nothing.
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    tls.flush().await.unwrap();
    let mut buf = [0u8; 1024];
    let started = std::time::Instant::now();
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("the server must close the connection")
        .unwrap_or(0);
    // The server answers 408 or just closes; either way the connection ends.
    if n > 0 {
        let more = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(more, 0, "the connection must close");
    }
    assert!(started.elapsed() < Duration::from_secs(4));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_closes_off_net_clients_at_once() {
    use tokio::io::AsyncReadExt;
    // No loopback in the ACL: the client counts as off-net.
    let h = harness(Options {
        extra_toml: "\n[acl]\nauto_local = false\nallow = [\"192.0.2.0/24\"]\n".to_owned(),
        ..Options::default()
    })
    .await;
    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
        .await
        .expect("closed at once")
        .unwrap_or(0);
    assert_eq!(n, 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_open_connections() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    // A keep-alive connection is open in the client pool.
    assert_eq!(h.get("/api/v1/lists", &s).await.status, StatusCode::OK);
    assert!(h.server.task_count() >= 1);
    h.stop().await;
}
