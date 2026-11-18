//! Integration tests of the review fixes for the admin listener (lane F3): sessions end on a
//! credential change (m13), the cross-site guard of the login (m12), and a failed bind of
//! one admin address (m16).

// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right
// result. Short names (h, s, r) keep the request chains readable.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::indexing_slicing,
    clippy::many_single_char_names
)]

mod common;

use std::time::Duration;

use common::{Creds, Harness, Options, PASSWORD, harness};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const NEW_PASSWORD: &str = "a new long password";

/// The TOTP secret from the setup response, and a function that gives the code at a time.
fn secret_of(setup: &Value) -> Vec<u8> {
    let uri = setup["otpauth_uri"].as_str().unwrap();
    let secret = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    rusthole_web::totp::base32_decode(secret).unwrap()
}

fn code_at(key: &[u8], wall: i64) -> String {
    format!(
        "{:06}",
        rusthole_web::totp::code_at(key, rusthole_web::totp::step_of(wall))
    )
}

async fn works(h: &Harness, s: &Creds) -> bool {
    h.get("/api/v1/blocking", s).await.status == StatusCode::OK
}

/// m13: `rusthole passwd` changes the file. The server must see the change at the next
/// request and end every open session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_password_change_on_disk_ends_all_sessions() {
    let h = harness(Options::default()).await;
    let s1 = h.login().await;
    let s2 = h.login().await;
    assert!(works(&h, &s1).await);
    assert!(works(&h, &s2).await);
    let hash = rusthole_web::password::hash_password(NEW_PASSWORD).unwrap();
    rusthole_web::config_edit::edit_file(&h.config_path, |c| c.admin.password_hash = hash).unwrap();
    // The refresh of the file runs at most one time in 2 s.
    h.clock.advance(Duration::from_secs(3));
    assert!(!works(&h, &s1).await, "an old session must end");
    assert!(!works(&h, &s2).await, "an old session must end");
    let probe = h.get("/api/v1/auth/session", &s1).await;
    assert_eq!(probe.status, StatusCode::UNAUTHORIZED);
    // The new password works; the old one does not.
    let old = h
        .req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": PASSWORD})),
            &Creds::default(),
        )
        .await;
    assert_eq!(old.code(), "invalid_credentials");
    let s3 = h.login_with(json!({"password": NEW_PASSWORD})).await;
    assert!(works(&h, &s3).await);
    h.stop().await;
}

/// m13: the session probe also sees a password change on disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_session_probe_sees_a_password_change_on_disk() {
    let h = harness(Options::default()).await;
    let s1 = h.login().await;
    let hash = rusthole_web::password::hash_password(NEW_PASSWORD).unwrap();
    rusthole_web::config_edit::edit_file(&h.config_path, |c| c.admin.password_hash = hash).unwrap();
    h.clock.advance(Duration::from_secs(3));
    let probe = h.get("/api/v1/auth/session", &s1).await;
    assert_eq!(probe.status, StatusCode::UNAUTHORIZED, "{}", probe.text);
    h.stop().await;
}

/// m13: a TOTP change through the API ends the other sessions. The session that made the
/// change stays: it gave the password and a code in the same flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_totp_change_through_the_api_ends_the_other_sessions() {
    let h = harness(Options::default()).await;
    let me = h.login().await;
    let other = h.login().await;
    let setup = h
        .req(
            Method::POST,
            "/api/v1/auth/totp/setup",
            Some(json!({"password": PASSWORD})),
            &me,
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.text);
    let key = secret_of(&setup.body);
    let wall = common::WALL;
    let confirm = h
        .req(
            Method::POST,
            "/api/v1/auth/totp/confirm",
            Some(json!({"code": code_at(&key, wall)})),
            &me,
        )
        .await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text);
    assert!(
        works(&h, &me).await,
        "the session that made the change stays"
    );
    assert!(!works(&h, &other).await, "the other session must end");

    // Turn TOTP off: a session made with TOTP on ends; the caller stays.
    h.clock.advance(Duration::from_secs(30));
    let other2 = h
        .login_with(json!({"password": PASSWORD, "totp": code_at(&key, wall + 30)}))
        .await;
    h.clock.advance(Duration::from_secs(30));
    let off = h
        .req(
            Method::POST,
            "/api/v1/auth/totp/disable",
            Some(json!({"password": PASSWORD, "code": code_at(&key, wall + 60)})),
            &me,
        )
        .await;
    assert_eq!(off.status, StatusCode::OK, "{}", off.text);
    assert!(works(&h, &me).await);
    assert!(!works(&h, &other2).await, "the other session must end");
    h.stop().await;
}

/// m13: an API token is not a session; a password change does not revoke it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_password_change_keeps_api_tokens() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let tok = h
        .req(
            Method::POST,
            "/api/v1/tokens",
            Some(json!({"name": "t", "password": PASSWORD})),
            &s,
        )
        .await;
    let bearer = Creds {
        bearer: Some(tok.body["secret"].as_str().unwrap().to_owned()),
        ..Creds::default()
    };
    let hash = rusthole_web::password::hash_password(NEW_PASSWORD).unwrap();
    rusthole_web::config_edit::edit_file(&h.config_path, |c| c.admin.password_hash = hash).unwrap();
    h.clock.advance(Duration::from_secs(3));
    assert!(works(&h, &bearer).await);
    assert!(!works(&h, &s).await);
    h.stop().await;
}

/// A login request with a wrong password, the given headers and no `Content-Type` unless
/// `headers` has one.
async fn bad_login(h: &Harness, body: &Value, headers: &[(&str, &str)]) -> StatusCode {
    let mut r = h
        .client
        .post(format!("{}/api/v1/auth/login", h.base))
        .body(serde_json::to_vec(body).unwrap());
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.send().await.unwrap().status()
}

/// m12: a login body with no JSON `Content-Type` gets 415 before the ban counts it. A page
/// of another site can send such a request with no preflight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_without_a_json_content_type_gets_415_and_no_ban_count() {
    let h = harness(Options::default()).await;
    let body = json!({"password": "wrong password"});
    for ct in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
    ] {
        for _ in 0..3 {
            let headers: Vec<(&str, &str)> = ct.map(|c| ("content-type", c)).into_iter().collect();
            assert_eq!(
                bad_login(&h, &body, &headers).await,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{ct:?}"
            );
        }
    }
    // Upper case is the same media type.
    let r = bad_login(
        &h,
        &json!({"password": PASSWORD}),
        &[("content-type", "Application/JSON; charset=utf-8")],
    )
    .await;
    assert_eq!(r, StatusCode::OK);
    // No lock: the login works.
    h.login().await;
    h.stop().await;
}

/// m12: a write request with the `Origin` of another site, `Origin: null` or
/// `Sec-Fetch-Site: cross-site` gets 403 before the ban counts it. Also with TOTP on and a
/// `totp` field (else the attempt does not count at all).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cross_site_login_gets_403_and_no_ban_count() {
    let h = harness(Options::default()).await;
    let secret = rusthole_web::totp::base32_encode(&[7u8; 20]);
    let key = rusthole_web::totp::base32_decode(&secret).unwrap();
    rusthole_web::config_edit::edit_file(&h.config_path, |c| c.admin.totp_secret = secret).unwrap();
    h.clock.advance(Duration::from_secs(3));
    let body = json!({"password": "wrong password", "totp": "123456"});
    let json_ct = ("content-type", "application/json");
    let cases: [&[(&str, &str)]; 6] = [
        &[json_ct, ("origin", "https://evil.example")],
        &[json_ct, ("origin", "null")],
        &[json_ct, ("origin", "http://127.0.0.1:8443")],
        &[json_ct, ("origin", "https://127.0.0.1:1")],
        &[json_ct, ("sec-fetch-site", "cross-site")],
        &[
            json_ct,
            ("origin", "https://evil.example"),
            ("sec-fetch-site", "same-origin"),
        ],
    ];
    for headers in cases {
        for _ in 0..2 {
            assert_eq!(
                bad_login(&h, &body, headers).await,
                StatusCode::FORBIDDEN,
                "{headers:?}"
            );
        }
    }
    // The admin origin and a request with no Origin (curl, scripts) pass.
    let origin = h.base.clone();
    let wall = common::WALL + 3;
    let ok = h
        .req_with(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"password": PASSWORD, "totp": code_at(&key, wall)})),
            &Creds::default(),
            &[("origin", &origin), ("sec-fetch-site", "same-origin")],
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text);
    h.stop().await;
}

/// m12: the guard covers every write of the API, also with a valid session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cross_site_write_with_a_session_gets_403() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let r = h
        .req_with(
            Method::PUT,
            "/api/v1/blocking",
            Some(json!({"enabled": false})),
            &s,
            &[("origin", "https://evil.example")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text);
    assert!(
        h.get("/api/v1/blocking", &s).await.body["enabled"]
            .as_bool()
            .unwrap()
    );
    // A GET with a foreign Origin is not a write: it passes the guard.
    let g = h
        .req_with(
            Method::GET,
            "/api/v1/blocking",
            None,
            &s,
            &[("sec-fetch-site", "cross-site")],
        )
        .await;
    assert_eq!(g.status, StatusCode::OK);
    h.stop().await;
}

/// m16: one admin address that cannot be bound is an error in the log, not a start error,
/// when another address is bound. No address at all is still an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_failed_admin_bind_keeps_the_other_addresses() {
    let h = harness(Options::default()).await;
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_addr = busy.local_addr().unwrap();
    let certs = h.state.deps().tls.clone().unwrap();
    let tls = rusthole_tls::admin_server_config(&certs).unwrap();
    let settings =
        rusthole_web::AdminSettings::new(vec![busy_addr, "127.0.0.1:0".parse().unwrap()]);
    let server = rusthole_web::start(settings, std::sync::Arc::clone(&tls), h.state.clone())
        .await
        .unwrap();
    assert_eq!(server.bound().len(), 1);
    assert_ne!(server.bound()[0], busy_addr);
    assert!(server.shutdown(Duration::from_secs(5)).await);
    let only_busy = rusthole_web::AdminSettings::new(vec![busy_addr]);
    assert!(
        rusthole_web::start(only_busy, tls, h.state.clone())
            .await
            .is_err()
    );
    drop(busy);
    h.stop().await;
}
