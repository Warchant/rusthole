//! The route table and the middleware stack.
//!
//! The router is built only from [`ROUTES`]. The auth middleware reads the access level of
//! each route from the same table: deny by default, with an explicit public list. A test
//! calls each route of the table without credentials and expects 401, so a new route that
//! is not public cannot skip the auth.
//!
//! ```mermaid
//! flowchart LR
//!     req[request] --> sec[security headers] --> host[Host check: 421]
//!     host --> to[time limit]
//!     to -->|/api/v1| api[no-store, JSON errors, secret filter, cross-site writes: 403, body limit 64 KiB] --> auth[auth: 401 / 403 / 429] --> h[handler]
//!     to -->|other paths| ui[embedded UI]
//! ```

use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, patch, post, put};
use http::{HeaderValue, Method, StatusCode, header};
use tower_http::limit::RequestBodyLimitLayer;

use crate::error::{ApiError, misdirected};
use crate::host::{cross_site, host_allowed};
use crate::routes;
use crate::state::AppState;

/// The largest request body (docs/API.md section 1).
pub const MAX_BODY: usize = 64 * 1024;
/// The time limit of one request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest API response that the secret filter reads.
pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;
/// The base path of the API.
pub const API_BASE: &str = "/api/v1";

/// Who can use a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// No session or token needed.
    Public,
    /// A session or an API token.
    Auth,
    /// A session only (an API token gets 403).
    SessionOnly,
}

/// One route of the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDef {
    /// The HTTP method.
    pub method: &'static str,
    /// The path below `/api/v1`, in axum syntax (`/lists/{id}`).
    pub path: &'static str,
    /// Who can use it.
    pub access: Access,
}

macro_rules! route_table {
    ($( $method:ident $path:literal $access:ident => $handler:path; )*) => {
        /// All routes of the API.
        pub const ROUTES: &[RouteDef] = &[
            $( RouteDef { method: stringify!($method), path: $path, access: Access::$access }, )*
        ];

        fn add_routes(mut r: Router<AppState>) -> Router<AppState> {
            $( r = r.route($path, $method($handler)); )*
            r
        }
    };
}

route_table! {
    post "/auth/login" Public => routes::auth::login;
    post "/auth/logout" SessionOnly => routes::auth::logout;
    get "/auth/session" Public => routes::auth::session;
    get "/auth/totp" SessionOnly => routes::auth::totp_state;
    post "/auth/totp/setup" SessionOnly => routes::auth::totp_setup;
    post "/auth/totp/confirm" SessionOnly => routes::auth::totp_confirm;
    post "/auth/totp/disable" SessionOnly => routes::auth::totp_disable;
    get "/blocking" Auth => routes::misc::blocking_get;
    put "/blocking" Auth => routes::misc::blocking_put;
    get "/stats/summary" Auth => routes::stats::summary;
    get "/stats/timeline" Auth => routes::stats::timeline;
    get "/stats/hours" Auth => routes::stats::hours;
    get "/stats/top/domains" Auth => routes::stats::top_domains;
    get "/stats/top/blocked" Auth => routes::stats::top_blocked;
    get "/stats/top/clients" Auth => routes::stats::top_clients;
    get "/stats/query-types" Auth => routes::stats::query_types;
    get "/stats/upstreams" Auth => routes::stats::upstreams;
    get "/stats/clients" Auth => routes::stats::clients;
    get "/stats/clients/{key}" Auth => routes::stats::client;
    get "/stats/clients/{key}/domains" Auth => routes::stats::client_domains;
    get "/stats/domains" Auth => routes::stats::domains;
    get "/stats/domains/{name}" Auth => routes::stats::domain;
    get "/queries/recent" Auth => routes::stats::recent;
    get "/lists" Auth => routes::items::lists_list;
    post "/lists" Auth => routes::items::lists_create;
    post "/lists/update" Auth => routes::items::lists_update_all;
    get "/lists/{id}" Auth => routes::items::lists_get;
    patch "/lists/{id}" Auth => routes::items::lists_patch;
    delete "/lists/{id}" Auth => routes::items::lists_delete;
    post "/lists/{id}/update" Auth => routes::items::lists_update_one;
    get "/search/domain" Auth => routes::misc::search_domain;
    get "/report/domain/{name}/{section}" Auth => routes::report::domain;
    get "/rules" Auth => routes::items::rules_list;
    post "/rules" Auth => routes::items::rules_create;
    post "/rules/test" Auth => routes::items::rules_test;
    get "/rules/{id}" Auth => routes::items::rules_get;
    patch "/rules/{id}" Auth => routes::items::rules_patch;
    delete "/rules/{id}" Auth => routes::items::rules_delete;
    get "/groups" Auth => routes::items::groups_list;
    post "/groups" Auth => routes::items::groups_create;
    get "/groups/{id}" Auth => routes::items::groups_get;
    patch "/groups/{id}" Auth => routes::items::groups_patch;
    delete "/groups/{id}" Auth => routes::items::groups_delete;
    get "/clients" Auth => routes::items::clients_list;
    post "/clients" Auth => routes::items::clients_create;
    get "/clients/seen" Auth => routes::stats::clients_seen;
    get "/clients/{id}" Auth => routes::items::clients_get;
    patch "/clients/{id}" Auth => routes::items::clients_patch;
    delete "/clients/{id}" Auth => routes::items::clients_delete;
    get "/dns/records" Auth => routes::items::records_list;
    post "/dns/records" Auth => routes::items::records_create;
    get "/dns/records/{id}" Auth => routes::items::records_get;
    patch "/dns/records/{id}" Auth => routes::items::records_patch;
    delete "/dns/records/{id}" Auth => routes::items::records_delete;
    get "/dns/cnames" Auth => routes::items::cnames_list;
    post "/dns/cnames" Auth => routes::items::cnames_create;
    get "/dns/cnames/{id}" Auth => routes::items::cnames_get;
    patch "/dns/cnames/{id}" Auth => routes::items::cnames_patch;
    delete "/dns/cnames/{id}" Auth => routes::items::cnames_delete;
    get "/dns/forwarders" Auth => routes::items::forwarders_list;
    post "/dns/forwarders" Auth => routes::items::forwarders_create;
    get "/dns/forwarders/{id}" Auth => routes::items::forwarders_get;
    patch "/dns/forwarders/{id}" Auth => routes::items::forwarders_patch;
    delete "/dns/forwarders/{id}" Auth => routes::items::forwarders_delete;
    get "/tokens" Auth => routes::misc::tokens_list;
    post "/tokens" SessionOnly => routes::misc::tokens_create;
    delete "/tokens/{id}" Auth => routes::misc::tokens_delete;
    get "/settings" Auth => routes::misc::settings_get;
    patch "/settings" Auth => routes::misc::settings_patch;
    get "/audit" Auth => routes::misc::audit_list;
    get "/system" Auth => routes::misc::system;
    get "/system/tls" Auth => routes::misc::system_tls;
    get "/system/tls/ca.pem" Auth => routes::misc::system_tls_ca;
}

/// The access level of a matched route (`path` is the full matched path). `None` for a
/// path that is not in the table: the middleware then asks for auth (deny by default).
pub fn access_of(method: &Method, path: &str) -> Option<Access> {
    let rel = path.strip_prefix(API_BASE).unwrap_or(path);
    let m = method.as_str();
    ROUTES
        .iter()
        .find(|r| {
            r.path == rel
                && (r.method.eq_ignore_ascii_case(m) || (m == "HEAD" && r.method == "get"))
        })
        .map(|r| r.access)
}

/// Builds the full router: the API, the UI files and the middleware.
pub fn build(state: AppState) -> Router {
    let api = add_routes(Router::new())
        .route_layer(from_fn_with_state(state.clone(), crate::auth::require_auth))
        .fallback(api_not_found)
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .layer(from_fn_with_state(state.clone(), cross_site_guard))
        .layer(from_fn_with_state(state.clone(), secret_filter))
        .layer(from_fn(api_responses));
    Router::new()
        .nest(API_BASE, api)
        .route("/api", any(api_not_found_json))
        .route("/api/{*rest}", any(api_not_found_json))
        .fallback(crate::assets::serve)
        .layer(from_fn(time_limit))
        .layer(from_fn_with_state(state.clone(), host_check))
        .layer(from_fn(security_headers))
        .with_state(state)
}

async fn api_not_found() -> Response {
    ApiError::not_found().into_response()
}

async fn api_not_found_json() -> Response {
    no_store(ApiError::not_found().into_response())
}

/// The Content-Security-Policy of every response.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Adds the security headers to every response (decision D9).
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut http::HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "content-security-policy", CSP);
    set(h, "strict-transport-security", "max-age=31536000");
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "no-referrer");
    set(
        h,
        "permissions-policy",
        "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()",
    );
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "cross-origin-resource-policy", "same-origin");
    set(h, "x-frame-options", "DENY");
    resp
}

/// The `Host` check (DNS rebinding defence): 421 for a host that does not name this server.
async fn host_check(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let host = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_owned())
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    if host_allowed(&host, &state.net().hosts) {
        next.run(req).await
    } else {
        tracing::debug!(host = %host.chars().take(64).collect::<String>(), "Host header refused");
        no_store(misdirected().into_response())
    }
}

/// The cross-site guard of the API (m12): 403 for a write with the `Origin` of another site
/// or with `Sec-Fetch-Site: cross-site` ([`cross_site`]). It runs before the auth, so such a
/// request never counts in the login ban.
async fn cross_site_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let h = req.headers();
    let site = h
        .get("sec-fetch-site")
        .map(|v| v.to_str().unwrap_or("cross-site"));
    let origins = h.get_all(header::ORIGIN).iter().map(|v| v.to_str().ok());
    if cross_site(req.method().as_str(), site, origins, &state.net().hosts) {
        tracing::debug!(method = %req.method(), "cross-site write refused");
        return ApiError::forbidden("A write from another site is not allowed.").into_response();
    }
    next.run(req).await
}

/// The time limit of a request.
async fn time_limit(req: Request, next: Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(r) => r,
        Err(_) => ApiError::for_status(StatusCode::REQUEST_TIMEOUT).into_response(),
    }
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn is_json(resp: &Response) -> bool {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
}

/// API responses: `Cache-Control: no-store`, and every error has the JSON error body (also
/// the errors of axum itself, for example 405 or 413).
async fn api_responses(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let status = resp.status();
    let resp = if status.as_u16() >= 400 && !is_json(&resp) {
        ApiError::for_status(status).into_response()
    } else {
        resp
    };
    no_store(resp)
}

/// The secret filter: a last check that no API response has a secret of the config (the
/// password hash, the TOTP secret, a token hash). A response with a secret is replaced with
/// 500 and an ERROR log line. The handlers never put a secret in a response; this filter
/// catches a fault.
async fn secret_filter(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    if !is_json(&resp) {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_RESPONSE).await else {
        tracing::error!("an API response is too large for the secret filter");
        return ApiError::internal().into_response();
    };
    let cfg = state.config();
    if let Some(what) = find_secret(&bytes, &cfg) {
        tracing::error!(
            what,
            "an API response had a secret; the response was replaced"
        );
        return ApiError::internal().into_response();
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// The kind of the first config secret that `body` holds, if any.
pub fn find_secret(body: &[u8], cfg: &rusthole_core::Config) -> Option<&'static str> {
    let has = |s: &str| !s.is_empty() && contains(body, s.as_bytes());
    if has(&cfg.admin.password_hash) {
        return Some("password hash");
    }
    if has(&cfg.admin.totp_secret) {
        return Some("TOTP secret");
    }
    for t in &cfg.admin.api_tokens {
        let hex = t.hash.strip_prefix("sha256:").unwrap_or(&t.hash);
        if has(&t.hash) || has(hex) {
            return Some("token hash");
        }
    }
    None
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_is_unique_and_below_the_api() {
        let mut seen = std::collections::HashSet::new();
        for r in ROUTES {
            assert!(r.path.starts_with('/'), "{r:?}");
            assert!(seen.insert((r.method, r.path)), "twice: {r:?}");
        }
        let public: Vec<_> = ROUTES
            .iter()
            .filter(|r| r.access == Access::Public)
            .map(|r| (r.method, r.path))
            .collect();
        assert_eq!(public, [("post", "/auth/login"), ("get", "/auth/session")]);
    }

    #[test]
    fn access_lookup() {
        assert_eq!(
            access_of(&Method::POST, "/api/v1/auth/login"),
            Some(Access::Public)
        );
        assert_eq!(
            access_of(&Method::POST, "/api/v1/tokens"),
            Some(Access::SessionOnly)
        );
        assert_eq!(
            access_of(&Method::GET, "/api/v1/lists/{id}"),
            Some(Access::Auth)
        );
        assert_eq!(access_of(&Method::GET, "/api/v1/nothing"), None);
    }

    /// A state with a config file in `dir` that has a password hash.
    fn test_state(dir: &std::path::Path) -> AppState {
        use std::sync::Arc;
        let path = dir.join("rusthole.toml");
        let text = "config_version = 1\n[admin]\npassword_hash = \"$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo\"\n";
        std::fs::write(&path, text).unwrap();
        let (store, _) = crate::config_edit::ConfigStore::open(&path).unwrap();
        AppState::new(crate::state::AdminDeps {
            config: Arc::new(store),
            clock: crate::clock::ManualClock::new(0),
            stats: None,
            lists: None,
            engine: rusthole_dns::engine_handle(rusthole_core::PolicyEngine::default()),
            blocking: Arc::new(rusthole_dns::BlockingControl::new(true)),
            live: Arc::new(crate::state::NoLiveApply),
            tls: None,
            system: crate::state::SystemStatic::default(),
            interfaces: Arc::new(rusthole_dns::StaticInterfaces::default()),
            assets: Arc::new(crate::assets::PlaceholderAssets),
            report: None,
        })
    }

    #[tokio::test]
    async fn secret_filter_replaces_a_leaking_response() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let hash = state.config().admin.password_hash.clone();
        let leak = axum::Router::new()
            .route(
                "/leak",
                get(move || {
                    let h = hash.clone();
                    async move { axum::Json(serde_json::json!({ "x": h })) }
                }),
            )
            .route(
                "/fine",
                get(|| async { axum::Json(serde_json::json!({ "x": 1 })) }),
            )
            .layer(from_fn_with_state(state.clone(), secret_filter))
            .with_state(state);
        let req = |p: &str| Request::builder().uri(p).body(Body::empty()).unwrap();
        let r = leak.clone().oneshot(req("/leak")).await.unwrap();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("argon2id"));
        let r = leak.oneshot(req("/fine")).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn secret_search() {
        let mut cfg = rusthole_core::Config::default();
        cfg.admin.totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DP".to_owned();
        assert_eq!(
            find_secret(b"{\"a\":\"JBSWY3DPEHPK3PXPJBSWY3DP\"}", &cfg),
            Some("TOTP secret")
        );
        assert_eq!(find_secret(b"{\"a\":1}", &cfg), None);
    }
}
