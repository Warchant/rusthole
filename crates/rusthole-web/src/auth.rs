//! Authentication: sessions, API tokens, the login ban, CSRF and the auth middleware
//! (decisions D9, D10, amendment A7). docs/SECURITY.md describes the rules.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method, header};
use parking_lot::Mutex;
use rusthole_core::Config;
use rusthole_core::ban::{BanEvent, BanOutcome, BanPolicy, BanTable, EntryState};
use rusthole_core::session::{SessionPolicy, SessionTable};
use rusthole_store::NewAudit;
use tokio::sync::Semaphore;

use crate::error::{ApiError, ApiResult};
use crate::router::{Access, access_of};
use crate::state::{AppState, ClientAddr};
use crate::util::{b64url, ct_eq, hex, random_bytes, sha256};

/// The session cookie name. The `__Host-` prefix makes the browser refuse the cookie
/// unless it has `Secure`, `Path=/` and no `Domain`.
pub const COOKIE: &str = "__Host-rusthole_session";
/// The CSRF header.
pub const CSRF_HEADER: &str = "x-csrf-token";
/// Parallel Argon2 checks, at most (amendment A7).
pub const MAX_PARALLEL_VERIFY: usize = 2;
/// Time limit to wait for an Argon2 slot.
pub const VERIFY_WAIT: Duration = Duration::from_secs(10);
/// Time limit for one Argon2 check.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// Time limit for the auth lock.
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
/// A pending TOTP setup ends after this time.
pub const TOTP_SETUP_TTL: Duration = Duration::from_secs(600);
/// The largest number of tokens with a "last used" record.
const MAX_TOKEN_USE: usize = 1024;
/// The prefix of an API token.
pub const TOKEN_PREFIX: &str = "rh_";
/// The longest bearer token that the server reads.
const MAX_TOKEN_LEN: usize = 256;

/// Who sent a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A browser session.
    Session {
        /// SHA-256 of the session id.
        key: [u8; 32],
    },
    /// An API token.
    Token {
        /// The token id.
        id: u32,
    },
}

impl Principal {
    /// The actor of the audit log: `session` or `token:{id}`.
    pub fn actor(&self) -> String {
        match self {
            Self::Session { .. } => "session".to_owned(),
            Self::Token { id } => format!("token:{id}"),
        }
    }
}

/// The data of a session.
#[derive(Debug, Clone)]
pub(crate) struct SessionData {
    pub(crate) csrf: String,
}

/// A TOTP setup that waits for its confirm.
#[derive(Debug, Clone)]
pub(crate) struct PendingTotp {
    pub(crate) secret: String,
    pub(crate) expires: rusthole_core::blocking_state::MonoTime,
}

pub(crate) struct AuthInner {
    pub(crate) sessions: SessionTable<SessionData>,
    pub(crate) ban: BanTable,
    pub(crate) totp_pending: Option<PendingTotp>,
    pub(crate) totp_last_step: Option<i64>,
    pub(crate) token_use: HashMap<u32, (i64, IpAddr)>,
}

/// The auth state.
pub(crate) struct Auth {
    inner: Mutex<AuthInner>,
    verify: Arc<Semaphore>,
}

impl Auth {
    pub(crate) fn new(cfg: &Config) -> Self {
        Self {
            inner: Mutex::new(AuthInner {
                sessions: SessionTable::new(SessionPolicy::from_ttl_seconds(
                    cfg.admin.session_ttl_seconds,
                )),
                ban: BanTable::new(BanPolicy::default()),
                totp_pending: None,
                totp_last_step: None,
                token_use: HashMap::new(),
            }),
            verify: Arc::new(Semaphore::new(MAX_PARALLEL_VERIFY)),
        }
    }

    /// Locks the state with a time limit.
    pub(crate) fn lock(&self) -> ApiResult<parking_lot::MutexGuard<'_, AuthInner>> {
        self.inner
            .try_lock_for(LOCK_TIMEOUT)
            .ok_or_else(|| ApiError::unavailable("The server is busy. Try again."))
    }

    /// Uses the session lifetime of a new config. When the TOTP secret changed, the TOTP
    /// replay record and the pending TOTP setup are cleared: the steps of the old secret do
    /// not apply to the new secret.
    pub(crate) fn set_config(&self, old: &Config, cfg: &Config) {
        match self.lock() {
            Ok(mut a) => {
                a.sessions.set_policy(SessionPolicy::from_ttl_seconds(
                    cfg.admin.session_ttl_seconds,
                ));
                let ids: Vec<u32> = cfg.admin.api_tokens.iter().filter_map(|t| t.id).collect();
                a.token_use.retain(|id, _| ids.contains(id));
                if !ct_eq(
                    old.admin.totp_secret.as_bytes(),
                    cfg.admin.totp_secret.as_bytes(),
                ) {
                    a.totp_last_step = None;
                    a.totp_pending = None;
                }
            }
            Err(_) => {
                tracing::error!("the auth lock timed out; the new auth config is not applied");
            }
        }
    }
}

/// The client address of a request (from the server). A request with no address (only in
/// tests that skip the server) counts as `0.0.0.0`.
pub(crate) fn client_ip(req_ext: &http::Extensions) -> IpAddr {
    req_ext
        .get::<ClientAddr>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip())
}

/// One attempt in the ban machine. Dropping it without [`Attempt::finish`] counts as a
/// failure (the request stopped in the middle, for example a closed connection).
pub(crate) struct Attempt {
    state: AppState,
    ip: IpAddr,
    done: bool,
}

impl Attempt {
    /// Starts an attempt: 429 during a ban.
    pub(crate) fn begin(state: &AppState, ip: IpAddr) -> ApiResult<Self> {
        let now = state.clock().mono();
        let out = state.0.auth.lock()?.ban.begin(ip, now);
        match out {
            BanOutcome::Allowed => Ok(Self {
                state: state.clone(),
                ip,
                done: false,
            }),
            BanOutcome::Banned { retry_after }
            | BanOutcome::Rejected { retry_after }
            | BanOutcome::Invalid { retry_after } => Err(ApiError::rate_limited(retry_after)),
            BanOutcome::Counted { .. } | BanOutcome::Done => {
                tracing::error!(?out, "unexpected ban outcome for begin; refusing");
                Err(ApiError::rate_limited(Duration::from_secs(1)))
            }
        }
    }

    fn step(&mut self, event: BanEvent) -> BanOutcome {
        self.done = true;
        let now = self.state.clock().mono();
        if let Ok(mut a) = self.state.0.auth.lock() {
            a.ban.step(self.ip, event, now)
        } else {
            tracing::error!(ip = %self.ip, ?event, "the auth lock timed out; the ban event is lost");
            BanOutcome::Invalid {
                retry_after: Duration::from_secs(1),
            }
        }
    }

    /// The check failed. Writes the audit lines; returns the error to send.
    pub(crate) async fn fail(mut self, actor: &str, detail: &str) -> ApiError {
        let out = self.step(BanEvent::Failure);
        let state = self.state.clone();
        let ip = self.ip;
        let at = state.clock().wall();
        state
            .audit(NewAudit {
                at,
                action: "auth.login_failed".to_owned(),
                target: None,
                actor: actor.to_owned(),
                client_ip: Some(ip),
                ok: false,
                detail: Some(detail.to_owned()),
            })
            .await;
        if let BanOutcome::Counted { locked: Some(lock) } = out {
            tracing::warn!(%ip, seconds = lock.as_secs(), "login ban");
            state
                .audit(NewAudit {
                    at,
                    action: "auth.ban".to_owned(),
                    target: Some(format!("ip:{ip}")),
                    actor: actor.to_owned(),
                    client_ip: Some(ip),
                    ok: true,
                    detail: Some(format!("{} s", lock.as_secs())),
                })
                .await;
        }
        ApiError::invalid_credentials()
    }

    /// The check worked. `Err` when the address was locked in the meantime.
    pub(crate) fn succeed(mut self) -> ApiResult<()> {
        match self.step(BanEvent::Success) {
            BanOutcome::Done => Ok(()),
            BanOutcome::Rejected { retry_after } | BanOutcome::Invalid { retry_after } => {
                Err(ApiError::rate_limited(retry_after))
            }
            other => {
                tracing::error!(?other, "unexpected ban outcome for success; refusing");
                Err(ApiError::rate_limited(Duration::from_secs(1)))
            }
        }
    }

    /// The attempt ended with no check (it does not count).
    pub(crate) fn cancel(mut self) {
        self.step(BanEvent::Cancel);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.done {
            self.step(BanEvent::Failure);
        }
    }
}

/// Checks a password against `admin.password_hash` on a blocking thread, with at most
/// [`MAX_PARALLEL_VERIFY`] checks at a time.
pub(crate) async fn verify_password(state: &AppState, password: String) -> ApiResult<bool> {
    let hash = state.config().admin.password_hash.clone();
    if hash.is_empty() {
        return Ok(false);
    }
    run_verify(state, move || {
        crate::password::verify_password(&password, &hash)
    })
    .await
}

async fn run_verify(
    state: &AppState,
    f: impl FnOnce() -> bool + Send + 'static,
) -> ApiResult<bool> {
    let permit = tokio::time::timeout(
        VERIFY_WAIT,
        Arc::clone(&state.0.auth.verify).acquire_owned(),
    )
    .await
    .map_err(|_| ApiError::unavailable("Too many logins at the same time. Try again."))?
    .map_err(|_| ApiError::internal())?;
    let task = tokio::task::spawn_blocking(move || {
        let ok = f();
        drop(permit);
        ok
    });
    match tokio::time::timeout(VERIFY_TIMEOUT, task).await {
        Ok(Ok(ok)) => Ok(ok),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "the password check task failed");
            Err(ApiError::internal())
        }
        Err(_) => Err(ApiError::unavailable("The password check took too long.")),
    }
}

/// Makes a new session. Returns the cookie value and the CSRF token.
pub(crate) fn new_session(state: &AppState) -> ApiResult<(String, String, i64)> {
    let id = b64url(&random_bytes::<32>().map_err(|_| ApiError::internal())?);
    let csrf = b64url(&random_bytes::<32>().map_err(|_| ApiError::internal())?);
    let now = state.clock().mono();
    let mut a = state.0.auth.lock()?;
    a.sessions.insert(
        sha256(id.as_bytes()),
        SessionData { csrf: csrf.clone() },
        now,
    );
    let deadline = a
        .sessions
        .touch(&sha256(id.as_bytes()), now)
        .map_or(now, |(_, d)| d);
    drop(a);
    Ok((id, csrf, expires_at(state, deadline)))
}

/// The wall time (Unix seconds) of a monotonic deadline.
pub(crate) fn expires_at(
    state: &AppState,
    deadline: rusthole_core::blocking_state::MonoTime,
) -> i64 {
    let left = deadline.saturating_since(state.clock().mono());
    state
        .clock()
        .wall()
        .saturating_add(i64::try_from(left.as_secs()).unwrap_or(i64::MAX))
}

/// The `Set-Cookie` value of a session.
pub(crate) fn session_cookie(id: &str) -> String {
    format!("{COOKIE}={id}; Path=/; Secure; HttpOnly; SameSite=Strict")
}

/// The `Set-Cookie` value that clears the session cookie.
pub(crate) fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// The session id from the `Cookie` headers.
pub(crate) fn cookie_value(headers: &HeaderMap) -> Option<String> {
    for v in headers.get_all(header::COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, val)) = part.trim().split_once('=')
                && k == COOKIE
                && !val.is_empty()
                && val.len() <= 128
            {
                return Some(val.to_owned());
            }
        }
    }
    None
}

/// The session of a request: its key and CSRF token, when it is live. It moves the idle
/// limit.
pub(crate) fn session_of(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<Option<([u8; 32], String, i64)>> {
    let Some(id) = cookie_value(headers) else {
        return Ok(None);
    };
    let key = sha256(id.as_bytes());
    let now = state.clock().mono();
    let found = state
        .0
        .auth
        .lock()?
        .sessions
        .touch(&key, now)
        .map(|(d, deadline)| (d.csrf.clone(), deadline));
    Ok(found.map(|(csrf, deadline)| (key, csrf, expires_at(state, deadline))))
}

/// True when the `X-CSRF-Token` header equals the session token (constant time).
pub fn csrf_ok(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|got| ct_eq(got.as_bytes(), expected.as_bytes()))
}

/// The `Authorization` header of a request.
#[derive(Debug, PartialEq, Eq)]
enum Bearer {
    /// No header.
    Absent,
    /// A header that is not a valid bearer header (it counts as a failed token).
    Bad,
    /// A bearer token.
    Token(String),
}

fn bearer(headers: &HeaderMap) -> Bearer {
    let Some(v) = headers.get(header::AUTHORIZATION) else {
        return Bearer::Absent;
    };
    v.to_str()
        .ok()
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN_LEN)
        .map_or(Bearer::Bad, |t| Bearer::Token(t.to_owned()))
}

/// Finds the token id of a bearer token among the `sha256:` token hashes. The compare is
/// constant time and fast, so it uses no ban try.
fn sha256_token_id(cfg: &Config, token: &str) -> Option<u32> {
    let digest = format!("sha256:{}", hex(&sha256(token.as_bytes())));
    let mut found = None;
    for t in &cfg.admin.api_tokens {
        // Compare with every token: the time does not show which one matched.
        if ct_eq(t.hash.as_bytes(), digest.as_bytes()) && found.is_none() {
            found = t.id;
        }
    }
    found
}

/// Finds the token id of a bearer token among the Argon2id token hashes. Each check uses a
/// password slot (slow).
async fn argon_token_id(state: &AppState, token: &str) -> ApiResult<Option<u32>> {
    let cfg = state.config();
    let argon: Vec<(Option<u32>, String)> = cfg
        .admin
        .api_tokens
        .iter()
        .filter(|t| t.hash.starts_with("$argon2id$"))
        .map(|t| (t.id, t.hash.clone()))
        .collect();
    for (id, hash) in argon {
        let tok = token.to_owned();
        if run_verify(state, move || crate::password::verify_password(&tok, &hash)).await? {
            return Ok(id);
        }
    }
    Ok(None)
}

/// The auth middleware for `/api/v1`. Deny by default: only the routes that the route
/// table marks as public pass without a session or a token.
pub(crate) async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(String::new, |m| m.as_str().to_owned());
    let access = access_of(req.method(), &path);
    if access == Some(Access::Public) {
        return next.run(req).await;
    }
    let headers = req.headers().clone();
    let method = req.method().clone();
    let ip = client_ip(req.extensions());
    match authenticate(&state, &headers, &method, ip, access).await {
        Ok(principal) => {
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// 429 when the address is locked now. It reads the ban state and reserves no try.
fn refuse_if_locked(state: &AppState, ip: IpAddr) -> ApiResult<()> {
    let now = state.clock().mono();
    let entry = state.0.auth.lock()?.ban.state(ip);
    match entry {
        Some(EntryState::Locked { until, .. }) if now < until => Err(ApiError::rate_limited(
            until.saturating_since(now).max(Duration::from_secs(1)),
        )),
        _ => Ok(()),
    }
}

/// Checks a bearer header and returns the token id.
///
/// - A locked address gets 429.
/// - A `sha256:` hash match uses no ban try, so parallel requests with a valid token all
///   pass.
/// - Only a slow Argon2id check reserves a ban try.
/// - A miss counts as a ban failure.
/// - A valid token never resets the failure count of the ban. Passwords and TOTP codes are
///   the last guard of `POST /tokens` and the TOTP paths, so a token holder must not get
///   more guesses.
async fn token_principal(state: &AppState, token: &Bearer, ip: IpAddr) -> ApiResult<u32> {
    refuse_if_locked(state, ip)?;
    let text = match token {
        Bearer::Token(t) => Some(t.as_str()),
        Bearer::Bad | Bearer::Absent => None,
    };
    if let Some(id) = text.and_then(|t| sha256_token_id(&state.config(), t)) {
        return Ok(id);
    }
    let attempt = Attempt::begin(state, ip)?;
    let slow = match text {
        Some(t) => match argon_token_id(state, t).await {
            Ok(found) => found,
            Err(e) => {
                // No check was done (the server is busy): this does not count.
                attempt.cancel();
                return Err(e);
            }
        },
        None => None,
    };
    let Some(id) = slow else {
        attempt.fail("anonymous", "api token").await;
        return Err(ApiError::unauthorized());
    };
    // Give the try back with no reset of the failure count (not `Success`).
    attempt.cancel();
    // Other attempts can have locked the address during the slow check.
    refuse_if_locked(state, ip)?;
    Ok(id)
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    ip: IpAddr,
    access: Option<Access>,
) -> ApiResult<Principal> {
    let token = bearer(headers);
    if token != Bearer::Absent {
        let id = token_principal(state, &token, ip).await?;
        let wall = state.clock().wall();
        if let Ok(mut a) = state.0.auth.lock()
            && (a.token_use.len() < MAX_TOKEN_USE || a.token_use.contains_key(&id))
        {
            a.token_use.insert(id, (wall, ip));
        }
        if access == Some(Access::SessionOnly) {
            return Err(ApiError::forbidden("An API token cannot use this path."));
        }
        return Ok(Principal::Token { id });
    }
    let Some((key, csrf, _)) = session_of(state, headers)? else {
        return Err(ApiError::unauthorized());
    };
    let safe = matches!(*method, Method::GET | Method::HEAD);
    if !safe && !csrf_ok(headers, &csrf) {
        return Err(ApiError::csrf_failed());
    }
    Ok(Principal::Session { key })
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=b; __Host-rusthole_session=abc; c=d"),
        );
        assert_eq!(cookie_value(&h).as_deref(), Some("abc"));
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("rusthole_session=abc"),
        );
        assert_eq!(cookie_value(&h), None);
    }

    #[test]
    fn cookie_attributes() {
        let c = session_cookie("x");
        for part in ["__Host-", "Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(c.contains(part), "{c}");
        }
        assert!(!c.contains("Domain"));
        assert!(!c.contains("Max-Age"));
        assert!(clear_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn bearer_parsing() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer(&h), Bearer::Absent);
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer rh_x"),
        );
        assert_eq!(bearer(&h), Bearer::Token("rh_x".to_owned()));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&h), Bearer::Bad);
    }

    /// A new TOTP secret clears the replay record of the old secret: the first valid code
    /// of the new secret at the same step is accepted.
    #[test]
    fn new_totp_secret_clears_the_replay_record() {
        let now = 1_794_903_000;
        let old_secret = crate::totp::base32_encode(&[1u8; 20]);
        let new_secret = crate::totp::base32_encode(&[2u8; 20]);
        let mut old = Config::default();
        old.admin.totp_secret.clone_from(&old_secret);
        let auth = Auth::new(&old);
        let code_of = |secret: &str| {
            let key = crate::totp::base32_decode(secret).unwrap();
            format!(
                "{:06}",
                crate::totp::code_at(&key, crate::totp::step_of(now))
            )
        };
        // A login accepts a code of the old secret.
        let step = crate::totp::verify(&old_secret, &code_of(&old_secret), now, None).unwrap();
        {
            let mut a = auth.lock().unwrap();
            a.totp_last_step = Some(step);
            a.totp_pending = Some(PendingTotp {
                secret: new_secret.clone(),
                expires: rusthole_core::blocking_state::MonoTime::from_duration(
                    Duration::from_secs(600),
                ),
            });
        }
        // A config change with the same secret keeps the record.
        auth.set_config(&old, &old);
        assert_eq!(auth.lock().unwrap().totp_last_step, Some(step));
        // A new secret clears the record and the pending setup.
        let mut new = old.clone();
        new.admin.totp_secret.clone_from(&new_secret);
        auth.set_config(&old, &new);
        let a = auth.lock().unwrap();
        assert_eq!(a.totp_last_step, None);
        assert!(a.totp_pending.is_none());
        assert_eq!(
            crate::totp::verify(&new_secret, &code_of(&new_secret), now, a.totp_last_step),
            Some(step)
        );
    }

    proptest! {
        /// The CSRF check accepts only the exact token.
        #[test]
        fn csrf_compare(expected in "[A-Za-z0-9_-]{1,64}", got in "[A-Za-z0-9_-]{0,64}") {
            let mut h = HeaderMap::new();
            h.insert(CSRF_HEADER, HeaderValue::from_str(&got).unwrap());
            prop_assert_eq!(csrf_ok(&h, &expected), got == expected);
            h.insert(CSRF_HEADER, HeaderValue::from_str(&expected).unwrap());
            prop_assert!(csrf_ok(&h, &expected));
            prop_assert!(!csrf_ok(&HeaderMap::new(), &expected));
        }
    }
}
