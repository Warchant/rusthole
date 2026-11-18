//! `/auth/*`: login, logout, the session probe and TOTP (docs/API.md sections 3 and 11).

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;

use super::{ApiJson, Caller, audit};
use crate::auth::{
    Attempt, PendingTotp, Principal, TOTP_SETUP_TTL, clear_cookie, expires_at, new_session,
    session_cookie, session_of, verify_password, verify_password_hash,
};
use crate::error::{ApiError, ApiResult};
use crate::model::{CodeReq, DisableTotpReq, LoginReq, PasswordReq};
use crate::state::AppState;
use crate::totp;
use crate::util::rfc3339;

#[derive(Serialize)]
struct SessionInfo {
    csrf_token: String,
    expires_at: String,
    totp_enabled: bool,
}

#[derive(Serialize)]
struct TotpState {
    enabled: bool,
    pending: bool,
}

#[derive(Serialize)]
struct TotpSetup {
    otpauth_uri: String,
    expires_at: String,
}

fn password_not_set() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "password_not_set",
        "No admin password is set. Run `rusthole passwd` on the server.",
    )
}

fn totp_required() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "totp_required",
        "Send the TOTP code too.",
    )
}

/// Checks a password with a ban attempt: 429 during a ban, 401 for a wrong password (it
/// counts). Returns the attempt for more checks.
async fn check_password(state: &AppState, caller: &Caller, password: String) -> ApiResult<Attempt> {
    let attempt = Attempt::begin(state, caller.ip)?;
    match verify_password(state, password).await {
        Ok(true) => Ok(attempt),
        Ok(false) => Err(attempt.fail(&caller.actor(), "password").await),
        Err(e) => {
            attempt.cancel();
            Err(e)
        }
    }
}

/// Checks a TOTP code against `secret` and stores the accepted step (no reuse).
fn check_code(state: &AppState, secret: &str, code: &str) -> ApiResult<bool> {
    let now = state.clock().wall();
    let mut a = state.0.auth.lock()?;
    match totp::verify(secret, code.trim(), now, a.totp_last_step) {
        Some(step) => {
            a.totp_last_step = Some(step);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// `POST /auth/login`.
pub(crate) async fn login(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<LoginReq>,
) -> ApiResult<Response> {
    let attempt = Attempt::begin(&state, caller.ip)?;
    // `rusthole passwd` changes the file; read it again when it changed (at most once in 2 s,
    // and only after the ban check).
    state.refresh_config_throttled().await;
    // The generation before the credentials are read: a change after this point gives no
    // session (m13).
    let generation = state.0.auth.generation()?;
    let cfg = state.config();
    if cfg.admin.password_hash.is_empty() {
        // No audit line: a new install has no password, and this path must not write to
        // the disk for each request.
        attempt.cancel();
        return Err(password_not_set());
    }
    let totp_on = !cfg.admin.totp_secret.is_empty();
    if totp_on && req.totp.as_deref().is_none_or(str::is_empty) {
        // The password is not checked here, so this answer does not count.
        attempt.cancel();
        return Err(totp_required());
    }
    match verify_password_hash(&state, req.password, cfg.admin.password_hash.clone()).await {
        Ok(true) => {}
        Ok(false) => return Err(attempt.fail("anonymous", "password").await),
        Err(e) => {
            attempt.cancel();
            return Err(e);
        }
    }
    if totp_on {
        let code = req.totp.unwrap_or_default();
        if !check_code(&state, &cfg.admin.totp_secret, &code)? {
            return Err(attempt.fail("anonymous", "totp").await);
        }
    }
    attempt.succeed()?;
    let (id, csrf, expires) = new_session(&state, generation)?;
    audit(&state, &caller, "auth.login", None, true, None).await;
    let body = SessionInfo {
        csrf_token: csrf,
        expires_at: rfc3339(expires),
        totp_enabled: totp_on,
    };
    let mut resp = Json(body).into_response();
    if let Ok(v) = HeaderValue::from_str(&session_cookie(&id)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

/// `GET /auth/session`: the anonymous session probe.
pub(crate) async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<impl Serialize>> {
    // A credential change on disk ends the sessions (m13); see it before the answer.
    state.refresh_config_soon().await;
    let Some((_, csrf, expires)) = session_of(&state, &headers)? else {
        return Err(ApiError::unauthorized());
    };
    Ok(Json(SessionInfo {
        csrf_token: csrf,
        expires_at: rfc3339(expires),
        totp_enabled: !state.config().admin.totp_secret.is_empty(),
    }))
}

/// `POST /auth/logout`.
pub(crate) async fn logout(State(state): State<AppState>, caller: Caller) -> ApiResult<Response> {
    if let Some(Principal::Session { key }) = &caller.principal {
        state.0.auth.lock()?.sessions.remove(key);
    }
    audit(&state, &caller, "auth.logout", None, true, None).await;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = HeaderValue::from_str(&clear_cookie()) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

fn totp_state_of(state: &AppState) -> ApiResult<TotpState> {
    let now = state.clock().mono();
    let pending = state
        .0
        .auth
        .lock()?
        .totp_pending
        .as_ref()
        .is_some_and(|p| now < p.expires);
    Ok(TotpState {
        enabled: !state.config().admin.totp_secret.is_empty(),
        pending,
    })
}

/// `GET /auth/totp`.
pub(crate) async fn totp_state(State(state): State<AppState>) -> ApiResult<Json<impl Serialize>> {
    Ok(Json(totp_state_of(&state)?))
}

/// `POST /auth/totp/setup`.
pub(crate) async fn totp_setup(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<PasswordReq>,
) -> ApiResult<Json<impl Serialize>> {
    if !state.config().admin.totp_secret.is_empty() {
        return Err(ApiError::conflict("TOTP is on. Turn it off first."));
    }
    let attempt = check_password(&state, &caller, req.password).await?;
    attempt.succeed()?;
    let secret = totp::new_secret().map_err(|_| ApiError::internal())?;
    let now = state.clock().mono();
    let expires = now
        .checked_add(TOTP_SETUP_TTL)
        .ok_or_else(ApiError::internal)?;
    state.0.auth.lock()?.totp_pending = Some(PendingTotp {
        secret: secret.clone(),
        expires,
    });
    audit(&state, &caller, "totp.setup", None, true, None).await;
    Ok(Json(TotpSetup {
        otpauth_uri: totp::otpauth_uri(&secret),
        expires_at: rfc3339(expires_at(&state, expires)),
    }))
}

/// `POST /auth/totp/confirm`.
pub(crate) async fn totp_confirm(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<CodeReq>,
) -> ApiResult<Json<impl Serialize>> {
    let now = state.clock().mono();
    let pending = state
        .0
        .auth
        .lock()?
        .totp_pending
        .clone()
        .filter(|p| now < p.expires)
        .ok_or_else(|| {
            ApiError::conflict("No TOTP setup waits for a confirm. Start the setup again.")
        })?;
    let attempt = Attempt::begin(&state, caller.ip)?;
    let wall = state.clock().wall();
    let Some(step) = totp::verify(&pending.secret, req.code.trim(), wall, None) else {
        return Err(attempt.fail(&caller.actor(), "totp").await);
    };
    attempt.succeed()?;
    let secret = pending.secret.clone();
    state
        .write_keeping(session_key(&caller), move |c| {
            c.admin.totp_secret = secret;
            Ok(())
        })
        .await?;
    {
        let mut a = state.0.auth.lock()?;
        a.totp_pending = None;
        a.totp_last_step = Some(step);
    }
    audit(&state, &caller, "totp.enable", None, true, None).await;
    Ok(Json(totp_state_of(&state)?))
}

/// `POST /auth/totp/disable`.
pub(crate) async fn totp_disable(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<DisableTotpReq>,
) -> ApiResult<Json<impl Serialize>> {
    let secret = state.config().admin.totp_secret.clone();
    if secret.is_empty() {
        return Err(ApiError::conflict("TOTP is off."));
    }
    let attempt = check_password(&state, &caller, req.password).await?;
    if !check_code(&state, &secret, &req.code)? {
        return Err(attempt.fail(&caller.actor(), "totp").await);
    }
    attempt.succeed()?;
    state
        .write_keeping(session_key(&caller), |c| {
            c.admin.totp_secret.clear();
            Ok(())
        })
        .await?;
    state.0.auth.lock()?.totp_last_step = None;
    audit(&state, &caller, "totp.disable", None, true, None).await;
    Ok(Json(totp_state_of(&state)?))
}

/// The session key of the caller (`None` for a token).
fn session_key(caller: &Caller) -> Option<[u8; 32]> {
    match &caller.principal {
        Some(Principal::Session { key }) => Some(*key),
        Some(Principal::Token { .. }) | None => None,
    }
}

/// Checks the password again for `POST /tokens`.
pub(crate) async fn recheck_password(
    state: &AppState,
    caller: &Caller,
    password: String,
) -> ApiResult<()> {
    check_password(state, caller, password).await?.succeed()
}
