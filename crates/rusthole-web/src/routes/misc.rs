//! Blocking, domain search, tokens, settings, audit log and system facts (docs/API.md
//! sections 4, 7.1, 11, 12, 13 and 14).

use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use rusthole_core::config::{IdKind, ListKind, RuleAction};
use rusthole_core::lists::{ListFormat, MatchKind, ParseLimits};
use rusthole_core::policy::{Action, MatchEffect, MatchSource, Reason};
use rusthole_core::{Config, DomainName};
use rusthole_store::AuditParams;
use serde_json::{Value, json};

use super::{ApiJson, Caller, Params, audit, path_id};
use crate::error::{ApiError, ApiResult};
use crate::model::{BlockingReq, TokenCreate, check_blocking, group_ids};
use crate::settings::{SettingsPatch, apply_patch, settings_of};
use crate::state::AppState;
use crate::util::{b64url, random_bytes, rfc3339};

// ---------------------------------------------------------------------------------------
// Blocking
// ---------------------------------------------------------------------------------------

fn blocking_json(state: &AppState) -> Value {
    let b = &state.deps().blocking;
    let enabled = b.is_blocking();
    let remaining = if enabled {
        None
    } else {
        b.remaining()
            .map(|d| d.as_secs() + u64::from(d.subsec_nanos() > 0))
    };
    let until = remaining.map(|s| {
        rfc3339(
            state
                .clock()
                .wall()
                .saturating_add(i64::try_from(s).unwrap_or(i64::MAX)),
        )
    });
    json!({ "enabled": enabled, "remaining_seconds": remaining, "until_at": until })
}

/// `GET /blocking`.
pub(crate) async fn blocking_get(State(state): State<AppState>) -> Json<Value> {
    Json(blocking_json(&state))
}

/// `PUT /blocking`: the runtime toggle (the config value `blocking.enabled` is the state at
/// start and does not change).
pub(crate) async fn blocking_put(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<BlockingReq>,
) -> ApiResult<Json<Value>> {
    check_blocking(&req)?;
    let b = &state.deps().blocking;
    let result = if req.enabled {
        b.enable()
    } else {
        b.disable(req.duration_seconds.map(Duration::from_secs))
    };
    let detail = match (req.enabled, req.duration_seconds) {
        (true, _) => "enabled=true".to_owned(),
        (false, Some(d)) => format!("enabled=false duration={d}"),
        (false, None) => "enabled=false".to_owned(),
    };
    match result {
        Ok(()) => {}
        Err(rusthole_dns::ToggleError::LockTimeout) => {
            return Err(ApiError::unavailable(
                "The blocking toggle is busy. Try again.",
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, "the blocking toggle refused the change");
            audit(&state, &caller, "blocking.set", None, false, Some(detail)).await;
            return Err(ApiError::internal());
        }
    }
    audit(&state, &caller, "blocking.set", None, true, Some(detail)).await;
    Ok(Json(blocking_json(&state)))
}

// ---------------------------------------------------------------------------------------
// Domain search (A9)
// ---------------------------------------------------------------------------------------

/// The largest number of matches of a search.
const MAX_MATCHES: usize = 100;
/// The time limit of the disk scan of a search.
const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

fn special_label(name: &str) -> &'static str {
    match name {
        "use-application-dns.net" => "Firefox DoH canary",
        "mask.icloud.com" | "mask-h2.icloud.com" => "iCloud Private Relay",
        _ => "Special domain",
    }
}

fn kind_str(k: ListKind) -> &'static str {
    match k {
        ListKind::Block => "block",
        ListKind::Allow => "allow",
    }
}

/// The reason text of a decision, with stable rule ids.
fn by_of(cfg: &Config, reason: Reason) -> Option<String> {
    let rule = |i: usize| {
        cfg.rules
            .get(i)
            .and_then(|r| r.id)
            .map(|id| format!("rule:{id}"))
    };
    match reason {
        Reason::NoMatch | Reason::BlockingDisabled => None,
        Reason::SpecialDomain => Some("special".to_owned()),
        Reason::ExactAllow { rule: i }
        | Reason::RegexAllow { rule: i }
        | Reason::ExactDeny { rule: i }
        | Reason::RegexDeny { rule: i } => rule(i),
        Reason::AllowList { lists } | Reason::BlockList { lists } => {
            lists.first().map(|id| format!("list:{id}"))
        }
    }
}

/// Scans the cached files of the disabled lists for `name` (the engine has only the enabled
/// lists). Stops after `max` matches or [`SCAN_TIMEOUT`].
async fn scan_disabled(
    state: &AppState,
    cfg: &Config,
    name: &DomainName,
    max: usize,
) -> (Vec<Value>, bool) {
    let Some(lists) = state.deps().lists.clone() else {
        return (Vec::new(), false);
    };
    let disabled: Vec<(u32, String, ListKind, Vec<u32>)> = cfg
        .lists
        .adlists
        .iter()
        .filter(|l| !l.enabled)
        .map(|l| (l.id, l.url.clone(), l.kind, group_ids(cfg, &l.groups)))
        .collect();
    if disabled.is_empty() || max == 0 {
        return (Vec::new(), false);
    }
    let q = name.as_str().to_owned();
    let task = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        let limits = ParseLimits::default();
        let max_bytes = u64::try_from(limits.max_bytes).unwrap_or(u64::MAX);
        for (id, url, kind, groups) in disabled {
            let Ok(Some(body)) = lists.cache().read_body(id, max_bytes) else {
                continue;
            };
            let text = String::from_utf8_lossy(&body);
            let Ok(parsed) = rusthole_core::lists::parse(&text, ListFormat::Auto, &limits) else {
                continue;
            };
            for e in parsed.entries() {
                let hit = match e.kind {
                    MatchKind::Exact => e.name == q,
                    MatchKind::Subtree => {
                        q == e.name || q.strip_suffix(e.name).is_some_and(|p| p.ends_with('.'))
                    }
                };
                if hit {
                    out.push(json!({
                        "source": "list",
                        "id": id,
                        "label": url,
                        "kind": kind_str(kind),
                        "match": if e.kind == MatchKind::Exact { "exact" } else { "parent" },
                        "pattern": if e.kind == MatchKind::Exact { e.name.to_owned() } else { format!("||{}^", e.name) },
                        "enabled": false,
                        "groups": groups,
                    }));
                    if out.len() >= max {
                        return (out, true);
                    }
                }
            }
        }
        (out, false)
    });
    match tokio::time::timeout(SCAN_TIMEOUT, task).await {
        Ok(Ok(r)) => r,
        _ => (Vec::new(), true),
    }
}

/// The JSON form of one match of [`PolicyEngine::explain`](rusthole_core::PolicyEngine).
fn match_json(cfg: &Config, m: &rusthole_core::policy::Match) -> Option<Value> {
    let effect_kind = match m.effect {
        MatchEffect::Allow => "allow",
        MatchEffect::Deny | MatchEffect::Special => "block",
    };
    Some(match &m.source {
        MatchSource::SpecialDomain => json!({
            "source": "special", "id": null, "label": special_label(&m.matched),
            "kind": "block", "match": "exact", "pattern": m.matched, "enabled": true, "groups": [],
        }),
        MatchSource::ExactRule { rule } | MatchSource::RegexRule { rule } => {
            let r = cfg.rules.get(*rule)?;
            let regex = matches!(m.source, MatchSource::RegexRule { .. });
            let label = r
                .comment
                .clone()
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| {
                    let action = if r.action == RuleAction::Allow {
                        "allow"
                    } else {
                        "deny"
                    };
                    format!("{} {action}", if regex { "regex" } else { "exact" })
                });
            json!({
                "source": "rule", "id": r.id, "label": label, "kind": effect_kind,
                "match": if regex { "regex" } else { "exact" }, "pattern": r.value,
                "enabled": r.enabled, "groups": group_ids(cfg, &r.groups),
            })
        }
        MatchSource::List { id, kind } => {
            let l = cfg.lists.adlists.iter().find(|l| l.id == *id);
            let exact = *kind == MatchKind::Exact;
            json!({
                "source": "list", "id": id,
                "label": l.map_or_else(String::new, |l| l.url.clone()),
                "kind": effect_kind,
                "match": if exact { "exact" } else { "parent" },
                "pattern": if exact { m.matched.clone() } else { format!("||{}^", m.matched) },
                "enabled": l.is_some_and(|l| l.enabled),
                "groups": l.map_or_else(Vec::new, |l| group_ids(cfg, &l.groups)),
            })
        }
    })
}

/// The verdict of each group for `name` (the blocking toggle has no effect here).
fn verdicts_json(
    cfg: &Config,
    engine: &rusthole_core::PolicyEngine,
    name: &DomainName,
) -> Vec<Value> {
    cfg.groups
        .iter()
        .map(|g| {
            let set = engine.groups_named([g.name.as_str()]);
            let d = engine.check(&set, true, name);
            let allowed = matches!(
                d.reason,
                Reason::ExactAllow { .. } | Reason::RegexAllow { .. } | Reason::AllowList { .. }
            );
            let verdict = match d.action {
                Action::Block(_) | Action::Special(_) => "blocked",
                Action::Allow if allowed => "allowed",
                Action::Allow => "none",
            };
            json!({
                "group_id": g.id,
                "group_name": g.name,
                "verdict": verdict,
                "by": by_of(cfg, d.reason),
            })
        })
        .collect()
}

/// `GET /search/domain`.
pub(crate) async fn search_domain(
    State(state): State<AppState>,
    p: Params,
) -> ApiResult<Json<Value>> {
    let raw = p
        .get("name")
        .ok_or_else(|| ApiError::bad_request("`name` is required."))?;
    let name = DomainName::parse_idn(raw.trim())
        .map_err(|e| ApiError::bad_request(format!("`name` is not a valid domain name: {e}.")))?;
    let cfg = state.config();
    let engine = state.engine();
    let mut matches: Vec<Value> = engine
        .explain(None, &name)
        .iter()
        .filter_map(|m| match_json(&cfg, m))
        .take(MAX_MATCHES)
        .collect();
    let mut truncated = matches.len() >= MAX_MATCHES;
    if !truncated {
        let (more, cut) = scan_disabled(&state, &cfg, &name, MAX_MATCHES - matches.len()).await;
        matches.extend(more);
        truncated = cut;
    }
    Ok(Json(json!({
        "name": name.as_str(),
        "verdicts": verdicts_json(&cfg, &engine, &name),
        "matches": matches,
        "truncated": truncated,
    })))
}

// ---------------------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------------------

fn token_json(state: &AppState, t: &rusthole_core::config::ApiToken) -> Value {
    let id = t.id.unwrap_or_default();
    let used = state
        .0
        .auth
        .lock()
        .ok()
        .and_then(|a| a.token_use.get(&id).copied());
    json!({
        "id": id,
        "name": t.name,
        "prefix": t.prefix.clone().unwrap_or_default(),
        "created_at": t.created_at,
        "last_used_at": used.map(|(at, _)| rfc3339(at)),
        "last_used_ip": used.map(|(_, ip)| ip.to_string()),
    })
}

/// `GET /tokens`.
pub(crate) async fn tokens_list(State(state): State<AppState>) -> Json<Value> {
    let cfg = state.config();
    let items: Vec<Value> = cfg
        .admin
        .api_tokens
        .iter()
        .map(|t| token_json(&state, t))
        .collect();
    Json(json!({ "items": items, "next_cursor": null }))
}

/// `POST /tokens` (session only, password again).
pub(crate) async fn tokens_create(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<TokenCreate>,
) -> ApiResult<Response> {
    super::auth::recheck_password(&state, &caller, req.password).await?;
    let secret = format!(
        "{}{}",
        crate::auth::TOKEN_PREFIX,
        b64url(&random_bytes::<32>().map_err(|_| ApiError::internal())?)
    );
    let now = rfc3339(state.clock().wall());
    let st = state.clone();
    let s = secret.clone();
    let name = req.name;
    let (id, cfg, _) = state
        .write(move |c| {
            let id = st.next_id(IdKind::Token, c)?;
            crate::model::create_token(c, &name, id, &s, &now)?;
            Ok(id)
        })
        .await?;
    let t = cfg
        .admin
        .api_tokens
        .iter()
        .find(|t| t.id == Some(id))
        .ok_or_else(ApiError::internal)?;
    audit(
        &state,
        &caller,
        "token.create",
        Some(format!("token:{id}")),
        true,
        None,
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token": token_json(&state, t), "secret": secret })),
    )
        .into_response())
}

/// `DELETE /tokens/{id}`: the revoke works at once.
pub(crate) async fn tokens_delete(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = path_id(&id)?;
    state
        .write(move |c| {
            let pos = c
                .admin
                .api_tokens
                .iter()
                .position(|t| t.id == Some(id))
                .ok_or_else(ApiError::not_found)?;
            c.admin.api_tokens.remove(pos);
            Ok(())
        })
        .await?;
    audit(
        &state,
        &caller,
        "token.revoke",
        Some(format!("token:{id}")),
        true,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------

/// `GET /settings`.
pub(crate) async fn settings_get(State(state): State<AppState>) -> Json<Value> {
    let cfg = state.config();
    let s = settings_of(&cfg, &state.net().local_subnets, state.restart_required());
    Json(serde_json::to_value(s).unwrap_or(Value::Null))
}

/// `PATCH /settings`.
pub(crate) async fn settings_patch(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<SettingsPatch>,
) -> ApiResult<Json<Value>> {
    let sections: Vec<&str> = [
        ("upstreams", req.upstreams.is_some()),
        ("blocking", req.blocking.is_some()),
        ("cache", req.cache.is_some()),
        ("rate_limit", req.rate_limit.is_some()),
        ("acl", req.acl.is_some()),
        ("stats", req.stats.is_some()),
        ("lists", req.lists.is_some()),
    ]
    .into_iter()
    .filter(|(_, set)| *set)
    .map(|(n, _)| n)
    .collect();
    let ((), cfg, _) = state.write(move |c| apply_patch(c, req)).await?;
    audit(
        &state,
        &caller,
        "settings.update",
        None,
        true,
        Some(sections.join(",")),
    )
    .await;
    let s = settings_of(&cfg, &state.net().local_subnets, state.restart_required());
    Ok(Json(serde_json::to_value(s).unwrap_or(Value::Null)))
}

// ---------------------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------------------

/// `GET /audit`.
pub(crate) async fn audit_list(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let params = AuditParams {
        action_prefix: p.get("action").filter(|a| !a.is_empty()).map(str::to_owned),
        cursor: p.get("cursor").filter(|c| !c.is_empty()).map(str::to_owned),
        limit: usize::try_from(p.int("limit", 50, 1, 500)?).unwrap_or(50),
    };
    let page = state.stats(move |s| s.audit(&params)).await?;
    let items: Vec<Value> = page
        .items
        .into_iter()
        .map(|a| {
            json!({
                "id": a.id,
                "at": rfc3339(a.at),
                "action": a.action,
                "target": a.target,
                "actor": a.actor,
                "client_ip": a.client_ip.map_or_else(String::new, |i| i.to_string()),
                "result": if a.ok { "ok" } else { "error" },
                "detail": a.detail,
            })
        })
        .collect();
    Ok(Json(
        json!({ "items": items, "next_cursor": page.next_cursor }),
    ))
}

// ---------------------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------------------

/// The resident memory of the process, from `/proc/self/status` (Linux only).
#[cfg(target_os = "linux")]
fn rss_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = text.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

#[cfg(not(target_os = "linux"))]
fn rss_bytes() -> Option<u64> {
    None
}

/// `GET /system`.
pub(crate) async fn system(State(state): State<AppState>) -> Json<Value> {
    let s = &state.deps().system;
    let listeners: Vec<Value> = state
        .listeners()
        .iter()
        .map(|(k, a)| json!({ "kind": k, "address": a.to_string() }))
        .collect();
    let rss = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(rss_bytes),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .flatten();
    Json(json!({
        "version": s.version,
        "commit": s.commit,
        "started_at": rfc3339(s.started_at),
        "uptime_seconds": state.uptime().as_secs(),
        "memory_rss_bytes": rss,
        "list_entries": state.engine().unique_domains(),
        "config_path": s.config_path,
        "data_dir": s.data_dir,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "listeners": listeners,
    }))
}

fn tls_mode_str(m: rusthole_core::config::TlsMode) -> &'static str {
    match m {
        rusthole_core::config::TlsMode::File => "file",
        rusthole_core::config::TlsMode::SelfSigned => "self-signed",
        rusthole_core::config::TlsMode::LocalCa => "local-ca",
    }
}

/// `GET /system/tls`: facts about the certificate of the admin listener.
pub(crate) async fn system_tls(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let store = state.deps().tls.as_ref().ok_or_else(ApiError::not_found)?;
    let info = store.info();
    let names: Vec<String> = info
        .sans
        .names
        .iter()
        .cloned()
        .chain(info.sans.ips.iter().map(ToString::to_string))
        .collect();
    Ok(Json(json!({
        "mode": tls_mode_str(info.mode),
        "fingerprint_sha256": info.fingerprint_sha256,
        "not_before_at": rfc3339(info.not_before),
        "not_after_at": rfc3339(info.not_after),
        "names": names,
        "ca_available": info.ca_cert_path.is_some(),
        "ca_fingerprint_sha256": info.ca_fingerprint_sha256,
    })))
}

/// `GET /system/tls/ca.pem`: the local CA certificate (mode `local-ca` only).
pub(crate) async fn system_tls_ca(State(state): State<AppState>) -> ApiResult<Response> {
    let store = state.deps().tls.as_ref().ok_or_else(ApiError::not_found)?;
    let path = store.info().ca_cert_path.ok_or_else(ApiError::not_found)?;
    let task = tokio::task::spawn_blocking(move || std::fs::read(path));
    let bytes = match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(Ok(Ok(b))) if b.len() < 64 * 1024 => b,
        _ => return Err(ApiError::internal()),
    };
    // Only the certificate: a PEM file of the CA never holds the key (it is ca.key), but
    // check it anyway.
    if String::from_utf8_lossy(&bytes).contains("PRIVATE KEY") {
        tracing::error!("the CA certificate file holds a private key; it is not served");
        return Err(ApiError::internal());
    }
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"rusthole-ca.pem\""),
    );
    Ok(resp)
}
