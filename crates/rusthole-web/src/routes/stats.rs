//! Statistics, recent queries and seen clients (docs/API.md sections 5, 6 and 9). The data
//! comes from the statistics store (part P4).

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, State};
use rusthole_core::Config;
use rusthole_core::config::Client;
use rusthole_core::net::{ClientId, MacAddr};
use rusthole_core::stats::Status;
use rusthole_core::stats::query::{
    ClientListParams, DomainSearchParams, GroupParams, Hours, Range, RangeSpec, Sort,
};
use rusthole_store::HoursFilter;
use rusthole_store::stats::RecentParams;
use serde_json::{Value, json};

use super::Params;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::util::{rfc3339, rfc3339_opt};

fn range_of(p: &Params) -> ApiResult<Range> {
    match p.get("range") {
        None => Ok(Range::Day),
        Some(r) => {
            Range::parse(r).ok_or_else(|| ApiError::bad_request("`range` must be 24h, 7d or 30d."))
        }
    }
}

fn offset_of(p: &Params) -> ApiResult<i32> {
    p.int("utc_offset_minutes", 0, -840, 840)
        .map(|v| i32::try_from(v).unwrap_or(0))
}

fn limit_of(p: &Params, default: i64, max: i64) -> ApiResult<usize> {
    p.int("limit", default, 1, max)
        .map(|v| usize::try_from(v).unwrap_or(1))
}

fn sort_of(p: &Params) -> ApiResult<Sort> {
    match p.get("sort") {
        None => Ok(Sort::Queries),
        Some(s) => Sort::parse(s).ok_or_else(|| {
            ApiError::bad_request("`sort` must be queries, blocked, last_seen or name.")
        }),
    }
}

fn cursor_of(p: &Params) -> Option<String> {
    p.get("cursor").filter(|c| !c.is_empty()).map(str::to_owned)
}

fn hours_json(h: &Hours) -> Value {
    json!({ "queries": h.queries.to_vec(), "blocked": h.blocked.to_vec() })
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// The configured client that matches an address, a MAC address and a name. The order is
/// the order of docs/CLIENTS.md: IP, MAC, host name, the most specific CIDR.
pub(crate) fn configured_client<'a>(
    cfg: &'a Config,
    ip: Option<IpAddr>,
    mac: Option<&str>,
    name: Option<&str>,
) -> Option<&'a Client> {
    let mac = mac.and_then(|m| MacAddr::parse(m).ok());
    let parsed: Vec<(&Client, ClientId)> = cfg
        .clients
        .iter()
        .filter_map(|c| ClientId::parse(&c.id).ok().map(|id| (c, id)))
        .collect();
    let by = |f: &dyn Fn(&ClientId) -> bool| parsed.iter().find(|(_, id)| f(id)).map(|(c, _)| *c);
    if let Some(ip) = ip
        && let Some(c) = by(&|id| matches!(id, ClientId::Ip(x) if *x == ip))
    {
        return Some(c);
    }
    if let Some(m) = mac
        && let Some(c) = by(&|id| matches!(id, ClientId::Mac(x) if *x == m))
    {
        return Some(c);
    }
    if let Some(n) = name
        && let Some(c) = by(&|id| matches!(id, ClientId::Hostname(h) if h.as_str() == n))
    {
        return Some(c);
    }
    let ip = ip?;
    parsed
        .iter()
        .filter_map(|(c, id)| match id {
            ClientId::Cidr(cidr) if cidr.contains(ip) => Some((cidr.prefix, *c)),
            _ => None,
        })
        .max_by_key(|(p, _)| *p)
        .map(|(_, c)| c)
}

/// The name and the configured id of a client: the configured comment wins.
fn client_facts(
    cfg: &Config,
    ip: Option<IpAddr>,
    mac: Option<&str>,
    name: Option<&str>,
) -> (Option<String>, Option<u32>) {
    let c = configured_client(cfg, ip, mac, name);
    let shown = c
        .and_then(|c| c.comment.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| name.map(str::to_owned));
    (shown, c.and_then(|c| c.uid))
}

/// `GET /stats/summary`.
pub(crate) async fn summary(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let now = state.clock().wall();
    let spec = RangeSpec::new(range, now);
    let s = state.stats(move |st| st.summary(range, now)).await?;
    Ok(Json(json!({
        "range": range.as_str(),
        "from": rfc3339(spec.from),
        "to": rfc3339(spec.to),
        "queries": s.counts.total,
        "blocked": s.counts.blocked,
        "blocked_percent": round2(s.blocked_percent),
        "cached": s.counts.cached,
        "forwarded": s.counts.forwarded,
        "local": s.counts.local,
        "unique_domains": s.unique_domains,
        "unique_clients": s.unique_clients,
    })))
}

/// `GET /stats/timeline`.
pub(crate) async fn timeline(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let client = p.get("client").map(str::to_owned);
    let domain = p.get("domain").map(str::to_ascii_lowercase);
    let now = state.clock().wall();
    let t = state
        .stats(move |st| st.timeline(range, now, client.as_deref(), domain.as_deref()))
        .await?;
    Ok(Json(json!({
        "range": range.as_str(),
        "from": rfc3339(t.from),
        "to": rfc3339(t.to),
        "bucket_seconds": t.bucket_seconds,
        "queries": t.queries,
        "blocked": t.blocked,
        "cached": t.cached,
        "forwarded": t.forwarded,
    })))
}

/// `GET /stats/hours`.
pub(crate) async fn hours(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let offset = offset_of(&p)?;
    let filter = HoursFilter {
        client: p.get("client").map(str::to_owned),
        domain: p.get("domain").map(str::to_ascii_lowercase),
        base: p.get("base").map(str::to_ascii_lowercase),
    };
    if filter.domain.is_some() && filter.base.is_some() {
        return Err(ApiError::bad_request("Use `domain` or `base`, not both."));
    }
    let now = state.clock().wall();
    let h = state
        .stats(move |st| st.hours(range, now, &filter, offset))
        .await?;
    let mut v = hours_json(&h);
    if let Some(o) = v.as_object_mut() {
        o.insert("range".into(), json!(range.as_str()));
        o.insert("utc_offset_minutes".into(), json!(h.utc_offset_minutes));
    }
    Ok(Json(v))
}

async fn top(state: &AppState, p: &Params, blocked: bool) -> ApiResult<Json<Value>> {
    let range = range_of(p)?;
    let limit = limit_of(p, 10, 100)?;
    let client = p.get("client").map(str::to_owned);
    let now = state.clock().wall();
    let rows = state
        .stats(move |st| st.top_domains(range, now, client.as_deref(), limit, blocked))
        .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| json!({ "name": r.name, "base": r.base, "count": r.count }))
        .collect();
    Ok(Json(json!({ "items": items, "next_cursor": null })))
}

/// `GET /stats/top/domains`.
pub(crate) async fn top_domains(
    State(state): State<AppState>,
    p: Params,
) -> ApiResult<Json<Value>> {
    top(&state, &p, false).await
}

/// `GET /stats/top/blocked`.
pub(crate) async fn top_blocked(
    State(state): State<AppState>,
    p: Params,
) -> ApiResult<Json<Value>> {
    top(&state, &p, true).await
}

/// `GET /stats/top/clients`.
pub(crate) async fn top_clients(
    State(state): State<AppState>,
    p: Params,
) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let limit = limit_of(&p, 10, 100)?;
    let now = state.clock().wall();
    let rows = state
        .stats(move |st| st.top_clients(range, now, limit))
        .await?;
    let cfg = state.config();
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let mac = r.key.contains(':').then_some(r.key.as_str());
            let (name, _) = client_facts(&cfg, Some(r.ip), mac, r.name.as_deref());
            json!({ "key": r.key, "name": name, "ip": r.ip.to_string(), "count": r.count, "blocked": r.blocked })
        })
        .collect();
    Ok(Json(json!({ "items": items, "next_cursor": null })))
}

/// `GET /stats/query-types`.
pub(crate) async fn query_types(
    State(state): State<AppState>,
    p: Params,
) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let now = state.clock().wall();
    let rows = state.stats(move |st| st.query_types(range, now)).await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| json!({ "type": r.name, "count": r.count }))
        .collect();
    Ok(Json(json!({ "items": items, "next_cursor": null })))
}

/// `GET /stats/upstreams`.
pub(crate) async fn upstreams(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let now = state.clock().wall();
    let rows = state.stats(move |st| st.upstreams(range, now)).await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "name": r.name,
                "kind": r.kind.as_str(),
                "count": r.count,
                "avg_ms": r.avg_ms.map(round2),
            })
        })
        .collect();
    Ok(Json(json!({ "items": items, "next_cursor": null })))
}

fn client_row_json(cfg: &Config, r: &rusthole_core::stats::query::ClientRow) -> Value {
    let (name, client_id) = client_facts(cfg, r.ip, r.mac.as_deref(), r.name.as_deref());
    json!({
        "key": r.key,
        "name": name,
        "ip": r.ip.map_or_else(String::new, |i| i.to_string()),
        "mac": r.mac,
        "client_id": client_id,
        "queries": r.counts.total,
        "blocked": r.counts.blocked,
        "blocked_percent": round2(r.blocked_percent),
        "unique_domains": r.unique_domains,
        "first_seen_at": rfc3339_opt(r.first_seen),
        "last_seen_at": rfc3339_opt(r.last_seen),
    })
}

/// `GET /stats/clients`.
pub(crate) async fn clients(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let params = ClientListParams {
        q: p.get("q").filter(|q| !q.is_empty()).map(str::to_owned),
        sort: sort_of(&p)?,
        cursor: cursor_of(&p),
        limit: limit_of(&p, 50, 500)?,
    };
    let now = state.clock().wall();
    let page = state
        .stats(move |st| st.clients(range, now, &params))
        .await?;
    let cfg = state.config();
    let items: Vec<Value> = page
        .items
        .iter()
        .map(|r| client_row_json(&cfg, r))
        .collect();
    Ok(Json(
        json!({ "items": items, "next_cursor": page.next_cursor }),
    ))
}

/// `GET /stats/clients/{key}`.
pub(crate) async fn client(
    State(state): State<AppState>,
    Path(key): Path<String>,
    params: Params,
) -> ApiResult<Json<Value>> {
    let range = range_of(&params)?;
    let offset = offset_of(&params)?;
    let now = state.clock().wall();
    let detail = state
        .stats(move |st| st.client(&key, range, now, offset))
        .await?;
    let cfg = state.config();
    let row = &detail.row;
    let mut out = client_row_json(&cfg, row);
    let configured = configured_client(&cfg, row.ip, row.mac.as_deref(), row.name.as_deref());
    let groups: Vec<u32> = match configured {
        Some(c) => crate::model::group_ids(&cfg, &c.groups),
        None => vec![rusthole_core::config::DEFAULT_GROUP_ID],
    };
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "ips".into(),
            json!(row.ips.iter().map(ToString::to_string).collect::<Vec<_>>()),
        );
        obj.insert("groups".into(), json!(groups));
        obj.insert("range".into(), json!(range.as_str()));
        obj.insert("unique_bases".into(), json!(row.unique_bases));
        obj.insert(
            "utc_offset_minutes".into(),
            json!(detail.hours.utc_offset_minutes),
        );
        obj.insert("hours".into(), hours_json(&detail.hours));
    }
    Ok(Json(out))
}

/// `GET /stats/clients/{key}/domains`.
pub(crate) async fn client_domains(
    State(state): State<AppState>,
    Path(key): Path<String>,
    p: Params,
) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let params = GroupParams {
        q: p.get("q")
            .filter(|q| !q.is_empty())
            .map(str::to_ascii_lowercase),
        sort: sort_of(&p)?,
        names_limit: usize::try_from(p.int("names_limit", 50, 1, 200)?).unwrap_or(50),
        blocked_only: p.flag("blocked_only")?,
        cursor: cursor_of(&p),
        limit: limit_of(&p, 50, 500)?,
    };
    let now = state.clock().wall();
    let page = state
        .stats(move |st| st.client_domains(&key, range, now, &params))
        .await?;
    let items: Vec<Value> = page
        .items
        .into_iter()
        .map(|g| {
            let names: Vec<Value> = g
                .names
                .into_iter()
                .map(|n| {
                    json!({
                        "name": n.name,
                        "queries": n.queries,
                        "blocked": n.blocked,
                        "first_seen_at": rfc3339(n.first_seen),
                        "last_seen_at": rfc3339(n.last_seen),
                    })
                })
                .collect();
            json!({
                "base": g.base,
                "queries": g.queries,
                "blocked": g.blocked,
                "first_seen_at": rfc3339(g.first_seen),
                "last_seen_at": rfc3339(g.last_seen),
                "names_total": g.names_total,
                "names": names,
            })
        })
        .collect();
    Ok(Json(
        json!({ "items": items, "next_cursor": page.next_cursor }),
    ))
}

/// `GET /stats/domains`.
pub(crate) async fn domains(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let q = p.get("q").unwrap_or_default().to_ascii_lowercase();
    if q.is_empty() || q.len() > 253 {
        return Err(ApiError::bad_request("`q` must have 1 to 253 characters."));
    }
    let params = DomainSearchParams {
        q,
        blocked_only: p.flag("blocked_only")?,
        cursor: cursor_of(&p),
        limit: limit_of(&p, 50, 500)?,
    };
    let now = state.clock().wall();
    let page = state
        .stats(move |st| st.domains(range, now, &params))
        .await?;
    let items: Vec<Value> = page
        .items
        .into_iter()
        .map(|d| {
            json!({
                "name": d.name,
                "base": d.base,
                "queries": d.queries,
                "blocked": d.blocked,
                "clients": d.clients,
                "last_seen_at": rfc3339(d.last_seen),
            })
        })
        .collect();
    Ok(Json(
        json!({ "items": items, "next_cursor": page.next_cursor }),
    ))
}

/// `GET /stats/domains/{name}`.
pub(crate) async fn domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
    p: Params,
) -> ApiResult<Json<Value>> {
    let range = range_of(&p)?;
    let offset = offset_of(&p)?;
    let name = name.to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return Err(ApiError::not_found());
    }
    let now = state.clock().wall();
    let d = state
        .stats(move |st| st.domain(&name, range, now, offset))
        .await?;
    let cfg = state.config();
    let clients: Vec<Value> = d
        .detail
        .clients
        .iter()
        .map(|c| {
            let mac = c.key.contains(':').then_some(c.key.as_str());
            let (shown, _) = client_facts(&cfg, Some(c.ip), mac, c.name.as_deref());
            json!({
                "key": c.key,
                "name": shown,
                "ip": c.ip.to_string(),
                "queries": c.queries,
                "blocked": c.blocked,
                "last_seen_at": rfc3339(c.last_seen),
            })
        })
        .collect();
    Ok(Json(json!({
        "name": d.detail.name,
        "base": d.detail.base,
        "range": range.as_str(),
        "queries": d.detail.counts.total,
        "blocked": d.detail.counts.blocked,
        "first_seen_at": rfc3339_opt(d.detail.first_seen),
        "last_seen_at": rfc3339_opt(d.detail.last_seen),
        "clients": clients,
        "utc_offset_minutes": d.hours.utc_offset_minutes,
        "hours": hours_json(&d.hours),
    })))
}

/// The name of the list or rule in a reason (`list:3`, `rule:7`), from the config.
pub(crate) fn reason_label(cfg: &Config, reason: &str) -> Option<String> {
    let (kind, id) = reason.split_once(':')?;
    match kind {
        "list" => {
            let id: u32 = id.parse().ok()?;
            cfg.lists
                .adlists
                .iter()
                .find(|l| l.id == id)
                .map(|l| l.url.clone())
        }
        "rule" => {
            let id: u32 = id.parse().ok()?;
            cfg.rules
                .iter()
                .find(|r| r.id == Some(id))
                .map(|r| r.value.clone())
        }
        "cname" => Some(id.to_owned()),
        _ => None,
    }
}

/// `GET /queries/recent`.
pub(crate) async fn recent(State(state): State<AppState>, p: Params) -> ApiResult<Json<Value>> {
    let status = match p.get("status") {
        None => None,
        Some(s) => {
            Some(Status::parse(s).ok_or_else(|| ApiError::bad_request("`status` is not valid."))?)
        }
    };
    let params = RecentParams {
        limit: limit_of(&p, 100, 1000)?,
        client: p.get("client").map(str::to_owned),
        status,
        q: p.get("q")
            .filter(|q| !q.is_empty())
            .map(str::to_ascii_lowercase),
    };
    let (events, index) = state
        .stats(move |st| Ok((st.recent(&params)?, st.clients_index()?)))
        .await?;
    let cfg = state.config();
    let items: Vec<Value> = events
        .into_iter()
        .map(|e| {
            let meta = index.get(e.client);
            let (name, _) = client_facts(
                &cfg,
                Some(e.client),
                meta.and_then(|m| m.mac.as_deref()),
                meta.and_then(|m| m.name.as_deref()),
            );
            let label = e.reason.as_deref().and_then(|r| reason_label(&cfg, r));
            json!({
                "at": rfc3339(e.at),
                "client_key": index.key_of(e.client),
                "client_ip": e.client.to_string(),
                "client_name": name,
                "name": e.name,
                "type": rusthole_core::stats::qtype_name(e.qtype),
                "status": e.status.as_str(),
                "reason": e.reason,
                "reason_label": label,
                "upstream": e.upstream,
                "duration_ms": round2(f64::from(u32::try_from(e.duration_us).unwrap_or(u32::MAX)) / 1000.0),
            })
        })
        .collect();
    Ok(Json(json!({ "items": items, "next_cursor": null })))
}

/// `GET /clients/seen`.
pub(crate) async fn clients_seen(
    State(state): State<AppState>,
    p: Params,
) -> ApiResult<Json<Value>> {
    let limit = limit_of(&p, 200, 500)?;
    let cursor = cursor_of(&p);
    let now = state.clock().wall();
    let page = state
        .stats(move |st| st.seen_clients(now, cursor.as_deref(), limit))
        .await?;
    let cfg = state.config();
    let items: Vec<Value> = page
        .items
        .into_iter()
        .map(|s| {
            let m = &s.meta;
            let c = configured_client(&cfg, Some(m.ip), m.mac.as_deref(), m.name.as_deref());
            json!({
                "ip": m.ip.to_string(),
                "mac": m.mac,
                "name": m.name,
                "first_seen_at": rfc3339(m.first_seen),
                "last_seen_at": rfc3339(m.last_seen),
                "queries": s.queries,
                "client_id": c.and_then(|c| c.uid),
            })
        })
        .collect();
    Ok(Json(
        json!({ "items": items, "next_cursor": page.next_cursor }),
    ))
}
