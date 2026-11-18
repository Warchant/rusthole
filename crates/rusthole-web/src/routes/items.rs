//! CRUD of the config items: lists, rules, groups, clients and local DNS (docs/API.md
//! sections 7 to 10). Each write goes through [`AppState::write`] (validate, write the file
//! atomically, apply live) and adds an audit line.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use rusthole_core::Config;
use rusthole_core::config::IdKind;
use rusthole_lists::{ListsStatus, UpdateError, UpdateTarget};
use serde_json::{Value, json};

use super::{ApiJson, Caller, Params, audit, path_id};
use crate::error::{ApiError, ApiResult};
use crate::model::{
    self, ClientCreate, ClientOut, ClientPatch, CnameCreate, CnamePatch, ForwarderCreate,
    ForwarderPatch, GroupCreate, GroupOut, GroupPatch, ListCreate, ListPatch, RecordCreate,
    RecordPatch, RuleCreate, RuleOut, RulePatch, RuleTest, RuleTestOut, client_out, group_ids,
    group_out, rule_out,
};
use crate::state::AppState;
use crate::util::{rfc3339, rfc3339_opt};

fn page(items: &[Value]) -> Value {
    json!({ "items": items, "next_cursor": null })
}

fn created(v: impl serde::Serialize) -> Response {
    (StatusCode::CREATED, Json(v)).into_response()
}

fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// Names of the fields that a patch body sets (for the audit detail).
fn fields_of(body: &impl serde::Serialize) -> Option<String> {
    let v = serde_json::to_value(body).ok()?;
    let names: Vec<String> = v
        .as_object()?
        .iter()
        .filter(|(_, x)| !x.is_null())
        .map(|(k, _)| k.clone())
        .collect();
    (!names.is_empty()).then(|| names.join(","))
}

// ---------------------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------------------

fn list_json(
    cfg: &Config,
    status: Option<&ListsStatus>,
    l: &rusthole_core::config::Adlist,
) -> Value {
    let s = status.and_then(|s| s.list(l.id));
    let st = match s {
        Some(s) => json!({
            "state": s.state.as_str(),
            "last_update_at": rfc3339_opt(s.last_update),
            "last_success_at": rfc3339_opt(s.last_success),
            "entries": s.entries.valid,
            "invalid_lines": s.entries.invalid,
            "size_bytes": s.size_bytes,
            "last_error": s.last_error,
        }),
        None => json!({
            "state": "never",
            "last_update_at": null,
            "last_success_at": null,
            "entries": 0,
            "invalid_lines": 0,
            "size_bytes": 0,
            "last_error": null,
        }),
    };
    json!({
        "id": l.id,
        "url": l.url,
        "comment": l.comment.clone().unwrap_or_default(),
        "kind": l.kind,
        "enabled": l.enabled,
        "groups": group_ids(cfg, &l.groups),
        "status": st,
    })
}

fn lists_status(state: &AppState) -> Option<ListsStatus> {
    state.deps().lists.as_ref().and_then(|l| l.status())
}

fn find_list(cfg: &Config, id: u32) -> ApiResult<&rusthole_core::config::Adlist> {
    cfg.lists
        .adlists
        .iter()
        .find(|l| l.id == id)
        .ok_or_else(ApiError::not_found)
}

/// `GET /lists`.
pub(crate) async fn lists_list(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let cfg = state.config();
    let status = lists_status(&state);
    let items: Vec<Value> = cfg
        .lists
        .adlists
        .iter()
        .map(|l| list_json(&cfg, status.as_ref(), l))
        .collect();
    let schedule = match &status {
        Some(s) => json!({
            "interval_hours": s.schedule.interval_hours,
            "next_run_at": rfc3339_opt(s.schedule.next_run),
            "running": s.schedule.running,
        }),
        None => json!({
            "interval_hours": cfg.lists.refresh_interval_hours,
            "next_run_at": null,
            "running": false,
        }),
    };
    Ok(Json(
        json!({ "items": items, "next_cursor": null, "schedule": schedule }),
    ))
}

/// `GET /lists/{id}`.
pub(crate) async fn lists_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = path_id(&id)?;
    let cfg = state.config();
    let l = find_list(&cfg, id)?;
    Ok(Json(list_json(&cfg, lists_status(&state).as_ref(), l)))
}

fn start_update(state: &AppState, target: UpdateTarget) -> ApiResult<()> {
    let lists = state
        .deps()
        .lists
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("The list refresher does not run."))?;
    match lists.update_now(target) {
        Ok(_) => Ok(()),
        Err(UpdateError::Busy) => Err(ApiError::unavailable(
            "The list refresher is busy. Try again.",
        )),
        Err(UpdateError::Disabled(_)) => Err(ApiError::conflict("The list is disabled.")),
        Err(UpdateError::UnknownList(_)) => Err(ApiError::not_found()),
    }
}

/// `POST /lists`.
pub(crate) async fn lists_create(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<ListCreate>,
) -> ApiResult<Response> {
    let st = state.clone();
    let (id, cfg, _) = state
        .write(move |c| {
            let id = st.next_id(IdKind::List, c)?;
            model::create_list(c, req, id)?;
            Ok(id)
        })
        .await?;
    let l = find_list(&cfg, id)?;
    if l.enabled {
        // The new config is in the refresher already (apply). A busy refresher fetches the
        // list with its schedule.
        if let Err(e) = start_update(&state, UpdateTarget::One(id)) {
            tracing::warn!(list = id, error = %e.message, "the first update of a new list did not start");
        }
    }
    audit(
        &state,
        &caller,
        "list.create",
        Some(format!("list:{id}")),
        true,
        None,
    )
    .await;
    Ok(created(list_json(&cfg, lists_status(&state).as_ref(), l)))
}

/// `PATCH /lists/{id}`.
pub(crate) async fn lists_patch(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ListPatch>,
) -> ApiResult<Json<Value>> {
    let id = path_id(&id)?;
    let detail = fields_of(&json!({
        "url": req.url, "comment": req.comment, "kind": req.kind, "enabled": req.enabled, "groups": req.groups,
    }));
    let ((), cfg, _) = state.write(move |c| model::patch_list(c, id, req)).await?;
    audit(
        &state,
        &caller,
        "list.update",
        Some(format!("list:{id}")),
        true,
        detail,
    )
    .await;
    let l = find_list(&cfg, id)?;
    Ok(Json(list_json(&cfg, lists_status(&state).as_ref(), l)))
}

/// `DELETE /lists/{id}`: also deletes the list files on disk.
pub(crate) async fn lists_delete(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = path_id(&id)?;
    state
        .write(move |c| {
            let pos = c
                .lists
                .adlists
                .iter()
                .position(|l| l.id == id)
                .ok_or_else(ApiError::not_found)?;
            c.lists.adlists.remove(pos);
            Ok(())
        })
        .await?;
    if let Some(lists) = state.deps().lists.clone() {
        let task = tokio::task::spawn_blocking(move || lists.cache().remove(id));
        match tokio::time::timeout(Duration::from_secs(10), task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => tracing::warn!(list = id, error = %e, "cannot delete the list files"),
            _ => tracing::warn!(list = id, "the delete of the list files did not end"),
        }
    }
    audit(
        &state,
        &caller,
        "list.delete",
        Some(format!("list:{id}")),
        true,
        None,
    )
    .await;
    Ok(no_content())
}

/// `POST /lists/{id}/update`.
pub(crate) async fn lists_update_one(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = path_id(&id)?;
    let cfg = state.config();
    let l = find_list(&cfg, id)?;
    if !l.enabled {
        return Err(ApiError::conflict("The list is disabled."));
    }
    if lists_status(&state)
        .as_ref()
        .and_then(|s| s.list(id))
        .is_some_and(|s| s.state == rusthole_lists::ListState::Updating)
    {
        return Err(ApiError::unavailable("An update of this list runs."));
    }
    start_update(&state, UpdateTarget::One(id))?;
    audit(
        &state,
        &caller,
        "list.refresh",
        Some(format!("list:{id}")),
        true,
        None,
    )
    .await;
    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))).into_response())
}

/// `POST /lists/update`.
pub(crate) async fn lists_update_all(
    State(state): State<AppState>,
    caller: Caller,
) -> ApiResult<Response> {
    if lists_status(&state).is_some_and(|s| s.schedule.running) {
        return Err(ApiError::unavailable("A list update runs."));
    }
    start_update(&state, UpdateTarget::All)?;
    audit(
        &state,
        &caller,
        "list.refresh",
        Some("list:all".to_owned()),
        true,
        None,
    )
    .await;
    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))).into_response())
}

// ---------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------

fn find_rule(cfg: &Config, id: u32) -> ApiResult<RuleOut> {
    cfg.rules
        .iter()
        .find(|r| r.id == Some(id))
        .map(|r| rule_out(cfg, r))
        .ok_or_else(ApiError::not_found)
}

/// `GET /rules`.
pub(crate) async fn rules_list(
    State(state): State<AppState>,
    params: Params,
) -> ApiResult<Json<Value>> {
    let cfg = state.config();
    let kind = params.get("kind");
    let action = params.get("action");
    if kind.is_some_and(|k| k != "exact" && k != "regex") {
        return Err(ApiError::bad_request("`kind` must be exact or regex."));
    }
    if action.is_some_and(|a| a != "allow" && a != "deny") {
        return Err(ApiError::bad_request("`action` must be allow or deny."));
    }
    let items: Vec<Value> = cfg
        .rules
        .iter()
        .map(|r| rule_out(&cfg, r))
        .filter(|r| {
            let k = serde_json::to_value(r.kind).ok();
            let a = serde_json::to_value(r.action).ok();
            kind.is_none_or(|x| k.as_ref().and_then(Value::as_str) == Some(x))
                && action.is_none_or(|x| a.as_ref().and_then(Value::as_str) == Some(x))
        })
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();
    Ok(Json(page(&items)))
}

/// `GET /rules/{id}`.
pub(crate) async fn rules_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RuleOut>> {
    Ok(Json(find_rule(&state.config(), path_id(&id)?)?))
}

/// `POST /rules`.
pub(crate) async fn rules_create(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<RuleCreate>,
) -> ApiResult<Response> {
    let st = state.clone();
    let now = rfc3339(state.clock().wall());
    let (id, cfg, _) = state
        .write(move |c| {
            let id = st.next_id(IdKind::Rule, c)?;
            model::create_rule(c, req, id, &now)?;
            Ok(id)
        })
        .await?;
    audit(
        &state,
        &caller,
        "rule.create",
        Some(format!("rule:{id}")),
        true,
        None,
    )
    .await;
    Ok(created(find_rule(&cfg, id)?))
}

/// `PATCH /rules/{id}`.
pub(crate) async fn rules_patch(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<RulePatch>,
) -> ApiResult<Json<RuleOut>> {
    let id = path_id(&id)?;
    let now = rfc3339(state.clock().wall());
    let detail = fields_of(&json!({
        "kind": req.kind, "action": req.action, "pattern": req.pattern, "enabled": req.enabled,
        "groups": req.groups, "comment": req.comment,
    }));
    let ((), cfg, _) = state
        .write(move |c| model::patch_rule(c, id, req, &now))
        .await?;
    audit(
        &state,
        &caller,
        "rule.update",
        Some(format!("rule:{id}")),
        true,
        detail,
    )
    .await;
    Ok(Json(find_rule(&cfg, id)?))
}

/// `DELETE /rules/{id}`.
pub(crate) async fn rules_delete(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = path_id(&id)?;
    state
        .write(move |c| {
            let pos = c
                .rules
                .iter()
                .position(|r| r.id == Some(id))
                .ok_or_else(ApiError::not_found)?;
            c.rules.remove(pos);
            Ok(())
        })
        .await?;
    audit(
        &state,
        &caller,
        "rule.delete",
        Some(format!("rule:{id}")),
        true,
        None,
    )
    .await;
    Ok(no_content())
}

/// `POST /rules/test`: runs on a blocking thread with a time limit.
pub(crate) async fn rules_test(ApiJson(req): ApiJson<RuleTest>) -> ApiResult<Json<RuleTestOut>> {
    let task = tokio::task::spawn_blocking(move || model::test_rule(&req));
    match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(Ok(r)) => r.map(Json),
        Ok(Err(_)) => Err(ApiError::internal()),
        Err(_) => Err(ApiError::unavailable("The test took too long.")),
    }
}

// ---------------------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------------------

fn find_group(cfg: &Config, id: u32) -> ApiResult<GroupOut> {
    cfg.groups
        .iter()
        .find(|g| g.id == Some(id))
        .map(|g| group_out(cfg, g))
        .ok_or_else(ApiError::not_found)
}

/// `GET /groups`.
pub(crate) async fn groups_list(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let cfg = state.config();
    let items: Vec<Value> = cfg
        .groups
        .iter()
        .filter_map(|g| serde_json::to_value(group_out(&cfg, g)).ok())
        .collect();
    Ok(Json(page(&items)))
}

/// `GET /groups/{id}`.
pub(crate) async fn groups_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<GroupOut>> {
    Ok(Json(find_group(&state.config(), path_id(&id)?)?))
}

/// `POST /groups`.
pub(crate) async fn groups_create(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<GroupCreate>,
) -> ApiResult<Response> {
    let st = state.clone();
    let (id, cfg, _) = state
        .write(move |c| {
            let id = st.next_id(IdKind::Group, c)?;
            model::create_group(c, req, id)?;
            Ok(id)
        })
        .await?;
    audit(
        &state,
        &caller,
        "group.create",
        Some(format!("group:{id}")),
        true,
        None,
    )
    .await;
    Ok(created(find_group(&cfg, id)?))
}

/// `PATCH /groups/{id}`.
pub(crate) async fn groups_patch(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<GroupPatch>,
) -> ApiResult<Json<GroupOut>> {
    let id = path_id(&id)?;
    let detail =
        fields_of(&json!({ "name": req.name, "enabled": req.enabled, "comment": req.comment }));
    let ((), cfg, _) = state.write(move |c| model::patch_group(c, id, req)).await?;
    audit(
        &state,
        &caller,
        "group.update",
        Some(format!("group:{id}")),
        true,
        detail,
    )
    .await;
    Ok(Json(find_group(&cfg, id)?))
}

/// `DELETE /groups/{id}`.
pub(crate) async fn groups_delete(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = path_id(&id)?;
    state.write(move |c| model::delete_group(c, id)).await?;
    audit(
        &state,
        &caller,
        "group.delete",
        Some(format!("group:{id}")),
        true,
        None,
    )
    .await;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------

fn find_client(cfg: &Config, id: u32) -> ApiResult<ClientOut> {
    cfg.clients
        .iter()
        .find(|c| c.uid == Some(id))
        .map(|c| client_out(cfg, c))
        .ok_or_else(ApiError::not_found)
}

/// `GET /clients`.
pub(crate) async fn clients_list(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let cfg = state.config();
    let items: Vec<Value> = cfg
        .clients
        .iter()
        .filter_map(|c| serde_json::to_value(client_out(&cfg, c)).ok())
        .collect();
    Ok(Json(page(&items)))
}

/// `GET /clients/{id}`.
pub(crate) async fn clients_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ClientOut>> {
    Ok(Json(find_client(&state.config(), path_id(&id)?)?))
}

/// `POST /clients`.
pub(crate) async fn clients_create(
    State(state): State<AppState>,
    caller: Caller,
    ApiJson(req): ApiJson<ClientCreate>,
) -> ApiResult<Response> {
    let st = state.clone();
    let (id, cfg, _) = state
        .write(move |c| {
            let id = st.next_id(IdKind::Client, c)?;
            model::create_client(c, req, id)?;
            Ok(id)
        })
        .await?;
    audit(
        &state,
        &caller,
        "client.create",
        Some(format!("client:{id}")),
        true,
        None,
    )
    .await;
    Ok(created(find_client(&cfg, id)?))
}

/// `PATCH /clients/{id}`.
pub(crate) async fn clients_patch(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ClientPatch>,
) -> ApiResult<Json<ClientOut>> {
    let id = path_id(&id)?;
    let detail =
        fields_of(&json!({ "match": req.match_, "groups": req.groups, "comment": req.comment }));
    let ((), cfg, _) = state
        .write(move |c| model::patch_client(c, id, req))
        .await?;
    audit(
        &state,
        &caller,
        "client.update",
        Some(format!("client:{id}")),
        true,
        detail,
    )
    .await;
    Ok(Json(find_client(&cfg, id)?))
}

/// `DELETE /clients/{id}`.
pub(crate) async fn clients_delete(
    State(state): State<AppState>,
    caller: Caller,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = path_id(&id)?;
    state
        .write(move |c| {
            let pos = c
                .clients
                .iter()
                .position(|x| x.uid == Some(id))
                .ok_or_else(ApiError::not_found)?;
            c.clients.remove(pos);
            Ok(())
        })
        .await?;
    audit(
        &state,
        &caller,
        "client.delete",
        Some(format!("client:{id}")),
        true,
        None,
    )
    .await;
    Ok(no_content())
}

// ---------------------------------------------------------------------------------------
// Local DNS
// ---------------------------------------------------------------------------------------

macro_rules! dns_crud {
    (
        $list:ident, $get:ident, $create:ident, $patch:ident, $delete:ident,
        field: $($field:ident).+, id: $idkind:expr, label: $label:literal,
        out: $out:path, create: $Create:ty => $create_fn:path, patch: $Patch:ty => $patch_fn:path
    ) => {
        /// The collection of this kind.
        pub(crate) async fn $list(State(state): State<AppState>) -> ApiResult<Json<Value>> {
            let cfg = state.config();
            let items: Vec<Value> = cfg.$($field).+
                .iter()
                .filter_map(|x| serde_json::to_value($out(x)).ok())
                .collect();
            Ok(Json(page(&items)))
        }

        /// One item.
        pub(crate) async fn $get(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
            let id = path_id(&id)?;
            let cfg = state.config();
            cfg.$($field).+
                .iter()
                .find(|x| x.id == Some(id))
                .and_then(|x| serde_json::to_value($out(x)).ok())
                .map(Json)
                .ok_or_else(ApiError::not_found)
        }

        /// Adds an item.
        pub(crate) async fn $create(
            State(state): State<AppState>,
            caller: Caller,
            ApiJson(req): ApiJson<$Create>,
        ) -> ApiResult<Response> {
            let st = state.clone();
            let (id, cfg, _) = state
                .write(move |c| {
                    let id = st.next_id($idkind, c)?;
                    $create_fn(c, req, id)?;
                    Ok(id)
                })
                .await?;
            audit(&state, &caller, "dns.create", Some(format!(concat!($label, ":{}"), id)), true, None).await;
            let item = cfg.$($field).+
                .iter()
                .find(|x| x.id == Some(id))
                .map($out)
                .ok_or_else(ApiError::internal)?;
            Ok(created(item))
        }

        /// Changes an item.
        pub(crate) async fn $patch(
            State(state): State<AppState>,
            caller: Caller,
            Path(id): Path<String>,
            ApiJson(req): ApiJson<$Patch>,
        ) -> ApiResult<Json<Value>> {
            let id = path_id(&id)?;
            let ((), cfg, _) = state.write(move |c| $patch_fn(c, id, req)).await?;
            audit(&state, &caller, "dns.update", Some(format!(concat!($label, ":{}"), id)), true, None).await;
            cfg.$($field).+
                .iter()
                .find(|x| x.id == Some(id))
                .and_then(|x| serde_json::to_value($out(x)).ok())
                .map(Json)
                .ok_or_else(ApiError::not_found)
        }

        /// Deletes an item.
        pub(crate) async fn $delete(
            State(state): State<AppState>,
            caller: Caller,
            Path(id): Path<String>,
        ) -> ApiResult<Response> {
            let id = path_id(&id)?;
            state
                .write(move |c| {
                    let v = &mut c.$($field).+;
                    let pos = v.iter().position(|x| x.id == Some(id)).ok_or_else(ApiError::not_found)?;
                    v.remove(pos);
                    Ok(())
                })
                .await?;
            audit(&state, &caller, "dns.delete", Some(format!(concat!($label, ":{}"), id)), true, None).await;
            Ok(no_content())
        }
    };
}

dns_crud!(
    records_list, records_get, records_create, records_patch, records_delete,
    field: local_dns.records, id: IdKind::Record, label: "record",
    out: model::record_out, create: RecordCreate => model::create_record, patch: RecordPatch => model::patch_record
);

dns_crud!(
    cnames_list, cnames_get, cnames_create, cnames_patch, cnames_delete,
    field: local_dns.cnames, id: IdKind::Cname, label: "cname",
    out: model::cname_out, create: CnameCreate => model::create_cname, patch: CnamePatch => model::patch_cname
);

dns_crud!(
    forwarders_list, forwarders_get, forwarders_create, forwarders_patch, forwarders_delete,
    field: local_dns.conditional_forwarding, id: IdKind::Forward, label: "forwarder",
    out: model::forwarder_out, create: ForwarderCreate => model::create_forwarder, patch: ForwarderPatch => model::patch_forwarder
);
