//! The JSON model of the API (docs/API.md) and its mapping to the config.
//!
//! Request bodies reject unknown and read-only fields (`deny_unknown_fields`, 422). The
//! functions that change a [`Config`] are pure: the handlers run them inside
//! [`AppState::write`](crate::state::AppState), which validates and writes the file.
//!
//! Response types never have a secret field: no password hash, TOTP secret or token hash.

use std::net::{IpAddr, Ipv4Addr};

use rusthole_core::config::{
    Adlist, ApiToken, Client, ConditionalForward, DEFAULT_GROUP, DEFAULT_GROUP_ID, Group, ListKind,
    LocalCname, LocalRecord, RecordType, Rule, RuleAction, RuleKind,
};
use rusthole_core::net::{Cidr, ClientId, parse_socket_addr};
use rusthole_core::{Config, DomainName};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

/// The 422 message for an IPv6 transport value (amendment A11).
pub const IPV6_LATER: &str = "IPv6 comes in a later version.";
/// The longest comment.
pub const MAX_COMMENT: usize = 500;
/// The longest token name.
pub const MAX_TOKEN_NAME: usize = 64;

fn comment_in(field: &str, c: Option<String>) -> ApiResult<Option<String>> {
    match c {
        Some(s) if s.chars().count() > MAX_COMMENT => Err(ApiError::invalid(
            field,
            format!("Use at most {MAX_COMMENT} characters."),
        )),
        Some(s) if s.chars().any(char::is_control) => {
            Err(ApiError::invalid(field, "Do not use control characters."))
        }
        Some(s) if s.is_empty() => Ok(None),
        other => Ok(other),
    }
}

fn comment_out(c: Option<&String>) -> String {
    c.cloned().unwrap_or_default()
}

/// The canonical form of a domain name field, or 422.
pub fn domain_in(field: &str, value: &str) -> ApiResult<String> {
    DomainName::parse_idn(value.trim())
        .map(|d| d.as_str().to_owned())
        .map_err(|e| ApiError::invalid(field, format!("Not a valid domain name: {e}.")))
}

/// Group ids to group names, or 422.
pub fn group_names(cfg: &Config, ids: &[u32]) -> ApiResult<Vec<String>> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        match cfg.group_name(*id) {
            Some(n) => {
                if !out.iter().any(|x: &String| x == n) {
                    out.push(n.to_owned());
                }
            }
            None => {
                return Err(ApiError::invalid(
                    "groups",
                    format!("No group has the id {id}."),
                ));
            }
        }
    }
    Ok(out)
}

/// Group names to group ids (unknown names are left out).
pub fn group_ids(cfg: &Config, names: &[String]) -> Vec<u32> {
    names.iter().filter_map(|n| cfg.group_id(n)).collect()
}

fn default_groups() -> Vec<String> {
    vec![DEFAULT_GROUP.to_owned()]
}

// ---------------------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------------------

/// `POST /lists`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListCreate {
    pub url: String,
    pub comment: Option<String>,
    pub kind: Option<ListKind>,
    pub enabled: Option<bool>,
    pub groups: Option<Vec<u32>>,
}

/// `PATCH /lists/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPatch {
    pub url: Option<String>,
    pub comment: Option<String>,
    pub kind: Option<ListKind>,
    pub enabled: Option<bool>,
    pub groups: Option<Vec<u32>>,
}

fn list_url(cfg: &Config, url: &str, except: Option<u32>) -> ApiResult<String> {
    let url = url.trim().to_owned();
    rusthole_core::config::check_list_url(&url)
        .map_err(|_| ApiError::invalid("url", "Use an http or https URL."))?;
    if cfg
        .lists
        .adlists
        .iter()
        .any(|l| l.url == url && Some(l.id) != except)
    {
        return Err(ApiError::conflict("A list with this URL exists."));
    }
    Ok(url)
}

/// Adds a list with id `id`.
pub fn create_list(cfg: &mut Config, req: ListCreate, id: u32) -> ApiResult<()> {
    let url = list_url(cfg, &req.url, None)?;
    let groups = match req.groups {
        Some(g) => group_names(cfg, &g)?,
        None => default_groups(),
    };
    cfg.lists.adlists.push(Adlist {
        id,
        url,
        kind: req.kind.unwrap_or(ListKind::Block),
        enabled: req.enabled.unwrap_or(true),
        groups,
        comment: comment_in("comment", req.comment)?,
    });
    Ok(())
}

/// Changes list `id`.
pub fn patch_list(cfg: &mut Config, id: u32, req: ListPatch) -> ApiResult<()> {
    let url = req.url.map(|u| list_url(cfg, &u, Some(id))).transpose()?;
    let groups = req.groups.map(|g| group_names(cfg, &g)).transpose()?;
    let comment = req
        .comment
        .map(|c| comment_in("comment", Some(c)))
        .transpose()?;
    let l = cfg
        .lists
        .adlists
        .iter_mut()
        .find(|l| l.id == id)
        .ok_or_else(ApiError::not_found)?;
    if let Some(u) = url {
        l.url = u;
    }
    if let Some(k) = req.kind {
        l.kind = k;
    }
    if let Some(e) = req.enabled {
        l.enabled = e;
    }
    if let Some(g) = groups {
        l.groups = g;
    }
    if let Some(c) = comment {
        l.comment = c;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------

/// A rule in a response.
#[derive(Debug, Clone, Serialize)]
pub struct RuleOut {
    pub id: u32,
    pub kind: RuleKind,
    pub action: RuleAction,
    pub pattern: String,
    pub enabled: bool,
    pub groups: Vec<u32>,
    pub comment: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// The API form of a rule.
pub fn rule_out(cfg: &Config, r: &Rule) -> RuleOut {
    RuleOut {
        id: r.id.unwrap_or_default(),
        kind: r.kind,
        action: r.action,
        pattern: r.value.clone(),
        enabled: r.enabled,
        groups: group_ids(cfg, &r.groups),
        comment: comment_out(r.comment.as_ref()),
        created_at: r.created_at.clone(),
        updated_at: r.updated_at.clone(),
    }
}

/// `POST /rules`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCreate {
    pub kind: RuleKind,
    pub action: RuleAction,
    pub pattern: String,
    pub enabled: Option<bool>,
    pub groups: Option<Vec<u32>>,
    pub comment: Option<String>,
}

/// `PATCH /rules/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePatch {
    pub kind: Option<RuleKind>,
    pub action: Option<RuleAction>,
    pub pattern: Option<String>,
    pub enabled: Option<bool>,
    pub groups: Option<Vec<u32>>,
    pub comment: Option<String>,
}

/// The canonical pattern of a rule, or 422.
pub fn rule_pattern(kind: RuleKind, pattern: &str) -> ApiResult<String> {
    match kind {
        RuleKind::Exact => domain_in("pattern", pattern),
        RuleKind::Regex => {
            rusthole_core::pattern::compile_rule_regex(pattern)
                .map_err(|e| ApiError::invalid("pattern", e.to_string()))?;
            Ok(pattern.to_owned())
        }
    }
}

fn rule_unique(
    cfg: &Config,
    kind: RuleKind,
    action: RuleAction,
    value: &str,
    except: Option<u32>,
) -> ApiResult<()> {
    if cfg
        .rules
        .iter()
        .any(|r| r.kind == kind && r.action == action && r.value == value && r.id != except)
    {
        return Err(ApiError::conflict("The same rule exists."));
    }
    Ok(())
}

/// Adds a rule with id `id` at wall time `now` (RFC 3339).
pub fn create_rule(cfg: &mut Config, req: RuleCreate, id: u32, now: &str) -> ApiResult<()> {
    let value = rule_pattern(req.kind, &req.pattern)?;
    rule_unique(cfg, req.kind, req.action, &value, None)?;
    let groups = match req.groups {
        Some(g) => group_names(cfg, &g)?,
        None => default_groups(),
    };
    cfg.rules.push(Rule {
        id: Some(id),
        kind: req.kind,
        action: req.action,
        value,
        enabled: req.enabled.unwrap_or(true),
        groups,
        comment: comment_in("comment", req.comment)?,
        created_at: Some(now.to_owned()),
        updated_at: Some(now.to_owned()),
    });
    Ok(())
}

/// Changes rule `id`.
pub fn patch_rule(cfg: &mut Config, id: u32, req: RulePatch, now: &str) -> ApiResult<()> {
    let cur = cfg
        .rules
        .iter()
        .find(|r| r.id == Some(id))
        .ok_or_else(ApiError::not_found)?
        .clone();
    let kind = req.kind.unwrap_or(cur.kind);
    let action = req.action.unwrap_or(cur.action);
    let value = match &req.pattern {
        Some(p) => rule_pattern(kind, p)?,
        None if req.kind.is_some() => rule_pattern(kind, &cur.value)?,
        None => cur.value.clone(),
    };
    rule_unique(cfg, kind, action, &value, Some(id))?;
    let groups = req.groups.map(|g| group_names(cfg, &g)).transpose()?;
    let comment = req
        .comment
        .map(|c| comment_in("comment", Some(c)))
        .transpose()?;
    let r = cfg
        .rules
        .iter_mut()
        .find(|r| r.id == Some(id))
        .ok_or_else(ApiError::not_found)?;
    r.kind = kind;
    r.action = action;
    r.value = value;
    if let Some(e) = req.enabled {
        r.enabled = e;
    }
    if let Some(g) = groups {
        r.groups = g;
    }
    if let Some(c) = comment {
        r.comment = c;
    }
    r.updated_at = Some(now.to_owned());
    Ok(())
}

/// `POST /rules/test`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTest {
    pub kind: RuleKind,
    pub pattern: String,
    pub domain: String,
}

/// The result of `POST /rules/test`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleTestOut {
    pub valid: bool,
    pub matches: bool,
    pub error: Option<String>,
}

/// Tests a pattern with the engine rules (Rust `regex`, case-insensitive, size limit).
/// Pure; the pattern and the name have length limits, and the regex is linear time.
pub fn test_rule(req: &RuleTest) -> ApiResult<RuleTestOut> {
    let name = DomainName::parse_idn(req.domain.trim())
        .map_err(|e| ApiError::invalid("domain", format!("Not a valid domain name: {e}.")))?;
    Ok(match req.kind {
        RuleKind::Exact => match DomainName::parse_idn(req.pattern.trim()) {
            Ok(p) => RuleTestOut {
                valid: true,
                matches: p == name,
                error: None,
            },
            Err(e) => RuleTestOut {
                valid: false,
                matches: false,
                error: Some(e.to_string()),
            },
        },
        RuleKind::Regex => match rusthole_core::pattern::compile_rule_regex(&req.pattern) {
            Ok(re) => RuleTestOut {
                valid: true,
                matches: re.is_match(name.as_str()),
                error: None,
            },
            Err(e) => RuleTestOut {
                valid: false,
                matches: false,
                error: Some(e.to_string()),
            },
        },
    })
}

// ---------------------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------------------

/// A group in a response.
#[derive(Debug, Clone, Serialize)]
pub struct GroupOut {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub comment: String,
    pub lists: usize,
    pub rules: usize,
    pub clients: usize,
}

/// The API form of a group, with its member counts.
pub fn group_out(cfg: &Config, g: &Group) -> GroupOut {
    let has = |groups: &[String]| groups.contains(&g.name);
    GroupOut {
        id: g.id.unwrap_or_default(),
        name: g.name.clone(),
        enabled: g.enabled,
        comment: comment_out(g.comment.as_ref()),
        lists: cfg.lists.adlists.iter().filter(|l| has(&l.groups)).count(),
        rules: cfg.rules.iter().filter(|r| has(&r.groups)).count(),
        clients: cfg.clients.iter().filter(|c| has(&c.groups)).count(),
    }
}

/// `POST /groups`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupCreate {
    pub name: String,
    pub enabled: Option<bool>,
    pub comment: Option<String>,
}

/// `PATCH /groups/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub comment: Option<String>,
}

fn group_name_in(cfg: &Config, name: &str, except: Option<u32>) -> ApiResult<String> {
    let name = name.trim().to_owned();
    if !rusthole_core::config::is_valid_group_name(&name) {
        return Err(ApiError::invalid(
            "name",
            "Use 1 to 64 characters: a-z, 0-9, '-', '_', '.'. Start with a letter or a digit.",
        ));
    }
    if cfg.groups.iter().any(|g| g.name == name && g.id != except) {
        return Err(ApiError::conflict("A group with this name exists."));
    }
    Ok(name)
}

/// Adds a group with id `id`.
pub fn create_group(cfg: &mut Config, req: GroupCreate, id: u32) -> ApiResult<()> {
    let name = group_name_in(cfg, &req.name, None)?;
    cfg.groups.push(Group {
        id: Some(id),
        name,
        enabled: req.enabled.unwrap_or(true),
        comment: comment_in("comment", req.comment)?,
    });
    Ok(())
}

fn rename_refs(groups: &mut [String], old: &str, new: &str) {
    for g in groups {
        if g == old {
            new.clone_into(g);
        }
    }
}

/// Changes group `id`. A new name changes the references in lists, rules and clients.
pub fn patch_group(cfg: &mut Config, id: u32, req: GroupPatch) -> ApiResult<()> {
    let old = cfg
        .groups
        .iter()
        .find(|g| g.id == Some(id))
        .ok_or_else(ApiError::not_found)?
        .name
        .clone();
    let name = match &req.name {
        Some(n) => {
            let n = group_name_in(cfg, n, Some(id))?;
            if old == DEFAULT_GROUP && n != DEFAULT_GROUP {
                return Err(ApiError::conflict(
                    "The default group cannot get a new name.",
                ));
            }
            Some(n)
        }
        None => None,
    };
    let comment = req
        .comment
        .map(|c| comment_in("comment", Some(c)))
        .transpose()?;
    if let Some(n) = &name {
        for l in &mut cfg.lists.adlists {
            rename_refs(&mut l.groups, &old, n);
        }
        for r in &mut cfg.rules {
            rename_refs(&mut r.groups, &old, n);
        }
        for c in &mut cfg.clients {
            rename_refs(&mut c.groups, &old, n);
        }
    }
    let g = cfg
        .groups
        .iter_mut()
        .find(|g| g.id == Some(id))
        .ok_or_else(ApiError::not_found)?;
    if let Some(n) = name {
        g.name = n;
    }
    if let Some(e) = req.enabled {
        g.enabled = e;
    }
    if let Some(c) = comment {
        g.comment = c;
    }
    Ok(())
}

/// Deletes group `id` and removes it from all lists, rules and clients. The default group
/// cannot be deleted.
pub fn delete_group(cfg: &mut Config, id: u32) -> ApiResult<()> {
    if id == DEFAULT_GROUP_ID {
        return Err(ApiError::conflict("The default group cannot be deleted."));
    }
    let pos = cfg
        .groups
        .iter()
        .position(|g| g.id == Some(id))
        .ok_or_else(ApiError::not_found)?;
    let name = cfg.groups.remove(pos).name;
    for l in &mut cfg.lists.adlists {
        l.groups.retain(|g| *g != name);
    }
    for r in &mut cfg.rules {
        r.groups.retain(|g| *g != name);
    }
    for c in &mut cfg.clients {
        c.groups.retain(|g| *g != name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------

/// A configured client in a response.
#[derive(Debug, Clone, Serialize)]
pub struct ClientOut {
    pub id: u32,
    #[serde(rename = "match")]
    pub match_: String,
    pub kind: &'static str,
    pub groups: Vec<u32>,
    pub comment: String,
}

/// The kind of a client match text.
pub fn client_kind(id: &ClientId) -> &'static str {
    match id {
        ClientId::Ip(_) => "ip",
        ClientId::Cidr(_) => "cidr",
        ClientId::Mac(_) => "mac",
        ClientId::Hostname(_) => "host",
    }
}

/// The API form of a client.
pub fn client_out(cfg: &Config, c: &Client) -> ClientOut {
    ClientOut {
        id: c.uid.unwrap_or_default(),
        match_: c.id.clone(),
        kind: ClientId::parse(&c.id).map_or("host", |id| client_kind(&id)),
        groups: group_ids(cfg, &c.groups),
        comment: comment_out(c.comment.as_ref()),
    }
}

/// `POST /clients`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCreate {
    #[serde(rename = "match")]
    pub match_: String,
    pub groups: Option<Vec<u32>>,
    pub comment: Option<String>,
}

/// `PATCH /clients/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPatch {
    #[serde(rename = "match")]
    pub match_: Option<String>,
    pub groups: Option<Vec<u32>>,
    pub comment: Option<String>,
}

fn client_match(cfg: &Config, text: &str, except: Option<u32>) -> ApiResult<String> {
    let id = ClientId::parse(text).map_err(|e| ApiError::invalid("match", e.to_string()))?;
    match &id {
        ClientId::Ip(ip) if ip.is_ipv6() => return Err(ApiError::invalid("match", IPV6_LATER)),
        ClientId::Cidr(c) if c.addr.is_ipv6() => {
            return Err(ApiError::invalid("match", IPV6_LATER));
        }
        _ => {}
    }
    if cfg
        .clients
        .iter()
        .any(|c| c.uid != except && ClientId::parse(&c.id).is_ok_and(|x| x == id))
    {
        return Err(ApiError::conflict("A client with this match exists."));
    }
    Ok(id.to_string())
}

/// Adds a client with id `id`.
pub fn create_client(cfg: &mut Config, req: ClientCreate, id: u32) -> ApiResult<()> {
    let m = client_match(cfg, &req.match_, None)?;
    let groups = match req.groups {
        Some(g) => group_names(cfg, &g)?,
        None => default_groups(),
    };
    cfg.clients.push(Client {
        uid: Some(id),
        id: m,
        groups,
        comment: comment_in("comment", req.comment)?,
    });
    Ok(())
}

/// Changes client `id`.
pub fn patch_client(cfg: &mut Config, id: u32, req: ClientPatch) -> ApiResult<()> {
    let m = req
        .match_
        .map(|m| client_match(cfg, &m, Some(id)))
        .transpose()?;
    let groups = req.groups.map(|g| group_names(cfg, &g)).transpose()?;
    let comment = req
        .comment
        .map(|c| comment_in("comment", Some(c)))
        .transpose()?;
    let c = cfg
        .clients
        .iter_mut()
        .find(|c| c.uid == Some(id))
        .ok_or_else(ApiError::not_found)?;
    if let Some(m) = m {
        c.id = m;
    }
    if let Some(g) = groups {
        c.groups = g;
    }
    if let Some(cm) = comment {
        c.comment = cm;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Local DNS
// ---------------------------------------------------------------------------------------

/// A local record in a response.
#[derive(Debug, Clone, Serialize)]
pub struct RecordOut {
    pub id: u32,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub address: String,
    pub comment: String,
    pub enabled: bool,
}

/// The API form of a local record.
pub fn record_out(r: &LocalRecord) -> RecordOut {
    RecordOut {
        id: r.id.unwrap_or_default(),
        name: r.name.clone(),
        record_type: r.record_type,
        address: r.value.clone(),
        comment: comment_out(r.comment.as_ref()),
        enabled: r.enabled,
    }
}

/// `POST /dns/records`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordCreate {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub address: String,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// `PATCH /dns/records/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordPatch {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub record_type: Option<RecordType>,
    pub address: Option<String>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

fn address_in(t: RecordType, addr: &str) -> ApiResult<String> {
    let ip: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| ApiError::invalid("address", "Not an IP address."))?;
    match (t, ip) {
        (RecordType::A, IpAddr::V4(_)) | (RecordType::Aaaa, IpAddr::V6(_)) => Ok(ip.to_string()),
        _ => Err(ApiError::invalid(
            "address",
            "The address family must match the type.",
        )),
    }
}

fn no_cname_on(cfg: &Config, name: &str) -> ApiResult<()> {
    if cfg.local_dns.cnames.iter().any(|c| c.name == name) {
        return Err(ApiError::conflict("This name has a local CNAME."));
    }
    Ok(())
}

/// Adds a local record with id `id`.
pub fn create_record(cfg: &mut Config, req: RecordCreate, id: u32) -> ApiResult<()> {
    let name = domain_in("name", &req.name)?;
    no_cname_on(cfg, &name)?;
    let value = address_in(req.record_type, &req.address)?;
    cfg.local_dns.records.push(LocalRecord {
        id: Some(id),
        name,
        record_type: req.record_type,
        value,
        enabled: req.enabled.unwrap_or(true),
        comment: comment_in("comment", req.comment)?,
    });
    Ok(())
}

/// Changes local record `id`.
pub fn patch_record(cfg: &mut Config, id: u32, req: RecordPatch) -> ApiResult<()> {
    let cur = cfg
        .local_dns
        .records
        .iter()
        .find(|r| r.id == Some(id))
        .ok_or_else(ApiError::not_found)?
        .clone();
    let name = match &req.name {
        Some(n) => {
            let n = domain_in("name", n)?;
            no_cname_on(cfg, &n)?;
            n
        }
        None => cur.name.clone(),
    };
    let t = req.record_type.unwrap_or(cur.record_type);
    let value = address_in(t, req.address.as_deref().unwrap_or(&cur.value))?;
    let comment = req
        .comment
        .map(|c| comment_in("comment", Some(c)))
        .transpose()?;
    let r = cfg
        .local_dns
        .records
        .iter_mut()
        .find(|r| r.id == Some(id))
        .ok_or_else(ApiError::not_found)?;
    r.name = name;
    r.record_type = t;
    r.value = value;
    if let Some(e) = req.enabled {
        r.enabled = e;
    }
    if let Some(c) = comment {
        r.comment = c;
    }
    Ok(())
}

/// A local CNAME in a response.
#[derive(Debug, Clone, Serialize)]
pub struct CnameOut {
    pub id: u32,
    pub name: String,
    pub target: String,
    pub comment: String,
    pub enabled: bool,
}

/// The API form of a local CNAME.
pub fn cname_out(c: &LocalCname) -> CnameOut {
    CnameOut {
        id: c.id.unwrap_or_default(),
        name: c.name.clone(),
        target: c.target.clone(),
        comment: comment_out(c.comment.as_ref()),
        enabled: c.enabled,
    }
}

/// `POST /dns/cnames`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CnameCreate {
    pub name: String,
    pub target: String,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// `PATCH /dns/cnames/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CnamePatch {
    pub name: Option<String>,
    pub target: Option<String>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

fn cname_name(cfg: &Config, name: &str, except: Option<u32>) -> ApiResult<String> {
    let name = domain_in("name", name)?;
    if cfg.local_dns.records.iter().any(|r| r.name == name) {
        return Err(ApiError::conflict(
            "This name has a local A or AAAA record.",
        ));
    }
    if cfg
        .local_dns
        .cnames
        .iter()
        .any(|c| c.name == name && c.id != except)
    {
        return Err(ApiError::conflict("A CNAME with this name exists."));
    }
    Ok(name)
}

/// Adds a local CNAME with id `id`.
pub fn create_cname(cfg: &mut Config, req: CnameCreate, id: u32) -> ApiResult<()> {
    let name = cname_name(cfg, &req.name, None)?;
    let target = domain_in("target", &req.target)?;
    cfg.local_dns.cnames.push(LocalCname {
        id: Some(id),
        name,
        target,
        ttl: None,
        enabled: req.enabled.unwrap_or(true),
        comment: comment_in("comment", req.comment)?,
    });
    Ok(())
}

/// Changes local CNAME `id`.
pub fn patch_cname(cfg: &mut Config, id: u32, req: CnamePatch) -> ApiResult<()> {
    let name = req
        .name
        .map(|n| cname_name(cfg, &n, Some(id)))
        .transpose()?;
    let target = req.target.map(|t| domain_in("target", &t)).transpose()?;
    let comment = req
        .comment
        .map(|c| comment_in("comment", Some(c)))
        .transpose()?;
    let c = cfg
        .local_dns
        .cnames
        .iter_mut()
        .find(|c| c.id == Some(id))
        .ok_or_else(ApiError::not_found)?;
    if let Some(n) = name {
        c.name = n;
    }
    if let Some(t) = target {
        c.target = t;
    }
    if let Some(e) = req.enabled {
        c.enabled = e;
    }
    if let Some(cm) = comment {
        c.comment = cm;
    }
    Ok(())
}

/// A conditional forwarding rule in a response.
#[derive(Debug, Clone, Serialize)]
pub struct ForwarderOut {
    pub id: u32,
    pub domain: String,
    pub servers: Vec<String>,
    pub comment: String,
    pub enabled: bool,
}

/// The reverse zone of an IPv4 network on an octet boundary (`/8`, `/16`, `/24`), for
/// example `2.0.192.in-addr.arpa` for `192.0.2.0/24`.
pub fn reverse_zone(cidr: &Cidr) -> Option<String> {
    let IpAddr::V4(v4) = cidr.addr else {
        return None;
    };
    let o = v4.octets();
    let n = match cidr.prefix {
        8 => 1,
        16 => 2,
        24 => 3,
        32 => 4,
        _ => return None,
    };
    let mut labels: Vec<String> = o.iter().take(n).map(ToString::to_string).collect();
    labels.reverse();
    Some(format!("{}.in-addr.arpa", labels.join(".")))
}

/// The network of an IPv4 reverse zone (`2.0.192.in-addr.arpa` gives `192.0.2.0/24`).
/// `Err` with the 422 message for an `ip6.arpa` zone; `Ok(None)` for a name that is not a
/// reverse zone.
pub fn zone_network(domain: &str) -> ApiResult<Option<Cidr>> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d == "ip6.arpa" || d.ends_with(".ip6.arpa") {
        return Err(ApiError::invalid("domain", IPV6_LATER));
    }
    let Some(rest) = d.strip_suffix(".in-addr.arpa") else {
        return Ok(None);
    };
    let labels: Vec<&str> = rest.split('.').collect();
    if labels.is_empty() || labels.len() > 4 {
        return Err(ApiError::invalid(
            "domain",
            "Not a valid IPv4 reverse zone.",
        ));
    }
    let mut octets = [0u8; 4];
    for (i, l) in labels.iter().rev().enumerate() {
        let v: u8 = l
            .parse()
            .ok()
            .filter(|_| !l.is_empty() && (l.len() == 1 || !l.starts_with('0')))
            .ok_or_else(|| ApiError::invalid("domain", "Not a valid IPv4 reverse zone."))?;
        if let Some(slot) = octets.get_mut(i) {
            *slot = v;
        }
    }
    let prefix = u8::try_from(labels.len() * 8).unwrap_or(32);
    Ok(Some(Cidr {
        addr: IpAddr::V4(Ipv4Addr::from(octets)),
        prefix,
    }))
}

/// The API form of a conditional forwarding rule. A rule with a domain shows the domain;
/// a rule with a network only shows its reverse zone (or the CIDR text when the network is
/// not on an octet boundary).
pub fn forwarder_out(f: &ConditionalForward) -> ForwarderOut {
    let domain = f.domain.clone().unwrap_or_else(|| {
        Cidr::parse(&f.cidr)
            .ok()
            .and_then(|c| reverse_zone(&c))
            .unwrap_or_else(|| f.cidr.clone())
    });
    ForwarderOut {
        id: f.id.unwrap_or_default(),
        domain,
        servers: vec![f.server.clone()],
        comment: comment_out(f.comment.as_ref()),
        enabled: f.enabled,
    }
}

/// `POST /dns/forwarders`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwarderCreate {
    pub domain: String,
    pub servers: Vec<String>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// `PATCH /dns/forwarders/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwarderPatch {
    pub domain: Option<String>,
    pub servers: Option<Vec<String>>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

/// The one server of a rule. v1 keeps one server for each rule (the config has one
/// `server` field); more than one gives 422.
fn forward_server(servers: &[String]) -> ApiResult<String> {
    match servers {
        [one] => {
            let addr = parse_socket_addr(one, 53)
                .map_err(|e| ApiError::invalid("servers", e.to_string()))?;
            if addr.is_ipv6() {
                return Err(ApiError::invalid("servers", IPV6_LATER));
            }
            Ok(one.trim().to_owned())
        }
        [] => Err(ApiError::invalid("servers", "Give one server.")),
        _ => Err(ApiError::invalid(
            "servers",
            "This version keeps one server for each rule. Add one rule for each server.",
        )),
    }
}

/// The `cidr` and `domain` fields of a rule for an API domain.
fn forward_target(domain: &str) -> ApiResult<(String, Option<String>)> {
    match zone_network(domain)? {
        Some(c) => Ok((c.to_string(), None)),
        None => Ok((String::new(), Some(domain_in("domain", domain)?))),
    }
}

/// Adds a conditional forwarding rule with id `id`.
pub fn create_forwarder(cfg: &mut Config, req: ForwarderCreate, id: u32) -> ApiResult<()> {
    let (cidr, domain) = forward_target(&req.domain)?;
    let server = forward_server(&req.servers)?;
    cfg.local_dns
        .conditional_forwarding
        .push(ConditionalForward {
            id: Some(id),
            enabled: req.enabled.unwrap_or(true),
            cidr,
            server,
            domain,
            comment: comment_in("comment", req.comment)?,
        });
    Ok(())
}

/// Changes conditional forwarding rule `id`. A domain that does not change keeps the
/// network of the rule.
pub fn patch_forwarder(cfg: &mut Config, id: u32, req: ForwarderPatch) -> ApiResult<()> {
    let cur = cfg
        .local_dns
        .conditional_forwarding
        .iter()
        .find(|f| f.id == Some(id))
        .ok_or_else(ApiError::not_found)?
        .clone();
    let target = match &req.domain {
        Some(d) if *d != forwarder_out(&cur).domain => Some(forward_target(d)?),
        _ => None,
    };
    let server = req.servers.as_deref().map(forward_server).transpose()?;
    let comment = req
        .comment
        .map(|c| comment_in("comment", Some(c)))
        .transpose()?;
    let f = cfg
        .local_dns
        .conditional_forwarding
        .iter_mut()
        .find(|f| f.id == Some(id))
        .ok_or_else(ApiError::not_found)?;
    if let Some((cidr, domain)) = target {
        f.cidr = cidr;
        f.domain = domain;
    }
    if let Some(s) = server {
        f.server = s;
    }
    if let Some(e) = req.enabled {
        f.enabled = e;
    }
    if let Some(c) = comment {
        f.comment = c;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------------------

/// A token in a response. The hash is never in it.
#[derive(Debug, Clone, Serialize)]
pub struct TokenOut {
    pub id: u32,
    pub name: String,
    pub prefix: String,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
    pub last_used_ip: Option<String>,
}

/// `POST /tokens`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenCreate {
    pub name: String,
    pub password: String,
}

/// Adds a token. `secret` is the full token; the config keeps only its hash.
pub fn create_token(
    cfg: &mut Config,
    name: &str,
    id: u32,
    secret: &str,
    now: &str,
) -> ApiResult<()> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_TOKEN_NAME
        || name.chars().any(char::is_control)
    {
        return Err(ApiError::invalid(
            "name",
            format!("Use 1 to {MAX_TOKEN_NAME} characters."),
        ));
    }
    if cfg.admin.api_tokens.iter().any(|t| t.name == name) {
        return Err(ApiError::conflict("A token with this name exists."));
    }
    cfg.admin.api_tokens.push(ApiToken {
        id: Some(id),
        name: name.to_owned(),
        hash: format!(
            "sha256:{}",
            crate::util::hex(&crate::util::sha256(secret.as_bytes()))
        ),
        prefix: Some(secret.chars().take(7).collect()),
        created_at: Some(now.to_owned()),
    });
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Other request bodies
// ---------------------------------------------------------------------------------------

/// `POST /auth/login`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginReq {
    pub password: String,
    pub totp: Option<String>,
}

/// `PUT /blocking`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockingReq {
    pub enabled: bool,
    pub duration_seconds: Option<u64>,
}

/// The longest timed disable (docs/API.md section 4).
pub const MAX_DISABLE_SECONDS: u64 = 86_400;

/// Checks a blocking request.
pub fn check_blocking(req: &BlockingReq) -> ApiResult<()> {
    match (req.enabled, req.duration_seconds) {
        (true, Some(_)) => Err(ApiError::invalid(
            "duration_seconds",
            "Send duration_seconds only with \"enabled\": false.",
        )),
        (false, Some(d)) if d == 0 || d > MAX_DISABLE_SECONDS => Err(ApiError::invalid(
            "duration_seconds",
            format!("Use 1 to {MAX_DISABLE_SECONDS} seconds."),
        )),
        _ => Ok(()),
    }
}

/// `POST /auth/totp/setup`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordReq {
    pub password: String,
}

/// `POST /auth/totp/confirm`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeReq {
    pub code: String,
}

/// `POST /auth/totp/disable`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableTotpReq {
    pub password: String,
    pub code: String,
}

#[cfg(test)]
mod tests;
