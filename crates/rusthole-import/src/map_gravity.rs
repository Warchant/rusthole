//! Pure mapping from [`Gravity`] to the rusthole config.
//!
//! Group membership stays exact. The `*_by_group` tables are the only source of membership:
//! an item with no group link gets an empty group list, so no client uses it (as in Pi-hole).

use std::collections::{BTreeMap, HashMap, HashSet};

use rusthole_core::DomainName;
use rusthole_core::config::{
    Adlist, Client, Config, DEFAULT_GROUP, Group, ListKind, MAX_GROUP_NAME_LEN, Rule, RuleAction,
    RuleKind, check_list_url, is_valid_group_name,
};
use rusthole_core::net::ClientId;
use rusthole_core::pattern::compile_rule_regex;

use crate::ImportReport;
use crate::gravity::{DomainRow, Gravity};

/// Pi-hole regex extensions that the `regex` crate does not know (decision D4).
const PIHOLE_REGEX_EXTENSIONS: [&str; 3] = [";querytype=", ";invert", ";reply="];

/// Changes a Pi-hole group name to a valid rusthole group name.
///
/// The function changes letters to lowercase, changes each other bad character to `-`, and
/// removes `-` at the start and the end. The result can be empty.
pub fn sanitize_group_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        let keep = c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c);
        let c = if keep { c } else { '-' };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    let trimmed = out.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    trimmed
        .char_indices()
        .take_while(|(i, _)| *i < MAX_GROUP_NAME_LEN - 12)
        .map(|(_, c)| c)
        .collect()
}

/// Gives each Pi-hole group a unique, valid rusthole name.
fn map_groups(g: &Gravity, config: &mut Config, report: &mut ImportReport) -> HashMap<i64, String> {
    let mut names: HashMap<i64, String> = HashMap::new();
    let mut used: HashSet<String> = config.groups.iter().map(|g| g.name.clone()).collect();
    let mut rows: Vec<_> = g.groups.iter().collect();
    rows.sort_by_key(|r| r.id);
    let mut seen_ids = HashSet::new();
    if !rows.iter().any(|r| r.id == 0) {
        report.report("gravity.db has no Default group (id 0); rusthole adds group \"default\"");
    }
    for row in rows {
        if !seen_ids.insert(row.id) {
            report.report(format!(
                "group id {}: the id occurs twice; the second row is not imported",
                row.id
            ));
            continue;
        }
        if row.id == 0 {
            if let Some(def) = config.groups.iter_mut().find(|g| g.name == DEFAULT_GROUP) {
                def.enabled = row.enabled;
                def.comment.clone_from(&row.description);
            }
            names.insert(0, DEFAULT_GROUP.to_owned());
            report.translate(format!(
                "group id 0 {:?} -> groups \"default\"{}",
                row.name,
                if row.enabled { "" } else { " (disabled)" }
            ));
            continue;
        }
        let base = sanitize_group_name(&row.name);
        let candidates = [
            base.clone(),
            format!("{base}-{}", row.id),
            format!("group-{}", row.id),
        ];
        // Each candidate list is finite, so this search ends.
        let name = candidates
            .into_iter()
            .chain((2..=g.groups.len() + 2).map(|n| format!("group-{}-{n}", row.id)))
            .find(|c| is_valid_group_name(c) && !used.contains(c));
        let Some(name) = name else {
            report.report(format!(
                "group id {} {:?}: no free name; the group is not imported",
                row.id, row.name
            ));
            continue;
        };
        if name != row.name {
            report.report(format!(
                "group id {}: renamed {:?} to {name:?} (rusthole group names use a-z, 0-9, '-', '_', '.' and are unique)",
                row.id, row.name
            ));
        }
        used.insert(name.clone());
        config.groups.push(Group {
            name: name.clone(),
            enabled: row.enabled,
            comment: row.description.clone(),
        });
        report.translate(format!(
            "group id {} {:?} -> groups {name:?}{}",
            row.id,
            row.name,
            if row.enabled { "" } else { " (disabled)" }
        ));
        names.insert(row.id, name);
    }
    names
}

/// Builds item ID -> group names from a link table. The names keep the Pi-hole group order.
fn links(
    pairs: &[(i64, i64)],
    groups: &HashMap<i64, String>,
    table: &str,
    report: &mut ImportReport,
) -> HashMap<i64, Vec<String>> {
    let mut by_item: HashMap<i64, BTreeMap<i64, String>> = HashMap::new();
    // Sort, so that the report has the same order as a read from SQLite.
    let mut sorted = pairs.to_vec();
    sorted.sort_unstable();
    for (item, group) in sorted {
        match groups.get(&group) {
            Some(name) => {
                by_item.entry(item).or_default().insert(group, name.clone());
            }
            None => report.report(format!(
                "{table}: link from id {item} to unknown group id {group} is not imported"
            )),
        }
    }
    by_item
        .into_iter()
        .map(|(k, v)| (k, v.into_values().collect()))
        .collect()
}

fn no_group_note(report: &mut ImportReport, what: &str) {
    report.report(format!(
        "{what} is in no group: no client uses it (the same as in Pi-hole)"
    ));
}

/// Maps the gravity tables into `config`. Each row ends up in the config or in the report.
///
/// Returns the rusthole name of each imported Pi-hole group ID.
pub fn map_gravity(
    g: &Gravity,
    config: &mut Config,
    report: &mut ImportReport,
) -> HashMap<i64, String> {
    let groups = map_groups(g, config, report);
    map_adlists(g, &groups, config, report);
    map_domainlist(g, &groups, config, report);
    map_clients(g, &groups, config, report);
    groups
}

fn map_adlists(
    g: &Gravity,
    groups: &HashMap<i64, String>,
    config: &mut Config,
    report: &mut ImportReport,
) {
    let by_list = links(&g.adlist_by_group, groups, "adlist_by_group", report);
    let mut ids = HashSet::new();
    let mut urls = HashSet::new();
    for row in &g.adlists {
        let what = format!("adlist id {}", row.id);
        let Ok(id) = u32::try_from(row.id) else {
            report.report(format!("{what}: the id is out of range; not imported"));
            continue;
        };
        if !ids.insert(id) {
            report.report(format!("{what}: the id occurs twice; not imported"));
            continue;
        }
        let kind = match row.kind {
            0 => ListKind::Block,
            1 => ListKind::Allow,
            other => {
                report.report(format!("{what}: unknown list type {other}; not imported"));
                continue;
            }
        };
        let url = row.address.trim();
        if let Err(why) = check_list_url(url) {
            report.report(format!(
                "{what}: {why}; rusthole fetches only http:// and https:// lists; not imported"
            ));
            continue;
        }
        if !urls.insert(url.to_owned()) {
            report.report(format!("{what}: the URL occurs twice; not imported"));
            continue;
        }
        let list_groups = by_list.get(&row.id).cloned().unwrap_or_default();
        if list_groups.is_empty() {
            no_group_note(report, &what);
        }
        report.translate(format!(
            "{what} {url} ({}{}) -> lists.adlists[{}], groups {:?}",
            match kind {
                ListKind::Block => "block",
                ListKind::Allow => "allow",
            },
            if row.enabled { "" } else { ", disabled" },
            config.lists.adlists.len(),
            list_groups
        ));
        config.lists.adlists.push(Adlist {
            id,
            url: url.to_owned(),
            kind,
            enabled: row.enabled,
            groups: list_groups,
            comment: row.comment.clone(),
        });
    }
}

/// The rule for one domainlist row, or the reason why it cannot be imported.
fn domain_rule(row: &DomainRow) -> Result<(RuleKind, RuleAction, String), String> {
    let (kind, action) = match row.kind {
        0 => (RuleKind::Exact, RuleAction::Allow),
        1 => (RuleKind::Exact, RuleAction::Deny),
        2 => (RuleKind::Regex, RuleAction::Allow),
        3 => (RuleKind::Regex, RuleAction::Deny),
        other => return Err(format!("unknown type {other}")),
    };
    let value = match kind {
        RuleKind::Exact => DomainName::parse_idn(row.domain.trim())
            .map_err(|e| format!("{:?} is not a valid domain name: {e}", row.domain))?
            .as_str()
            .to_owned(),
        RuleKind::Regex => {
            if let Some(ext) = PIHOLE_REGEX_EXTENSIONS
                .iter()
                .find(|ext| row.domain.contains(*ext))
            {
                return Err(format!(
                    "regex {:?} uses the Pi-hole extension {ext:?}, which rusthole does not support yet",
                    row.domain
                ));
            }
            compile_rule_regex(&row.domain)
                .map_err(|e| format!("regex {:?} cannot be used: {e}", row.domain))?;
            row.domain.clone()
        }
    };
    Ok((kind, action, value))
}

fn map_domainlist(
    g: &Gravity,
    groups: &HashMap<i64, String>,
    config: &mut Config,
    report: &mut ImportReport,
) {
    let by_rule = links(
        &g.domainlist_by_group,
        groups,
        "domainlist_by_group",
        report,
    );
    for row in &g.domainlist {
        let what = format!("domainlist id {}", row.id);
        match domain_rule(row) {
            Err(why) => report.report(format!("{what}: {why}; not imported")),
            Ok((kind, action, value)) => {
                let rule_groups = by_rule.get(&row.id).cloned().unwrap_or_default();
                if rule_groups.is_empty() {
                    no_group_note(report, &what);
                }
                report.translate(format!(
                    "{what} {} {} {value:?}{} -> rules[{}], groups {rule_groups:?}",
                    match kind {
                        RuleKind::Exact => "exact",
                        RuleKind::Regex => "regex",
                    },
                    match action {
                        RuleAction::Allow => "allow",
                        RuleAction::Deny => "deny",
                    },
                    if row.enabled { "" } else { " (disabled)" },
                    config.rules.len(),
                ));
                config.rules.push(Rule {
                    kind,
                    action,
                    value,
                    enabled: row.enabled,
                    groups: rule_groups,
                    comment: row.comment.clone(),
                });
            }
        }
    }
}

fn map_clients(
    g: &Gravity,
    groups: &HashMap<i64, String>,
    config: &mut Config,
    report: &mut ImportReport,
) {
    let by_client = links(&g.client_by_group, groups, "client_by_group", report);
    let mut seen: HashSet<ClientId> = HashSet::new();
    for row in &g.clients {
        let what = format!("client id {}", row.id);
        let parsed = match ClientId::parse(&row.ip) {
            Ok(id) => id,
            Err(e) => {
                report.report(format!("{what}: {e}; not imported"));
                continue;
            }
        };
        if !seen.insert(parsed.clone()) {
            report.report(format!(
                "{what}: {:?} is the same client as an earlier row; not imported",
                row.ip
            ));
            continue;
        }
        let client_groups = by_client.get(&row.id).cloned().unwrap_or_default();
        if client_groups.is_empty() {
            report.report(format!(
                "{what} is in no group: no list or rule applies to it (the same as in Pi-hole)"
            ));
        }
        let id = parsed.to_string();
        report.translate(format!(
            "{what} {id} -> clients[{}], groups {client_groups:?}",
            config.clients.len()
        ));
        config.clients.push(Client {
            id,
            groups: client_groups,
            comment: row.comment.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_group_name("Kids"), "kids");
        assert_eq!(sanitize_group_name("Smart TV & IoT"), "smart-tv-iot");
        assert_eq!(sanitize_group_name("  --x--  "), "x");
        assert_eq!(sanitize_group_name("\u{1f600}"), "");
        assert!(sanitize_group_name(&"a".repeat(200)).len() <= MAX_GROUP_NAME_LEN - 12);
    }

    #[test]
    fn regex_extensions_are_reported() {
        for ext in [";querytype=AAAA", ";invert", ";reply=nxdomain"] {
            let row = DomainRow {
                id: 1,
                kind: 3,
                domain: format!("^ads\\.{ext}"),
                enabled: true,
                comment: None,
            };
            let err = domain_rule(&row).unwrap_err();
            assert!(err.contains("Pi-hole extension"), "{err}");
        }
    }
}
