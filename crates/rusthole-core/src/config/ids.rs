//! Stable ids of config items for the admin API (docs/API.md section 16).
//!
//! The API names each list, rule, group, client, local record, CNAME, forwarding rule and
//! API token by an integer id. The config keeps the id (`id`, or `uid` for clients, because
//! the client key `id` holds the match text). An older file has no ids: at load, each item
//! without an id gets one in memory ([`Config::assign_ids`]): the highest id of its
//! collection plus one, in file order. The first write of the API then writes all ids to
//! the file.

use super::Config;

/// The id of the group `default`.
pub const DEFAULT_GROUP_ID: u32 = 0;

/// The kinds of items that have an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdKind {
    /// `lists.adlists`.
    List,
    /// `rules`.
    Rule,
    /// `groups`.
    Group,
    /// `clients` (key `uid`).
    Client,
    /// `local_dns.records`.
    Record,
    /// `local_dns.cnames`.
    Cname,
    /// `local_dns.conditional_forwarding`.
    Forward,
    /// `admin.api_tokens`.
    Token,
}

/// The next free id: one more than the highest of `used` and `floor - 1`. `None` when the
/// ids are used up (the highest id is `u32::MAX`).
///
/// `floor` is the smallest id to give. Groups use 1, because 0 is the group `default`.
pub fn next_free_id(used: impl IntoIterator<Item = u32>, floor: u32) -> Option<u32> {
    match used.into_iter().max() {
        None => Some(floor),
        Some(max) => max.checked_add(1).map(|n| n.max(floor)),
    }
}

/// Gives each `None` slot the next free id, in order. The ids that are set do not change.
fn fill(slots: Vec<&mut Option<u32>>, floor: u32) {
    let mut next = next_free_id(slots.iter().filter_map(|s| **s), floor);
    for slot in slots {
        if slot.is_none() {
            *slot = next;
            next = next.and_then(|n| n.checked_add(1));
        }
    }
}

impl Config {
    /// Gives an id to each item that has none (in memory only). See the module
    /// documentation. The group `default` gets id 0 when it has none. A second call
    /// changes nothing.
    pub fn assign_ids(&mut self) {
        for g in &mut self.groups {
            if g.id.is_none() && g.name == super::DEFAULT_GROUP {
                g.id = Some(DEFAULT_GROUP_ID);
            }
        }
        let floor_groups = DEFAULT_GROUP_ID + 1;
        fill(
            self.groups
                .iter_mut()
                .filter(|g| g.name != super::DEFAULT_GROUP || g.id.is_some())
                .map(|g| &mut g.id)
                .collect(),
            floor_groups,
        );
        fill(self.rules.iter_mut().map(|r| &mut r.id).collect(), 1);
        fill(self.clients.iter_mut().map(|c| &mut c.uid).collect(), 1);
        let l = &mut self.local_dns;
        fill(l.records.iter_mut().map(|r| &mut r.id).collect(), 1);
        fill(l.cnames.iter_mut().map(|c| &mut c.id).collect(), 1);
        fill(
            l.conditional_forwarding
                .iter_mut()
                .map(|f| &mut f.id)
                .collect(),
            1,
        );
        fill(
            self.admin
                .api_tokens
                .iter_mut()
                .map(|t| &mut t.id)
                .collect(),
            1,
        );
    }

    /// True when every item has an id (after [`Config::assign_ids`]).
    pub fn has_all_ids(&self) -> bool {
        self.groups.iter().all(|g| g.id.is_some())
            && self.rules.iter().all(|r| r.id.is_some())
            && self.clients.iter().all(|c| c.uid.is_some())
            && self.local_dns.records.iter().all(|r| r.id.is_some())
            && self.local_dns.cnames.iter().all(|c| c.id.is_some())
            && self
                .local_dns
                .conditional_forwarding
                .iter()
                .all(|f| f.id.is_some())
            && self.admin.api_tokens.iter().all(|t| t.id.is_some())
    }

    /// The ids that are used now in a collection.
    pub fn ids_of(&self, kind: IdKind) -> Vec<u32> {
        let l = &self.local_dns;
        match kind {
            IdKind::List => self.lists.adlists.iter().map(|a| a.id).collect(),
            IdKind::Rule => self.rules.iter().filter_map(|r| r.id).collect(),
            IdKind::Group => self.groups.iter().filter_map(|g| g.id).collect(),
            IdKind::Client => self.clients.iter().filter_map(|c| c.uid).collect(),
            IdKind::Record => l.records.iter().filter_map(|r| r.id).collect(),
            IdKind::Cname => l.cnames.iter().filter_map(|c| c.id).collect(),
            IdKind::Forward => l
                .conditional_forwarding
                .iter()
                .filter_map(|f| f.id)
                .collect(),
            IdKind::Token => self.admin.api_tokens.iter().filter_map(|t| t.id).collect(),
        }
    }

    /// The id of each group name (after [`Config::assign_ids`]).
    pub fn group_id(&self, name: &str) -> Option<u32> {
        self.groups
            .iter()
            .find(|g| g.name == name)
            .and_then(|g| g.id)
    }

    /// The name of the group with this id.
    pub fn group_name(&self, id: u32) -> Option<&str> {
        self.groups
            .iter()
            .find(|g| g.id == Some(id))
            .map(|g| g.name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Group, Rule, RuleAction, RuleKind};

    fn rule(id: Option<u32>) -> Rule {
        Rule {
            id,
            kind: RuleKind::Exact,
            action: RuleAction::Deny,
            value: "a.example".to_owned(),
            enabled: true,
            groups: vec!["default".to_owned()],
            comment: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn next_free_id_is_max_plus_one() {
        assert_eq!(next_free_id([], 1), Some(1));
        assert_eq!(next_free_id([3, 7, 2], 1), Some(8));
        assert_eq!(next_free_id([0], 1), Some(1));
        assert_eq!(next_free_id([u32::MAX], 1), None);
    }

    #[test]
    fn assign_keeps_set_ids_and_fills_in_file_order() {
        let mut c = Config {
            rules: vec![rule(None), rule(Some(5)), rule(None)],
            ..Config::default()
        };
        c.groups.push(Group {
            id: None,
            name: "kids".to_owned(),
            enabled: true,
            comment: None,
        });
        c.assign_ids();
        let ids: Vec<_> = c.rules.iter().map(|r| r.id).collect();
        assert_eq!(ids, [Some(6), Some(5), Some(7)]);
        assert_eq!(c.group_id("default"), Some(0));
        assert_eq!(c.group_id("kids"), Some(1));
        assert_eq!(c.group_name(1), Some("kids"));
        assert!(c.has_all_ids());
        let before = c.clone();
        c.assign_ids();
        assert_eq!(c, before);
    }

    #[test]
    fn default_group_with_an_id_keeps_it() {
        let mut c = Config::default();
        c.groups[0].id = Some(4);
        c.assign_ids();
        assert_eq!(c.group_id("default"), Some(4));
    }
}
