//! Client identity (part P3c): which groups apply to the queries of one client.
//!
//! The functions here are pure. The DNS crate gives the facts that it knows about a client:
//! the IP address, the MAC address from the neighbor table, and a host name from a reverse
//! lookup. [`ClientTable::resolve`] gives the groups of the client.
//!
//! Precedence (docs/CLIENTS.md):
//!
//! 1. A `[[clients]]` entry with the exact IP address.
//! 2. An entry with the MAC address.
//! 3. An entry with the host name.
//! 4. The entry with the most specific CIDR block that holds the address. When two blocks
//!    have the same prefix length, the first one in the config wins.
//! 5. No entry: the group `default`.
//!
//! A disabled group, or a group that the config does not define, gives nothing.
//!
//! [`TtlLru`] is a bounded map with a time to live. The DNS crate uses it to keep the result
//! for each client address for a short time, so that a MAC address that comes later is used.

use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;

use crate::config::{Config, ConfigIssue, DEFAULT_GROUP};
use crate::domain::DomainName;
use crate::net::{Cidr, ClientId, MacAddr};

/// Entries in the client cache of the DNS crate, at most.
pub const CLIENT_CACHE_ENTRIES: usize = 4096;
/// Time to live of one entry of the client cache, in milliseconds. It is short, so that a
/// MAC address or a host name that comes later is used soon.
pub const CLIENT_CACHE_TTL_MS: u64 = 10_000;

/// Which kind of `[[clients]]` entry matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchedBy {
    /// The exact IP address.
    Ip,
    /// The MAC address.
    Mac,
    /// The host name.
    Hostname,
    /// A CIDR block.
    Cidr,
    /// No entry: the group `default`.
    Default,
}

/// The result of [`ClientTable::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Which kind of entry matched.
    pub matched: MatchedBy,
    /// The index of the entry in `clients` of the config. `None` for [`MatchedBy::Default`].
    pub entry: Option<usize>,
    /// The enabled groups of the client, in config order, without duplicates.
    pub groups: Arc<[String]>,
}

/// The facts that the DNS crate knows about one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientFacts<'a> {
    /// The source address of the query.
    pub ip: IpAddr,
    /// The MAC address from the neighbor table, if known.
    pub mac: Option<MacAddr>,
    /// The host name from a reverse lookup, if known.
    pub hostname: Option<&'a DomainName>,
}

/// The `[[clients]]` entries of a config, ready for fast lookups.
#[derive(Debug, Clone)]
pub struct ClientTable {
    by_ip: HashMap<IpAddr, usize>,
    by_mac: HashMap<MacAddr, usize>,
    by_host: HashMap<DomainName, usize>,
    /// Sorted by prefix length (longest first), then by config index.
    cidrs: Vec<(Cidr, usize)>,
    /// The enabled groups of each config entry (same index as `clients`).
    entry_groups: Vec<Arc<[String]>>,
    default_groups: Arc<[String]>,
}

impl Default for ClientTable {
    /// A table with the default config: no client entry, group `default`.
    fn default() -> Self {
        Self::from_config(&Config::default()).0
    }
}

/// The names of the enabled groups of a config. The first definition of a name wins, as in
/// the policy engine.
fn enabled_groups(config: &Config) -> HashSet<&str> {
    let mut seen = HashSet::new();
    let mut enabled = HashSet::new();
    for g in &config.groups {
        if seen.insert(g.name.as_str()) && g.enabled {
            enabled.insert(g.name.as_str());
        }
    }
    enabled
}

/// The names in `names` that are enabled, in order, without duplicates.
fn effective(names: &[String], enabled: &HashSet<&str>) -> Arc<[String]> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        if enabled.contains(n.as_str()) && !out.contains(n) {
            out.push(n.clone());
        }
    }
    out.into()
}

impl ClientTable {
    /// Makes the table from a config. The config does not need to be valid: an entry that
    /// does not parse, or a second entry with the same ID, is skipped and reported.
    pub fn from_config(config: &Config) -> (Self, Vec<ConfigIssue>) {
        let enabled = enabled_groups(config);
        let mut issues = Vec::new();
        let mut table = Self {
            by_ip: HashMap::new(),
            by_mac: HashMap::new(),
            by_host: HashMap::new(),
            cidrs: Vec::new(),
            entry_groups: Vec::with_capacity(config.clients.len()),
            default_groups: effective(&[DEFAULT_GROUP.to_owned()], &enabled),
        };
        for (i, client) in config.clients.iter().enumerate() {
            table.entry_groups.push(effective(&client.groups, &enabled));
            let path = format!("clients[{i}].id");
            let id = match ClientId::parse(&client.id) {
                Ok(id) => id,
                Err(e) => {
                    issues.push(ConfigIssue {
                        path,
                        message: format!("{e}; the client is ignored"),
                    });
                    continue;
                }
            };
            let duplicate = match id {
                ClientId::Ip(ip) => insert_first(&mut table.by_ip, ip, i),
                ClientId::Mac(mac) => insert_first(&mut table.by_mac, mac, i),
                ClientId::Hostname(name) => insert_first(&mut table.by_host, name, i),
                ClientId::Cidr(c) => {
                    let dup = table.cidrs.iter().any(|(old, _)| *old == c);
                    if !dup {
                        table.cidrs.push((c, i));
                    }
                    dup
                }
            };
            if duplicate {
                issues.push(ConfigIssue {
                    path,
                    message: "the client is defined twice; the first entry is used".to_owned(),
                });
            }
        }
        // Longest prefix first; the stable sort keeps the config order for equal prefixes.
        table
            .cidrs
            .sort_by_key(|(c, _)| std::cmp::Reverse(c.prefix));
        (table, issues)
    }

    /// True when the config has a client entry with a host name. Only then the DNS crate
    /// needs reverse lookups for client names.
    pub fn has_hostnames(&self) -> bool {
        !self.by_host.is_empty()
    }

    /// True when the config has a client entry with a MAC address.
    pub fn has_macs(&self) -> bool {
        !self.by_mac.is_empty()
    }

    /// The groups of the client with these facts. See the module documentation for the
    /// precedence.
    pub fn resolve(&self, facts: &ClientFacts<'_>) -> Resolved {
        let hit = |matched, i: usize| Resolved {
            matched,
            entry: Some(i),
            groups: self
                .entry_groups
                .get(i)
                .cloned()
                .unwrap_or_else(|| Arc::from(Vec::<String>::new())),
        };
        if let Some(&i) = self.by_ip.get(&facts.ip) {
            return hit(MatchedBy::Ip, i);
        }
        if let Some(&i) = facts.mac.and_then(|m| self.by_mac.get(&m)) {
            return hit(MatchedBy::Mac, i);
        }
        if let Some(&i) = facts.hostname.and_then(|h| self.by_host.get(h)) {
            return hit(MatchedBy::Hostname, i);
        }
        // Bounded by the number of CIDR entries in the config.
        if let Some(&(_, i)) = self.cidrs.iter().find(|(c, _)| c.contains(facts.ip)) {
            return hit(MatchedBy::Cidr, i);
        }
        Resolved {
            matched: MatchedBy::Default,
            entry: None,
            groups: Arc::clone(&self.default_groups),
        }
    }
}

/// Inserts `key` only when it is new. Returns true for a duplicate.
fn insert_first<K: Hash + Eq>(map: &mut HashMap<K, usize>, key: K, index: usize) -> bool {
    if map.contains_key(&key) {
        return true;
    }
    map.insert(key, index);
    false
}

/// A bounded map with a time to live for each entry. Pure: the caller gives `now_ms` from a
/// monotonic clock. A full map drops the least recently used entry.
#[derive(Debug)]
pub struct TtlLru<K: Hash + Eq, V> {
    map: LruCache<K, (u64, V)>,
}

impl<K: Hash + Eq, V> TtlLru<K, V> {
    /// A map with at most `max_entries` entries (at least 1).
    pub fn new(max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            map: LruCache::new(cap),
        }
    }

    /// The value of `key` when it did not expire at `now_ms`. An expired entry is removed.
    pub fn get(&mut self, key: &K, now_ms: u64) -> Option<&V> {
        let expired = match self.map.peek(key) {
            None => return None,
            Some((expires, _)) => now_ms >= *expires,
        };
        if expired {
            self.map.pop(key);
            return None;
        }
        self.map.get(key).map(|(_, v)| v)
    }

    /// Inserts `value` for `key`. It expires at `now_ms + ttl_ms`.
    pub fn insert(&mut self, key: K, value: V, ttl_ms: u64, now_ms: u64) {
        self.map.put(key, (now_ms.saturating_add(ttl_ms), value));
    }

    /// Removes `key`.
    pub fn remove(&mut self, key: &K) {
        self.map.pop(key);
    }

    /// Number of entries (also expired ones that no `get` removed yet).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when the map has no entry.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The size limit.
    pub fn capacity(&self) -> usize {
        self.map.cap().get()
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        self.map.clear();
    }
}

#[cfg(test)]
mod tests;
