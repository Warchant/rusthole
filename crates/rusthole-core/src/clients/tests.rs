use std::collections::HashMap;

use proptest::prelude::*;

use super::*;
use crate::config::{Client, Group};

fn group(name: &str, enabled: bool) -> Group {
    Group {
        id: None,
        name: name.to_owned(),
        enabled,
        comment: None,
    }
}

fn client(id: &str, groups: &[&str]) -> Client {
    Client {
        uid: None,
        id: id.to_owned(),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        comment: None,
    }
}

fn config(groups: Vec<Group>, clients: Vec<Client>) -> Config {
    Config {
        groups,
        clients,
        ..Config::default()
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn mac(s: &str) -> MacAddr {
    MacAddr::parse(s).unwrap()
}

fn names(r: &Resolved) -> Vec<&str> {
    r.groups.iter().map(String::as_str).collect()
}

fn facts<'a>(ip_text: &str, mac: Option<MacAddr>, host: Option<&'a DomainName>) -> ClientFacts<'a> {
    ClientFacts {
        ip: ip(ip_text),
        mac,
        hostname: host,
    }
}

/// One config with an entry of each kind. Each entry has its own group, so the result
/// shows which entry matched.
fn all_kinds() -> Config {
    config(
        vec![
            group("default", true),
            group("by-ip", true),
            group("by-mac", true),
            group("by-host", true),
            group("by-wide", true),
            group("by-narrow", true),
        ],
        vec![
            client("192.0.2.0/24", &["by-wide"]),
            client("printer.lan", &["by-host"]),
            client("192.0.2.128/25", &["by-narrow"]),
            client("02:00:00:00:00:01", &["by-mac"]),
            client("192.0.2.200", &["by-ip"]),
        ],
    )
}

#[test]
fn precedence_ip_mac_host_cidr_default() {
    let (t, issues) = ClientTable::from_config(&all_kinds());
    assert!(issues.is_empty(), "{issues:?}");
    let host = DomainName::parse("printer.lan").unwrap();
    let m = Some(mac("02:00:00:00:00:01"));
    // Exact IP beats all.
    let r = t.resolve(&facts("192.0.2.200", m, Some(&host)));
    assert_eq!((r.matched, names(&r)), (MatchedBy::Ip, vec!["by-ip"]));
    assert_eq!(r.entry, Some(4));
    // MAC beats host name and CIDR.
    let r = t.resolve(&facts("192.0.2.201", m, Some(&host)));
    assert_eq!((r.matched, names(&r)), (MatchedBy::Mac, vec!["by-mac"]));
    // Host name beats CIDR.
    let r = t.resolve(&facts("192.0.2.201", None, Some(&host)));
    assert_eq!(
        (r.matched, names(&r)),
        (MatchedBy::Hostname, vec!["by-host"])
    );
    // The most specific CIDR wins, not the first one.
    let r = t.resolve(&facts("192.0.2.201", None, None));
    assert_eq!((r.matched, names(&r)), (MatchedBy::Cidr, vec!["by-narrow"]));
    let r = t.resolve(&facts("192.0.2.5", None, None));
    assert_eq!((r.matched, names(&r)), (MatchedBy::Cidr, vec!["by-wide"]));
    // No entry: default.
    let r = t.resolve(&facts("198.51.100.1", None, None));
    assert_eq!(
        (r.matched, names(&r)),
        (MatchedBy::Default, vec!["default"])
    );
    assert_eq!(r.entry, None);
    // An unknown MAC or host name gives nothing.
    let other = DomainName::parse("other.lan").unwrap();
    let r = t.resolve(&facts(
        "198.51.100.1",
        Some(mac("02:00:00:00:00:09")),
        Some(&other),
    ));
    assert_eq!(r.matched, MatchedBy::Default);
    assert!(t.has_hostnames());
    assert!(t.has_macs());
}

#[test]
fn equal_prefix_keeps_config_order() {
    let cfg = config(
        vec![group("default", true), group("a", true), group("b", true)],
        vec![
            client("192.0.2.0/24", &["a"]),
            client("192.0.2.7/24", &["b"]),
        ],
    );
    let (t, _) = ClientTable::from_config(&cfg);
    let r = t.resolve(&facts("192.0.2.9", None, None));
    assert_eq!(names(&r), vec!["a"]);
}

#[test]
fn disabled_and_unknown_groups_give_nothing() {
    let cfg = config(
        vec![
            group("default", false),
            group("kids", true),
            group("off", false),
        ],
        vec![
            client("192.0.2.1", &["kids", "off", "ghost", "kids"]),
            client("192.0.2.2", &[]),
        ],
    );
    let (t, _) = ClientTable::from_config(&cfg);
    assert_eq!(
        names(&t.resolve(&facts("192.0.2.1", None, None))),
        vec!["kids"]
    );
    // `groups = []`: no group.
    let r = t.resolve(&facts("192.0.2.2", None, None));
    assert_eq!(r.matched, MatchedBy::Ip);
    assert!(r.groups.is_empty());
    // A disabled `default` gives no group to an unknown client.
    assert!(t.resolve(&facts("192.0.2.3", None, None)).groups.is_empty());
}

#[test]
fn first_group_definition_wins() {
    let cfg = config(
        vec![
            group("default", true),
            group("kids", false),
            group("kids", true),
        ],
        vec![client("192.0.2.1", &["kids"])],
    );
    let (t, _) = ClientTable::from_config(&cfg);
    assert!(t.resolve(&facts("192.0.2.1", None, None)).groups.is_empty());
}

#[test]
fn bad_and_duplicate_entries_are_reported() {
    let cfg = config(
        vec![group("default", true), group("a", true), group("b", true)],
        vec![
            client("bad id!", &["a"]),
            client("192.0.2.1", &["a"]),
            client("192.0.2.1", &["b"]),
            client("192.0.2.0/24", &["a"]),
            client("192.0.2.0/24", &["b"]),
        ],
    );
    let (t, issues) = ClientTable::from_config(&cfg);
    let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["clients[0].id", "clients[2].id", "clients[4].id"]
    );
    assert_eq!(
        names(&t.resolve(&facts("192.0.2.1", None, None))),
        vec!["a"]
    );
    assert_eq!(
        names(&t.resolve(&facts("192.0.2.9", None, None))),
        vec!["a"]
    );
    assert!(!t.has_hostnames());
}

#[test]
fn default_table_uses_default_group() {
    let t = ClientTable::default();
    let r = t.resolve(&facts("192.0.2.1", None, None));
    assert_eq!(
        (r.matched, names(&r)),
        (MatchedBy::Default, vec!["default"])
    );
}

#[test]
fn ttl_lru_expires_and_is_bounded() {
    let mut c: TtlLru<u32, &str> = TtlLru::new(2);
    c.insert(1, "a", 100, 0);
    assert_eq!(c.get(&1, 99), Some(&"a"));
    // The entry ends exactly at its deadline.
    assert_eq!(c.get(&1, 100), None);
    assert!(c.is_empty());
    c.insert(1, "a", 100, 0);
    c.insert(2, "b", 100, 0);
    // 1 is now the most recently used.
    assert_eq!(c.get(&1, 1), Some(&"a"));
    c.insert(3, "c", 100, 0);
    assert_eq!(c.len(), 2);
    assert_eq!(c.get(&2, 1), None);
    assert_eq!(c.get(&3, 1), Some(&"c"));
    c.remove(&3);
    assert_eq!(c.get(&3, 1), None);
    c.clear();
    assert!(c.is_empty());
    assert_eq!(TtlLru::<u8, u8>::new(0).capacity(), 1);
    // A huge TTL saturates; it does not wrap to the past.
    c.insert(9, "z", u64::MAX, 5);
    assert_eq!(c.get(&9, u64::MAX - 1), Some(&"z"));
}

// ---------- property tests ----------

const GROUP_NAMES: [&str; 4] = ["default", "kids", "iot", "guest"];

fn arb_group() -> impl Strategy<Value = Group> {
    (0..GROUP_NAMES.len(), any::<bool>()).prop_map(|(i, e)| group(GROUP_NAMES[i], e))
}

fn arb_id() -> impl Strategy<Value = String> {
    prop_oneof![
        (0u8..8).prop_map(|i| format!("192.0.2.{i}")),
        (0u8..8, 24u8..=32).prop_map(|(i, p)| format!("192.0.2.{i}/{p}")),
        (0u8..3).prop_map(|p| format!("192.0.{p}.0/{}", 16 + p * 4)),
        (1u8..5).prop_map(|i| format!("02:00:00:00:00:0{i}")),
        (0u8..4).prop_map(|i| format!("h{i}.lan")),
        Just("bad id!".to_owned()),
    ]
}

fn arb_client() -> impl Strategy<Value = Client> {
    (
        arb_id(),
        proptest::collection::vec(
            prop_oneof![
                (0..GROUP_NAMES.len()).prop_map(|i| GROUP_NAMES[i]),
                Just("ghost")
            ],
            0..4,
        ),
    )
        .prop_map(|(id, gs)| client(&id, &gs))
}

fn arb_config() -> impl Strategy<Value = Config> {
    (
        proptest::collection::vec(arb_group(), 0..6),
        proptest::collection::vec(arb_client(), 0..10),
    )
        .prop_map(|(g, c)| config(g, c))
}

/// The facts of one query: IP (index), MAC (index), host name (index).
fn arb_facts() -> impl Strategy<Value = (String, Option<u8>, Option<u8>)> {
    (
        prop_oneof![
            (0u8..10).prop_map(|i| format!("192.0.2.{i}")),
            Just("192.0.1.9".to_owned()),
            Just("198.51.100.1".to_owned()),
        ],
        proptest::option::of(1u8..6),
        proptest::option::of(0u8..5),
    )
}

/// The reference model: a direct reading of the precedence rules, with linear scans.
fn reference(cfg: &Config, f: &ClientFacts<'_>) -> (MatchedBy, Option<usize>, Vec<String>) {
    let mut first_def: HashMap<&str, bool> = HashMap::new();
    for g in &cfg.groups {
        first_def.entry(g.name.as_str()).or_insert(g.enabled);
    }
    let keep = |names: &[String]| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for n in names {
            if first_def.get(n.as_str()) == Some(&true) && !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    };
    let ids: Vec<Option<ClientId>> = cfg
        .clients
        .iter()
        .map(|c| ClientId::parse(&c.id).ok())
        .collect();
    let find =
        |pred: &dyn Fn(&ClientId) -> bool| ids.iter().position(|id| id.as_ref().is_some_and(pred));
    let pick = |m, i: usize| (m, Some(i), keep(&cfg.clients[i].groups));
    if let Some(i) = find(&|id| *id == ClientId::Ip(f.ip)) {
        return pick(MatchedBy::Ip, i);
    }
    if let Some(m) = f.mac
        && let Some(i) = find(&|id| *id == ClientId::Mac(m))
    {
        return pick(MatchedBy::Mac, i);
    }
    if let Some(h) = f.hostname
        && let Some(i) = find(&|id| *id == ClientId::Hostname(h.clone()))
    {
        return pick(MatchedBy::Hostname, i);
    }
    let mut best: Option<(u8, usize)> = None;
    for (i, id) in ids.iter().enumerate() {
        if let Some(ClientId::Cidr(c)) = id
            && c.contains(f.ip)
            && best.is_none_or(|(p, _)| c.prefix > p)
        {
            best = Some((c.prefix, i));
        }
    }
    if let Some((_, i)) = best {
        return pick(MatchedBy::Cidr, i);
    }
    (MatchedBy::Default, None, keep(&[DEFAULT_GROUP.to_owned()]))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// For any config and any facts, the table gives the result of the reference model.
    /// No group comes from an entry that did not match, and no disabled or unknown group
    /// applies.
    #[test]
    fn resolve_equals_reference((cfg, f) in (arb_config(), arb_facts())) {
        let (t, _) = ClientTable::from_config(&cfg);
        let host = f.2.map(|i| DomainName::parse(&format!("h{i}.lan")).unwrap());
        let facts = ClientFacts {
            ip: ip(&f.0),
            mac: f.1.map(|i| mac(&format!("02:00:00:00:00:0{i}"))),
            hostname: host.as_ref(),
        };
        let r = t.resolve(&facts);
        let want = reference(&cfg, &facts);
        prop_assert_eq!((r.matched, r.entry, r.groups.to_vec()), want);

        // A client never gets a group that its entry (or `default`) does not name.
        let named: Vec<String> = match r.entry {
            Some(i) => cfg.clients[i].groups.clone(),
            None => vec![DEFAULT_GROUP.to_owned()],
        };
        for g in r.groups.iter() {
            prop_assert!(named.contains(g), "{} is not in {:?}", g, named);
            let first = cfg.groups.iter().find(|d| &d.name == g);
            prop_assert!(first.is_some_and(|d| d.enabled), "{} is not enabled", g);
        }
    }
}
