//! End-to-end import tests and property tests of the pure mapping.

use std::collections::{BTreeMap, HashMap};

use proptest::prelude::*;
use rusthole_core::config::{
    Adlist, Client, Config, Group, ListKind, LocalRecord, RecordType, Rule, RuleAction, RuleKind,
    Upstream,
};

use crate::gravity::{AdlistRow, ClientRow, DomainRow, GroupRow};
use crate::testkit::{
    FAKE_PWHASH, HOME_REGEXES, build_gravity_db, build_zip, home_gravity, home_pihole_toml,
    home_zip,
};
use crate::{Gravity, ImportError, ImportReport, Limits, import_teleporter, map_gravity};

/// The config that the home fixture must give, written out in full.
fn expected_home_config() -> Config {
    let mut e = Config::default();
    e.upstreams.servers = [
        "udp://192.0.2.53:53",
        "udp://192.0.2.54:53",
        "udp://[2001:db8::53]:53",
        "udp://[2001:db8::54]:53",
    ]
    .iter()
    .map(|u| Upstream {
        url: (*u).to_owned(),
        bootstrap: vec![],
    })
    .collect();
    e.groups[0].comment = Some("The default group".into());
    e.groups.push(Group {
        name: "kids".into(),
        enabled: true,
        comment: Some("Tablets".into()),
    });
    e.lists.adlists = (1..=9u32)
        .map(|i| Adlist {
            id: i,
            url: format!("https://lists{i}.example/hosts.txt"),
            kind: ListKind::Block,
            enabled: i != 7,
            groups: vec!["default".into()],
            comment: (i % 2 == 0).then(|| format!("list {i}")),
        })
        .collect();
    let rule = |kind, action, value: String, comment: Option<&str>| Rule {
        kind,
        action,
        value,
        enabled: true,
        groups: vec!["default".into()],
        comment: comment.map(str::to_owned),
    };
    for i in 1..=5 {
        e.rules.push(rule(
            RuleKind::Exact,
            RuleAction::Allow,
            format!("cdn{i}.example.org"),
            Some("needed"),
        ));
    }
    for i in 1..=20 {
        e.rules.push(rule(
            RuleKind::Exact,
            RuleAction::Deny,
            format!("tracker{i}.example.net"),
            None,
        ));
    }
    for re in HOME_REGEXES {
        e.rules
            .push(rule(RuleKind::Regex, RuleAction::Deny, re.to_owned(), None));
    }
    e.clients = (1..=13)
        .map(|i| Client {
            id: if i == 13 {
                "192.0.2.13".into()
            } else {
                format!("02:00:00:00:00:{i:02x}")
            },
            groups: vec![if i >= 12 { "kids" } else { "default" }.into()],
            comment: Some(format!("device {i}")),
        })
        .collect();
    e.local_dns.records = vec![LocalRecord {
        name: "nas.lan".into(),
        record_type: RecordType::A,
        value: "192.0.2.10".into(),
    }];
    e
}

/// The translated lines that the home fixture must give, written out in full.
const HOME_TRANSLATED: [&str; 68] = [
    r#"dns.upstreams "192.0.2.53" -> upstreams.servers[0] "udp://192.0.2.53:53""#,
    r#"dns.upstreams "192.0.2.54" -> upstreams.servers[1] "udp://192.0.2.54:53""#,
    r#"dns.upstreams "2001:db8::53" -> upstreams.servers[2] "udp://[2001:db8::53]:53""#,
    r#"dns.upstreams "2001:db8::54" -> upstreams.servers[3] "udp://[2001:db8::54]:53""#,
    r"dns.blocking.active = true -> blocking.enabled",
    r#"dns.blocking.mode NULL -> blocking.mode "null""#,
    r"dns.rateLimit.count = 1000 -> rate_limit.queries",
    r"dns.rateLimit.interval = 60 -> rate_limit.interval_seconds",
    r"dns.cache.size = 10000 -> cache.max_entries",
    r#"group id 0 "Default" -> groups "default""#,
    r#"group id 1 "Kids" -> groups "kids""#,
    r#"adlist id 1 https://lists1.example/hosts.txt (block) -> lists.adlists[0], groups ["default"]"#,
    r#"adlist id 2 https://lists2.example/hosts.txt (block) -> lists.adlists[1], groups ["default"]"#,
    r#"adlist id 3 https://lists3.example/hosts.txt (block) -> lists.adlists[2], groups ["default"]"#,
    r#"adlist id 4 https://lists4.example/hosts.txt (block) -> lists.adlists[3], groups ["default"]"#,
    r#"adlist id 5 https://lists5.example/hosts.txt (block) -> lists.adlists[4], groups ["default"]"#,
    r#"adlist id 6 https://lists6.example/hosts.txt (block) -> lists.adlists[5], groups ["default"]"#,
    r#"adlist id 7 https://lists7.example/hosts.txt (block, disabled) -> lists.adlists[6], groups ["default"]"#,
    r#"adlist id 8 https://lists8.example/hosts.txt (block) -> lists.adlists[7], groups ["default"]"#,
    r#"adlist id 9 https://lists9.example/hosts.txt (block) -> lists.adlists[8], groups ["default"]"#,
    r#"domainlist id 1 exact allow "cdn1.example.org" -> rules[0], groups ["default"]"#,
    r#"domainlist id 2 exact allow "cdn2.example.org" -> rules[1], groups ["default"]"#,
    r#"domainlist id 3 exact allow "cdn3.example.org" -> rules[2], groups ["default"]"#,
    r#"domainlist id 4 exact allow "cdn4.example.org" -> rules[3], groups ["default"]"#,
    r#"domainlist id 5 exact allow "cdn5.example.org" -> rules[4], groups ["default"]"#,
    r#"domainlist id 6 exact deny "tracker1.example.net" -> rules[5], groups ["default"]"#,
    r#"domainlist id 7 exact deny "tracker2.example.net" -> rules[6], groups ["default"]"#,
    r#"domainlist id 8 exact deny "tracker3.example.net" -> rules[7], groups ["default"]"#,
    r#"domainlist id 9 exact deny "tracker4.example.net" -> rules[8], groups ["default"]"#,
    r#"domainlist id 10 exact deny "tracker5.example.net" -> rules[9], groups ["default"]"#,
    r#"domainlist id 11 exact deny "tracker6.example.net" -> rules[10], groups ["default"]"#,
    r#"domainlist id 12 exact deny "tracker7.example.net" -> rules[11], groups ["default"]"#,
    r#"domainlist id 13 exact deny "tracker8.example.net" -> rules[12], groups ["default"]"#,
    r#"domainlist id 14 exact deny "tracker9.example.net" -> rules[13], groups ["default"]"#,
    r#"domainlist id 15 exact deny "tracker10.example.net" -> rules[14], groups ["default"]"#,
    r#"domainlist id 16 exact deny "tracker11.example.net" -> rules[15], groups ["default"]"#,
    r#"domainlist id 17 exact deny "tracker12.example.net" -> rules[16], groups ["default"]"#,
    r#"domainlist id 18 exact deny "tracker13.example.net" -> rules[17], groups ["default"]"#,
    r#"domainlist id 19 exact deny "tracker14.example.net" -> rules[18], groups ["default"]"#,
    r#"domainlist id 20 exact deny "tracker15.example.net" -> rules[19], groups ["default"]"#,
    r#"domainlist id 21 exact deny "tracker16.example.net" -> rules[20], groups ["default"]"#,
    r#"domainlist id 22 exact deny "tracker17.example.net" -> rules[21], groups ["default"]"#,
    r#"domainlist id 23 exact deny "tracker18.example.net" -> rules[22], groups ["default"]"#,
    r#"domainlist id 24 exact deny "tracker19.example.net" -> rules[23], groups ["default"]"#,
    r#"domainlist id 25 exact deny "tracker20.example.net" -> rules[24], groups ["default"]"#,
    r#"domainlist id 26 regex deny "(\\.|^)example\\.com$" -> rules[25], groups ["default"]"#,
    r#"domainlist id 27 regex deny "ads\\d+\\.example" -> rules[26], groups ["default"]"#,
    r#"domainlist id 28 regex deny "^track(er)?[0-9]*\\." -> rules[27], groups ["default"]"#,
    r#"domainlist id 29 regex deny "(\\.|^)telemetry\\.example\\.net$" -> rules[28], groups ["default"]"#,
    r#"domainlist id 30 regex deny "^ad[sv]?\\." -> rules[29], groups ["default"]"#,
    r#"domainlist id 31 regex deny "(\\.|^)clicks\\.example$" -> rules[30], groups ["default"]"#,
    r#"domainlist id 32 regex deny "^pixel\\." -> rules[31], groups ["default"]"#,
    r#"domainlist id 33 regex deny "(\\.|^)metrics\\.example\\.org$" -> rules[32], groups ["default"]"#,
    r#"domainlist id 34 regex deny "^analytics[0-9]*\\.example\\." -> rules[33], groups ["default"]"#,
    r#"client id 1 02:00:00:00:00:01 -> clients[0], groups ["default"]"#,
    r#"client id 2 02:00:00:00:00:02 -> clients[1], groups ["default"]"#,
    r#"client id 3 02:00:00:00:00:03 -> clients[2], groups ["default"]"#,
    r#"client id 4 02:00:00:00:00:04 -> clients[3], groups ["default"]"#,
    r#"client id 5 02:00:00:00:00:05 -> clients[4], groups ["default"]"#,
    r#"client id 6 02:00:00:00:00:06 -> clients[5], groups ["default"]"#,
    r#"client id 7 02:00:00:00:00:07 -> clients[6], groups ["default"]"#,
    r#"client id 8 02:00:00:00:00:08 -> clients[7], groups ["default"]"#,
    r#"client id 9 02:00:00:00:00:09 -> clients[8], groups ["default"]"#,
    r#"client id 10 02:00:00:00:00:0a -> clients[9], groups ["default"]"#,
    r#"client id 11 02:00:00:00:00:0b -> clients[10], groups ["default"]"#,
    r#"client id 12 02:00:00:00:00:0c -> clients[11], groups ["kids"]"#,
    r#"client id 13 192.0.2.13 -> clients[12], groups ["kids"]"#,
    r"etc/hosts: nas.lan A 192.0.2.10 -> local_dns.records[0]",
];

#[test]
fn home_fixture_gives_exact_config_and_report() {
    let imported = import_teleporter(&home_zip(), &Limits::default()).unwrap();
    let c = &imported.config;
    assert_eq!(*c, expected_home_config());
    assert_eq!(c.validate(), []);

    let r = &imported.report;
    assert_eq!(
        r.reported,
        [
            "dns.dnssec = true: rusthole v1 does not validate DNSSEC; it sets the DO bit and passes the AD bit of the upstream through",
            "webserver.port = \"80o,443os,[::]:80o,[::]:443os\": the rusthole admin UI uses server.admin.port (default 8443, HTTPS)",
            "webserver.api.pwhash: the Pi-hole password cannot be imported; set a new password with `rusthole passwd`",
            "group id 1: renamed \"Kids\" to \"kids\" (rusthole group names use a-z, 0-9, '-', '_', '.' and are unique)",
        ]
    );
    // 4 upstreams, blocking active, blocking mode, cache size, rate limit count and interval,
    // 2 groups, 9 lists, 34 rules, 13 clients, 1 host record.
    assert_eq!(r.translated, HOME_TRANSLATED, "{:#?}", r.translated);
    assert_eq!(
        r.ignored,
        [
            "zip entry etc/pihole/dhcp.leases: not used by rusthole",
            "pihole.toml dns.queryLogging: not used by rusthole",
            "etc/hosts: system entry localhost 127.0.0.1 is not imported",
            "etc/hosts: system entry localhost ::1 is not imported",
            "etc/hosts: system entry ip6-localhost ::1 is not imported",
            "etc/hosts: system entry ip6-loopback ::1 is not imported",
            "etc/hosts: system entry ip6-allnodes ff02::1 is not imported",
            "etc/hosts: system entry ip6-allrouters ff02::2 is not imported",
            "etc/hosts: system entry pihole 127.0.1.1 is not imported",
        ]
    );
}

#[test]
fn kids_clients_stay_only_in_kids() {
    let c = import_teleporter(&home_zip(), &Limits::default())
        .unwrap()
        .config;
    let kids: Vec<_> = c.clients.iter().filter(|x| x.groups == ["kids"]).collect();
    assert_eq!(kids.len(), 2);
    // No list and no rule is in group "kids", so these clients are not blocked.
    assert!(
        c.lists
            .adlists
            .iter()
            .all(|l| !l.groups.contains(&"kids".to_owned()))
    );
    assert!(
        c.rules
            .iter()
            .all(|r| !r.groups.contains(&"kids".to_owned()))
    );
}

#[test]
fn secrets_never_reach_output() {
    let imported = import_teleporter(&home_zip(), &Limits::default()).unwrap();
    let toml = imported.config.to_toml_string().unwrap();
    let report = imported.report.to_string();
    let debug = format!("{imported:?}");
    for part in [
        FAKE_PWHASH,
        "ZmFrZXNhbHRmYWtlc2FsdA",
        "ZmFrZWhhc2g",
        "BALLOON",
    ] {
        assert!(!toml.contains(part));
        assert!(!report.contains(part));
        assert!(!debug.contains(part));
    }
}

#[test]
fn output_round_trips_through_toml() {
    let c = import_teleporter(&home_zip(), &Limits::default())
        .unwrap()
        .config;
    let text = c.to_toml_string().unwrap();
    assert_eq!(Config::from_toml_str(&text).unwrap(), c);
}

#[test]
fn missing_gravity_db_is_an_error() {
    let zip = build_zip(&[("etc/pihole/pihole.toml", home_pihole_toml().as_bytes())]);
    assert_eq!(
        import_teleporter(&zip, &Limits::default()),
        Err(ImportError::MissingEntry("etc/pihole/gravity.db"))
    );
}

#[test]
fn missing_pihole_toml_is_reported() {
    let db = build_gravity_db(&home_gravity());
    let zip = build_zip(&[("etc/pihole/gravity.db", &db)]);
    let imported = import_teleporter(&zip, &Limits::default()).unwrap();
    assert!(imported.report.reported[0].contains("no etc/pihole/pihole.toml"));
    assert_eq!(imported.config.upstreams, Config::default().upstreams);
}

#[test]
fn report_has_no_raw_control_characters() {
    let db = build_gravity_db(&home_gravity());
    let toml = "[dns]\n\"k\\u001b[2J\" = 1\n";
    let zip = build_zip(&[
        ("etc/pihole/gravity.db", &db),
        ("etc/pihole/pihole.toml", toml.as_bytes()),
        ("etc/x\u{1b}[31mred", b"x"),
    ]);
    let imported = import_teleporter(&zip, &Limits::default()).unwrap();
    let text = imported.report.to_string();
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "{text:?}"
    );
    assert!(
        imported
            .report
            .ignored
            .contains(&r"zip entry etc/x\u{1b}[31mred: not used by rusthole".to_owned()),
        "{:#?}",
        imported.report.ignored
    );
}

#[test]
fn bad_rows_are_reported_not_lost() {
    let mut g = home_gravity();
    g.groups.push(GroupRow {
        id: 5,
        enabled: false,
        name: "Default".into(),
        description: None,
    });
    g.domainlist.push(DomainRow {
        id: 100,
        kind: 3,
        domain: r"^ads\.;querytype=AAAA".into(),
        enabled: true,
        comment: None,
    });
    g.domainlist.push(DomainRow {
        id: 101,
        kind: 2,
        domain: "(?<=x)y".into(),
        enabled: true,
        comment: None,
    });
    g.domainlist.push(DomainRow {
        id: 102,
        kind: 1,
        domain: "not a domain".into(),
        enabled: true,
        comment: None,
    });
    g.domainlist.push(DomainRow {
        id: 103,
        kind: 9,
        domain: "x.example".into(),
        enabled: true,
        comment: None,
    });
    g.domainlist.push(DomainRow {
        id: 104,
        kind: 1,
        domain: "b\u{fc}cher.example".into(),
        enabled: true,
        comment: None,
    });
    g.domainlist_by_group.push((104, 5));
    g.clients.push(ClientRow {
        id: 50,
        ip: ":eth0".into(),
        comment: None,
    });
    g.clients.push(ClientRow {
        id: 51,
        ip: "02:00:00:00:00:01".into(),
        comment: None,
    });
    // An IPv6 address that starts with "::" is not an interface.
    g.clients.push(ClientRow {
        id: 52,
        ip: "::ffff:192.0.2.52".into(),
        comment: None,
    });
    g.adlists.push(AdlistRow {
        id: 60,
        address: "file:///etc/pihole/local.list".into(),
        enabled: true,
        comment: None,
        kind: 0,
    });
    let mut c = Config::default();
    let mut r = ImportReport::default();
    let names = map_gravity(&g, &mut c, &mut r);
    assert_eq!(names.get(&5).map(String::as_str), Some("default-5"));
    let has = |prefix: &str| r.reported.iter().any(|l| l.starts_with(prefix));
    assert!(has("domainlist id 100: regex"), "{:#?}", r.reported);
    assert!(has("domainlist id 101: regex"));
    assert!(has("domainlist id 102: "));
    assert!(has("domainlist id 103: unknown type 9"));
    assert!(has("client id 50: "));
    assert!(has("client id 51: "));
    assert!(!has("client id 52: "), "{:#?}", r.reported);
    assert!(c.clients.iter().any(|x| x.id == "::ffff:192.0.2.52"));
    assert!(has("adlist id 60: "));
    assert!(has("group id 5: renamed"));
    let idn = c
        .rules
        .iter()
        .find(|x| x.value.starts_with("xn--"))
        .unwrap();
    assert_eq!(idn.value, "xn--bcher-kva.example");
    assert_eq!(idn.groups, ["default-5"]);
    assert_eq!(c.validate(), []);
}

// ---------------------------------------------------------------------------------------------
// Property tests.

fn domain_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z0-9]{1,8}(\\.[a-z0-9]{1,8}){0,3}",
        "[A-Za-z0-9.-]{0,12}",
        "\\PC{0,12}",
        r"\(\\\.\|\^\)[a-z]{1,6}\\\.example\$",
        "[a-z(\\\\.|^$)]{1,10}(;querytype=A|;invert|;reply=nodata)?",
    ]
}

fn client_text() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<[u8; 6]>().prop_map(|m| m
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")),
        any::<[u8; 4]>().prop_map(|b| std::net::Ipv4Addr::from(b).to_string()),
        (any::<[u8; 4]>(), 0u8..40)
            .prop_map(|(b, p)| format!("{}/{p}", std::net::Ipv4Addr::from(b))),
        "[a-z]{1,8}",
        ":[a-z]{1,4}[0-9]",
        "\\PC{0,10}",
    ]
}

prop_compose! {
    fn gravity()(
        has_default in any::<bool>(),
        groups in prop::collection::btree_map(1i64..12, ("\\PC{0,10}|Default|default|[A-Z][a-z]{1,5}", any::<bool>()), 0..6),
        lists in prop::collection::vec(("https://[a-z]{1,6}\\.example/[a-z]{0,4}|ftp://x|\\PC{0,8}", -1i64..3, any::<bool>()), 0..6),
        rules in prop::collection::vec((domain_text(), -1i64..6, any::<bool>(), prop::option::of("\\PC{0,8}")), 0..20),
        clients in prop::collection::vec((client_text(), prop::option::of("\\PC{0,8}")), 0..10),
        links in prop::collection::vec((0usize..40, 0i64..14, 0u8..3), 0..60),
        dup_group in prop::option::of((0i64..12, "\\PC{0,6}", any::<bool>())),
    ) -> Gravity {
        let mut g = Gravity::default();
        if has_default {
            g.groups.push(GroupRow { id: 0, enabled: true, name: "Default".into(), description: None });
        }
        for (id, (name, enabled)) in groups {
            g.groups.push(GroupRow { id, enabled, name: name.clone(), description: Some(name) });
        }
        // A second row with an ID that may already exist: only the first row counts.
        if let Some((id, name, enabled)) = dup_group {
            g.groups.push(GroupRow { id, enabled, name, description: Some("dup".into()) });
        }
        g.adlists = lists.into_iter().zip(1..).map(|((address, kind, enabled), id)| AdlistRow {
            id, address, enabled, comment: None, kind,
        }).collect();
        g.domainlist = rules.into_iter().zip(1..).map(|((domain, kind, enabled, comment), id)| DomainRow {
            id, kind, domain, enabled, comment,
        }).collect();
        g.clients = clients.into_iter().zip(1..).map(|((ip, comment), id)| ClientRow { id, ip, comment }).collect();
        let mut seen = std::collections::HashSet::new();
        for (item, group, table) in links {
            let item = i64::try_from(item).unwrap();
            if !seen.insert((item, group, table)) {
                continue;
            }
            match table {
                0 => g.adlist_by_group.push((item, group)),
                1 => g.domainlist_by_group.push((item, group)),
                _ => g.client_by_group.push((item, group)),
            }
        }
        g
    }
}

/// The first `group` row of each group ID, from the gravity input (not from the mapper).
fn input_groups(g: &Gravity) -> BTreeMap<i64, &GroupRow> {
    let mut out = BTreeMap::new();
    for row in &g.groups {
        out.entry(row.id).or_insert(row);
    }
    out
}

/// The group names that a row with `id` must have after the import.
///
/// The group IDs come from the link table of the input. A link to an ID with no `group` row is
/// not membership. `names` gives only the name of each ID; `check_group_names` proves that it
/// has each input group.
fn expected_groups(
    links: &[(i64, i64)],
    id: i64,
    groups: &BTreeMap<i64, &GroupRow>,
    names: &HashMap<i64, String>,
) -> Vec<String> {
    let gids: std::collections::BTreeSet<i64> = links
        .iter()
        .filter(|(item, gid)| *item == id && groups.contains_key(gid))
        .map(|(_, gid)| *gid)
        .collect();
    gids.into_iter()
        .filter_map(|gid| names.get(&gid).cloned())
        .collect()
}

/// Checks the group names that `map_gravity` returns against the gravity input.
fn check_group_names(
    g: &Gravity,
    c: &Config,
    r: &ImportReport,
    names: &HashMap<i64, String>,
) -> Result<(), TestCaseError> {
    let groups = input_groups(g);
    for (gid, row) in &groups {
        if let Some(name) = names.get(gid) {
            // The group is in the config with the flags of its first row.
            let group = c.groups.iter().find(|x| &x.name == name);
            prop_assert!(group.is_some(), "group {} {} missing", gid, name);
            let group = group.unwrap();
            prop_assert_eq!(group.enabled, row.enabled, "group id {}", gid);
            prop_assert_eq!(&group.comment, &row.description, "group id {}", gid);
        } else {
            // A group that is not imported must have a report line that says why.
            let colon = format!("group id {gid}:");
            let space = format!("group id {gid} ");
            let why = r.reported.iter().any(|l| {
                (l.starts_with(&colon) || l.starts_with(&space)) && l.contains("not imported")
            });
            prop_assert!(
                why,
                "group id {} is not imported and not reported: {:#?}",
                gid,
                r.reported
            );
        }
    }
    for gid in names.keys() {
        prop_assert!(
            groups.contains_key(gid),
            "names has group id {} with no row",
            gid
        );
    }
    let distinct: std::collections::HashSet<&String> = names.values().collect();
    prop_assert_eq!(
        distinct.len(),
        names.len(),
        "two group ids have one name: {:?}",
        names
    );
    Ok(())
}

// The case count comes from PROPTEST_CASES (default 256), so CI can raise it.
proptest! {
    #[test]
    fn no_domainlist_row_is_lost(g in gravity()) {
        let mut c = Config::default();
        let mut r = ImportReport::default();
        let names = map_gravity(&g, &mut c, &mut r);
        let groups = input_groups(&g);
        let mut rules = c.rules.iter();
        for row in &g.domainlist {
            let translated = r.translated.iter().any(|l| l.starts_with(&format!("domainlist id {} ", row.id)));
            let reported = r.reported.iter().any(|l| l.starts_with(&format!("domainlist id {}: ", row.id)) && l.ends_with("not imported"));
            prop_assert!(translated != reported, "row {:?}: translated {}, reported {}", row, translated, reported);
            if translated {
                // Rules keep the row order, so the next rule belongs to this row.
                let rule = rules.next().unwrap();
                prop_assert_eq!(&rule.groups, &expected_groups(&g.domainlist_by_group, row.id, &groups, &names));
                prop_assert_eq!(rule.enabled, row.enabled);
                prop_assert_eq!(&rule.comment, &row.comment);
            }
        }
        prop_assert!(rules.next().is_none());
    }

    #[test]
    fn group_membership_is_preserved(g in gravity()) {
        let mut c = Config::default();
        let mut r = ImportReport::default();
        let names = map_gravity(&g, &mut c, &mut r);
        // First prove that each input group reaches `names` (or the report), with a unique
        // name. Then the expected memberships below do not depend on the mapper.
        check_group_names(&g, &c, &r, &names)?;
        let groups = input_groups(&g);
        for list in &c.lists.adlists {
            prop_assert_eq!(&list.groups, &expected_groups(&g.adlist_by_group, i64::from(list.id), &groups, &names));
        }
        let mut clients = c.clients.iter();
        for row in &g.clients {
            if r.translated.iter().any(|l| l.starts_with(&format!("client id {} ", row.id))) {
                let client = clients.next().unwrap();
                prop_assert_eq!(&client.groups, &expected_groups(&g.client_by_group, row.id, &groups, &names));
            } else {
                let prefix = format!("client id {}: ", row.id);
                prop_assert!(r.reported.iter().any(|l| l.starts_with(&prefix)));
            }
        }
        prop_assert!(clients.next().is_none());
    }

    #[test]
    fn import_output_is_always_valid(g in gravity()) {
        let mut c = Config::default();
        let mut r = ImportReport::default();
        map_gravity(&g, &mut c, &mut r);
        prop_assert_eq!(c.validate(), vec![]);
        let text = c.to_toml_string().unwrap();
        prop_assert_eq!(Config::from_toml_str(&text).unwrap(), c);
    }
}

proptest! {
    // Each case builds a SQLite file and a zip, so run fewer cases.
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn io_layer_is_lossless(g in gravity()) {
        // gravity.db has UNIQUE constraints on group names in real Pi-hole files; the
        // synthetic schema has them too, so drop rows that break them.
        let mut g = g;
        let mut names = std::collections::HashSet::new();
        g.groups.retain(|x| names.insert(x.name.clone()));
        // The group ID is the primary key, so drop a second row with the same ID too.
        let mut ids = std::collections::HashSet::new();
        g.groups.retain(|x| ids.insert(x.id));
        let db = build_gravity_db(&g);
        let zip = build_zip(&[("etc/pihole/gravity.db", &db)]);
        let imported = import_teleporter(&zip, &Limits::default()).unwrap();
        let mut c = Config::default();
        let mut r = ImportReport::default();
        r.report("zip has no etc/pihole/pihole.toml: settings keep the rusthole defaults");
        map_gravity(&g, &mut c, &mut r);
        prop_assert_eq!(imported.config, c);
        prop_assert_eq!(imported.report, r);
    }
}
