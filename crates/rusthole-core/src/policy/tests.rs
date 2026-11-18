use std::mem::discriminant;

use super::*;
use crate::config::{Adlist, Group, Rule};
use crate::lists::{EntryAction, ListFormat, parse_default};
use proptest::prelude::*;

fn name(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

fn groups(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

fn rule(kind: RuleKind, action: RuleAction, value: &str, g: &[&str]) -> Rule {
    Rule {
        id: None,
        kind,
        action,
        value: value.to_owned(),
        enabled: true,
        groups: groups(g),
        comment: None,
        created_at: None,
        updated_at: None,
    }
}

fn adlist(id: u32, kind: ListKind, g: &[&str]) -> Adlist {
    Adlist {
        id,
        url: format!("https://lists.example/{id}.txt"),
        kind,
        enabled: true,
        groups: groups(g),
        comment: None,
    }
}

fn base_config() -> Config {
    Config {
        groups: vec![
            Group {
                id: None,
                name: "default".into(),
                enabled: true,
                comment: None,
            },
            Group {
                id: None,
                name: "kids".into(),
                enabled: true,
                comment: None,
            },
            Group {
                id: None,
                name: "off".into(),
                enabled: false,
                comment: None,
            },
        ],
        ..Config::default()
    }
}

fn parsed(text: &str) -> ParsedList {
    parse_default(text, ListFormat::Auto).unwrap()
}

/// A config with one item for each step of the decision order.
fn order_engine() -> PolicyEngine {
    let mut c = base_config();
    c.lists.adlists = vec![
        adlist(1, ListKind::Block, &["default"]),
        adlist(2, ListKind::Allow, &["default"]),
    ];
    c.rules = vec![
        rule(
            RuleKind::Exact,
            RuleAction::Allow,
            "exact-allow.example",
            &["default"],
        ),
        rule(
            RuleKind::Regex,
            RuleAction::Allow,
            "^regex-allow\\.",
            &["default"],
        ),
        rule(
            RuleKind::Exact,
            RuleAction::Deny,
            "exact-deny.example",
            &["default"],
        ),
        rule(
            RuleKind::Regex,
            RuleAction::Deny,
            "(^|\\.)example$",
            &["default"],
        ),
        // Deny rules for the names that an allow must win against.
        rule(
            RuleKind::Exact,
            RuleAction::Deny,
            "exact-allow.example",
            &["default"],
        ),
        rule(
            RuleKind::Exact,
            RuleAction::Deny,
            "list-allow.example",
            &["default"],
        ),
    ];
    let block = parsed(
        "exact-allow.example\nregex-allow.example\nlist-allow.example\nexact-deny.example\nlisted.example\n",
    );
    let allow = parsed("list-allow.example\n");
    let (e, report) = PolicyEngine::build(&c, [(1, block), (2, allow)]);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    e
}

#[test]
fn decision_order() {
    let e = order_engine();
    let g = e.default_groups();
    let check = |s: &str| e.check(&g, true, &name(s));

    let d = e.check(&g, false, &name("listed.example"));
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.reason, Reason::BlockingDisabled);

    let d = check("use-application-dns.net");
    assert_eq!(d.action, Action::Special(SpecialReply::Nxdomain));
    assert_eq!(d.reason, Reason::SpecialDomain);
    assert_eq!(check("mask.icloud.com").reason, Reason::SpecialDomain);
    assert_eq!(check("x.mask.icloud.com").reason, Reason::NoMatch);

    assert_eq!(
        check("exact-allow.example").reason,
        Reason::ExactAllow { rule: 0 }
    );
    assert_eq!(
        check("regex-allow.example").reason,
        Reason::RegexAllow { rule: 1 }
    );
    let d = check("list-allow.example");
    assert_eq!(d.action, Action::Allow);
    assert!(matches!(d.reason, Reason::AllowList { lists } if lists.first() == Some(2)));

    let d = check("exact-deny.example");
    assert_eq!(d.action, Action::Block(BlockReply::Null));
    assert_eq!(d.reason, Reason::ExactDeny { rule: 2 });
    let d = check("listed.example");
    assert!(matches!(d.reason, Reason::BlockList { lists } if lists.first() == Some(1)));
    assert_eq!(check("other.example").reason, Reason::RegexDeny { rule: 3 });
    let d = check("other.test");
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.reason, Reason::NoMatch);
    assert!(!d.is_blocked());
}

#[test]
fn special_domains_can_be_turned_off() {
    let mut c = base_config();
    c.blocking.special_domains.clear();
    let (e, _) = PolicyEngine::build(&c, std::iter::empty());
    let d = e.check(&e.default_groups(), true, &name("use-application-dns.net"));
    assert_eq!(d.reason, Reason::NoMatch);
}

#[test]
fn subtree_and_exact_matching() {
    let mut c = base_config();
    c.lists.adlists = vec![adlist(7, ListKind::Block, &["default"])];
    let (e, _) = PolicyEngine::build(&c, [(7, parsed("||ads.example^\nexact.example\n"))]);
    let g = e.default_groups();
    let blocked = |s: &str| e.check(&g, true, &name(s)).is_blocked();
    assert!(blocked("ads.example"));
    assert!(blocked("x.ads.example"));
    assert!(blocked("a.b.c.ads.example"));
    assert!(!blocked("xads.example"));
    assert!(!blocked("example"));
    assert!(!blocked("ads.example.net"));
    assert!(blocked("exact.example"));
    assert!(!blocked("sub.exact.example"));
}

#[test]
fn abp_allow_entries_need_an_allow_kind_list() {
    let mut c = base_config();
    c.lists.adlists = vec![
        adlist(1, ListKind::Block, &["default"]),
        adlist(2, ListKind::Allow, &["default"]),
    ];
    c.rules = vec![rule(
        RuleKind::Exact,
        RuleAction::Deny,
        "b.example",
        &["default"],
    )];
    let (e, report) = PolicyEngine::build(
        &c,
        [
            (1, parsed("||a.example^\n@@||a.example^\n@@||b.example^\n")),
            (2, parsed("@@||c.example^\n")),
        ],
    );
    assert_eq!(report.lists[0].ignored_allow_entries, 2);
    let g = e.default_groups();
    // The `@@` entries of the block list do not allow.
    assert!(e.check(&g, true, &name("x.a.example")).is_blocked());
    assert!(e.check(&g, true, &name("b.example")).is_blocked());
    // An allow-kind list allows the name and its subdomains.
    let d = e.check(&g, true, &name("x.c.example"));
    assert!(matches!(d.reason, Reason::AllowList { .. }));
}

#[test]
fn groups_isolate_rules_and_lists() {
    let mut c = base_config();
    c.lists.adlists = vec![
        adlist(1, ListKind::Block, &["kids"]),
        adlist(2, ListKind::Block, &["off"]),
    ];
    c.rules = vec![
        rule(RuleKind::Exact, RuleAction::Deny, "rule.example", &["kids"]),
        rule(RuleKind::Regex, RuleAction::Deny, "^re\\.", &["off"]),
        rule(RuleKind::Exact, RuleAction::Deny, "none.example", &[]),
    ];
    let (e, _) = PolicyEngine::build(
        &c,
        [(1, parsed("kids.example\n")), (2, parsed("off.example\n"))],
    );
    let default = e.client_groups::<String>(None);
    let kids = e.client_groups(Some(&["kids"][..]));
    let both = e.groups_named(["default", "kids", "off", "unknown"]);
    let nothing = e.client_groups::<&str>(Some(&[]));
    assert!(nothing.is_empty());
    assert!(!default.is_empty());
    for (gs, blocked) in [
        (&default, false),
        (&kids, true),
        (&both, true),
        (&nothing, false),
    ] {
        assert_eq!(
            e.check(gs, true, &name("kids.example")).is_blocked(),
            blocked
        );
        assert_eq!(
            e.check(gs, true, &name("rule.example")).is_blocked(),
            blocked
        );
        // The disabled group "off" never applies.
        assert!(!e.check(gs, true, &name("off.example")).is_blocked());
        assert!(!e.check(gs, true, &name("re.example")).is_blocked());
        // A rule with no group applies to nobody.
        assert!(!e.check(gs, true, &name("none.example")).is_blocked());
    }
    // A disabled "default" group gives an empty default set.
    c.groups[0].enabled = false;
    let (e, _) = PolicyEngine::build(&c, std::iter::empty());
    assert!(e.default_groups().is_empty());
}

#[test]
fn cname_chain() {
    let mut c = base_config();
    c.lists.adlists = vec![adlist(1, ListKind::Block, &["default"])];
    c.rules = vec![
        rule(
            RuleKind::Exact,
            RuleAction::Allow,
            "shop.example",
            &["default"],
        ),
        rule(
            RuleKind::Exact,
            RuleAction::Allow,
            "ok.tracker.example",
            &["default"],
        ),
    ];
    let (e, _) = PolicyEngine::build(&c, [(1, parsed("||tracker.example^\n"))]);
    let g = e.default_groups();
    let chain = [
        name("shop.example"),
        name("cdn.example"),
        name("x.tracker.example"),
    ];
    let d = e.check_chain(&g, true, &chain);
    assert!(d.is_blocked());
    assert_eq!(d.name_index, 2);
    assert!(matches!(d.reason, Reason::BlockList { .. }));
    // The target itself is allowed: the answer is allowed.
    let chain2 = [name("shop.example"), name("ok.tracker.example")];
    let d = e.check_chain(&g, true, &chain2);
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.reason, Reason::ExactAllow { rule: 0 });
    assert_eq!(d.name_index, 0);
    // Blocking off, or an empty chain: allowed.
    assert!(!e.check_chain(&g, false, &chain).is_blocked());
    assert_eq!(e.check_chain(&g, true, &[]).reason, Reason::NoMatch);
    // A blocked query name decides at index 0.
    let d = e.check_chain(&g, true, &[name("tracker.example"), name("cdn.example")]);
    assert_eq!(d.name_index, 0);
    // Without the deep CNAME check, only the query name counts.
    c.blocking.deep_cname_check = false;
    let (e, _) = PolicyEngine::build(&c, [(1, parsed("||tracker.example^\n"))]);
    assert!(
        !e.check_chain(&e.default_groups(), true, &chain)
            .is_blocked()
    );
}

#[test]
fn explain_lists_every_match() {
    let mut c = base_config();
    c.lists.adlists = vec![
        adlist(1, ListKind::Block, &["default"]),
        adlist(2, ListKind::Block, &["kids"]),
        adlist(3, ListKind::Allow, &["default", "kids"]),
    ];
    c.rules = vec![
        rule(RuleKind::Regex, RuleAction::Deny, "ads", &["default"]),
        rule(
            RuleKind::Exact,
            RuleAction::Deny,
            "a.ads.example",
            &["kids"],
        ),
        rule(
            RuleKind::Exact,
            RuleAction::Allow,
            "a.ads.example",
            &["default"],
        ),
    ];
    let (e, _) = PolicyEngine::build(
        &c,
        [
            (1, parsed("||ads.example^\na.ads.example\n")),
            (2, parsed("a.ads.example\n")),
            (3, parsed("@@||ads.example^\n")),
        ],
    );
    let all = e.explain(None, &name("a.ads.example"));
    let sources: Vec<_> = all.iter().map(|m| (m.source.clone(), m.effect)).collect();
    assert_eq!(
        sources,
        [
            (MatchSource::RegexRule { rule: 0 }, MatchEffect::Deny),
            (MatchSource::ExactRule { rule: 1 }, MatchEffect::Deny),
            (MatchSource::ExactRule { rule: 2 }, MatchEffect::Allow),
            (
                MatchSource::List {
                    id: 1,
                    kind: MatchKind::Exact
                },
                MatchEffect::Deny
            ),
            (
                MatchSource::List {
                    id: 2,
                    kind: MatchKind::Exact
                },
                MatchEffect::Deny
            ),
            (
                MatchSource::List {
                    id: 1,
                    kind: MatchKind::Subtree
                },
                MatchEffect::Deny
            ),
            (
                MatchSource::List {
                    id: 3,
                    kind: MatchKind::Subtree
                },
                MatchEffect::Allow
            ),
        ]
    );
    assert_eq!(all[5].matched, "ads.example");
    assert_eq!(all[6].matched, "ads.example");
    assert_eq!(all[6].groups, ["default", "kids"]);
    let kids = e.groups_named(["kids"]);
    let k = e.explain(Some(&kids), &name("a.ads.example"));
    assert_eq!(k.len(), 3);
    assert!(k.iter().all(|m| m.groups.iter().any(|g| g == "kids")));
    let special = e.explain(Some(&GroupSet::none()), &name("mask.icloud.com"));
    assert_eq!(special.len(), 1);
    assert_eq!(special[0].source, MatchSource::SpecialDomain);
}

#[test]
fn build_report_lists_problems() {
    let mut c = base_config();
    c.lists.adlists = vec![
        adlist(1, ListKind::Block, &["default", "ghost"]),
        adlist(2, ListKind::Block, &["default"]),
        adlist(3, ListKind::Block, &["default"]),
        adlist(1, ListKind::Allow, &["default"]),
    ];
    c.lists.adlists[1].enabled = false;
    c.rules = vec![
        rule(RuleKind::Regex, RuleAction::Deny, "(unclosed", &["default"]),
        rule(RuleKind::Exact, RuleAction::Deny, "bad name", &["default"]),
        Rule {
            enabled: false,
            ..rule(
                RuleKind::Exact,
                RuleAction::Deny,
                "off.example",
                &["default"],
            )
        },
    ];
    c.blocking.special_domains.push("not valid!".into());
    c.blocking.mode = BlockingMode::Ip;
    c.blocking.ipv4 = Some("192.0.2.9".into());
    c.blocking.ipv6 = Some("not-an-ip".into());
    let (e, r) = PolicyEngine::build(
        &c,
        [
            (1, parsed("a.example\nb.example\n")),
            (2, parsed("c.example\n")),
            (9, parsed("d.example\n")),
            (1, parsed("e.example\n")),
        ],
    );
    let statuses: Vec<_> = r.lists.iter().map(|l| (l.id, l.status)).collect();
    assert_eq!(
        statuses,
        [
            (1, ListStatus::Used),
            (2, ListStatus::Disabled),
            (9, ListStatus::NotInConfig),
            (1, ListStatus::Duplicate),
        ]
    );
    assert_eq!(r.lists[0].new_domains, 2);
    assert_eq!(r.missing_lists, [3]);
    assert_eq!(r.unique_domains, 2);
    assert_eq!(r.entries, 2);
    let paths: Vec<_> = r.issues.iter().map(|i| i.path.as_str()).collect();
    for p in [
        "lists.adlists[3].id",
        "lists.adlists[0].groups[1]",
        "rules[0].value",
        "rules[1].value",
        "blocking.special_domains[3]",
        "blocking.ipv6",
    ] {
        assert!(paths.contains(&p), "{p} not in {paths:?}");
    }
    assert_eq!(
        e.block_reply(),
        BlockReply::Ip {
            ipv4: Some(Ipv4Addr::new(192, 0, 2, 9)),
            ipv6: None
        }
    );
    assert_eq!(e.blocked_ttl(), 2);
    assert_eq!(e.list_count(), 1);
    assert_eq!(e.unique_domains(), 2);
    assert!(r.memory_bytes > 0);
    assert!(
        e.check(&e.default_groups(), true, &name("a.example"))
            .is_blocked()
    );
    assert!(
        !e.check(&e.default_groups(), true, &name("off.example"))
            .is_blocked()
    );
    assert!(format!("{e:?}").contains("unique_domains: 2"));
}

#[test]
fn reply_modes() {
    for (mode, reply) in [
        (BlockingMode::Null, BlockReply::Null),
        (BlockingMode::Nxdomain, BlockReply::Nxdomain),
        (BlockingMode::Nodata, BlockReply::Nodata),
    ] {
        let mut c = base_config();
        c.blocking.mode = mode;
        c.rules = vec![rule(
            RuleKind::Exact,
            RuleAction::Deny,
            "x.example",
            &["default"],
        )];
        let (e, _) = PolicyEngine::build(&c, std::iter::empty());
        assert_eq!(
            e.check(&e.default_groups(), true, &name("x.example"))
                .action,
            Action::Block(reply)
        );
    }
}

#[test]
fn regex_set_fallback_gives_same_result() {
    let compiled: Vec<(u32, Regex)> = ["^a\\.", "b\\.example$", "[0-9]{3}"]
        .iter()
        .enumerate()
        .map(|(i, p)| (u32::try_from(i).unwrap(), compile_rule_regex(p).unwrap()))
        .collect();
    let mut report = BuildReport::default();
    let set = RegexRules::with_limit(compiled.clone(), REGEX_SET_SIZE_LIMIT, "x", &mut report);
    assert!(matches!(set.matcher, Matcher::Set(_)));
    let each = RegexRules::with_limit(compiled, 10, "x", &mut report);
    assert!(matches!(each.matcher, Matcher::Each(_)));
    assert_eq!(report.issues.len(), 1);
    for n in [
        "a.example",
        "x.b.example",
        "h123.example",
        "none.example",
        "A.EXAMPLE",
    ] {
        let mut h1 = Vec::new();
        set.find_match(n, |r| {
            h1.push(r);
            false
        });
        let mut h2 = Vec::new();
        each.find_match(n, |r| {
            h2.push(r);
            false
        });
        assert_eq!(h1, h2, "{n}");
        assert_eq!(set.is_match(n), each.is_match(n));
    }
    assert!(format!("{set:?}").contains("set"));
}

#[test]
fn many_lists() {
    let mut c = base_config();
    let count: u32 = 1100;
    c.lists.adlists = (0..count)
        .map(|i| {
            adlist(
                i,
                ListKind::Block,
                if i % 2 == 0 { &["default"] } else { &["kids"] },
            )
        })
        .collect();
    let lists = (0..count).map(|i| (i, parsed(&format!("l{i}.example\nshared.example\n"))));
    let (e, r) = PolicyEngine::build(&c, lists);
    assert_eq!(e.list_count(), 1100);
    assert_eq!(r.unique_domains, 1101);
    let kids = e.groups_named(["kids"]);
    let d = e.check(&kids, true, &name("l1099.example"));
    assert!(matches!(d.reason, Reason::BlockList { lists } if lists.first() == Some(1099)));
    assert!(!e.check(&kids, true, &name("l1098.example")).is_blocked());
    let d = e.check(&kids, true, &name("shared.example"));
    let Reason::BlockList { lists } = d.reason else {
        panic!("{d:?}")
    };
    assert_eq!(lists.iter().collect::<Vec<_>>(), [1, 3, 5, 7]);
    assert!(lists.has_more());
    assert_eq!(e.explain(Some(&kids), &name("shared.example")).len(), 550);
}

#[test]
fn engine_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PolicyEngine>();
    let e = PolicyEngine::default();
    assert_eq!(e.unique_domains(), 0);
}

#[test]
fn list_ids_bounded() {
    let mut ids = ListIds::default();
    assert!(ids.is_empty());
    for i in [5, 5, 6, 7, 8, 9, 5] {
        ids.push(i);
    }
    assert_eq!(ids.iter().collect::<Vec<_>>(), [5, 6, 7, 8]);
    assert!(ids.has_more());
}

// ---- Property tests ----

const BASES: [&str; 3] = ["example.com", "example.net", "test.org"];
const LABELS: [&str; 4] = ["a", "ads", "x", "cdn"];

/// A small pool of names, so that rules and lists often hit the same names.
fn pool_name() -> impl Strategy<Value = String> {
    (prop::collection::vec(0..LABELS.len(), 0..3), 0..BASES.len()).prop_map(|(labels, base)| {
        let mut parts: Vec<&str> = labels.iter().map(|i| LABELS[*i]).collect();
        parts.push(BASES[base]);
        parts.join(".")
    })
}

#[derive(Debug, Clone)]
enum Item {
    Rule {
        regex: bool,
        allow: bool,
        name: String,
        groups: Vec<String>,
    },
    Entry {
        list: u32,
        subtree: bool,
        name: String,
    },
}

const GROUP_NAMES: [&str; 3] = ["default", "kids", "off"];

fn group_list() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(0..GROUP_NAMES.len(), 0..3)
        .prop_map(|v| v.into_iter().map(|i| GROUP_NAMES[i].to_owned()).collect())
}

fn item() -> impl Strategy<Value = Item> {
    prop_oneof![
        (any::<bool>(), any::<bool>(), pool_name(), group_list()).prop_map(
            |(regex, allow, name, groups)| Item::Rule {
                regex,
                allow,
                name,
                groups
            }
        ),
        (0u32..4, any::<bool>(), pool_name()).prop_map(|(list, subtree, name)| Item::Entry {
            list,
            subtree,
            name
        }),
    ]
}

/// List setup: kind and groups of lists 0..4.
fn list_setup() -> impl Strategy<Value = Vec<(bool, Vec<String>)>> {
    prop::collection::vec((any::<bool>(), group_list()), 4)
}

fn regex_for(name: &str) -> String {
    format!("(^|\\.){}$", regex::escape(name))
}

/// Builds an engine from items. `lists` gives (allow kind, groups) of each list.
fn engine_from(items: &[Item], lists: &[(bool, Vec<String>)], list_order: &[u32]) -> PolicyEngine {
    let mut c = base_config();
    for &i in list_order {
        let Some((allow, g)) = lists.get(i as usize) else {
            continue;
        };
        let kind = if *allow {
            ListKind::Allow
        } else {
            ListKind::Block
        };
        c.lists.adlists.push(Adlist {
            groups: g.clone(),
            ..adlist(i, kind, &[])
        });
    }
    let mut data: Vec<ParsedList> = (0..4).map(|_| ParsedList::new()).collect();
    for it in items {
        match it {
            Item::Rule {
                regex,
                allow,
                name: n,
                groups: g,
            } => c.rules.push(Rule {
                id: None,
                created_at: None,
                updated_at: None,
                kind: if *regex {
                    RuleKind::Regex
                } else {
                    RuleKind::Exact
                },
                action: if *allow {
                    RuleAction::Allow
                } else {
                    RuleAction::Deny
                },
                value: if *regex { regex_for(n) } else { n.clone() },
                enabled: true,
                groups: g.clone(),
                comment: None,
            }),
            Item::Entry {
                list,
                subtree,
                name: n,
            } => {
                let kind = if *subtree {
                    MatchKind::Subtree
                } else {
                    MatchKind::Exact
                };
                data[*list as usize]
                    .push(&name(n), kind, EntryAction::Deny)
                    .unwrap();
            }
        }
    }
    let feed: Vec<(u32, ParsedList)> = list_order
        .iter()
        .map(|&i| (i, data[i as usize].clone()))
        .collect();
    let (e, report) = PolicyEngine::build(&c, feed);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    e
}

fn client_groups() -> impl Strategy<Value = Vec<String>> {
    group_list()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// An allow match beats any deny for the same client and name.
    #[test]
    fn allow_beats_any_deny(
        items in prop::collection::vec(item(), 0..24),
        lists in list_setup(),
        target in pool_name(),
        allow_kind in 0u8..4,
    ) {
        let mut items = items;
        let mut lists = lists;
        let all = vec!["default".to_owned()];
        // Add one allow source for `target` in the group "default".
        match allow_kind {
            0 => items.push(Item::Rule { regex: false, allow: true, name: target.clone(), groups: all.clone() }),
            1 => items.push(Item::Rule { regex: true, allow: true, name: target.clone(), groups: all.clone() }),
            2 => {
                lists[3] = (true, all.clone());
                items.push(Item::Entry { list: 3, subtree: false, name: target.clone() });
            }
            _ => {
                lists[3] = (true, all.clone());
                let parent = target.split_once('.').map_or(target.as_str(), |(_, p)| p).to_owned();
                let parent = if parent.contains('.') { parent } else { target.clone() };
                items.push(Item::Entry { list: 3, subtree: true, name: parent });
            }
        }
        let e = engine_from(&items, &lists, &[0, 1, 2, 3]);
        let d = e.check(&e.default_groups(), true, &name(&target));
        prop_assert_eq!(d.action, Action::Allow, "{:?}", d);
    }

    /// A client sees only the rules and lists of its enabled groups. The decision for a
    /// client equals the decision of an engine that has only the items of the client's
    /// enabled groups, all moved to "default".
    #[test]
    fn group_isolation(
        items in prop::collection::vec(item(), 0..24),
        lists in list_setup(),
        client in client_groups(),
        target in pool_name(),
    ) {
        let full = engine_from(&items, &lists, &[0, 1, 2, 3]);
        let gs = full.client_groups(Some(&client[..]));
        let enabled: Vec<&str> = client.iter().map(String::as_str).filter(|g| *g != "off").collect();
        let shares = |g: &[String]| g.iter().any(|x| enabled.contains(&x.as_str()));
        let only: Vec<Item> = items
            .iter()
            .filter_map(|it| match it {
                Item::Rule { regex, allow, name, groups } => shares(groups).then(|| Item::Rule {
                    regex: *regex,
                    allow: *allow,
                    name: name.clone(),
                    groups: vec!["default".into()],
                }),
                Item::Entry { list, .. } => shares(&lists[*list as usize].1).then(|| it.clone()),
            })
            .collect();
        let only_lists: Vec<(bool, Vec<String>)> = lists
            .iter()
            .map(|(k, g)| (*k, if shares(g) { vec!["default".into()] } else { vec![] }))
            .collect();
        let reduced = engine_from(&only, &only_lists, &[0, 1, 2, 3]);
        let a = full.check(&gs, true, &name(&target));
        let b = reduced.check(&reduced.default_groups(), true, &name(&target));
        prop_assert_eq!(a.action, b.action);
        prop_assert_eq!(discriminant(&a.reason), discriminant(&b.reason));
    }

    /// The decision does not depend on the order of rules, list entries or lists.
    #[test]
    fn order_does_not_matter(
        items in prop::collection::vec(item(), 0..24),
        lists in list_setup(),
        client in client_groups(),
        target in pool_name(),
        seed in any::<u64>(),
    ) {
        let a = engine_from(&items, &lists, &[0, 1, 2, 3]);
        let mut shuffled = items.clone();
        // A simple deterministic shuffle from the seed.
        let mut s = seed | 1;
        for i in (1..shuffled.len()).rev() {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            shuffled.swap(i, usize::try_from(s % (i as u64 + 1)).unwrap());
        }
        let b = engine_from(&shuffled, &lists, &[3, 1, 0, 2]);
        let ga = a.client_groups(Some(&client[..]));
        let gb = b.client_groups(Some(&client[..]));
        let da = a.check(&ga, true, &name(&target));
        let db = b.check(&gb, true, &name(&target));
        prop_assert_eq!(da.action, db.action);
        prop_assert_eq!(discriminant(&da.reason), discriminant(&db.reason));
        if let (Reason::BlockList { lists: la }, Reason::BlockList { lists: lb }) = (da.reason, db.reason) {
            let mut x: Vec<_> = la.iter().collect();
            let mut y: Vec<_> = lb.iter().collect();
            x.sort_unstable();
            y.sort_unstable();
            if !la.has_more() && !lb.has_more() {
                prop_assert_eq!(x, y);
            }
        }
    }

    /// A subtree entry matches the name and every subdomain, and no lookalike name.
    #[test]
    fn subtree_matches_subdomains_only(
        base in "[a-z]{1,8}\\.[a-z]{2,4}",
        prefix in prop::collection::vec("[a-z0-9]{1,6}", 0..4),
        glue in "[a-z0-9-]{1,4}",
    ) {
        let mut c = base_config();
        c.lists.adlists = vec![adlist(1, ListKind::Block, &["default"])];
        let (e, _) = PolicyEngine::build(&c, [(1, parsed(&format!("||{base}^\n")))]);
        let g = e.default_groups();
        let mut sub = prefix.clone();
        sub.push(base.clone());
        prop_assert!(e.check(&g, true, &name(&sub.join("."))).is_blocked());
        // Lookalike: the same text with no dot before the base.
        let look = format!("{glue}{base}");
        prop_assert!(!e.check(&g, true, &name(&look)).is_blocked());
        if let Some((_, parent)) = base.split_once('.') {
            prop_assert!(!e.check(&g, true, &name(parent)).is_blocked());
        }
    }

    /// A chain is blocked if and only if some name in it is blocked (and not allowed), and
    /// the decision names the first such name.
    #[test]
    fn chain_blocked_iff_some_name_blocked(
        items in prop::collection::vec(item(), 0..24),
        lists in list_setup(),
        chain in prop::collection::vec(pool_name(), 1..5),
    ) {
        let e = engine_from(&items, &lists, &[0, 1, 2, 3]);
        let g = e.default_groups();
        let chain: Vec<DomainName> = chain.iter().map(|s| name(s)).collect();
        let d = e.check_chain(&g, true, &chain);
        let first_blocked = chain.iter().position(|n| e.check(&g, true, n).is_blocked());
        prop_assert_eq!(d.is_blocked(), first_blocked.is_some());
        if let Some(i) = first_blocked {
            prop_assert_eq!(d.name_index, i);
        }
    }
}

#[test]
fn seed_gives_a_repeatable_build_and_the_report_shows_the_probe() {
    use std::fmt::Write as _;
    let mut cfg = base_config();
    cfg.lists.adlists = vec![adlist(1, ListKind::Block, &["default"])];
    let mut text = String::new();
    for i in 0..5000 {
        writeln!(text, "host-{i}.example").unwrap();
    }
    let (first, first_report) = PolicyEngine::build_with_seed(&cfg, [(1, parsed(&text))], [7, 9]);
    let (second, second_report) = PolicyEngine::build_with_seed(&cfg, [(1, parsed(&text))], [7, 9]);
    let (random, random_report) = PolicyEngine::build(&cfg, [(1, parsed(&text))]);
    assert_eq!(first_report, second_report);
    assert_eq!(first_report.set_rehashes, 0);
    assert!(
        first_report.set_max_probe < MAX_PROBE,
        "{}",
        first_report.set_max_probe
    );
    assert_eq!(random_report.unique_domains, 5000);
    let groups = first.default_groups();
    for host in ["host-0.example", "host-4999.example", "host-5000.example"] {
        let n = name(host);
        let want = first.check(&groups, true, &n);
        assert_eq!(want, second.check(&groups, true, &n));
        assert_eq!(want, random.check(&groups, true, &n));
    }
    assert!(matches!(
        first.check(&groups, true, &name("host-17.example")).action,
        Action::Block(_)
    ));
}
