use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use rusthole_core::Config;
use rusthole_core::clients::{ClientTable, MatchedBy};
use rusthole_core::config::{
    Adlist, BlockingMode, Client, Group, ListKind, Rule, RuleAction, RuleKind,
};
use rusthole_core::lists::{ListFormat, parse_default};
use rusthole_core::localdns::LocalZone;
use rusthole_core::net::MacAddr;
use rusthole_core::policy::Reason;

use super::*;
use crate::filter::ClientTransport;
use crate::identity::IdentitySettings;
use crate::neighbors::NeighborTable;

fn d(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

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

fn rule(kind: RuleKind, action: RuleAction, value: &str) -> Rule {
    Rule {
        id: None,
        created_at: None,
        updated_at: None,
        kind,
        action,
        value: value.to_owned(),
        enabled: true,
        groups: vec!["default".to_owned()],
        comment: None,
    }
}

/// A config with a block list (id 1) and an exact deny rule for `default`, a group `kids`
/// with no list and no rule, and clients by IP and by MAC in `kids`.
fn config() -> Config {
    let mut cfg = Config {
        groups: vec![
            group("default", true),
            group("kids", true),
            group("off", false),
        ],
        ..Config::default()
    };
    cfg.clients = vec![
        client("192.0.2.77", &["kids"]),
        client("02:00:00:00:00:01", &["kids"]),
        client("192.0.2.79", &["off", "default"]),
    ];
    cfg.lists.adlists = vec![Adlist {
        id: 1,
        url: "https://lists.example/hosts.txt".to_owned(),
        kind: ListKind::Block,
        enabled: true,
        groups: vec!["default".to_owned()],
        comment: None,
    }];
    cfg.rules = vec![
        rule(RuleKind::Exact, RuleAction::Deny, "tracker.example"),
        rule(RuleKind::Exact, RuleAction::Allow, "www.example.com"),
    ];
    cfg
}

fn engine_of(cfg: &Config) -> PolicyEngine {
    let list = parse_default(
        "0.0.0.0 blocked.example\n||ads.example^\n",
        ListFormat::Auto,
    )
    .unwrap();
    PolicyEngine::build_with_seed(cfg, [(1, list)], [7, 9]).0
}

struct Fixture {
    filter: PolicyFilter,
    neighbors: Arc<NeighborTable>,
}

fn fixture(cfg: &Config) -> Fixture {
    let neighbors = Arc::new(NeighborTable::new());
    let resolver = ClientResolver::new(
        ClientTable::from_config(cfg).0,
        Arc::new(LocalZone::from_config(cfg).0),
        Arc::clone(&neighbors),
        IdentitySettings::default(),
    );
    let filter = PolicyFilter::new(
        engine_handle(engine_of(cfg)),
        Arc::new(BlockingControl::new(cfg.blocking.enabled)),
        Arc::new(resolver),
    );
    Fixture { filter, neighbors }
}

fn ctx(client: &str, qname: &str) -> QueryContext {
    QueryContext {
        client: client.parse().unwrap(),
        transport: ClientTransport::Udp,
        qname: qname.to_owned(),
        domain: DomainName::parse(qname).ok(),
        qtype: 1,
        qclass: 1,
    }
}

const LAN: &str = "192.0.2.5";

fn query(f: &PolicyFilter, client: &str, qname: &str) -> FilterOutcome {
    let c = ctx(client, qname);
    f.decide_query(&c, &f.identify(c.client))
}

fn answer(f: &PolicyFilter, client: &str, qname: &str, names: &[&str]) -> FilterOutcome {
    let c = ctx(client, qname);
    let names: Vec<DomainName> = names.iter().map(|n| d(n)).collect();
    f.decide_answer(&c, &f.identify(c.client), &names)
}

fn null(ttl: u32) -> FilterVerdict {
    FilterVerdict::Block(BlockReply {
        kind: BlockKind::Null,
        ttl,
    })
}

#[test]
fn blocks_list_and_rule_names_for_default_clients() {
    let fx = fixture(&config());
    let f = &fx.filter;
    let o = query(f, LAN, "blocked.example");
    assert_eq!(o.verdict, null(2));
    let d0 = o.decision.unwrap();
    let Reason::BlockList { lists } = d0.reason else {
        panic!("{d0:?}");
    };
    assert_eq!(lists.first(), Some(1));
    // A subtree entry blocks subdomains.
    assert_eq!(query(f, LAN, "x.ads.example").verdict, null(2));
    let o = query(f, LAN, "tracker.example");
    assert_eq!(o.decision.unwrap().reason, Reason::ExactDeny { rule: 0 });
    // Allowed names pass, with the reason.
    let o = query(f, LAN, "fine.example");
    assert_eq!(o.verdict, FilterVerdict::Allow);
    assert_eq!(o.decision.unwrap().reason, Reason::NoMatch);
    // A name that is not a host name: no decision.
    let o = query(f, LAN, ".");
    assert_eq!(o, FilterOutcome::from(FilterVerdict::Allow));
}

#[test]
fn clients_in_a_group_without_lists_are_not_blocked() {
    let fx = fixture(&config());
    let f = &fx.filter;
    let c = f.identify("192.0.2.77".parse().unwrap());
    assert_eq!(c.matched, Some(MatchedBy::Ip));
    assert_eq!(c.groups.as_ref(), ["kids".to_owned()]);
    assert_eq!(
        query(f, "192.0.2.77", "blocked.example").verdict,
        FilterVerdict::Allow
    );
    // A disabled group gives nothing; the other group applies.
    assert_eq!(query(f, "192.0.2.79", "blocked.example").verdict, null(2));
}

#[test]
fn mac_clients_get_their_group() {
    let fx = fixture(&config());
    let ip = Ipv4Addr::new(192, 0, 2, 78);
    let mac = MacAddr::parse("02:00:00:00:00:01").unwrap();
    fx.neighbors.replace(HashMap::from([(ip, mac)]));
    let c = fx.filter.identify(IpAddr::V4(ip));
    assert_eq!(c.mac, Some(mac));
    assert_eq!(c.matched, Some(MatchedBy::Mac));
    assert_eq!(
        query(&fx.filter, "192.0.2.78", "blocked.example").verdict,
        FilterVerdict::Allow
    );
}

#[test]
fn cname_chain_check_and_query_name_first() {
    let fx = fixture(&config());
    let f = &fx.filter;
    // A query name with no match and a CNAME to a blocked target is blocked.
    let o = answer(f, LAN, "fine.example", &["fine.example", "blocked.example"]);
    assert_eq!(o.verdict, null(2));
    assert_eq!(o.decision.unwrap().name_index, 1);
    assert_eq!(o.cname_target, Some(d("blocked.example")));
    // The Pi-hole rule: an allow rule on the query name allows the full answer.
    let o = answer(
        f,
        LAN,
        "www.example.com",
        &["www.example.com", "blocked.example"],
    );
    assert_eq!(o.verdict, FilterVerdict::Allow);
    assert_eq!(o.decision.unwrap().name_index, 0);
    assert_eq!(o.cname_target, None);
    // The query name is checked also when the answer does not name it.
    let o = answer(f, LAN, "tracker.example", &["other.example"]);
    assert_eq!(o.verdict, null(2));
    assert_eq!(o.cname_target, None);
    // A clean chain is allowed.
    let o = answer(f, LAN, "fine.example", &["fine.example", "cdn.example"]);
    assert_eq!(o.verdict, FilterVerdict::Allow);
    // The kids client is not blocked by a target either.
    let o = answer(f, "192.0.2.77", "fine.example", &["blocked.example"]);
    assert_eq!(o.verdict, FilterVerdict::Allow);
    // An empty chain (root query, no names) is allowed.
    let o = answer(f, LAN, ".", &[]);
    assert_eq!(o, FilterOutcome::from(FilterVerdict::Allow));
}

#[test]
fn deep_cname_check_off_checks_the_query_name_only() {
    let mut cfg = config();
    cfg.blocking.deep_cname_check = false;
    let fx = fixture(&cfg);
    let o = answer(
        &fx.filter,
        LAN,
        "fine.example",
        &["fine.example", "blocked.example"],
    );
    assert_eq!(o.verdict, FilterVerdict::Allow);
    let o = answer(&fx.filter, LAN, "blocked.example", &["fine.example"]);
    assert_eq!(o.verdict, null(2));
}

#[test]
fn special_domains_and_reply_modes() {
    let fx = fixture(&config());
    let o = query(&fx.filter, "192.0.2.77", "use-application-dns.net");
    assert_eq!(
        o.verdict,
        FilterVerdict::Block(BlockReply {
            kind: BlockKind::Nxdomain,
            ttl: 2
        })
    );
    assert_eq!(o.decision.unwrap().reason, Reason::SpecialDomain);
    let ip4 = Ipv4Addr::new(192, 0, 2, 99);
    let cases = [
        (BlockingMode::Nxdomain, None, None, BlockKind::Nxdomain),
        (BlockingMode::Nodata, None, None, BlockKind::Nodata),
        (
            BlockingMode::Ip,
            Some(ip4),
            None,
            BlockKind::Ip {
                v4: Some(ip4),
                v6: None,
            },
        ),
    ];
    for (mode, v4, v6, kind) in cases {
        let mut cfg = config();
        cfg.blocking.mode = mode;
        cfg.blocking.ipv4 = v4.map(|ip| ip.to_string());
        cfg.blocking.ipv6 = v6.map(|ip: Ipv6Addr| ip.to_string());
        cfg.blocking.blocked_ttl = 9;
        let fx = fixture(&cfg);
        assert_eq!(
            query(&fx.filter, LAN, "blocked.example").verdict,
            FilterVerdict::Block(BlockReply { kind, ttl: 9 }),
            "{mode:?}"
        );
    }
}

#[test]
fn engine_swap_applies_at_once() {
    let fx = fixture(&config());
    assert_eq!(
        query(&fx.filter, LAN, "new.example").verdict,
        FilterVerdict::Allow
    );
    let mut cfg = config();
    cfg.rules
        .push(rule(RuleKind::Exact, RuleAction::Deny, "new.example"));
    fx.filter.engine().store(Arc::new(engine_of(&cfg)));
    assert_eq!(query(&fx.filter, LAN, "new.example").verdict, null(2));
}

#[test]
fn toggle_turns_blocking_off_and_on() {
    let fx = fixture(&config());
    let b = Arc::clone(fx.filter.blocking());
    assert!(b.is_blocking());
    b.disable(None).unwrap();
    let o = query(&fx.filter, LAN, "blocked.example");
    assert_eq!(o.verdict, FilterVerdict::Allow);
    assert_eq!(o.decision.unwrap().reason, Reason::BlockingDisabled);
    assert_eq!(b.remaining(), None);
    b.enable().unwrap();
    assert_eq!(query(&fx.filter, LAN, "blocked.example").verdict, null(2));
    // A timer: blocking comes on again by itself.
    b.disable(Some(Duration::from_millis(150))).unwrap();
    assert!(b.remaining().is_some());
    assert!(matches!(
        b.state(),
        Some(ToggleState::Disabled { until: Some(_) })
    ));
    assert_eq!(
        query(&fx.filter, LAN, "blocked.example").verdict,
        FilterVerdict::Allow
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(query(&fx.filter, LAN, "blocked.example").verdict, null(2));
    // An invalid event is refused and blocking stays on.
    b.disable(None).unwrap();
    assert_eq!(
        b.disable(Some(Duration::ZERO)),
        Err(ToggleError::Invalid(InvalidEvent::ZeroDuration))
    );
    assert!(b.is_blocking());
    // A config with blocking off starts off.
    let mut cfg = config();
    cfg.blocking.enabled = false;
    let fx = fixture(&cfg);
    assert_eq!(
        query(&fx.filter, LAN, "blocked.example").verdict,
        FilterVerdict::Allow
    );
}

#[test]
fn old_trait_methods_use_the_policy() {
    let fx = fixture(&config());
    let c = ctx(LAN, "blocked.example");
    assert_eq!(fx.filter.on_query(&c), null(2));
    assert_eq!(
        fx.filter
            .on_answer(&ctx(LAN, "fine.example"), &[d("blocked.example")]),
        null(2)
    );
    assert!(Arc::ptr_eq(fx.filter.clients().neighbors(), &fx.neighbors));
}
