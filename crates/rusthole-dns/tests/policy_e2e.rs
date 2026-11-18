//! End-to-end tests of part P3c: a real server on 127.0.0.1 with the policy filter, a fake
//! neighbor source, a fake public upstream and a fake conditional forwarding server.
// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use rusthole_core::clients::{ClientTable, MatchedBy};
use rusthole_core::config::{
    Adlist, Client, ConditionalForward, Group, ListKind, LocalRecord, RecordType as CfgType, Rule,
    RuleAction, RuleKind,
};
use rusthole_core::lists::{ListFormat, parse_default};
use rusthole_core::net::MacAddr;
use rusthole_core::policy::{Action, Reason};
use rusthole_core::{Config, PolicyEngine};
use rusthole_dns::{
    AnswerSource, BlockingControl, DnsServer, DnsSettings, IdentityService, IdentitySettings,
    ListenMode, PolicyFilter, QueryEvent, QueryObserver, ServerDeps, StaticInterfaces,
    StaticNeighbors, UpstreamProto, UpstreamServer, Verdict, engine_handle,
};
use tokio::net::UdpSocket;

const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
const WAIT: Duration = Duration::from_secs(3);

// ---------- fake upstream ----------

/// A UDP DNS server on 127.0.0.1. `cname.example` gets a CNAME to `blocked.example` and an
/// A record; other names get an A record `192.0.2.<last>`. It counts the queries.
struct Fake {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
}

async fn fake(last: u8) -> Fake {
    let sock = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            c.fetch_add(1, Ordering::SeqCst);
            let mut m = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
            m.metadata.recursion_available = true;
            m.queries.clone_from(&q.queries);
            if let Some(query) = q.queries.first() {
                let name = query.name().clone();
                let a = |owner: Name| {
                    Record::from_rdata(owner, 300, RData::A(A(Ipv4Addr::new(192, 0, 2, last))))
                };
                if name.to_ascii().eq_ignore_ascii_case("cname.example.") {
                    let target = Name::from_ascii("blocked.example.").unwrap();
                    m.answers.push(Record::from_rdata(
                        name,
                        300,
                        RData::CNAME(CNAME(target.clone())),
                    ));
                    m.answers.push(a(target));
                } else if query.query_type() == RecordType::A {
                    m.answers.push(a(name));
                }
            }
            let _ = sock.send_to(&m.to_vec().unwrap(), peer).await;
        }
    });
    Fake { addr, count }
}

impl Fake {
    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

// ---------- config and server ----------

fn group(name: &str) -> Group {
    Group {
        id: None,
        name: name.to_owned(),
        enabled: true,
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

/// A config with a block list (id 1, group `default`), a deny rule for `local.lan` (a local
/// record: it must not be blocked), a local record, and a conditional forward for `corp`.
fn base_config(cf_server: SocketAddr) -> Config {
    let mut cfg = Config {
        groups: vec![group("default"), group("kids")],
        ..Config::default()
    };
    cfg.lists.adlists = vec![Adlist {
        id: 1,
        url: "https://lists.example/hosts.txt".to_owned(),
        kind: ListKind::Block,
        enabled: true,
        groups: vec!["default".to_owned()],
        comment: None,
    }];
    cfg.rules = vec![Rule {
        id: None,
        created_at: None,
        updated_at: None,
        kind: RuleKind::Exact,
        action: RuleAction::Deny,
        value: "nas.lan".to_owned(),
        enabled: true,
        groups: vec!["default".to_owned()],
        comment: None,
    }];
    cfg.local_dns.records = vec![LocalRecord {
        id: None,
        enabled: true,
        comment: None,
        name: "nas.lan".to_owned(),
        record_type: CfgType::A,
        value: "192.0.2.10".to_owned(),
    }];
    cfg.local_dns.conditional_forwarding = vec![ConditionalForward {
        id: None,
        comment: None,
        enabled: true,
        cidr: "198.51.100.0/24".to_owned(),
        server: cf_server.to_string(),
        domain: Some("corp".to_owned()),
    }];
    assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
    cfg
}

#[derive(Debug, Default)]
struct Recorder {
    events: parking_lot::Mutex<Vec<QueryEvent>>,
}

impl QueryObserver for Recorder {
    fn on_event(&self, event: &QueryEvent) {
        self.events.lock().push(event.clone());
    }
}

impl Recorder {
    fn last(&self) -> QueryEvent {
        self.events.lock().last().cloned().unwrap()
    }
}

struct Harness {
    server: DnsServer,
    identity: IdentityService,
    filter: Arc<PolicyFilter>,
    events: Arc<Recorder>,
    addr: SocketAddr,
}

async fn harness(cfg: &Config, upstream: &Fake, neighbors: Arc<StaticNeighbors>) -> Harness {
    let (mut settings, warnings) = DnsSettings::from_config(cfg).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    settings.listen = ListenMode::Addrs(vec![IpAddr::V4(LOCALHOST)]);
    settings.port = 0;
    settings.pool.servers = vec![UpstreamServer {
        addr: upstream.addr,
        proto: UpstreamProto::Udp,
    }];
    settings.pool.timeout = Duration::from_secs(1);
    let identity = IdentityService::start(
        ClientTable::from_config(cfg).0,
        Arc::clone(&settings.local),
        neighbors,
        IdentitySettings::default(),
    )
    .unwrap();
    let list = parse_default("0.0.0.0 blocked.example\n", ListFormat::Auto).unwrap();
    let (engine, _) = PolicyEngine::build_with_seed(cfg, [(1, list)], [3, 4]);
    let filter = Arc::new(PolicyFilter::new(
        engine_handle(engine),
        Arc::new(BlockingControl::new(cfg.blocking.enabled)),
        identity.resolver(),
    ));
    let events = Arc::new(Recorder::default());
    let server = rusthole_dns::start(
        settings,
        ServerDeps {
            interfaces: Arc::new(StaticInterfaces::default()),
            filter: filter.clone(),
            observer: events.clone(),
            ..ServerDeps::default()
        },
    )
    .await
    .unwrap();
    let addr = server.bound()[0].udp;
    Harness {
        server,
        identity,
        filter,
        events,
        addr,
    }
}

impl Harness {
    async fn stop(self) {
        assert!(self.server.shutdown(Duration::from_secs(2)).await);
        assert!(self.identity.shutdown(Duration::from_secs(2)).await);
        assert_eq!(self.server.task_count(), 0);
        assert_eq!(self.identity.task_count(), 0);
    }
}

async fn ask(server: SocketAddr, qname: &str, qtype: RecordType) -> Message {
    ask_query(
        server,
        Query::query(Name::from_ascii(qname).unwrap(), qtype),
    )
    .await
}

async fn ask_query(server: SocketAddr, query: Query) -> Message {
    let qname = query.name().to_ascii();
    let mut m = Message::new(4321, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(query);
    let sock = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
    sock.send_to(&m.to_vec().unwrap(), server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(WAIT, sock.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("no answer for {qname}"))
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

fn data(m: &Message) -> Vec<RData> {
    m.answers.iter().map(|r| r.data.clone()).collect()
}

// ---------- tests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocks_by_type_and_checks_cname_targets() {
    let up = fake(1).await;
    let cf = fake(50).await;
    let h = harness(
        &base_config(cf.addr),
        &up,
        Arc::new(StaticNeighbors::default()),
    )
    .await;

    let m = ask(h.addr, "blocked.example.", RecordType::A).await;
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::UNSPECIFIED))]);
    let ev = h.events.last();
    assert_eq!(ev.verdict, Verdict::BlockedQuery);
    assert_eq!(ev.policy.groups.as_ref(), ["default".to_owned()]);
    assert_eq!(ev.policy.matched, Some(MatchedBy::Default));
    let decision = ev.policy.decision.unwrap();
    assert!(matches!(decision.reason, Reason::BlockList { lists } if lists.first() == Some(1)));

    let m = ask(h.addr, "blocked.example.", RecordType::AAAA).await;
    assert_eq!(data(&m), vec![RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))]);
    let m = ask(h.addr, "blocked.example.", RecordType::HTTPS).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(m.answers.len(), 0);
    assert_eq!(up.count(), 0, "a blocked name never goes upstream");

    // An allowed name passes.
    let m = ask(h.addr, "www.example.com.", RecordType::A).await;
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))]);
    assert_eq!(h.events.last().verdict, Verdict::Allowed);

    // A CNAME to a blocked target is blocked, also on the cache hit.
    for source in [AnswerSource::Upstream, AnswerSource::Cache] {
        let m = ask(h.addr, "cname.example.", RecordType::A).await;
        assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::UNSPECIFIED))]);
        let ev = h.events.last();
        assert_eq!((ev.verdict, ev.source), (Verdict::BlockedAnswer, source));
        assert_eq!(ev.policy.cname_target.unwrap().as_str(), "blocked.example");
    }
    assert_eq!(up.count(), 2);
    assert_eq!(cf.count(), 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_without_lists_and_mac_clients_are_not_blocked() {
    let up = fake(1).await;
    let cf = fake(50).await;
    // 127.0.0.1 is in `kids` by IP: no list applies.
    let mut cfg = base_config(cf.addr);
    cfg.clients = vec![client("127.0.0.1", &["kids"])];
    let h = harness(&cfg, &up, Arc::new(StaticNeighbors::default())).await;
    let m = ask(h.addr, "blocked.example.", RecordType::A).await;
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))]);
    let ev = h.events.last();
    assert_eq!(ev.policy.matched, Some(MatchedBy::Ip));
    assert_eq!(ev.policy.groups.as_ref(), ["kids".to_owned()]);
    h.stop().await;

    // 127.0.0.1 is in `kids` by MAC (fake neighbor table).
    let mac = MacAddr::parse("02:00:00:00:00:01").unwrap();
    let mut cfg = base_config(cf.addr);
    cfg.clients = vec![client("02:00:00:00:00:01", &["kids"])];
    let neighbors = Arc::new(StaticNeighbors::new(HashMap::from([(LOCALHOST, mac)])));
    let h = harness(&cfg, &up, neighbors).await;
    let m = ask(h.addr, "blocked.example.", RecordType::A).await;
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))]);
    let ev = h.events.last();
    assert_eq!(ev.policy.matched, Some(MatchedBy::Mac));
    assert_eq!(ev.policy.client_mac, Some(mac));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_records_forwarding_and_private_reverse() {
    let up = fake(1).await;
    let cf = fake(50).await;
    let h = harness(
        &base_config(cf.addr),
        &up,
        Arc::new(StaticNeighbors::default()),
    )
    .await;

    // A local record: authoritative, not blocked by the deny rule, no upstream query.
    let m = ask(h.addr, "NAS.lan.", RecordType::A).await;
    assert!(m.metadata.authoritative);
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::new(192, 0, 2, 10)))]);
    assert_eq!(h.events.last().source, AnswerSource::LocalDns);
    // Another type for a local name: NODATA, still no upstream query.
    let m = ask(h.addr, "nas.lan.", RecordType::AAAA).await;
    assert!(m.metadata.authoritative);
    assert_eq!(m.answers.len(), 0);
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    // The reverse map.
    let m = ask(h.addr, "10.2.0.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(m.answers.len(), 1);
    assert_eq!(up.count(), 0);

    // Conditional forwarding: the domain and the reverse zone go to the local server.
    let m = ask(h.addr, "printer.corp.", RecordType::A).await;
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::new(192, 0, 2, 50)))]);
    let ev = h.events.last();
    assert_eq!(ev.upstream, Some(cf.addr));
    assert_eq!(ev.policy.forward_rule, Some(0));
    let _ = ask(h.addr, "7.100.51.198.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(cf.count(), 2);
    assert_eq!(up.count(), 0);
    // Label boundary: `xcorp` is not under `corp`.
    let _ = ask(h.addr, "printer.xcorp.", RecordType::A).await;
    assert_eq!((cf.count(), up.count()), (2, 1));

    // A private reverse lookup with no forward gets NXDOMAIN and never goes upstream.
    let m = ask(h.addr, "5.1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(h.events.last().source, AnswerSource::LocalDns);
    assert_eq!((cf.count(), up.count()), (2, 1));
    // The same for a name with more labels (DNS-SD browse), for a name that is not a valid
    // domain name (RFC 2317) and for a class that is not IN.
    let m = ask(
        h.addr,
        "lb._dns-sd._udp.0.1.168.192.in-addr.arpa.",
        RecordType::PTR,
    )
    .await;
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    let rfc2317 = Name::from_labels([
        b"0/25".as_slice(),
        b"1",
        b"168",
        b"192",
        b"in-addr",
        b"arpa",
    ])
    .unwrap();
    let m = ask_query(h.addr, Query::query(rfc2317, RecordType::PTR)).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    for class in [DNSClass::CH, DNSClass::ANY] {
        let mut q = Query::query(
            Name::from_ascii("5.1.168.192.in-addr.arpa.").unwrap(),
            RecordType::PTR,
        );
        q.set_query_class(class);
        let m = ask_query(h.addr, q).await;
        assert_eq!(
            m.metadata.response_code,
            ResponseCode::NXDomain,
            "{class:?}"
        );
    }
    assert_eq!((cf.count(), up.count()), (2, 1));
    // A name with more labels in a forwarded reverse zone goes to the local server.
    let _ = ask(
        h.addr,
        "b._dns-sd._udp.7.100.51.198.in-addr.arpa.",
        RecordType::PTR,
    )
    .await;
    assert_eq!((cf.count(), up.count()), (3, 1));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn toggle_off_then_timer_ends() {
    let up = fake(1).await;
    let cf = fake(50).await;
    let h = harness(
        &base_config(cf.addr),
        &up,
        Arc::new(StaticNeighbors::default()),
    )
    .await;
    let blocked = |m: &Message| data(m) == vec![RData::A(A(Ipv4Addr::UNSPECIFIED))];

    assert!(blocked(
        &ask(h.addr, "blocked.example.", RecordType::A).await
    ));
    h.filter.blocking().disable(None).unwrap();
    assert!(!blocked(
        &ask(h.addr, "blocked.example.", RecordType::A).await
    ));
    let d = h.events.last().policy.decision.unwrap();
    assert_eq!(
        (d.action, d.reason),
        (Action::Allow, Reason::BlockingDisabled)
    );
    // A CNAME target is not blocked either.
    assert!(!blocked(
        &ask(h.addr, "cname.example.", RecordType::A).await
    ));

    h.filter
        .blocking()
        .disable(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(!blocked(
        &ask(h.addr, "blocked.example.", RecordType::A).await
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(blocked(
        &ask(h.addr, "blocked.example.", RecordType::A).await
    ));
    assert!(blocked(&ask(h.addr, "cname.example.", RecordType::A).await));
    h.stop().await;
}

/// Part P5: a config change applies live. A new local record answers, a new client entry
/// gets its group, a new `acl.allow` network is in the ACL, and a listener change asks for a
/// restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_changes_apply_live() {
    let up = fake(1).await;
    let cf = fake(50).await;
    let cfg = base_config(cf.addr);
    let h = harness(&cfg, &up, Arc::new(StaticNeighbors::default())).await;
    let (mut old, _) = DnsSettings::from_config(&cfg).unwrap();
    old.listen = ListenMode::Addrs(vec![IpAddr::V4(LOCALHOST)]);
    old.port = 0;
    old.pool.servers = vec![UpstreamServer {
        addr: up.addr,
        proto: UpstreamProto::Udp,
    }];
    old.pool.timeout = Duration::from_secs(1);

    // Before: blocked for the default group; no record for new.lan.
    let m = ask(h.addr, "blocked.example.", RecordType::A).await;
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::UNSPECIFIED))]);
    let m = ask(h.addr, "new.lan.", RecordType::A).await;
    assert!(!m.metadata.authoritative);

    let mut cfg2 = cfg.clone();
    cfg2.local_dns.records.push(LocalRecord {
        id: None,
        name: "new.lan".to_owned(),
        record_type: rusthole_core::config::RecordType::A,
        value: "192.0.2.77".to_owned(),
        enabled: true,
        comment: None,
    });
    cfg2.clients = vec![client("127.0.0.1", &["kids"])];
    cfg2.acl.allow = vec!["198.51.100.0/24".to_owned()];
    assert!(cfg2.validate().is_empty(), "{:?}", cfg2.validate());
    let (mut new, _) = DnsSettings::from_config(&cfg2).unwrap();
    new.listen = old.listen.clone();
    new.port = old.port;
    new.pool = old.pool.clone();
    assert!(
        h.filter
            .clients()
            .set_config(ClientTable::from_config(&cfg2).0, Arc::clone(&new.local))
    );
    assert!(
        !h.server.apply_live(&old, &new),
        "no restart for these changes"
    );

    let m = ask(h.addr, "new.lan.", RecordType::A).await;
    assert!(m.metadata.authoritative);
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::new(192, 0, 2, 77)))]);
    // 127.0.0.1 is in `kids` now: no list applies.
    let m = ask(h.addr, "blocked.example.", RecordType::A).await;
    assert_eq!(data(&m), vec![RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))]);
    assert_eq!(h.events.last().policy.groups.as_ref(), ["kids".to_owned()]);
    let acl = h.server.acl().unwrap();
    assert!(acl.allows(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))));
    assert!(acl.allows(IpAddr::V4(LOCALHOST)));

    // A listener change needs a restart.
    let mut moved = new.clone();
    moved.port = 5300;
    assert!(h.server.apply_live(&new, &moved));
    h.stop().await;
}
