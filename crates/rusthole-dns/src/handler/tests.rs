// Short names (h, q, p, r, m) for handler, query, pending, reply and message keep the tests readable.
#![allow(clippy::many_single_char_names)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

use hickory_proto::op::{Edns, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rusthole_core::DomainName;
use rusthole_core::acl::InterfaceNet;
use rusthole_core::net::Cidr;

use super::*;
use crate::filter::{AllowAll, BlockKind, BlockReply, NoopObserver};

const ON_NET: &str = "192.0.2.77:40000";
const OFF_NET: &str = "198.51.100.7:40000";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The ACL of a host with one interface `192.0.2.10/24` (a fake interface list).
fn lan_acl() -> Acl {
    Acl::build(
        true,
        &[InterfaceNet {
            addr: Ipv4Addr::new(192, 0, 2, 10),
            prefix: 24,
        }],
        &[],
    )
}

fn handler_with(filter: Arc<dyn QueryFilter>, observer: Arc<dyn QueryObserver>) -> Handler {
    Handler::new(
        &HandlerSettings::default(),
        lan_acl(),
        filter,
        observer,
        Clock::new(),
    )
}

fn handler() -> Handler {
    handler_with(Arc::new(AllowAll), Arc::new(NoopObserver))
}

fn query(id: u16, qname: &str, qtype: RecordType, edns: Option<(u16, bool)>) -> Vec<u8> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(qname).unwrap(), qtype));
    if let Some((size, dnssec_ok)) = edns {
        let mut e = Edns::new();
        e.set_max_payload(size);
        e.set_dnssec_ok(dnssec_ok);
        m.set_edns(e);
    }
    m.to_vec().unwrap()
}

fn a_record(owner: &str, ttl: u32, last: u8) -> Record {
    Record::from_rdata(
        Name::from_ascii(owner).unwrap(),
        ttl,
        RData::A(A(Ipv4Addr::new(192, 0, 2, last))),
    )
}

fn upstream_answer(p: &Pending, records: Vec<Record>) -> UpstreamAnswer {
    let mut m = Message::new(4242, MessageType::Response, OpCode::Query);
    m.add_query(p.request().query.clone());
    m.answers = records;
    UpstreamAnswer {
        message: m,
        upstream: addr("192.0.2.53:53"),
        fallback: false,
    }
}

fn pending(f: Front) -> Box<Pending> {
    match f {
        Front::Resolve(p) => p,
        other => panic!("expected Resolve, got {other:?}"),
    }
}

fn reply(f: Front) -> Reply {
    match f {
        Front::Reply(r) => r,
        other => panic!("expected Reply, got {other:?}"),
    }
}

fn parse(r: &Reply) -> Message {
    Message::from_vec(&r.bytes).unwrap()
}

#[test]
fn garbage_and_responses_are_dropped() {
    let h = handler();
    assert!(matches!(
        h.front(&[], addr(ON_NET), ClientTransport::Udp),
        Front::Drop
    ));
    assert!(matches!(
        h.front(&[1, 2, 3], addr(ON_NET), ClientTransport::Tcp),
        Front::Drop
    ));
    let mut resp = query(1, "example.com.", RecordType::A, None);
    resp[2] |= 0x80;
    assert!(matches!(
        h.front(&resp, addr(ON_NET), ClientTransport::Udp),
        Front::Drop
    ));
}

#[test]
fn off_net_udp_is_dropped_and_tcp_refused() {
    let h = handler();
    let q = query(9, "example.com.", RecordType::A, None);
    assert!(matches!(
        h.front(&q, addr(OFF_NET), ClientTransport::Udp),
        Front::Drop
    ));
    let r = reply(h.front(&q, addr(OFF_NET), ClientTransport::Tcp));
    assert!(r.close);
    let m = parse(&r);
    assert_eq!(m.metadata.id, 9);
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    // On-net and loopback clients go on.
    assert!(matches!(
        h.front(&q, addr(ON_NET), ClientTransport::Udp),
        Front::Resolve(_)
    ));
    assert!(matches!(
        h.front(&q, addr("127.0.0.1:5000"), ClientTransport::Udp),
        Front::Resolve(_)
    ));
}

#[test]
fn acl_update_applies_at_once() {
    let h = handler();
    let q = query(1, "example.com.", RecordType::A, None);
    h.set_acl(Acl::build(
        false,
        &[],
        &[Cidr::parse("198.51.100.0/24").unwrap()],
    ));
    assert!(matches!(
        h.front(&q, addr(OFF_NET), ClientTransport::Udp),
        Front::Resolve(_)
    ));
    assert!(matches!(
        h.front(&q, addr(ON_NET), ClientTransport::Udp),
        Front::Drop
    ));
}

#[test]
fn rate_limit_drops_udp_and_refuses_tcp() {
    let settings = HandlerSettings {
        rate_queries: 2,
        rate_interval_seconds: 3600,
        ..HandlerSettings::default()
    };
    let h = Handler::new(
        &settings,
        lan_acl(),
        Arc::new(AllowAll),
        Arc::new(NoopObserver),
        Clock::new(),
    );
    let q = query(3, "example.com.", RecordType::A, None);
    assert!(matches!(
        h.front(&q, addr(ON_NET), ClientTransport::Udp),
        Front::Resolve(_)
    ));
    assert!(matches!(
        h.front(&q, addr(ON_NET), ClientTransport::Udp),
        Front::Resolve(_)
    ));
    assert!(matches!(
        h.front(&q, addr(ON_NET), ClientTransport::Udp),
        Front::Drop
    ));
    let r = reply(h.front(&q, addr(ON_NET), ClientTransport::Tcp));
    assert_eq!(parse(&r).metadata.response_code, ResponseCode::Refused);
    // Another client has its own bucket.
    assert!(matches!(
        h.front(&q, addr("192.0.2.78:1"), ClientTransport::Udp),
        Front::Resolve(_)
    ));
}

#[test]
fn opcode_and_malformed_requests() {
    let h = handler();
    let mut notify = query(5, "example.com.", RecordType::A, None);
    notify[2] = (notify[2] & 0x87) | (4 << 3);
    let m = parse(&reply(h.front(&notify, addr(ON_NET), ClientTransport::Udp)));
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    assert_eq!(m.metadata.id, 5);
    assert_eq!(m.metadata.op_code, OpCode::Notify);

    let mut cut = query(6, "example.com.", RecordType::A, None);
    cut.truncate(cut.len() - 3);
    let m = parse(&reply(h.front(&cut, addr(ON_NET), ClientTransport::Udp)));
    assert_eq!(m.metadata.response_code, ResponseCode::FormErr);
    assert_eq!(m.metadata.id, 6);

    let mut two = Message::new(7, MessageType::Query, OpCode::Query);
    two.add_query(Query::query(
        Name::from_ascii("a.example.").unwrap(),
        RecordType::A,
    ));
    two.add_query(Query::query(
        Name::from_ascii("b.example.").unwrap(),
        RecordType::A,
    ));
    let m = parse(&reply(h.front(
        &two.to_vec().unwrap(),
        addr(ON_NET),
        ClientTransport::Udp,
    )));
    assert_eq!(m.metadata.response_code, ResponseCode::FormErr);

    let axfr = query(8, "example.com.", RecordType::AXFR, None);
    let m = parse(&reply(h.front(&axfr, addr(ON_NET), ClientTransport::Tcp)));
    assert_eq!(m.metadata.response_code, ResponseCode::NotImp);
}

#[test]
fn upstream_answer_is_cached_and_served_with_client_id() {
    let h = handler();
    let p = pending(h.front(
        &query(100, "WWW.Example.com.", RecordType::A, None),
        addr(ON_NET),
        ClientTransport::Udp,
    ));
    let r = h.complete(
        &p,
        Ok(upstream_answer(
            &p,
            vec![a_record("www.example.com.", 300, 1)],
        )),
    );
    let m = parse(&r);
    assert_eq!(m.metadata.id, 100);
    assert!(m.metadata.recursion_available);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(h.cache_len(), 1);

    // The second query (other ID, other case) is a cache hit.
    let r = reply(h.front(
        &query(101, "www.example.COM.", RecordType::A, None),
        addr(ON_NET),
        ClientTransport::Udp,
    ));
    let m = parse(&r);
    assert_eq!(m.metadata.id, 101);
    assert_eq!(m.queries[0].name().to_ascii(), "www.example.COM.");
    assert_eq!(m.answers.len(), 1);
    assert!(m.answers[0].ttl <= 300);

    // The DO bit is part of the key: a DO query is a miss.
    assert!(matches!(
        h.front(
            &query(102, "www.example.com.", RecordType::A, Some((1232, true))),
            addr(ON_NET),
            ClientTransport::Udp,
        ),
        Front::Resolve(_)
    ));
}

/// m3: an answer from a fallback server stays in the cache for at most
/// `FALLBACK_MAX_TTL` seconds, also with a long upstream TTL. An answer from another server
/// keeps its TTL.
#[test]
fn fallback_answers_get_a_short_ttl() {
    let h = handler();
    for (i, (name, fallback, want)) in [
        ("fb.example.", true, FALLBACK_MAX_TTL),
        ("enc.example.", false, 86_400),
    ]
    .into_iter()
    .enumerate()
    {
        let id = 300 + u16::try_from(i).unwrap() * 2;
        let q = query(id, name, RecordType::A, None);
        let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
        let mut ans = upstream_answer(&p, vec![a_record(name, 86_400, 1)]);
        ans.fallback = fallback;
        let m = parse(&h.complete(&p, Ok(ans)));
        assert_eq!(m.answers[0].ttl, want, "{name}");
        // The cache hit has the same limit.
        let q = query(id + 1, name, RecordType::A, None);
        let m = parse(&reply(h.front(&q, addr(ON_NET), ClientTransport::Udp)));
        assert!(
            m.answers[0].ttl <= want && m.answers[0].ttl + 1 >= want,
            "{name}"
        );
    }
    // A negative answer from a fallback server: the SOA TTL is capped too.
    let q = query(310, "nx.example.", RecordType::A, None);
    let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
    let mut ans = upstream_answer(&p, vec![]);
    ans.message.metadata.response_code = ResponseCode::NXDomain;
    ans.message.authorities.push(Record::from_rdata(
        Name::from_ascii("example.").unwrap(),
        3600,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.example.").unwrap(),
            Name::from_ascii("host.example.").unwrap(),
            1,
            3600,
            600,
            86_400,
            3600,
        )),
    ));
    ans.fallback = true;
    let m = parse(&h.complete(&p, Ok(ans)));
    assert!(m.authorities.iter().all(|r| r.ttl <= FALLBACK_MAX_TTL));
}

#[test]
fn fallback_policy_caps_each_limit() {
    let p = TtlPolicy {
        min_ttl: 600,
        max_ttl: 86_400,
        negative_ttl: 300,
    };
    let f = fallback_policy(&p);
    assert_eq!(
        (f.min_ttl, f.max_ttl, f.negative_ttl),
        (FALLBACK_MAX_TTL, FALLBACK_MAX_TTL, FALLBACK_MAX_TTL)
    );
    let small = TtlPolicy {
        min_ttl: 0,
        max_ttl: 10,
        negative_ttl: 5,
    };
    assert_eq!(fallback_policy(&small), small);
}

#[test]
fn servfail_and_errors_are_not_cached() {
    let h = handler();
    let q = query(1, "example.com.", RecordType::A, None);
    let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
    let mut ans = upstream_answer(&p, vec![]);
    ans.message.metadata.response_code = ResponseCode::ServFail;
    let m = parse(&h.complete(&p, Ok(ans)));
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(h.cache_len(), 0);

    let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
    let m = parse(&h.complete(&p, Err(UpstreamError::Timeout)));
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(m.metadata.id, 1);
    assert_eq!(h.cache_len(), 0);
}

#[test]
fn negative_answer_is_cached() {
    let h = handler();
    let q = query(1, "nope.example.", RecordType::A, None);
    let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
    let mut ans = upstream_answer(&p, vec![]);
    ans.message.metadata.response_code = ResponseCode::NXDomain;
    let m = parse(&h.complete(&p, Ok(ans)));
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    let m = parse(&reply(h.front(&q, addr(ON_NET), ClientTransport::Udp)));
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
}

#[test]
fn ad_bit_passes_only_with_do() {
    let h = handler();
    for (dnssec_ok, expect) in [(false, false), (true, true)] {
        let q = query(1, "signed.example.", RecordType::A, Some((1232, dnssec_ok)));
        let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
        let mut ans = upstream_answer(&p, vec![a_record("signed.example.", 60, 3)]);
        ans.message.metadata.authentic_data = true;
        let m = parse(&h.complete(&p, Ok(ans)));
        assert_eq!(m.metadata.authentic_data, expect);
        assert_eq!(m.edns.as_ref().unwrap().flags().dnssec_ok, dnssec_ok);
    }
}

#[test]
fn big_answer_is_truncated_for_udp_but_not_tcp() {
    let h = handler();
    let records: Vec<Record> = (0..80).map(|i| a_record("big.example.", 60, i)).collect();
    let q = query(1, "big.example.", RecordType::A, None);
    let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
    let r = h.complete(&p, Ok(upstream_answer(&p, records)));
    assert!(r.bytes.len() <= 512);
    let m = parse(&r);
    assert!(m.metadata.truncation);
    assert_eq!(m.answers.len(), 0);
    // TCP gets the full answer from the cache.
    let r = reply(h.front(&q, addr(ON_NET), ClientTransport::Tcp));
    let m = parse(&r);
    assert!(!m.metadata.truncation);
    assert_eq!(m.answers.len(), 80);
    // EDNS 1232 fits more than 512.
    let q = query(2, "big.example.", RecordType::A, Some((4096, false)));
    let r = reply(h.front(&q, addr(ON_NET), ClientTransport::Udp));
    assert!(r.bytes.len() <= 1232);
}

#[test]
fn answer_above_the_cache_size_limit_is_served_but_not_cached() {
    let h = handler();
    // About 16 bytes for each compressed A record: 400 records are more than 4 KiB.
    let records: Vec<Record> = (0..400)
        .map(|i| a_record("huge.example.", 60, u8::try_from(i % 250).unwrap()))
        .collect();
    let q = query(1, "huge.example.", RecordType::A, None);
    let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Tcp));
    let r = h.complete(&p, Ok(upstream_answer(&p, records)));
    assert!(r.bytes.len() > wire::MAX_CACHEABLE_BYTES);
    let m = parse(&r);
    assert_eq!(m.answers.len(), 400);
    assert_eq!(h.cache_len(), 0);
    // The next query goes to the upstream again.
    assert!(matches!(
        h.front(&q, addr(ON_NET), ClientTransport::Tcp),
        Front::Resolve(_)
    ));
}

/// Blocks `ads.example` on query and `tracker.example.net` in answers, when `on` is set.
#[derive(Debug, Default)]
struct TestFilter {
    on: AtomicBool,
}

impl QueryFilter for TestFilter {
    fn on_query(&self, ctx: &QueryContext) -> FilterVerdict {
        if self.on.load(Ordering::SeqCst) && ctx.qname == "ads.example" {
            return FilterVerdict::Block(BlockReply {
                kind: BlockKind::Null,
                ttl: 2,
            });
        }
        FilterVerdict::Allow
    }

    fn on_answer(&self, _ctx: &QueryContext, names: &[DomainName]) -> FilterVerdict {
        if self.on.load(Ordering::SeqCst)
            && names.iter().any(|n| n.as_str() == "tracker.example.net")
        {
            return FilterVerdict::Block(BlockReply {
                kind: BlockKind::Nxdomain,
                ttl: 2,
            });
        }
        FilterVerdict::Allow
    }
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

#[test]
fn filter_blocks_on_query_and_on_answer_and_cache_stays_unfiltered() {
    let filter = Arc::new(TestFilter::default());
    filter.on.store(true, Ordering::SeqCst);
    let rec = Arc::new(Recorder::default());
    let h = handler_with(filter.clone(), rec.clone());

    let m = parse(&reply(h.front(
        &query(1, "ADS.example.", RecordType::A, None),
        addr(ON_NET),
        ClientTransport::Udp,
    )));
    assert_eq!(m.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

    let q = query(2, "www.example.com.", RecordType::A, None);
    let p = pending(h.front(&q, addr(ON_NET), ClientTransport::Udp));
    let cname = Record::from_rdata(
        Name::from_ascii("www.example.com.").unwrap(),
        300,
        RData::CNAME(CNAME(Name::from_ascii("tracker.example.net.").unwrap())),
    );
    let ans = upstream_answer(&p, vec![cname, a_record("tracker.example.net.", 300, 9)]);
    let m = parse(&h.complete(&p, Ok(ans)));
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);

    // The cache holds the unfiltered answer: with the filter off, the hit is the answer.
    filter.on.store(false, Ordering::SeqCst);
    let m = parse(&reply(h.front(&q, addr(ON_NET), ClientTransport::Udp)));
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(m.answers.len(), 2);

    let events = rec.events.lock();
    let kinds: Vec<(Verdict, AnswerSource)> =
        events.iter().map(|e| (e.verdict, e.source)).collect();
    assert_eq!(
        kinds,
        vec![
            (Verdict::BlockedQuery, AnswerSource::Filter),
            (Verdict::BlockedAnswer, AnswerSource::Upstream),
            (Verdict::Allowed, AnswerSource::Cache),
        ]
    );
    assert_eq!(events[0].qname, "ads.example");
    assert_eq!(events[1].upstream, Some(addr("192.0.2.53:53")));
    assert_eq!(events[1].rcode, 3);
    assert_eq!(events[2].client, addr(ON_NET).ip());
}
