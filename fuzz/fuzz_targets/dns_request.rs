#![no_main]
//! Fuzz the DNS request pipeline with a fake upstream: the input holds a client query and
//! an upstream reply. Nothing may panic. Each reply has QR=1, the client ID, and a size
//! within the limit of the transport.
//!
//! Input layout: byte 0 = flags (bit 0: TCP, bit 1: off-net client, bit 2: no upstream
//! answer, bit 3: DoH; it wins over bit 0), bytes 1..3 = query length (big endian), then the query, then the upstream reply.

use std::net::SocketAddr;
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use rusthole_core::Config;
use rusthole_core::acl::Acl;
use rusthole_core::config::{ConditionalForward, LocalCname, LocalRecord, RecordType};
use rusthole_core::localdns::LocalZone;
use rusthole_core::net::Cidr;
use rusthole_dns::wire::{self, RawHeader};
use rusthole_dns::{
    AllowAll, ClientTransport, Clock, Front, Handler, HandlerSettings, NoopObserver, Reply,
    UpstreamAnswer, UpstreamError,
};

/// Local data for the fuzzer: a record, a CNAME and a conditional forward (part P3c), so
/// that the local answers and the forward route run too.
fn local_zone() -> Arc<LocalZone> {
    let mut cfg = Config::default();
    cfg.local_dns.records = vec![LocalRecord {
        id: None,
        enabled: true,
        comment: None,
        name: "nas.lan".to_owned(),
        record_type: RecordType::A,
        value: "192.0.2.10".to_owned(),
    }];
    cfg.local_dns.cnames = vec![LocalCname {
        id: None,
        enabled: true,
        comment: None,
        name: "media.lan".to_owned(),
        target: "nas.lan".to_owned(),
        ttl: None,
    }];
    cfg.local_dns.conditional_forwarding = vec![ConditionalForward {
        id: None,
        comment: None,
        enabled: true,
        cidr: "198.51.100.0/24".to_owned(),
        server: "192.0.2.1".to_owned(),
        domain: Some("corp".to_owned()),
    }];
    Arc::new(LocalZone::from_config(&cfg).0)
}

fn check(reply: &Reply, query: &[u8], max_len: usize) {
    assert!(reply.bytes.len() <= max_len, "reply too long");
    let h = RawHeader::parse(&reply.bytes).expect("a reply has a header");
    let q = RawHeader::parse(query).expect("only a query with a header gets a reply");
    assert!(h.qr, "a reply has QR=1");
    assert_eq!(h.id, q.id, "a reply has the client ID");
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let Some(len_bytes) = rest.get(..2) else {
        return;
    };
    let qlen = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    let rest = &rest[2..];
    let query = &rest[..qlen.min(rest.len())];
    let upstream = &rest[qlen.min(rest.len())..];

    let transport = if flags & 8 != 0 {
        ClientTransport::Https
    } else if flags & 1 != 0 {
        ClientTransport::Tcp
    } else {
        ClientTransport::Udp
    };
    let client: SocketAddr = if flags & 2 != 0 {
        "198.51.100.7:5353".parse().unwrap()
    } else {
        "192.0.2.7:5353".parse().unwrap()
    };
    let settings = HandlerSettings {
        cache_entries: 16,
        rate_max_clients: 16,
        ..HandlerSettings::default()
    };
    let acl = Acl::build(false, &[], &[Cidr::parse("192.0.2.0/24").unwrap()]);
    let handler = Handler::new(
        &settings,
        acl,
        Arc::new(AllowAll),
        Arc::new(NoopObserver),
        Clock::new(),
    )
    .with_local_zone(local_zone());
    // The size limit of a reply from `front`. A cache hit is a full answer, so its UDP limit
    // is the client EDNS size (512 without EDNS). 1232 is only for a header-only reply to a
    // query that does not parse.
    let front_max = match transport {
        ClientTransport::Udp => wire::parse_request(query)
            .map_or(usize::from(wire::MAX_UDP_PAYLOAD), |(req, _)| {
                req.max_udp_len()
            }),
        ClientTransport::Tcp | ClientTransport::Https => wire::MAX_TCP_MESSAGE,
    };

    // Two rounds: the second one can be a cache hit.
    for _ in 0..2 {
        match handler.front(query, client, transport) {
            Front::Drop => {}
            Front::Reply(r) => check(&r, query, front_max),
            Front::Resolve(p) => {
                let max_len = match transport {
                    ClientTransport::Udp => p.request().max_udp_len(),
                    ClientTransport::Tcp | ClientTransport::Https => wire::MAX_TCP_MESSAGE,
                };
                // The fake upstream uses its own ID, so the ID check passes and the
                // question check and the answer handling run.
                let outcome = match RawHeader::parse(upstream) {
                    Some(h) if flags & 4 == 0 => {
                        match wire::check_upstream_reply(upstream, h.id, &p.request().query) {
                            Ok(message) => Ok(UpstreamAnswer {
                                message,
                                upstream: "192.0.2.53:53".parse().unwrap(),
                            }),
                            Err(_) => Err(UpstreamError::BadReply),
                        }
                    }
                    _ => Err(UpstreamError::Timeout),
                };
                let r = handler.complete(&p, outcome);
                check(&r, query, max_len);
            }
        }
    }
});
