//! Memory bound of the DNS answer cache (review item M1).
//!
//! This test binary counts every heap byte with a counting allocator, so it has its own file
//! and one test only. It fills the cache through the real pipeline ([`Handler::front`] and
//! [`Handler::complete`]) with worst-case answers and checks that the heap bytes of the
//! cache stay below the byte budget.
// Test code: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::many_single_char_names
)]

use peak_alloc::PeakAlloc;

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

#[cfg(test)]
mod memory {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use rusthole_core::acl::Acl;
    use rusthole_core::net::Cidr;
    use rusthole_dns::{
        AllowAll, ClientTransport, Clock, Front, Handler, HandlerSettings, NoopObserver,
        UpstreamAnswer,
    };

    use super::ALLOC;

    /// The byte budget of the cache in this test.
    const BUDGET: usize = 4 * 1024 * 1024;

    fn handler(entries: usize) -> Handler {
        let settings = HandlerSettings {
            cache_entries: entries,
            cache_bytes: BUDGET,
            // No rate limit: one client sends all queries.
            rate_queries: 0,
            rate_max_clients: 16,
            ..HandlerSettings::default()
        };
        let acl = Acl::build(false, &[], &[Cidr::parse("192.0.2.0/24").unwrap()]);
        Handler::new(
            &settings,
            acl,
            Arc::new(AllowAll),
            Arc::new(NoopObserver),
            Clock::new(),
        )
    }

    fn client() -> SocketAddr {
        "192.0.2.7:5353".parse().unwrap()
    }

    /// Sends a query for `name` and gives the upstream answer `records` with TTL 86400.
    fn fill_one(h: &Handler, name: &Name, records: usize) {
        let mut q = Message::new(7, MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.add_query(Query::query(name.clone(), RecordType::A));
        let bytes = q.to_vec().unwrap();
        let Front::Resolve(p) = h.front(&bytes, client(), ClientTransport::Tcp) else {
            panic!("the query must go to the upstream");
        };
        let mut a = Message::new(9, MessageType::Response, OpCode::Query);
        a.metadata.recursion_available = true;
        a.add_query(Query::query(name.clone(), RecordType::A));
        for i in 0..records {
            let [_, _, x, y] = u32::try_from(i).unwrap().to_be_bytes();
            a.answers.push(Record::from_rdata(
                name.clone(),
                86_400,
                RData::A(A(Ipv4Addr::new(192, 0, x, y))),
            ));
        }
        let reply = h.complete(
            &p,
            Ok(UpstreamAnswer {
                message: a,
                upstream: "192.0.2.53:53".parse().unwrap(),
                fallback: false,
            }),
        );
        // More than the 12-byte header: the reply has the answer.
        assert!(reply.bytes.len() > 12);
    }

    /// The most A records for one answer that still encodes in 4096 bytes: the largest
    /// answer that the cache keeps, with the most parsed records.
    fn max_records(name: &Name) -> usize {
        let mut a = Message::new(9, MessageType::Response, OpCode::Query);
        a.add_query(Query::query(name.clone(), RecordType::A));
        let mut n = 0;
        loop {
            a.answers.push(Record::from_rdata(
                name.clone(),
                86_400,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            ));
            if a.to_vec().unwrap().len() > 4096 {
                return n;
            }
            n += 1;
        }
    }

    /// A long name (about 250 bytes on the wire) with bytes that the text form escapes as
    /// `\DDD`, so the cache key text is about 1000 bytes: the worst key.
    fn long_name(i: usize) -> Name {
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut first = format!("{i:08}").into_bytes();
        first.resize(62, 1);
        labels.push(first);
        for _ in 0..3 {
            labels.push(vec![1u8; 60]);
        }
        Name::from_labels(labels).unwrap()
    }

    /// Fills a fresh cache with `count` answers made by `make` and returns the largest heap
    /// growth after an answer, from before the handler was made.
    fn fill(entries: usize, count: usize, make: impl Fn(usize) -> (Name, usize)) -> usize {
        let base = ALLOC.current_usage();
        let h = handler(entries);
        let mut worst = 0;
        for i in 0..count {
            let (name, records) = make(i);
            fill_one(&h, &name, records);
            let used = ALLOC.current_usage().saturating_sub(base);
            worst = worst.max(used);
            assert!(
                used <= BUDGET + SLACK,
                "after {i} answers the handler uses {used} bytes; the budget is {BUDGET}"
            );
        }
        // The cache is full: the test checks the bound, not an empty cache.
        assert!(worst > BUDGET / 2, "{worst}");
        assert!(h.cache_bytes() <= BUDGET);
        worst
    }

    /// Heap bytes of the handler parts that are not the cache (rate limiter, ACL, filter):
    /// measured with the cache off.
    const SLACK: usize = 64 * 1024;

    #[test]
    fn worst_case_answers_stay_under_the_byte_budget() {
        // The parts that are not the cache must fit in SLACK.
        let base = ALLOC.current_usage();
        let off = handler(0);
        fill_one(&off, &Name::from_ascii("off.example.").unwrap(), 1);
        assert!(ALLOC.current_usage().saturating_sub(base) <= SLACK);
        drop(off);

        // Many small records near 4 KiB: the parsed form was about 17 times the wire form.
        let big = Name::from_ascii("n00000000.example.").unwrap();
        let records = max_records(&big);
        assert!(records > 150, "{records}");
        let worst = fill(10_000, 3_000, |i| {
            (
                Name::from_ascii(format!("n{i:08}.example.")).unwrap(),
                records,
            )
        });
        println!("big answers: worst {worst} bytes, budget {BUDGET}");

        // Tiny answers with the longest key: the fixed cost of each entry.
        let worst = fill(1_000_000, 12_000, |i| (long_name(i), 1));
        println!("long keys: worst {worst} bytes, budget {BUDGET}");
    }
}
