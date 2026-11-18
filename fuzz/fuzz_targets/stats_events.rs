#![no_main]
//! Fuzz the statistics aggregate with any event sequence and any `now` (also far in the past
//! or the future, and going back). The invariants:
//!
//! - The keys stay in the bound, and the key count is correct.
//! - No event is lost without a count: events in RAM + evicted events + events taken by a
//!   flush (and not put back) = all events.
//! - The hour histogram and the groups add up to the totals in RAM.
//! - A page never has more items than its limit; any cursor text gives no panic.

use libfuzzer_sys::fuzz_target;
use rusthole_core::stats::agg::{Aggregator, HourBucket, Snapshot};
use rusthole_core::stats::page::decode;
use rusthole_core::stats::query::{
    Filter, GroupParams, Range, RangeSpec, domain_groups, hours, timeline, totals,
};
use rusthole_core::stats::{StatsEvent, Status};

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn u32(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 8) | u32::from(self.byte()?);
        }
        Some(v)
    }

    fn i64(&mut self) -> Option<i64> {
        let hi = u64::from(self.u32()?);
        let lo = u64::from(self.u32()?);
        Some(((hi << 32) | lo) as i64)
    }

    fn text(&mut self) -> Option<String> {
        let n = usize::from(self.byte()? % 64);
        let mut s = Vec::with_capacity(n);
        for _ in 0..n {
            s.push(self.byte()?);
        }
        Some(String::from_utf8_lossy(&s).into_owned())
    }
}

const NAMES: [&str; 8] = [
    "www.example.com",
    "cdn.example.com",
    "a.b.example.co.uk",
    "co.uk",
    "localhost",
    "10.2.0.192.in-addr.arpa",
    "ads.example.net",
    ".",
];

const STATUSES: [Status; 6] = Status::ALL;

fn all() -> Filter {
    Filter::hours(i64::MIN / 4, i64::MAX / 4)
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(max) = input.byte() else {
        return;
    };
    let mut agg = Aggregator::new(usize::from(max) * 4);
    let mut applied = 0u64;
    let mut taken_out = 0u64;
    let mut held: Option<Snapshot> = None;
    // A base time; events move around it, and some use any i64.
    let mut base: i64 = 1_794_873_600;
    for _ in 0..2000 {
        let Some(op) = input.byte() else {
            break;
        };
        match op % 8 {
            0..=3 => {
                let (Some(c), Some(n), Some(s), Some(dt)) =
                    (input.byte(), input.byte(), input.byte(), input.u32())
                else {
                    break;
                };
                let at = if op & 0x80 != 0 {
                    match input.i64() {
                        Some(v) => v,
                        None => break,
                    }
                } else {
                    base.saturating_add(i64::from(dt % 200_000)).saturating_sub(100_000)
                };
                let status = STATUSES[usize::from(s) % STATUSES.len()];
                let name = if n & 0x80 != 0 {
                    format!("n{}.example.org", n & 0x3f)
                } else {
                    NAMES[usize::from(n) % NAMES.len()].to_owned()
                };
                agg.apply(&StatsEvent {
                    at,
                    client: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, c % 16)),
                    name,
                    qtype: u16::from(s),
                    status,
                    reason: (status == Status::Blocked).then(|| format!("list:{}", c % 4)),
                    upstream: (status == Status::Forwarded).then(|| format!("192.0.2.{}:53", c % 3)),
                    duration_us: u64::from(dt),
                });
                applied += 1;
            }
            4 => {
                // A flush takes the data; it may fail later and put it back.
                let snap = agg.take();
                taken_out += snap.total_events();
                if let Some(old) = held.replace(snap) {
                    // The old snapshot was written (the flush succeeded).
                    drop(old);
                }
            }
            5 => {
                if let Some(snap) = held.take() {
                    taken_out -= snap.total_events();
                    agg.restore(snap);
                }
            }
            6 => {
                let Some(h) = input.i64() else {
                    break;
                };
                agg.evict_before(h / 3600);
                if let Some(b) = input.u32() {
                    base = base.saturating_add(i64::from(b) - i64::from(u32::MAX / 2));
                }
            }
            _ => {
                let (Some(limit), Some(offset), Some(text)) =
                    (input.byte(), input.u32(), input.text())
                else {
                    break;
                };
                let pairs = agg.pairs(&all());
                let h = hours(&agg.hour_counts(&all()), offset as i32);
                let t = totals(&pairs);
                assert_eq!(h.queries.iter().sum::<u64>(), t.total);
                assert_eq!(h.blocked.iter().sum::<u64>(), t.blocked);
                assert_eq!(h.utc_offset_minutes % 60, 0);
                let _ = decode(&text);
                let page = domain_groups(
                    &pairs,
                    &GroupParams {
                        limit: usize::from(limit),
                        names_limit: usize::from(limit),
                        cursor: (limit & 1 == 1).then(|| text.clone()),
                        ..GroupParams::default()
                    },
                );
                if let Ok(page) = page {
                    assert!(page.items.len() <= usize::from(limit).max(1));
                }
                let all_groups = domain_groups(
                    &pairs,
                    &GroupParams {
                        limit: 500,
                        names_limit: 200,
                        ..GroupParams::default()
                    },
                )
                .expect("no cursor, no error");
                if all_groups.next_cursor.is_none() {
                    let sum: u64 = all_groups.items.iter().map(|g| g.queries).sum();
                    assert_eq!(sum, t.total);
                }
                let spec = RangeSpec::new(Range::Day, base);
                let (a, b) = spec.ten_minutes();
                let tl = timeline(&spec, &agg.timeline(a, b), 600);
                assert_eq!(tl.queries.len(), 144);
            }
        }
        assert!(agg.keys() <= agg.max_keys());
        let recount: usize = agg.hours().values().map(HourBucket::keys).sum();
        assert_eq!(recount, agg.keys());
        assert_eq!(
            agg.total_events() + agg.evicted_events() + taken_out,
            applied,
            "an event was lost without a count"
        );
    }
});
