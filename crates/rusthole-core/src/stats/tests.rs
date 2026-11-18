//! Unit tests and property tests of the statistics core.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;

use super::agg::{Aggregator, MIN_MAX_KEYS};
use super::base::registrable;
use super::page::CursorError;
use super::policy::{
    effective_utc_offset, flush_due, hour_of_day, retention_cutoff_hour, retention_due, warn_due,
};
use super::query::{
    ClientListParams, ClientMeta, Clients, DomainSearchParams, Filter, GroupParams, NameFilter,
    Range, RangeSpec, Sort, domain_groups, domain_search, hours, query_types, summary, timeline,
    top_clients, top_domains, upstream_share,
};
use super::{Counts, HOUR_SECONDS, StatsEvent, Status, hour_of, ten_minutes_of};

/// 2026-11-17T00:00:00Z.
const DAY0: i64 = 1_794_873_600;

const NAMES: [&str; 12] = [
    "www.example.com",
    "cdn.example.com",
    "example.com",
    "a.b.example.co.uk",
    "example.co.uk",
    "ads.example.net",
    "t.ads.example.net",
    "printer.home.lan",
    "localhost",
    "co.uk",
    "10.2.0.192.in-addr.arpa",
    "x.example.org",
];

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
}

fn ev(at: i64, client: u8, name: &str, status: Status) -> StatsEvent {
    StatsEvent {
        at,
        client: ip(client),
        name: name.to_owned(),
        qtype: 1,
        status,
        reason: (status == Status::Blocked).then(|| "list:1".to_owned()),
        upstream: (status == Status::Forwarded).then(|| "192.0.2.53:53".to_owned()),
        duration_us: 1500,
    }
}

fn status_strategy() -> impl Strategy<Value = Status> {
    prop_oneof![
        Just(Status::Forwarded),
        Just(Status::Cached),
        Just(Status::Blocked),
        Just(Status::Local),
        Just(Status::Refused),
        Just(Status::Error),
    ]
}

/// Events in a window of `window` seconds from `DAY0`.
fn events_strategy(window: i64, max: usize) -> impl Strategy<Value = Vec<StatsEvent>> {
    prop::collection::vec(
        (
            0..window,
            0u8..6,
            0usize..NAMES.len(),
            status_strategy(),
            prop::sample::select(vec![1u16, 28, 65, 12, 65280]),
        ),
        0..max,
    )
    .prop_map(|v| {
        v.into_iter()
            .map(|(dt, c, n, st, qt)| {
                let mut e = ev(DAY0 + dt, c, NAMES[n], st);
                e.qtype = qt;
                e
            })
            .collect()
    })
}

fn all_hours() -> Filter {
    Filter::hours(i64::MIN / 2, i64::MAX / 2)
}

fn clients_none() -> Clients {
    Clients::default()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).map_or(200, |env: u32| env.max(200))
    ))]

    /// The totals equal the number of events: overall, per client, per name and blocked.
    #[test]
    fn totals_equal_the_events(events in events_strategy(3 * 86_400, 300)) {
        let mut agg = Aggregator::new(1_000_000);
        for e in &events {
            agg.apply(e);
        }
        prop_assert_eq!(agg.total_events(), events.len() as u64);
        prop_assert_eq!(agg.evicted_events(), 0);
        let pairs = agg.pairs(&all_hours());

        let mut want_client: HashMap<IpAddr, u64> = HashMap::new();
        let mut want_name: HashMap<&str, (u64, u64)> = HashMap::new();
        let mut want = Counts::default();
        for e in &events {
            *want_client.entry(e.client).or_default() += 1;
            let n = want_name.entry(e.name.as_str()).or_default();
            n.0 += 1;
            n.1 += u64::from(e.status == Status::Blocked);
            want.add_status(e.status);
        }
        let mut got_client: HashMap<IpAddr, u64> = HashMap::new();
        let mut got_name: HashMap<&str, (u64, u64)> = HashMap::new();
        for (k, t) in &pairs {
            *got_client.entry(k.client).or_default() += t.counts.total;
            let n = got_name.entry(&*k.name).or_default();
            n.0 += t.counts.total;
            n.1 += t.counts.blocked;
        }
        prop_assert_eq!(got_client, want_client);
        prop_assert_eq!(got_name, want_name);
        let s = summary(&pairs, &clients_none());
        prop_assert_eq!(s.counts, want);

        // Types and the timeline count each event once (the timeline keeps about a day).
        let types: u64 = agg.types(i64::MIN / 2, i64::MAX / 2).values().sum();
        prop_assert_eq!(types, events.len() as u64);
        let up = agg.upstreams(i64::MIN / 2, i64::MAX / 2);
        let up_count: u64 = up.values().map(|t| t.count).sum();
        prop_assert_eq!(up_count, want.forwarded);
        let reasons: u64 = agg.reasons(i64::MIN / 2, i64::MAX / 2).values().sum();
        prop_assert_eq!(reasons, want.blocked);
    }

    /// Hour histograms add up to the totals, for each offset, also with filters.
    #[test]
    fn hour_histograms_sum_to_totals(
        events in events_strategy(3 * 86_400, 200),
        offset in -900i32..900,
        client in 0u8..6,
    ) {
        let mut agg = Aggregator::new(1_000_000);
        for e in &events {
            agg.apply(e);
        }
        let h = hours(&agg.hour_counts(&all_hours()), offset);
        prop_assert_eq!(h.queries.iter().sum::<u64>(), events.len() as u64);
        let blocked = events.iter().filter(|e| e.status == Status::Blocked).count() as u64;
        prop_assert_eq!(h.blocked.iter().sum::<u64>(), blocked);
        prop_assert_eq!(h.utc_offset_minutes % 60, 0);

        let mut f = all_hours();
        f.clients = Some([ip(client)].into_iter().collect());
        f.name = Some(NameFilter::Base("example.com".to_owned()));
        let h = hours(&agg.hour_counts(&f), offset);
        let want = events
            .iter()
            .filter(|e| e.client == ip(client) && registrable(&e.name) == "example.com")
            .count() as u64;
        prop_assert_eq!(h.queries.iter().sum::<u64>(), want);
    }

    /// The 24 h timeline counts each event of the last 24 h once.
    #[test]
    fn timeline_counts_each_event(events in events_strategy(86_400, 200)) {
        let mut agg = Aggregator::new(1_000_000);
        for e in &events {
            agg.apply(e);
        }
        let now = DAY0 + 86_399;
        let spec = RangeSpec::new(Range::Day, now);
        let (from, to) = spec.ten_minutes();
        let t = timeline(&spec, &agg.timeline(from, to), 600);
        let want = events.iter().filter(|e| e.at >= spec.from && e.at < spec.to).count() as u64;
        prop_assert_eq!(t.queries.iter().sum::<u64>(), want);
        prop_assert_eq!(t.queries.len(), 144);

        let spec = RangeSpec::new(Range::Week, now);
        let (hf, ht) = spec.hours();
        let t = timeline(&spec, &agg.hour_counts(&Filter::hours(hf, ht)), HOUR_SECONDS);
        prop_assert_eq!(t.queries.iter().sum::<u64>(), events.len() as u64);
        prop_assert_eq!(t.queries.len(), 168);
    }

    /// Each full name is under exactly one registrable domain: its own base.
    #[test]
    fn grouping_puts_each_name_in_one_group(events in events_strategy(86_400, 200)) {
        let mut agg = Aggregator::new(1_000_000);
        for e in &events {
            agg.apply(e);
        }
        let pairs = agg.pairs(&all_hours());
        let page = domain_groups(&pairs, &GroupParams {
            names_limit: 200,
            limit: 500,
            ..GroupParams::default()
        }).unwrap();
        prop_assert!(page.next_cursor.is_none());
        let mut seen: HashSet<String> = HashSet::new();
        let mut total = 0;
        for g in &page.items {
            prop_assert_eq!(g.names_total, g.names.len());
            prop_assert_eq!(g.queries, g.names.iter().map(|n| n.queries).sum::<u64>());
            total += g.queries;
            for n in &g.names {
                prop_assert_eq!(registrable(&n.name), g.base.as_str());
                prop_assert!(seen.insert(n.name.clone()), "name in two groups: {}", n.name);
            }
        }
        let want: HashSet<String> = events.iter().map(|e| e.name.clone()).collect();
        prop_assert_eq!(seen, want);
        prop_assert_eq!(total, events.len() as u64);
    }

    /// Paging never splits a group and never loses or repeats a group, for each sort.
    #[test]
    fn paging_never_splits_loses_or_repeats(
        events in events_strategy(86_400, 300),
        limit in 1usize..5,
        sort in prop::sample::select(vec![Sort::Queries, Sort::Blocked, Sort::LastSeen, Sort::Name]),
        blocked_only in any::<bool>(),
    ) {
        let mut agg = Aggregator::new(1_000_000);
        for e in &events {
            agg.apply(e);
        }
        let pairs = agg.pairs(&all_hours());
        let base = GroupParams { sort, names_limit: 200, blocked_only, limit: 500, ..GroupParams::default() };
        let all = domain_groups(&pairs, &base).unwrap().items;
        let mut paged = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..=all.len() + 1 {
            let page = domain_groups(&pairs, &GroupParams { cursor: cursor.clone(), limit, ..base.clone() }).unwrap();
            prop_assert!(page.items.len() <= limit);
            paged.extend(page.items);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        prop_assert!(cursor.is_none(), "paging did not end");
        // Same groups in the same order, each group whole.
        prop_assert_eq!(&paged, &all);
        let bases: BTreeSet<&str> = paged.iter().map(|g| g.base.as_str()).collect();
        prop_assert_eq!(bases.len(), paged.len());

        // The same for the client list and the domain search.
        let p = ClientListParams { sort, limit: 500, ..ClientListParams::default() };
        let all = super::query::client_list(&pairs, &clients_none(), &p).unwrap().items;
        let mut paged = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..=all.len() + 1 {
            let page = super::query::client_list(&pairs, &clients_none(), &ClientListParams { cursor: cursor.clone(), limit, ..p.clone() }).unwrap();
            paged.extend(page.items);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        prop_assert_eq!(paged, all);

        let p = DomainSearchParams { q: "example".to_owned(), blocked_only, limit: 500, ..DomainSearchParams::default() };
        let all = domain_search(&pairs, &clients_none(), &p).unwrap().items;
        let mut paged = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..=all.len() + 1 {
            let page = domain_search(&pairs, &clients_none(), &DomainSearchParams { cursor: cursor.clone(), limit, ..p.clone() }).unwrap();
            paged.extend(page.items);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        prop_assert_eq!(paged, all);
    }

    /// With a small key bound, the keys stay in the bound and no event is lost without a
    /// count: the events in RAM plus the evicted events equal all events.
    #[test]
    fn key_bound_holds_and_evictions_are_counted(
        events in events_strategy(5 * 86_400, 400),
        max_keys in 0usize..200,
    ) {
        let mut agg = Aggregator::new(max_keys);
        for e in &events {
            agg.apply(e);
            prop_assert!(agg.keys() <= agg.max_keys());
            let recount: usize = agg.hours().values().map(super::agg::HourBucket::keys).sum();
            prop_assert_eq!(recount, agg.keys());
        }
        prop_assert!(agg.max_keys() >= MIN_MAX_KEYS);
        prop_assert_eq!(agg.total_events() + agg.evicted_events(), events.len() as u64);
    }

    /// A failed flush puts the data back: take then restore gives the same state.
    #[test]
    fn take_then_restore_keeps_all_data(
        first in events_strategy(2 * 86_400, 100),
        second in events_strategy(2 * 86_400, 100),
    ) {
        let mut agg = Aggregator::new(1_000_000);
        let mut want = Aggregator::new(1_000_000);
        for e in &first {
            agg.apply(e);
            want.apply(e);
        }
        let snap = agg.take();
        prop_assert_eq!(agg.keys(), 0);
        prop_assert_eq!(snap.total_events(), first.len() as u64);
        for e in &second {
            agg.apply(e);
            want.apply(e);
        }
        agg.restore(snap);
        prop_assert_eq!(agg.keys(), want.keys());
        prop_assert_eq!(agg.hours(), want.hours());
        prop_assert_eq!(agg.timeline(i64::MIN / 2, i64::MAX / 2), want.timeline(i64::MIN / 2, i64::MAX / 2));
    }

    /// Any time (also far in the past or future) gives no panic and a valid hour of day.
    #[test]
    fn any_time_is_safe(at in any::<i64>(), offset in any::<i32>()) {
        let mut agg = Aggregator::new(100);
        agg.apply(&ev(at, 1, "www.example.com", Status::Cached));
        prop_assert_eq!(agg.total_events(), 1);
        let h = hours(&agg.hour_counts(&all_hours()), offset);
        prop_assert!(hour_of_day(hour_of(at), effective_utc_offset(offset)) < 24);
        let _ = h;
        let spec = RangeSpec::new(Range::Month, at);
        prop_assert!(spec.from <= spec.to);
        let _ = ten_minutes_of(at);
    }
}

#[test]
fn utc_offset_rounds_down_to_whole_hours() {
    assert_eq!(effective_utc_offset(330), 300); // +5:30 -> +5
    assert_eq!(effective_utc_offset(-210), -240); // -3:30 -> -4
    assert_eq!(effective_utc_offset(120), 120);
    assert_eq!(effective_utc_offset(0), 0);
    assert_eq!(effective_utc_offset(59), 0);
    assert_eq!(effective_utc_offset(-1), -60);
    assert_eq!(effective_utc_offset(840), 840);
    assert_eq!(effective_utc_offset(-840), -840);
    assert_eq!(effective_utc_offset(900), 840);
    assert_eq!(effective_utc_offset(-900), -840);
    assert_eq!(effective_utc_offset(i32::MIN), -840);
}

#[test]
fn hour_histogram_moves_by_the_offset() {
    let mut agg = Aggregator::new(1000);
    // 23:30 UTC.
    agg.apply(&ev(
        DAY0 + 23 * 3600 + 1800,
        1,
        "www.example.com",
        Status::Blocked,
    ));
    let map = agg.hour_counts(&all_hours());
    let h = hours(&map, 330);
    assert_eq!(h.utc_offset_minutes, 300);
    assert_eq!(h.queries[4], 1); // 23 + 5 = 28 = 4 next day
    assert_eq!(h.blocked[4], 1);
    let h = hours(&map, -210);
    assert_eq!(h.utc_offset_minutes, -240);
    assert_eq!(h.queries[19], 1); // 23 - 4
    let h = hours(&map, 0);
    assert_eq!(h.queries[23], 1);
}

#[test]
fn range_spec_is_aligned() {
    let now = DAY0 + 8 * 3600 + 40 * 60 + 17; // 08:40:17
    let d = RangeSpec::new(Range::Day, now);
    assert_eq!(d.to, DAY0 + 8 * 3600 + 50 * 60);
    assert_eq!(d.from, d.to - 144 * 600);
    assert_eq!(d.bucket_seconds, 600);
    let w = RangeSpec::new(Range::Week, now);
    assert_eq!(w.to, DAY0 + 9 * 3600);
    assert_eq!(w.from, w.to - 168 * 3600);
    let m = RangeSpec::new(Range::Month, now);
    assert_eq!(m.to % 14_400, 0);
    assert_eq!(m.to, DAY0 + 12 * 3600);
    assert_eq!(m.from, m.to - 180 * 14_400);
    // 24 h: the first full hour after `from` (09:00 the day before) to the current hour.
    assert_eq!(d.hours(), (hour_of(d.from) + 1, hour_of(now)));
    assert_eq!(w.hours(), (hour_of(w.from), hour_of(now)));
    assert_eq!(m.hours(), (hour_of(m.from), hour_of(m.to - 1)));
    assert_eq!(Range::parse("7d"), Some(Range::Week));
    assert_eq!(Range::parse("1y"), None);
}

/// For each `now` in one hour (60 s steps), the 24 h range has exactly 24 distinct hours,
/// and a histogram of one event in each stored hour has 1 in each of the 24 bars.
#[test]
fn day_range_has_exactly_24_hours() {
    for step in 0..60 {
        let now = DAY0 + 2 * 86_400 + 12 * 3600 + step * 60;
        let spec = RangeSpec::new(Range::Day, now);
        let (from, to) = spec.hours();
        assert_eq!(to - from + 1, 24, "now = {now}");
        assert_eq!(to, hour_of(now), "now = {now}");
        assert!(from * HOUR_SECONDS >= spec.from, "now = {now}");
        // One event in each hour of the last 3 days.
        let mut agg = Aggregator::new(1_000_000);
        for h in (hour_of(now) - 72)..=hour_of(now) {
            agg.apply(&ev(
                h * HOUR_SECONDS,
                1,
                "www.example.com",
                Status::Forwarded,
            ));
        }
        let h = hours(&agg.hour_counts(&spec.filter()), 0);
        assert_eq!(h.queries, [1; 24], "now = {now}");
    }
}

#[test]
fn flush_policy() {
    // RAM only: never.
    assert!(!flush_due(0, 1_000_000, 0, true));
    assert!(!flush_due(60_000, 59_999, 0, false));
    assert!(flush_due(60_000, 60_000, 0, false));
    // Near the bound: early, but not more often than the gap.
    assert!(!flush_due(60_000, 4_999, 0, true));
    assert!(flush_due(60_000, 5_000, 0, true));
    // A clock that goes back gives no flush storm.
    assert!(!flush_due(60_000, 0, 10_000, false));
}

#[test]
fn retention_policy() {
    assert!(retention_due(None, DAY0));
    assert!(!retention_due(Some(DAY0 / 86_400), DAY0 + 86_399));
    assert!(retention_due(Some(DAY0 / 86_400), DAY0 + 86_400));
    assert_eq!(retention_cutoff_hour(DAY0, 30), DAY0 / 3600 - 720);
    assert_eq!(retention_cutoff_hour(DAY0, 0), DAY0 / 3600 - 24);
    // No overflow at the edges.
    assert!(retention_cutoff_hour(i64::MIN, u32::MAX) < hour_of(i64::MIN));
    assert!(retention_cutoff_hour(i64::MAX, u32::MAX) < hour_of(i64::MAX));
}

#[test]
fn warn_policy() {
    assert!(warn_due(None, 0, 10_000));
    assert!(!warn_due(Some(5_000), 14_999, 10_000));
    assert!(warn_due(Some(5_000), 15_000, 10_000));
    assert!(!warn_due(Some(5_000), 1_000, 10_000));
}

#[test]
fn evict_before_drops_old_hours_and_counts_them() {
    let mut agg = Aggregator::new(1000);
    for h in 0..5 {
        agg.apply(&ev(DAY0 + h * 3600, 1, "www.example.com", Status::Cached));
        agg.apply(&ev(DAY0 + h * 3600, 2, "www.example.com", Status::Cached));
    }
    let n = agg.evict_before(hour_of(DAY0) + 3);
    assert_eq!(n, 3);
    assert_eq!(agg.evicted_buckets(), 3);
    assert_eq!(agg.evicted_events(), 6);
    assert_eq!(agg.total_events(), 4);
    assert_eq!(agg.hours().len(), 2);
    let tl: u64 = agg
        .timeline(i64::MIN / 2, i64::MAX / 2)
        .values()
        .map(|c| c.total)
        .sum();
    assert_eq!(tl, 4);
}

#[test]
fn domain_groups_follow_the_api_rules() {
    let mut agg = Aggregator::new(1000);
    for _ in 0..5 {
        agg.apply(&ev(DAY0 + 10, 1, "www.example.com", Status::Forwarded));
    }
    for _ in 0..3 {
        agg.apply(&ev(DAY0 + 20, 1, "cdn.example.com", Status::Cached));
    }
    agg.apply(&ev(DAY0 + 30, 1, "telemetry.example.com", Status::Blocked));
    agg.apply(&ev(DAY0 + 40, 1, "ads.example.net", Status::Blocked));
    agg.apply(&ev(DAY0 + 40, 1, "ads.example.net", Status::Blocked));
    let pairs = agg.pairs(&all_hours());

    let page = domain_groups(
        &pairs,
        &GroupParams {
            names_limit: 2,
            limit: 10,
            ..GroupParams::default()
        },
    )
    .unwrap();
    assert_eq!(page.items.len(), 2);
    let g = &page.items[0];
    assert_eq!(g.base, "example.com");
    assert_eq!((g.queries, g.blocked, g.names_total), (9, 1, 3));
    assert_eq!(g.names.len(), 2);
    assert_eq!(g.names[0].name, "www.example.com");
    assert_eq!(g.names[1].name, "cdn.example.com");
    assert_eq!((g.first_seen, g.last_seen), (DAY0 + 10, DAY0 + 30));

    // `q` on a name: only the matching names count.
    let page = domain_groups(
        &pairs,
        &GroupParams {
            q: Some("CDN".to_owned()),
            names_limit: 50,
            limit: 10,
            ..GroupParams::default()
        },
    )
    .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!((page.items[0].queries, page.items[0].names_total), (3, 1));

    // `q` on a base: all names of the group.
    let page = domain_groups(
        &pairs,
        &GroupParams {
            q: Some("example.com".to_owned()),
            names_limit: 50,
            limit: 10,
            ..GroupParams::default()
        },
    )
    .unwrap();
    assert_eq!(page.items[0].names_total, 3);

    // Blocked only, sorted by blocked.
    let page = domain_groups(
        &pairs,
        &GroupParams {
            blocked_only: true,
            sort: Sort::Blocked,
            names_limit: 50,
            limit: 10,
            ..GroupParams::default()
        },
    )
    .unwrap();
    let bases: Vec<&str> = page.items.iter().map(|g| g.base.as_str()).collect();
    assert_eq!(bases, vec!["example.net", "example.com"]);
    assert_eq!(page.items[1].names_total, 1);

    // A bad cursor is an error, not a panic.
    let bad = domain_groups(
        &pairs,
        &GroupParams {
            cursor: Some("garbage".to_owned()),
            ..GroupParams::default()
        },
    );
    assert_eq!(bad, Err(CursorError));
}

#[test]
fn top_lists_types_and_upstreams() {
    let mut agg = Aggregator::new(1000);
    for _ in 0..4 {
        agg.apply(&ev(DAY0, 1, "www.example.com", Status::Forwarded));
    }
    agg.apply(&ev(DAY0, 2, "www.example.com", Status::Cached));
    agg.apply(&ev(DAY0, 2, "ads.example.net", Status::Blocked));
    let mut aaaa = ev(DAY0, 2, "ads.example.net", Status::Blocked);
    aaaa.qtype = 28;
    agg.apply(&aaaa);
    let pairs = agg.pairs(&all_hours());

    let top = top_domains(&pairs, 10, false);
    assert_eq!(top.len(), 1);
    assert_eq!((top[0].name.as_str(), top[0].count), ("www.example.com", 5));
    let top = top_domains(&pairs, 10, true);
    assert_eq!(
        (top[0].name.as_str(), top[0].base.as_str(), top[0].count),
        ("ads.example.net", "example.net", 2)
    );

    let metas = vec![ClientMeta {
        ip: ip(1),
        mac: Some("02:00:00:00:00:01".to_owned()),
        name: Some("laptop".to_owned()),
        first_seen: DAY0 - 100,
        last_seen: DAY0,
    }];
    let clients = Clients::new(metas);
    let top = top_clients(&pairs, &clients, 10);
    assert_eq!(top[0].key, "02:00:00:00:00:01");
    assert_eq!(top[0].name.as_deref(), Some("laptop"));
    assert_eq!((top[0].count, top[0].blocked), (4, 0));
    assert_eq!(
        (top[1].key.as_str(), top[1].count, top[1].blocked),
        ("192.0.2.2", 3, 2)
    );

    let types = query_types(&agg.types(i64::MIN / 2, i64::MAX / 2));
    assert_eq!(types[0].name, "A");
    assert_eq!(types[0].count, 6);
    assert_eq!(types[1].name, "AAAA");

    let s = summary(&pairs, &clients);
    let share = upstream_share(&agg.upstreams(i64::MIN / 2, i64::MAX / 2), &s.counts);
    assert_eq!(share[0].name, "192.0.2.53:53");
    assert_eq!(share[0].count, 4);
    assert_eq!(share[0].avg_ms, Some(1.5));
    let kinds: Vec<(&str, u64)> = share.iter().map(|r| (r.kind.as_str(), r.count)).collect();
    assert_eq!(
        kinds,
        vec![("upstream", 4), ("cache", 1), ("blocked", 2), ("local", 0)]
    );
    assert!((s.blocked_percent - 28.57).abs() < 1e-9);
    assert_eq!(s.unique_clients, 2);
    assert_eq!(s.unique_domains, 2);
}

#[test]
fn client_keys_merge_addresses_with_one_mac() {
    let mac = Some("02:00:00:00:00:01".to_owned());
    let clients = Clients::new(vec![
        ClientMeta {
            ip: ip(10),
            mac: mac.clone(),
            name: None,
            first_seen: DAY0 - 50,
            last_seen: DAY0,
        },
        ClientMeta {
            ip: ip(110),
            mac,
            name: Some("laptop".to_owned()),
            first_seen: DAY0 - 10,
            last_seen: DAY0 + 5,
        },
    ]);
    let ips = clients.ips_of("02:00:00:00:00:01");
    assert_eq!(ips, [ip(10), ip(110)].into_iter().collect());
    assert_eq!(clients.ips_of("192.0.2.7"), [ip(7)].into_iter().collect());
    let mut agg = Aggregator::new(1000);
    agg.apply(&ev(DAY0, 10, "www.example.com", Status::Cached));
    agg.apply(&ev(DAY0 + 1, 110, "cdn.example.com", Status::Blocked));
    let pairs = agg.pairs(&all_hours());
    let row = super::query::client_detail(&pairs, &clients, "02:00:00:00:00:01");
    assert_eq!(row.counts.total, 2);
    assert_eq!(row.ips, vec![ip(10), ip(110)]);
    assert_eq!(row.ip, Some(ip(110)));
    assert_eq!(row.unique_domains, 2);
    assert_eq!(row.unique_bases, 1);
    assert_eq!(row.first_seen, Some(DAY0 - 50));
    assert_eq!(row.name.as_deref(), Some("laptop"));
    let none = super::query::client_detail(
        &BTreeMap::new().into_iter().collect(),
        &clients,
        "192.0.2.99",
    );
    assert_eq!(none.counts.total, 0);
    assert_eq!(none.ip, Some(ip(99)));
}

#[test]
fn domain_detail_lists_clients() {
    let mut agg = Aggregator::new(1000);
    for c in 1..=3u8 {
        for _ in 0..c {
            agg.apply(&ev(
                DAY0 + i64::from(c),
                c,
                "ads.example.net",
                Status::Blocked,
            ));
        }
    }
    agg.apply(&ev(DAY0, 1, "www.example.com", Status::Cached));
    let pairs = agg.pairs(&all_hours());
    let d = super::query::domain_detail(&pairs, &clients_none(), "ads.example.net", None);
    assert_eq!(d.counts.total, 6);
    assert_eq!(d.base, "example.net");
    assert_eq!(d.clients.len(), 3);
    assert_eq!(d.clients[0].ip, ip(3));
    assert_eq!(
        (d.first_seen, d.last_seen),
        (Some(DAY0 + 1), Some(DAY0 + 3))
    );
    let none = super::query::domain_detail(&pairs, &clients_none(), "nothing.example", None);
    assert_eq!(none.counts.total, 0);
    assert_eq!(none.clients.len(), 0);
    assert_eq!(none.first_seen, None);
    // The stored first query wins when it is earlier than the range.
    let d = super::query::domain_detail(&pairs, &clients_none(), "ads.example.net", Some(DAY0 - 5));
    assert_eq!(d.first_seen, Some(DAY0 - 5));
    let d = super::query::domain_detail(&pairs, &clients_none(), "ads.example.net", Some(DAY0 + 9));
    assert_eq!(d.first_seen, Some(DAY0 + 1));
}

#[test]
fn status_names_round_trip() {
    for s in Status::ALL {
        assert_eq!(Status::parse(s.as_str()), Some(s));
    }
    assert_eq!(Status::parse("other"), None);
    assert_eq!(super::qtype_name(65), "HTTPS");
    assert_eq!(super::qtype_name(65280), "TYPE65280");
}
