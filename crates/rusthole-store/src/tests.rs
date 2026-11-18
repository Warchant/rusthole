//! Tests of the store: flush and reload, the write counter, retention, migrations,
//! RAM-only mode, the audit log, the worker thread and its shutdown.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use proptest::prelude::*;
use rusthole_core::stats::StatsEvent;
use rusthole_core::stats::Status;
use rusthole_core::stats::page::Page;
use rusthole_core::stats::query::{
    ClientListParams, ClientRow, DomainGroup, DomainRow, DomainSearchParams, GroupParams, Hours,
    Range, ReasonRow, Sort, Summary, Timeline, TopClient, TopDomain, TypeRow, UpstreamRow,
};

use crate::service::FinalFlush;
use crate::stats::{ClientDetail, DomainDetailHours, HoursFilter, RecentParams};
use crate::{
    AuditParams, DB_FILE, Identity, NewAudit, Recorder, Stats, StatsService, StatsSettings,
    StoreError,
};

/// 2026-11-17T00:00:00Z.
const DAY0: i64 = 1_794_873_600;
/// "Now" of the tests: 2026-11-19T12:34:56Z.
const NOW: i64 = DAY0 + 2 * 86_400 + 12 * 3600 + 34 * 60 + 56;

const NAMES: [&str; 10] = [
    "www.example.com",
    "cdn.example.com",
    "example.com",
    "a.b.example.co.uk",
    "ads.example.net",
    "t.ads.example.net",
    "printer.home.lan",
    "localhost",
    "10.2.0.192.in-addr.arpa",
    "x_y.example.org",
];

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
}

fn ev(at: i64, client: u8, name: &str, status: Status) -> StatsEvent {
    StatsEvent {
        at,
        client: ip(client),
        name: name.to_owned(),
        qtype: if client.is_multiple_of(2) { 1 } else { 28 },
        status,
        reason: (status == Status::Blocked).then(|| format!("list:{}", client % 3)),
        upstream: (status == Status::Forwarded).then(|| format!("192.0.2.{}:53", 50 + client % 2)),
        duration_us: 1000 + u64::from(client) * 100,
    }
}

/// The base of the test temp directories: `RUSTHOLE_TEST_TMP`, else `target/test-tmp`. Not
/// the system temp directory (drive C is nearly full on the development host).
pub(crate) fn scratch_base() -> PathBuf {
    let base = std::env::var_os("RUSTHOLE_TEST_TMP").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-tmp"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("rusthole-store-")
        .tempdir_in(scratch_base())
        .unwrap()
}

fn disk_settings(dir: &Path) -> StatsSettings {
    StatsSettings {
        db_path: Some(dir.join(DB_FILE)),
        flush_interval: Duration::from_secs(60),
        retention_days: 30,
        recent_queries: 100,
        max_keys: 1_000_000,
        channel_capacity: 1024,
    }
}

fn open(dir: &Path) -> Stats {
    Stats::open(&disk_settings(dir), Arc::new(AtomicU64::new(0))).unwrap()
}

fn apply(stats: &Stats, events: &[StatsEvent]) {
    let mut v = events.to_vec();
    stats.apply(&mut v).unwrap();
}

/// All query results that P5 needs, for one store state.
#[derive(Debug, Clone, PartialEq)]
struct Bundle {
    summaries: Vec<Summary>,
    timelines: Vec<Timeline>,
    hours: Vec<Hours>,
    top_domains: Vec<Vec<TopDomain>>,
    top_clients: Vec<TopClient>,
    types: Vec<TypeRow>,
    upstreams: Vec<UpstreamRow>,
    reasons: Vec<ReasonRow>,
    clients: Page<ClientRow>,
    client: ClientDetail,
    groups: Vec<Page<DomainGroup>>,
    domains: Page<DomainRow>,
    domain: DomainDetailHours,
}

fn bundle(s: &Stats) -> Bundle {
    let ranges = [Range::Day, Range::Week, Range::Month];
    Bundle {
        summaries: ranges.iter().map(|r| s.summary(*r, NOW).unwrap()).collect(),
        timelines: vec![
            s.timeline(Range::Day, NOW, None, None).unwrap(),
            s.timeline(Range::Week, NOW, None, None).unwrap(),
            s.timeline(Range::Month, NOW, None, None).unwrap(),
            s.timeline(Range::Day, NOW, Some("192.0.2.1"), None)
                .unwrap(),
            s.timeline(Range::Week, NOW, None, Some("www.example.com"))
                .unwrap(),
        ],
        hours: vec![
            s.hours(Range::Week, NOW, &HoursFilter::default(), 330)
                .unwrap(),
            s.hours(
                Range::Week,
                NOW,
                &HoursFilter {
                    client: Some("192.0.2.2".to_owned()),
                    base: Some("example.com".to_owned()),
                    domain: None,
                },
                -210,
            )
            .unwrap(),
            s.hours(
                Range::Day,
                NOW,
                &HoursFilter {
                    domain: Some("ads.example.net".to_owned()),
                    ..HoursFilter::default()
                },
                0,
            )
            .unwrap(),
        ],
        top_domains: vec![
            s.top_domains(Range::Week, NOW, None, 10, false).unwrap(),
            s.top_domains(Range::Week, NOW, None, 10, true).unwrap(),
            s.top_domains(Range::Day, NOW, Some("192.0.2.3"), 5, false)
                .unwrap(),
        ],
        top_clients: s.top_clients(Range::Week, NOW, 10).unwrap(),
        types: s.query_types(Range::Week, NOW).unwrap(),
        upstreams: s.upstreams(Range::Week, NOW).unwrap(),
        reasons: s.top_reasons(Range::Week, NOW, 10).unwrap(),
        clients: s
            .clients(
                Range::Week,
                NOW,
                &ClientListParams {
                    sort: Sort::Blocked,
                    limit: 100,
                    ..ClientListParams::default()
                },
            )
            .unwrap(),
        client: s.client("192.0.2.1", Range::Week, NOW, 120).unwrap(),
        groups: vec![
            s.client_domains(
                "192.0.2.1",
                Range::Week,
                NOW,
                &GroupParams {
                    names_limit: 50,
                    limit: 100,
                    ..GroupParams::default()
                },
            )
            .unwrap(),
            s.client_domains(
                "192.0.2.2",
                Range::Day,
                NOW,
                &GroupParams {
                    q: Some("example".to_owned()),
                    sort: Sort::LastSeen,
                    blocked_only: true,
                    names_limit: 1,
                    limit: 100,
                    ..GroupParams::default()
                },
            )
            .unwrap(),
        ],
        domains: s
            .domains(
                Range::Month,
                NOW,
                &DomainSearchParams {
                    q: "example".to_owned(),
                    limit: 100,
                    ..DomainSearchParams::default()
                },
            )
            .unwrap(),
        domain: s.domain("ads.example.net", Range::Week, NOW, 0).unwrap(),
    }
}

fn events_strategy(max: usize) -> impl Strategy<Value = Vec<StatsEvent>> {
    prop::collection::vec(
        (
            // The last 3 days before NOW, and a little after NOW (a clock that jumps).
            -3 * 86_400i64..600,
            0u8..5,
            0usize..NAMES.len(),
            prop::sample::select(vec![
                Status::Forwarded,
                Status::Cached,
                Status::Blocked,
                Status::Local,
                Status::Refused,
                Status::Error,
            ]),
        ),
        1..max,
    )
    .prop_map(|v| {
        v.into_iter()
            .map(|(dt, c, n, st)| ev(NOW + dt, c, NAMES[n], st))
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Flush, then reload from SQLite, gives the same query results as the RAM state. Also
    /// with a flush in the middle (data in the database and in RAM at the same time).
    #[test]
    fn flush_then_reload_gives_the_same_results(
        events in events_strategy(200),
        split in 0usize..200,
        chunk in 1usize..40,
    ) {
        let dir = tempdir();
        let s = open(dir.path());
        apply(&s, &events);
        let ram = bundle(&s);

        // All data in the database.
        prop_assert!(s.flush(NOW).unwrap().is_some());
        prop_assert_eq!(&bundle(&s), &ram);

        // A new store on the same file (a restart).
        drop(s);
        let s2 = open(dir.path());
        prop_assert_eq!(&bundle(&s2), &ram);
        drop(s2);

        // Part in the database, part in RAM.
        let dir = tempdir();
        let s = open(dir.path());
        let split = split.min(events.len());
        apply(&s, &events[..split]);
        s.flush(NOW).unwrap();
        apply(&s, &events[split..]);
        prop_assert_eq!(&bundle(&s), &ram);

        // Many flushes: the same rows get counts from more than one flush (the upsert
        // adds them).
        let dir = tempdir();
        let s = open(dir.path());
        for chunk in events.chunks(chunk.max(1)) {
            apply(&s, chunk);
            s.flush(NOW).unwrap();
        }
        prop_assert_eq!(&bundle(&s), &ram);
    }
}

#[test]
fn no_disk_write_between_flushes() {
    let dir = tempdir();
    let s = open(dir.path());
    let db = dir.path().join(DB_FILE);
    let wal = dir.path().join(format!("{DB_FILE}-wal"));
    let file_state = || {
        [&db, &wal].map(|p| {
            std::fs::metadata(p)
                .ok()
                .map(|m| (m.len(), m.modified().ok()))
        })
    };
    let (writes0, mut last_changes) = s.db_write_counters().unwrap().unwrap();
    assert_eq!(writes0, 1, "the migration is one write");
    let mut last_files = file_state();

    for round in 0..3u64 {
        for i in 0..500u32 {
            let st = if i % 7 == 0 {
                Status::Blocked
            } else {
                Status::Cached
            };
            apply(
                &s,
                &[ev(
                    NOW - i64::from(i) * 13,
                    u8::try_from(i % 5).unwrap(),
                    NAMES[usize::try_from(i).unwrap() % NAMES.len()],
                    st,
                )],
            );
        }
        s.tick(NOW);
        let _ = bundle(&s);
        let _ = s.counters();
        // No write: not by our code, not in SQLite, not on the files.
        let (writes, changes) = s.db_write_counters().unwrap().unwrap();
        assert_eq!(writes, writes0 + round);
        assert_eq!(changes, last_changes);
        assert_eq!(file_state(), last_files);
        // One flush is one write transaction.
        assert!(s.flush(NOW).unwrap().is_some());
        let (writes, changes) = s.db_write_counters().unwrap().unwrap();
        assert_eq!(writes, writes0 + round + 1);
        assert!(changes > last_changes);
        last_changes = changes;
        last_files = file_state();
    }
    // A flush with nothing to write does not write.
    let before = s.db_write_counters().unwrap().unwrap();
    assert_eq!(s.flush(NOW).unwrap(), None);
    assert_eq!(s.db_write_counters().unwrap().unwrap(), before);
}

#[test]
fn ram_only_mode_never_opens_the_database() {
    let dir = tempdir();
    // The settings come from the config with the real data directory.
    let cfg = rusthole_core::config::Stats {
        flush_interval_seconds: 0,
        ..rusthole_core::config::Stats::default()
    };
    let settings = StatsSettings::from_config(&cfg, dir.path());
    assert_eq!(settings.db_path, None);
    let svc = StatsService::start(&settings).unwrap();
    let rec = svc.recorder();
    // The worker uses the wall clock for the RAM retention, so the events use it too.
    let now = crate::wall_now();
    for i in 0..100 {
        rec.record(ev(now - i, 1, "www.example.com", Status::Cached));
    }
    let stats = svc.stats();
    assert!(stats.is_ram_only());
    let report = svc.shutdown(Duration::from_secs(2));
    assert!(report.stopped);
    assert_eq!(report.final_flush, Some(FinalFlush::NotNeeded));
    assert_eq!(stats.summary(Range::Day, now).unwrap().counts.total, 100);
    assert_eq!(stats.db_write_counters().unwrap(), None);
    assert_eq!(stats.flush(now).unwrap(), None);
    stats
        .append_audit(&audit_line(now, "blocking.set"))
        .unwrap();
    // No file in the data directory: no database, no WAL, no journal.
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn schema_migration_from_an_empty_file() {
    let dir = tempdir();
    let path = dir.path().join(DB_FILE);
    std::fs::write(&path, b"").unwrap();
    let s = open(dir.path());
    assert_eq!(
        s.with_db(crate::db::Db::schema_version)
            .unwrap()
            .unwrap()
            .unwrap(),
        crate::db::SCHEMA_VERSION
    );
    apply(&s, &[ev(NOW, 1, "www.example.com", Status::Cached)]);
    s.flush(NOW).unwrap();
    drop(s);
    // A second open runs no migration (no write).
    let s = open(dir.path());
    assert_eq!(s.db_write_counters().unwrap().unwrap().0, 0);
    assert_eq!(s.summary(Range::Day, NOW).unwrap().counts.total, 1);
}

#[test]
fn a_newer_schema_is_an_error() {
    let dir = tempdir();
    let path = dir.path().join(DB_FILE);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.pragma_update(None, "user_version", 99).unwrap();
    }
    let err = Stats::open(&disk_settings(dir.path()), Arc::new(AtomicU64::new(0))).unwrap_err();
    assert!(
        matches!(err, StoreError::NewerSchema { found: 99, .. }),
        "{err}"
    );
}

#[test]
fn retention_deletes_only_old_rows() {
    let dir = tempdir();
    let s = open(dir.path());
    let old = NOW - 40 * 86_400;
    let edge_old = NOW - 30 * 86_400 - 3600;
    let edge_new = NOW - 30 * 86_400 + 3600;
    let new = NOW - 3600;
    for at in [old, edge_old, edge_new, new] {
        apply(&s, &[ev(at, 1, "www.example.com", Status::Forwarded)]);
    }
    apply(&s, &[ev(old, 2, "old-only.example", Status::Blocked)]);
    s.append_audit(&NewAudit {
        at: old,
        action: "list.update".to_owned(),
        target: Some("list:1".to_owned()),
        actor: "session".to_owned(),
        client_ip: Some(ip(9)),
        ok: true,
        detail: None,
    })
    .unwrap();
    // The first flush stores all rows; the retention (due: never ran) deletes the old ones.
    let r = s.flush(NOW).unwrap().unwrap();
    assert!(r.retention_ran);
    let rows = s.with_db(|d| d.hourly_rows().unwrap()).unwrap().unwrap();
    assert_eq!(rows, 2, "only the two rows inside 30 days stay");
    // The 30 d range starts at a 4-hour bucket boundary, so the row at the retention edge
    // (719 hours ago) is older than the range start.
    let m = s.summary(Range::Month, NOW).unwrap();
    assert_eq!(m.counts.total, 1);
    let clients = s.clients_index().unwrap();
    assert!(
        clients.get(ip(2)).is_none(),
        "a client with only old rows is deleted"
    );
    assert_eq!(
        s.audit(&AuditParams {
            limit: 10,
            ..AuditParams::default()
        })
        .unwrap()
        .items
        .len(),
        0
    );

    // The retention runs once a day: not again on the same day.
    apply(&s, &[ev(old, 1, "www.example.com", Status::Forwarded)]);
    let r = s.flush(NOW + 60).unwrap().unwrap();
    assert!(!r.retention_ran);
    assert_eq!(s.with_db(|d| d.hourly_rows().unwrap()).unwrap().unwrap(), 3);
    // The next day it runs again.
    let r = s.flush(NOW + 86_400).unwrap().unwrap();
    assert!(r.retention_ran);
    assert_eq!(s.with_db(|d| d.hourly_rows().unwrap()).unwrap().unwrap(), 1);
}

#[test]
fn ram_only_retention_evicts_old_hours() {
    let mut settings = StatsSettings::ram_only();
    settings.retention_days = 1;
    let s = Stats::open(&settings, Arc::new(AtomicU64::new(0))).unwrap();
    apply(
        &s,
        &[
            ev(NOW - 3 * 86_400, 1, "www.example.com", Status::Cached),
            ev(NOW - 3600, 1, "www.example.com", Status::Cached),
        ],
    );
    s.tick(NOW);
    let c = s.counters();
    assert_eq!(c.evicted_buckets, 1);
    assert_eq!(c.evicted_events, 1);
    assert_eq!(s.summary(Range::Month, NOW).unwrap().counts.total, 1);
}

#[test]
fn utc_offset_rounds_down_per_the_api_rule() {
    let s = Stats::open(&StatsSettings::ram_only(), Arc::new(AtomicU64::new(0))).unwrap();
    // 23:30 UTC on the day before NOW.
    apply(
        &s,
        &[ev(
            DAY0 + 86_400 + 23 * 3600 + 1800,
            1,
            "www.example.com",
            Status::Cached,
        )],
    );
    let h = s
        .hours(Range::Week, NOW, &HoursFilter::default(), 330)
        .unwrap();
    assert_eq!(h.utc_offset_minutes, 300);
    assert_eq!(h.queries[4], 1);
    let h = s
        .hours(Range::Week, NOW, &HoursFilter::default(), -210)
        .unwrap();
    assert_eq!(h.utc_offset_minutes, -240);
    assert_eq!(h.queries[19], 1);
}

#[test]
fn a_failed_flush_keeps_the_data_in_ram() {
    let dir = tempdir();
    let s = open(dir.path());
    let events: Vec<StatsEvent> = (0..50)
        .map(|i| {
            ev(
                NOW - i * 60,
                u8::try_from(i % 3).unwrap(),
                "www.example.com",
                Status::Forwarded,
            )
        })
        .collect();
    apply(&s, &events);
    let want = bundle(&s);
    s.with_db(|d| d.execute_raw("DROP TABLE hourly_types").unwrap())
        .unwrap();
    assert!(s.flush(NOW).is_err());
    assert_eq!(s.counters().flush_failures, 1);
    assert_eq!(s.summary(Range::Week, NOW).unwrap().counts.total, 50);
    s.with_db(|d| {
        d.execute_raw(
            "CREATE TABLE hourly_types (hour_utc INTEGER NOT NULL, qtype INTEGER NOT NULL, \
             count INTEGER NOT NULL, PRIMARY KEY (hour_utc, qtype)) WITHOUT ROWID",
        )
        .unwrap();
    })
    .unwrap();
    assert!(s.flush(NOW).unwrap().is_some());
    assert_eq!(bundle(&s), want);
    assert_eq!(s.counters().ram_keys, 0);
}

#[test]
fn client_identity_gives_the_mac_key() {
    let dir = tempdir();
    let s = open(dir.path());
    apply(
        &s,
        &[
            ev(NOW - 10, 10, "www.example.com", Status::Cached),
            ev(NOW - 5, 110, "cdn.example.com", Status::Cached),
        ],
    );
    let mac = Some("02:00:00:00:00:01".to_owned());
    for n in [10, 110] {
        s.set_client_identity(
            ip(n),
            Identity {
                mac: mac.clone(),
                name: Some("laptop".to_owned()),
            },
        )
        .unwrap();
    }
    let check = |s: &Stats| {
        let d = s.client("02:00:00:00:00:01", Range::Day, NOW, 0).unwrap();
        assert_eq!(d.row.counts.total, 2);
        assert_eq!(d.row.ips, vec![ip(10), ip(110)]);
        assert_eq!(d.row.name.as_deref(), Some("laptop"));
        let top = s.top_clients(Range::Day, NOW, 10).unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].key, "02:00:00:00:00:01");
    };
    check(&s);
    s.flush(NOW).unwrap();
    drop(s);
    check(&open(dir.path()));
}

/// An identity that comes before the first flush of its address is not lost: the flush of
/// the address later writes the MAC, also when no identity changed in between.
#[test]
fn identity_before_the_first_flush_of_the_address_is_kept() {
    let dir = tempdir();
    let s = open(dir.path());
    s.set_client_identity(
        ip(20),
        Identity {
            mac: Some("02:00:00:00:00:02".to_owned()),
            name: Some("tablet".to_owned()),
        },
    )
    .unwrap();
    // A flush with no event of 192.0.2.20: the address has no `clients` row yet.
    apply(&s, &[ev(NOW - 20, 21, "www.example.com", Status::Cached)]);
    s.flush(NOW - 15).unwrap();
    // The first event of 192.0.2.20 comes after that flush.
    apply(&s, &[ev(NOW - 10, 20, "cdn.example.com", Status::Cached)]);
    s.flush(NOW).unwrap();
    drop(s);
    let s = open(dir.path());
    let d = s.client("02:00:00:00:00:02", Range::Day, NOW, 0).unwrap();
    assert_eq!(d.row.counts.total, 1);
    assert_eq!(d.row.ips, vec![ip(20)]);
    assert_eq!(d.row.name.as_deref(), Some("tablet"));
}

fn ip6(n: u16) -> IpAddr {
    IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n))
}

/// A MAC with more addresses than one SQL statement takes (for example IPv6 privacy
/// addresses) gets the counts of all its addresses, before and after a flush.
#[test]
fn client_with_more_addresses_than_one_statement() {
    let n = u16::try_from(crate::db::MAX_FILTER_CLIENTS + 44).unwrap();
    let dir = tempdir();
    let s = open(dir.path());
    let mac = "02:00:00:00:00:03";
    let mut events = Vec::new();
    for i in 1..=n {
        s.set_client_identity(
            ip6(i),
            Identity {
                mac: Some(mac.to_owned()),
                name: None,
            },
        )
        .unwrap();
        let mut e = ev(NOW - 100, 1, "www.example.com", Status::Cached);
        e.client = ip6(i);
        events.push(e);
    }
    apply(&s, &events);
    let check = |s: &Stats| {
        let d = s.client(mac, Range::Day, NOW, 0).unwrap();
        assert_eq!(d.row.counts.total, u64::from(n));
        assert_eq!(d.row.ips.len(), usize::from(n));
        assert_eq!(d.hours.queries.iter().sum::<u64>(), u64::from(n));
        let top = s
            .top_domains(Range::Day, NOW, Some(mac), 10, false)
            .unwrap();
        assert_eq!(top[0].count, u64::from(n));
    };
    check(&s);
    s.flush(NOW).unwrap();
    check(&s);
    drop(s);
    check(&open(dir.path()));
}

/// A read from the database stops at the row cap; the cap counts the rows of all chunks.
#[test]
fn pairs_read_stops_at_the_row_cap() {
    use rusthole_core::stats::query::Filter;
    let dir = tempdir();
    let s = open(dir.path());
    let n = crate::db::MAX_FILTER_CLIENTS + 44;
    let mut events = Vec::new();
    for i in 1..=n {
        let mut e = ev(NOW - 100, 1, "www.example.com", Status::Cached);
        e.client = ip6(u16::try_from(i).unwrap());
        events.push(e);
    }
    apply(&s, &events);
    s.flush(NOW).unwrap();
    let hour = NOW.div_euclid(3600);
    let all = Filter::hours(hour - 1, hour);
    let some = Filter {
        clients: Some((1..=n).map(|i| ip6(u16::try_from(i).unwrap())).collect()),
        ..all.clone()
    };
    for f in [&all, &some] {
        let got = s.with_db(|db| db.pairs_capped(f, n)).unwrap().unwrap();
        assert_eq!(got.unwrap().len(), n);
        let over = s.with_db(|db| db.pairs_capped(f, n - 1)).unwrap().unwrap();
        assert!(
            matches!(over, Err(StoreError::TooLarge { limit }) if limit == n - 1),
            "{over:?}"
        );
    }
    // The production cap is far above this database.
    let got = s.with_db(|db| db.pairs(&all)).unwrap().unwrap();
    assert_eq!(got.unwrap().len(), n);
}

/// `first_seen` of a name is the first query in all stored data, not only in the range
/// (docs/API.md section 5.7), in RAM and after a flush.
#[test]
fn domain_first_seen_is_from_all_stored_data() {
    let dir = tempdir();
    let s = open(dir.path());
    let old = NOW - 5 * 86_400;
    apply(
        &s,
        &[
            ev(old, 1, "www.example.com", Status::Cached),
            ev(NOW - 60, 2, "www.example.com", Status::Cached),
        ],
    );
    let check = |s: &Stats| {
        let d = s.domain("www.example.com", Range::Day, NOW, 0).unwrap();
        assert_eq!(d.detail.counts.total, 1);
        assert_eq!(d.detail.first_seen, Some(old));
        assert_eq!(d.detail.last_seen, Some(NOW - 60));
    };
    check(&s);
    s.flush(NOW - 30).unwrap();
    check(&s);
    // An earlier query that comes late (a clock jump) lowers the stored value.
    apply(&s, &[ev(old - 100, 3, "www.example.com", Status::Cached)]);
    s.flush(NOW).unwrap();
    drop(s);
    let s = open(dir.path());
    let d = s.domain("www.example.com", Range::Day, NOW, 0).unwrap();
    assert_eq!(d.detail.first_seen, Some(old - 100));
    let stored = s
        .with_db(|db| db.domain_first_seen("www.example.com"))
        .unwrap()
        .unwrap();
    assert_eq!(stored.unwrap(), Some(old - 100));
}

/// The database file, its WAL and a new data directory are private to the owner (Unix).
#[cfg(target_os = "linux")]
#[test]
fn database_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let Some(base) = scratch_keeping_modes("database_files_are_private") else {
        return;
    };
    let data = base.path().join("data");
    let s = open(&data);
    apply(&s, &[ev(NOW - 10, 1, "www.example.com", Status::Cached)]);
    s.flush(NOW).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&data), 0o700);
    for f in [DB_FILE.to_owned(), format!("{DB_FILE}-wal")] {
        let p = data.join(&f);
        assert_eq!(mode(&p) & 0o077, 0, "{f}: {:o}", mode(&p));
    }
}

/// A temp directory on a file system that keeps Unix modes. A Windows drive in WSL keeps
/// no Unix modes, so the function tries the scratch base, then `/dev/shm`, then the system
/// temp directory. When no base keeps modes, it prints a skip message and gives `None`.
#[cfg(target_os = "linux")]
fn scratch_keeping_modes(test: &str) -> Option<tempfile::TempDir> {
    for base in [
        scratch_base(),
        PathBuf::from("/dev/shm/rusthole-test"),
        std::env::temp_dir().join("rusthole-test"),
    ] {
        if std::fs::create_dir_all(&base).is_err() {
            continue;
        }
        if let Ok(dir) = tempfile::tempdir_in(&base)
            && keeps_modes(dir.path())
        {
            return Some(dir);
        }
    }
    eprintln!("SKIP {test}: no temp file system keeps Unix modes");
    None
}

#[cfg(target_os = "linux")]
fn keeps_modes(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let probe = dir.join("probe");
    std::fs::write(&probe, b"x").unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o640)).unwrap();
    let ok = std::fs::metadata(&probe).unwrap().permissions().mode() & 0o777 == 0o640;
    std::fs::remove_file(&probe).unwrap();
    ok
}

#[test]
fn recent_queries_are_newest_first_and_filtered() {
    let s = Stats::open(&StatsSettings::ram_only(), Arc::new(AtomicU64::new(0))).unwrap();
    for i in 0..20u8 {
        let st = if i % 2 == 0 {
            Status::Blocked
        } else {
            Status::Cached
        };
        apply(
            &s,
            &[ev(NOW + i64::from(i), i % 2, &format!("n{i}.example"), st)],
        );
    }
    let got = s
        .recent(&RecentParams {
            limit: 3,
            client: Some("192.0.2.0".to_owned()),
            status: Some(Status::Blocked),
            q: None,
        })
        .unwrap();
    let ats: Vec<i64> = got.iter().map(|e| e.at - NOW).collect();
    assert_eq!(ats, vec![18, 16, 14]);
}

fn audit_line(at: i64, action: &str) -> NewAudit {
    NewAudit {
        at,
        action: action.to_owned(),
        target: Some("list:3".to_owned()),
        actor: "session".to_owned(),
        client_ip: Some(ip(10)),
        ok: true,
        detail: Some("x".repeat(5000)),
    }
}

fn audit_pages_work(s: &Stats) {
    for i in 0..25 {
        let action = if i % 2 == 0 {
            "list.update"
        } else {
            "rule.create"
        };
        s.append_audit(&audit_line(NOW + i, action)).unwrap();
    }
    let mut seen = Vec::new();
    let mut cursor = None;
    for _ in 0..10 {
        let page = s
            .audit(&AuditParams {
                action_prefix: Some("list.".to_owned()),
                cursor: cursor.clone(),
                limit: 4,
            })
            .unwrap();
        seen.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen.len(), 13);
    assert!(seen.windows(2).all(|w| w[0].id > w[1].id), "newest first");
    assert!(seen.iter().all(|l| l.action == "list.update"));
    assert_eq!(
        seen[0].detail.as_ref().map(String::len),
        Some(crate::audit::MAX_DETAIL_LEN)
    );
    assert_eq!(seen[0].client_ip, Some(ip(10)));
    let bad = s.audit(&AuditParams {
        cursor: Some("not-a-cursor".to_owned()),
        ..AuditParams::default()
    });
    assert!(matches!(bad, Err(StoreError::Cursor(_))));
}

#[test]
fn audit_log_pages_on_disk_and_in_ram() {
    let dir = tempdir();
    let s = open(dir.path());
    let before = s.db_write_counters().unwrap().unwrap().0;
    audit_pages_work(&s);
    // Choice: each audit line is written at once (one write each).
    assert_eq!(s.db_write_counters().unwrap().unwrap().0, before + 25);
    let ram = Stats::open(&StatsSettings::ram_only(), Arc::new(AtomicU64::new(0))).unwrap();
    audit_pages_work(&ram);
}

#[test]
fn recorder_never_blocks_and_counts_drops() {
    let (rec, rx) = Recorder::detached(2);
    let started = Instant::now();
    for i in 0..1000 {
        rec.record(ev(NOW + i, 1, "www.example.com", Status::Cached));
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(rec.dropped(), 998);
    drop(rx);
    rec.record(ev(NOW, 1, "www.example.com", Status::Cached));
    assert_eq!(rec.dropped(), 999, "a stopped worker also counts as a drop");
}

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    for _ in 0..10_000 {
        if f() {
            return true;
        }
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    f()
}

#[test]
fn service_counts_events_and_shutdown_flushes_once() {
    let dir = tempdir();
    let mut settings = disk_settings(dir.path());
    settings.flush_interval = Duration::from_secs(3600);
    let svc = StatsService::start(&settings).unwrap();
    let rec = svc.recorder();
    let stats = svc.stats();
    // The worker uses the wall clock for the retention, so the events use it too.
    let now = crate::wall_now();
    for i in 0..300 {
        rec.record(ev(
            now - i,
            u8::try_from(i % 4).unwrap(),
            "www.example.com",
            Status::Cached,
        ));
    }
    assert!(wait_until(Duration::from_secs(5), || stats
        .summary(Range::Day, now)
        .is_ok_and(|s| s.counts.total == 300)));
    // The interval is long: no flush yet (only the migration wrote).
    assert_eq!(stats.db_write_counters().unwrap().unwrap().0, 1);
    let alive = svc.worker_alive().unwrap();
    let report = svc.shutdown(Duration::from_secs(3));
    assert!(report.stopped);
    assert_eq!(report.final_flush, Some(FinalFlush::Done));
    assert!(!alive.load(Ordering::Acquire));
    assert_eq!(
        stats.db_write_counters().unwrap().unwrap().0,
        2,
        "exactly one final flush"
    );
    // Events after the stop are dropped, not queued forever.
    rec.record(ev(now, 1, "www.example.com", Status::Cached));
    assert_eq!(rec.dropped(), 1);
    drop(stats);
    let s = open(dir.path());
    assert_eq!(s.summary(Range::Day, now).unwrap().counts.total, 300);
}

#[test]
fn service_flushes_on_its_interval() {
    let dir = tempdir();
    let mut settings = disk_settings(dir.path());
    settings.flush_interval = Duration::from_millis(300);
    let svc = StatsService::start(&settings).unwrap();
    let stats = svc.stats();
    svc.recorder()
        .record(ev(rusthole_now(), 1, "www.example.com", Status::Cached));
    assert!(wait_until(Duration::from_secs(5), || stats
        .counters()
        .flushes
        >= 1));
    assert_eq!(stats.counters().ram_keys, 0);
    drop(svc);
}

fn rusthole_now() -> i64 {
    crate::wall_now()
}

#[test]
fn drop_stops_the_worker() {
    let dir = tempdir();
    let svc = StatsService::start(&disk_settings(dir.path())).unwrap();
    let alive = svc.worker_alive().unwrap();
    assert!(alive.load(Ordering::Acquire));
    let started = Instant::now();
    drop(svc);
    assert!(!alive.load(Ordering::Acquire));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn shutdown_gives_up_when_the_database_is_busy_and_still_stops() {
    let dir = tempdir();
    let svc = StatsService::start(&disk_settings(dir.path())).unwrap();
    let stats = svc.stats();
    svc.recorder()
        .record(ev(crate::wall_now(), 1, "www.example.com", Status::Cached));
    assert!(wait_until(Duration::from_secs(5), || stats
        .counters()
        .ram_keys
        > 0));
    let alive = svc.worker_alive().unwrap();
    // Hold the database lock in another thread for longer than the deadline.
    let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(1);
    let holder = {
        let stats = stats.clone();
        std::thread::spawn(move || {
            stats
                .with_db(|_| {
                    locked_tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(1500));
                })
                .unwrap();
        })
    };
    locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let report = svc.shutdown(Duration::from_millis(200));
    assert!(report.stopped, "the give-up path still stops the thread");
    assert_eq!(report.final_flush, Some(FinalFlush::Failed));
    assert!(!alive.load(Ordering::Acquire));
    holder.join().unwrap();
}

#[test]
fn settings_from_config() {
    let cfg = rusthole_core::config::Stats::default();
    let s = StatsSettings::from_config(&cfg, Path::new("data"));
    assert_eq!(s.db_path, Some(PathBuf::from("data").join(DB_FILE)));
    assert_eq!(s.flush_interval, Duration::from_secs(60));
    assert_eq!(s.recent_queries, 1000);
}
