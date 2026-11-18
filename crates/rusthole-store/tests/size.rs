//! Size and flush-time test: one day of synthetic traffic for 20 clients and 2,000 domains,
//! with a flush every 60 s (1,440 flushes). It prints the numbers for docs/STATS.md.
//!
//! It is slow, so it is ignored by default. Run it with:
//!
//! ```text
//! cargo test -p rusthole-store --test size -- --ignored --nocapture
//! ```

// A test file: a panic is the wanted result of a failed step.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use rusthole_core::stats::query::Range;
use rusthole_core::stats::{StatsEvent, Status};
use rusthole_store::{DB_FILE, Stats, StatsSettings};

const CLIENTS: u32 = 20;
const DOMAINS: u32 = 2_000;
/// 2026-11-17T00:00:00Z.
const DAY0: i64 = 1_794_873_600;

/// A small deterministic hash (`SplitMix64`).
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn name(d: u32) -> String {
    format!("host{}.site{}.example", d % 5, d / 5)
}

/// The traffic model.
#[derive(Clone, Copy, Debug)]
enum Model {
    /// Each client queries each of the 2,000 names in each hour (worst case for rows).
    EveryPairEveryHour,
    /// Each client queries 50 popular names in each hour, and 1/12 of the others in each
    /// hour (each name about 2 times a day).
    Typical,
}

impl Model {
    fn queried(self, client: u32, domain: u32, hour: u32) -> bool {
        match self {
            Model::EveryPairEveryHour => true,
            Model::Typical => {
                domain < 50
                    || mix(u64::from(client) << 40 | u64::from(domain) << 8 | u64::from(hour))
                        .is_multiple_of(12)
            }
        }
    }
}

/// The base of the test temp directories. The first variable that is set wins:
/// `RUSTHOLE_TEST_TMP`, then `TMPDIR` (`scripts/linux.sh` sets a RAM file system), then
/// `CARGO_TARGET_DIR/test-tmp`, then `<repo>/target/test-tmp`. A copy of `scratch_base` in
/// `src/tests.rs`; its unit test covers the order. The function does not use
/// `std::env::temp_dir()`: on Windows it is on drive C, and drive C is nearly full on the
/// development host.
fn scratch_base() -> std::path::PathBuf {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    let base = var("RUSTHOLE_TEST_TMP")
        .or_else(|| var("TMPDIR"))
        .map_or_else(
            || {
                let target = var("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into());
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join(target)
                    .join("test-tmp")
            },
            std::path::PathBuf::from,
        );
    std::fs::create_dir_all(&base).unwrap();
    base
}

struct Report {
    events: u64,
    flushes: u32,
    total_flush: Duration,
    max_flush: Duration,
    rows: u64,
    bytes: u64,
}

fn run(model: Model) -> Report {
    let dir = tempfile::Builder::new()
        .prefix("rusthole-size-")
        .tempdir_in(scratch_base())
        .unwrap();
    let settings = StatsSettings {
        db_path: Some(dir.path().join(DB_FILE)),
        max_keys: 1_000_000,
        ..StatsSettings::ram_only()
    };
    let stats = Stats::open(&settings, Arc::new(AtomicU64::new(0))).unwrap();
    let mut report = Report {
        events: 0,
        flushes: 0,
        total_flush: Duration::ZERO,
        max_flush: Duration::ZERO,
        rows: 0,
        bytes: 0,
    };
    // Events of each minute: (client, domain) pairs whose hashed minute is this minute.
    let mut batch = Vec::new();
    for hour in 0..24u32 {
        let mut by_minute: Vec<Vec<(u32, u32)>> = vec![Vec::new(); 60];
        for c in 0..CLIENTS {
            for d in 0..DOMAINS {
                if model.queried(c, d, hour) {
                    let h = mix(u64::from(c) << 32 | u64::from(d) << 8 | u64::from(hour));
                    let minute = usize::try_from(h % 60).unwrap();
                    by_minute[minute].push((c, d));
                    // Popular names get more queries in the same hour.
                    if d < 50 {
                        by_minute[(minute + 17) % 60].push((c, d));
                    }
                }
            }
        }
        for (minute, pairs) in by_minute.into_iter().enumerate() {
            let at = DAY0 + i64::from(hour) * 3600 + i64::try_from(minute).unwrap() * 60;
            for (c, d) in pairs {
                let h = mix(u64::from(c) ^ u64::from(d) << 20);
                let st = match h % 10 {
                    0 => Status::Blocked,
                    1..=5 => Status::Cached,
                    _ => Status::Forwarded,
                };
                batch.push(StatsEvent {
                    at,
                    client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, u8::try_from(c + 1).unwrap())),
                    name: name(d),
                    qtype: if h.is_multiple_of(3) { 28 } else { 1 },
                    status: st,
                    reason: (st == Status::Blocked).then(|| format!("list:{}", h % 4)),
                    upstream: (st == Status::Forwarded)
                        .then(|| format!("192.0.2.{}:53", 50 + h % 2)),
                    duration_us: 2_000 + h % 20_000,
                });
                report.events += 1;
            }
            stats.apply(&mut batch).unwrap();
            let started = Instant::now();
            stats.flush(at + 59).unwrap();
            let took = started.elapsed();
            report.total_flush += took;
            report.max_flush = report.max_flush.max(took);
            report.flushes += 1;
        }
    }
    let end = DAY0 + 86_399;
    let summary = stats.summary(Range::Day, end).unwrap();
    assert_eq!(summary.counts.total, report.events);
    stats
        .with_db(|db| {
            db.checkpoint().unwrap();
            report.rows = db.hourly_rows().unwrap();
        })
        .unwrap();
    drop(stats);
    report.bytes = std::fs::metadata(dir.path().join(DB_FILE)).unwrap().len();
    report
}

#[test]
#[ignore = "slow: run by hand for docs/STATS.md"]
#[allow(clippy::cast_precision_loss)] // Report numbers only.
fn one_day_of_traffic() {
    for model in [Model::Typical, Model::EveryPairEveryHour] {
        let r = run(model);
        let mean = r.total_flush / r.flushes;
        println!(
            "{model:?}: events={} flushes={} hourly_rows={} db_bytes={} ({:.1} MiB) \
             flush_total={:.2?} flush_mean={:.2?} flush_max={:.2?} bytes_per_row={:.1}",
            r.events,
            r.flushes,
            r.rows,
            r.bytes,
            r.bytes as f64 / 1_048_576.0,
            r.total_flush,
            mean,
            r.max_flush,
            r.bytes as f64 / r.rows as f64,
        );
    }
}
