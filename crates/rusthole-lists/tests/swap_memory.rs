//! Peak heap during a list refresh: the old engine stays in use while the new body is
//! fetched, checked, parsed and built (requirement 4 of part P3b).
//!
//! This test binary counts every heap byte with a counting allocator, so it has its own
//! file. The fast tests use 100 000 names (one list, or 3 lists that change at the same
//! time). The slow tests use 1 000 000 names and 3 x 1 000 000 names; run them with:
//!
//! ```text
//! cargo test --release -p rusthole-lists --test swap_memory -- --include-ignored --nocapture --test-threads 1
//! ```
//!
//! docs/LISTS.md has the measured numbers.

// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::{Resp, TestClock, blocked, config, serve, settings, temp_dir, test_lookup, wait_for};
use peak_alloc::PeakAlloc;
use rusthole_lists::{BuildStage, RefreshPhase, Refresher, UpdateTarget};

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

/// The allocator counters are global, so the tests in this file run one at a time.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The heap (current, peak) at each swap, from the build hook: old and new engine together.
static AT_SWAP: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

const PREFIXES: [&str; 8] = [
    "ads", "trk", "pixel", "metrics", "cdn", "stats", "beacon", "track",
];
const MIDDLES: [&str; 6] = [
    "example",
    "test",
    "sample-host",
    "adnet",
    "media-cdn",
    "invalid",
];
const TLDS: [&str; 4] = ["com", "net", "org", "io"];

/// A deterministic, unique name of about 25 characters for number `i`.
fn name(i: u64) -> String {
    let mut h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    h ^= h >> 29;
    let pick = |n: usize, shift: u32| usize::try_from((h >> shift) % n as u64).unwrap();
    format!(
        "{}-{i:x}.{}.{}",
        PREFIXES[pick(PREFIXES.len(), 3)],
        MIDDLES[pick(MIDDLES.len(), 11)],
        TLDS[pick(TLDS.len(), 19)]
    )
}

/// A hosts-format list with names `from..to` (about 34 bytes per line).
fn write_list(path: &std::path::Path, from: u64, to: u64) -> u64 {
    let mut text = String::with_capacity(usize::try_from((to - from) * 36).unwrap());
    for i in from..to {
        writeln!(text, "0.0.0.0 {}", name(i)).unwrap();
    }
    std::fs::write(path, &text).unwrap();
    text.len() as u64
}

fn mb(bytes: usize) -> f64 {
    #[allow(clippy::cast_precision_loss)] // Display only.
    let b = bytes as f64;
    b / 1_000_000.0
}

/// Measures one refresh of a list with `names` names (5 % of the names change).
async fn measure(names: u64) -> (usize, usize, usize, u64, (usize, usize)) {
    measure_lists(1, names).await
}

/// Measures one refresh of `count` lists with `names` names each. All lists change at the
/// same time (one "update now" for all), 5 % of the names of each list change.
async fn measure_lists(count: u32, names: u64) -> (usize, usize, usize, u64, (usize, usize)) {
    let www = temp_dir();
    let mut size = 0;
    let mut files = Vec::new();
    for i in 0..u64::from(count) {
        // Each list has its own range of names.
        let base = i * 2 * names;
        let v1 = www.path().join(format!("v1-{i}.txt"));
        let v2 = www.path().join(format!("v2-{i}.txt"));
        size += write_list(&v1, base, base + names);
        write_list(&v2, base + names / 20, base + names + names / 20);
        files.push((v1, v2));
    }
    let second = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&second);
    let server = serve(move |req| {
        let i: usize = req.path.trim_start_matches("/l").parse().unwrap();
        let (v1, v2) = &files[i];
        Resp {
            file: Some(if flag.load(Ordering::SeqCst) {
                v2.clone()
            } else {
                v1.clone()
            }),
            ..Resp::status(200)
        }
    })
    .await;
    let dir = temp_dir();
    let urls: Vec<String> = (0..count).map(|i| server.url(&format!("/l{i}"))).collect();
    let lists: Vec<(u32, &str)> = urls
        .iter()
        .zip(1..)
        .map(|(u, id)| (id, u.as_str()))
        .collect();
    let cfg = Arc::new(config(dir.path(), &lists));
    let clock = TestClock::new(1_800_000_000);
    let mut s = settings(&cfg, &clock);
    AT_SWAP.lock().unwrap().clear();
    s.build_hook = Some(Arc::new(|stage| {
        if stage != BuildStage::BeforeSwap {
            return;
        }
        AT_SWAP
            .lock()
            .unwrap()
            .push((ALLOC.current_usage(), ALLOC.peak_usage()));
    }));
    s.limits.total_timeout = Duration::from_secs(120);
    s.limits.read_timeout = Duration::from_secs(60);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    let wait = Duration::from_secs(600);
    wait_for(&r, wait, |st| {
        st.lists.iter().all(|l| l.in_engine) && !st.engine.building
    })
    .await;
    let engine = r.engine();
    // Let the first fetch tasks end and free their buffers. A build request that came during
    // the last build gives one more build: wait for it too.
    tokio::time::sleep(Duration::from_millis(500)).await;
    wait_for(&r, wait, |st| !st.engine.building).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let steady = ALLOC.current_usage();
    ALLOC.reset_peak_usage();
    second.store(true, Ordering::SeqCst);
    clock.advance(10);
    r.update_now(UpdateTarget::All).unwrap();
    let last_name = |i: u64| name(i * 2 * names + names);
    wait_for(&r, wait, |st| {
        (0..u64::from(count)).all(|i| blocked(&engine, &last_name(i)))
            && st.lists.iter().all(|l| l.phase == RefreshPhase::Idle)
            && !st.engine.building
    })
    .await;
    // A build request that came during the last build gives one more build: wait for it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    wait_for(&r, wait, |st| !st.engine.building).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let peak = ALLOC.peak_usage();
    let after = ALLOC.current_usage();
    // The new names are in the engine, the removed ones are not.
    for i in 0..u64::from(count) {
        assert!(blocked(&engine, &last_name(i)));
        assert!(!blocked(&engine, &name(i * 2 * names)));
    }
    assert!(r.shutdown(Duration::from_secs(10)).await);
    drop(r);
    let swap = AT_SWAP.lock().unwrap().last().copied().unwrap();
    (steady, peak, after, size, swap)
}

#[allow(clippy::print_stdout)] // The test prints the measured numbers (run with --nocapture).
fn report(what: &str, m: (usize, usize, usize, u64, (usize, usize))) {
    let (steady, peak, after, size, (swap_now, swap_peak)) = m;
    println!(
        "{what}, lists {:.1} MB: heap before {:.1} MB, peak during refresh {:.1} MB \
         (+{:.1} MB), at the swap {:.1} MB (peak until then {:.1} MB), after {:.1} MB",
        mb(usize::try_from(size).unwrap()),
        mb(steady),
        mb(peak),
        mb(peak.saturating_sub(steady)),
        mb(swap_now),
        mb(swap_peak),
        mb(after)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_frees_the_old_engine_100k() {
    let _guard = LOCK.lock().await;
    let m = measure(100_000).await;
    report("100 000 names", m);
    let (steady, peak, after, _, _) = m;
    // The old engine is freed after the swap: the heap after the refresh is close to the
    // heap before it (the new engine has the same size), not twice as large.
    assert!(
        after < steady + steady / 4,
        "steady {steady}, after {after}"
    );
    // The refresh holds the old engine, the body and the new engine at the peak.
    assert!(peak > steady);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: run with --release -- --ignored --nocapture"]
async fn refresh_peak_1m() {
    let _guard = LOCK.lock().await;
    let m = measure(1_000_000).await;
    report("1 000 000 names", m);
    let (steady, _, after, _, _) = m;
    assert!(
        after < steady + steady / 4,
        "steady {steady}, after {after}"
    );
}

/// Three lists change at the same time. The work permit lets one store step (parse) or one
/// build run at a time, so the peak stays near the peak of one list of the same total size.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_lists_at_once_100k() {
    let _guard = LOCK.lock().await;
    let m = measure_lists(3, 33_334).await;
    report("3 lists of 33 334 names", m);
    let (steady, _, after, _, _) = m;
    assert!(
        after < steady + steady / 4,
        "steady {steady}, after {after}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: run with --release -- --ignored --nocapture"]
async fn three_lists_at_once_1m() {
    let _guard = LOCK.lock().await;
    let m = measure_lists(3, 333_334).await;
    report("3 lists of 333 334 names", m);
    let (steady, _, after, _, _) = m;
    assert!(
        after < steady + steady / 4,
        "steady {steady}, after {after}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: run with --release -- --ignored --nocapture"]
async fn three_lists_at_once_3m() {
    let _guard = LOCK.lock().await;
    let m = measure_lists(3, 1_000_000).await;
    report("3 lists of 1 000 000 names", m);
    let (steady, _, after, _, _) = m;
    assert!(
        after < steady + steady / 4,
        "steady {steady}, after {after}"
    );
}
