//! The refresher against a local HTTP server on 127.0.0.1: disk cache, schedule, status,
//! engine swap and shutdown.

// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::{
    Resp, TestClock, WAIT, blocked, config, serve, settings, temp_dir, test_lookup, wait_for,
};
use rusthole_core::refresh::parse_meta;
use rusthole_lists::{
    BuildStage, ListState, RefreshPhase, Refresher, StaticResolver, UpdateError, UpdateTarget,
};

const T0: i64 = 1_800_000_000;

fn mtime(path: &std::path::Path) -> std::time::SystemTime {
    std::fs::metadata(path).unwrap().modified().unwrap()
}

/// A server that answers 304 to the right `If-None-Match`, else 200 with `ETag: "v1"`.
async fn etag_server(body: &'static str) -> common::TestServer {
    serve(move |req| {
        if req.header("if-none-match") == Some("\"v1\"") {
            Resp::status(304).header("ETag", "\"v1\"")
        } else {
            Resp::ok(body).header("ETag", "\"v1\"")
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_then_not_modified_writes_nothing() {
    let dir = temp_dir();
    let server = etag_server("ads.example\n0.0.0.0 track.example\n").await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/list"))]));
    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    let engine = r.engine();
    assert!(!blocked(&engine, "ads.example"));
    let st = r.status().unwrap();
    assert_eq!(st.list(1).unwrap().state, ListState::Updating);

    r.start(test_lookup()).unwrap();
    let st = wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().state == ListState::Ok && s.list(1).unwrap().in_engine
    })
    .await;
    let l = st.list(1).unwrap();
    assert_eq!(l.entries.valid, 2);
    assert_eq!(l.last_success, Some(T0));
    assert_eq!(l.phase, RefreshPhase::Idle);
    assert!(l.next_due.unwrap() >= T0 + 24 * 3600);
    assert!(blocked(&engine, "ads.example"));
    assert!(blocked(&engine, "track.example"));
    let generation = engine.generation();

    let body_path = r.cache().body_path(1);
    let meta_path = r.cache().meta_path(1);
    let body_time = mtime(&body_path);
    let meta_bytes = std::fs::read(&meta_path).unwrap();
    let meta_time = mtime(&meta_path);
    let meta = parse_meta(&meta_bytes).unwrap();
    assert_eq!(meta.etag.as_deref(), Some("\"v1\""));

    // Same time: 304, and no file changes.
    assert_eq!(r.update_now(UpdateTarget::One(1)), Ok(1));
    wait_for(&r, WAIT, |_| server.request_count() == 2).await;
    wait_for(&r, WAIT, |s| s.list(1).unwrap().phase == RefreshPhase::Idle).await;
    assert_eq!(
        server.last_request().header("if-none-match"),
        Some("\"v1\"")
    );
    assert_eq!(mtime(&body_path), body_time);
    assert_eq!(mtime(&meta_path), meta_time);
    assert_eq!(std::fs::read(&meta_path).unwrap(), meta_bytes);
    // No rebuild for "not modified".
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(engine.generation(), generation);

    // Later: 304 again; only the metadata (times) is written.
    clock.advance(100);
    r.update_now(UpdateTarget::All).unwrap();
    wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().last_success == Some(T0 + 100)
    })
    .await;
    assert_eq!(mtime(&body_path), body_time);
    let new_meta = parse_meta(&std::fs::read(&meta_path).unwrap()).unwrap();
    assert_eq!(new_meta.last_success, Some(T0 + 100));
    assert_eq!(new_meta.changed_at, Some(T0));
    assert_eq!(new_meta.body_hash, meta.body_hash);
    assert_eq!(engine.generation(), generation);
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_body_without_etag_is_not_rewritten() {
    let dir = temp_dir();
    let server = serve(|_| Resp::ok("ads.example\n")).await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/list"))]));
    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
    let generation = r.engine().generation();
    let body_time = mtime(&r.cache().body_path(1));
    clock.advance(10);
    r.update_now(UpdateTarget::One(1)).unwrap();
    wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().last_success == Some(T0 + 10)
    })
    .await;
    // No conditional header was possible, the body is the same: no body write, no build.
    assert_eq!(server.last_request().header("if-none-match"), None);
    assert_eq!(mtime(&r.cache().body_path(1)), body_time);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r.engine().generation(), generation);
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_error_gives_backoff_and_keeps_the_old_copy() {
    let dir = temp_dir();
    let fail = Arc::new(AtomicBool::new(false));
    let f = Arc::clone(&fail);
    let server = serve(move |_| {
        if f.load(Ordering::SeqCst) {
            Resp::status(500)
        } else {
            Resp::ok("ads.example\n")
        }
    })
    .await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/list"))]));
    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;

    fail.store(true, Ordering::SeqCst);
    clock.advance(5);
    r.update_now(UpdateTarget::One(1)).unwrap();
    let st = wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().phase == RefreshPhase::Backoff
    })
    .await;
    let l = st.list(1).unwrap();
    assert_eq!(l.state, ListState::Error);
    assert_eq!(l.failures, 1);
    assert_eq!(l.last_error.as_deref(), Some("HTTP 500"));
    assert_eq!(l.last_success, Some(T0));
    assert_eq!(l.last_update, Some(T0 + 5));
    // The retry is due after the base backoff (60 s).
    let due = l.next_due.unwrap();
    assert!((T0 + 5 + 59..=T0 + 5 + 61).contains(&due), "{due}");
    // The old copy is still in use and on disk.
    assert!(blocked(&r.engine(), "ads.example"));
    assert!(l.in_engine);
    assert_eq!(l.entries.valid, 1);
    let meta = parse_meta(&std::fs::read(r.cache().meta_path(1)).unwrap()).unwrap();
    assert_eq!(meta.last_error.as_deref(), Some("HTTP 500"));
    assert!(meta.body_hash.is_some());
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_cache_files_give_a_refetch() {
    let dir = temp_dir();
    let server = serve(|_| Resp::ok("fresh.example\n")).await;
    let cfg = Arc::new(config(
        dir.path(),
        &[(1, &server.url("/a")), (2, &server.url("/b"))],
    ));
    let lists = dir.path().join("lists");
    std::fs::create_dir_all(&lists).unwrap();
    // List 1: metadata that is not JSON. List 2: valid metadata, but a body with another
    // hash.
    std::fs::write(lists.join("1.json"), b"{ this is not json").unwrap();
    std::fs::write(lists.join("1.txt"), b"old.example\n").unwrap();
    let mut meta = rusthole_core::refresh::ListMeta::new(&server.url("/b"));
    meta.body_hash = Some("0".repeat(64));
    meta.etag = Some("\"old\"".into());
    meta.last_success = Some(T0);
    std::fs::write(
        lists.join("2.json"),
        rusthole_core::refresh::render_meta(&meta),
    )
    .unwrap();
    std::fs::write(lists.join("2.txt"), b"old.example\n").unwrap();

    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    // Nothing bad is used, and both lists are due at once.
    assert!(!blocked(&r.engine(), "old.example"));
    let st = r.status().unwrap();
    assert_eq!(st.list(1).unwrap().phase, RefreshPhase::Due);
    assert_eq!(st.list(2).unwrap().phase, RefreshPhase::Due);
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.lists.iter().all(|l| l.in_engine)).await;
    assert!(blocked(&r.engine(), "fresh.example"));
    // The bad body was not used for a conditional request.
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|q| q.header("if-none-match").is_none())
    );
    assert!(parse_meta(&std::fs::read(lists.join("1.json")).unwrap()).is_ok());
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_from_disk_with_the_network_down() {
    let dir = temp_dir();
    let server = serve(|_| Resp::ok("cached.example\n")).await;
    let url = server.host_url("http", "/list");
    let cfg = Arc::new(config(dir.path(), &[(1, &url)]));
    let clock = TestClock::new(T0);
    {
        let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
            .await
            .unwrap();
        r.start(test_lookup()).unwrap();
        wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
        assert!(r.shutdown(WAIT).await);
    }
    drop(server);

    // Two days later, with no network: the name lookup fails.
    clock.advance(2 * 24 * 3600);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    // The engine has the list from the disk before any fetch.
    assert!(blocked(&r.engine(), "cached.example"));
    let st = r.status().unwrap();
    assert!(st.list(1).unwrap().in_engine);
    assert_eq!(st.list(1).unwrap().state, ListState::Updating);
    r.start(Arc::new(StaticResolver::new())).unwrap();
    let st = wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().phase == RefreshPhase::Backoff
    })
    .await;
    let l = st.list(1).unwrap();
    assert_eq!(l.state, ListState::Error);
    assert!(
        l.last_error.as_deref().unwrap().contains("lists.test"),
        "{l:?}"
    );
    assert!(blocked(&r.engine(), "cached.example"));
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_cache_is_not_fetched_at_start() {
    let dir = temp_dir();
    let server = serve(|_| Resp::ok("ads.example\n")).await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    {
        let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
            .await
            .unwrap();
        r.start(test_lookup()).unwrap();
        wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
        assert!(r.shutdown(WAIT).await);
    }
    // One hour later: the list is due in 23 hours plus the jitter.
    clock.advance(3600);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    r.start(test_lookup()).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server.request_count(), 1);
    let st = r.status().unwrap();
    let l = st.list(1).unwrap();
    assert_eq!(l.phase, RefreshPhase::Idle);
    let due = l.next_due.unwrap();
    assert!(
        (T0 + 24 * 3600 - 1..=T0 + 24 * 3600 + 600 + 1).contains(&due),
        "{due}"
    );
    assert_eq!(st.schedule.next_run, Some(due));
    assert_eq!(st.schedule.interval_hours, 24);
    assert!(!st.schedule.running);
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_that_fails_to_parse_keeps_the_old_copy() {
    let dir = temp_dir();
    let big = Arc::new(AtomicBool::new(false));
    let b = Arc::clone(&big);
    let server = serve(move |_| {
        if b.load(Ordering::SeqCst) {
            Resp::ok("a.example\nb.example\nc.example\n")
        } else {
            Resp::ok("old.example\n")
        }
    })
    .await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    let mut s = settings(&cfg, &clock);
    s.parse_limits.max_entries = 2;
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
    let body = std::fs::read(r.cache().body_path(1)).unwrap();
    big.store(true, Ordering::SeqCst);
    r.update_now(UpdateTarget::One(1)).unwrap();
    let st = wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().phase == RefreshPhase::Backoff
    })
    .await;
    assert!(
        st.list(1)
            .unwrap()
            .last_error
            .as_deref()
            .unwrap()
            .contains("more than 2")
    );
    assert_eq!(std::fs::read(r.cache().body_path(1)).unwrap(), body);
    assert!(blocked(&r.engine(), "old.example"));
    assert!(!blocked(&r.engine(), "a.example"));
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_now_checks_the_target() {
    let dir = temp_dir();
    let mut c = config(
        dir.path(),
        &[(1, "http://127.0.0.1:9/a"), (2, "http://127.0.0.1:9/b")],
    );
    c.lists.adlists[1].enabled = false;
    let cfg = Arc::new(c);
    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    assert_eq!(
        r.update_now(UpdateTarget::One(7)),
        Err(UpdateError::UnknownList(7))
    );
    assert_eq!(
        r.update_now(UpdateTarget::One(2)),
        Err(UpdateError::Disabled(2))
    );
    assert_eq!(r.update_now(UpdateTarget::All), Ok(1));
    let st = r.status().unwrap();
    assert_eq!(st.list(2).unwrap().phase, RefreshPhase::Disabled);
    assert_eq!(st.list(2).unwrap().state, ListState::Never);
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_fetch_limit_is_kept() {
    let dir = temp_dir();
    let server = serve(|_| Resp::hang()).await;
    let urls: Vec<String> = (0..6).map(|i| server.url(&format!("/l{i}"))).collect();
    let lists: Vec<(u32, &str)> = urls
        .iter()
        .enumerate()
        .map(|(i, u)| (u32::try_from(i).unwrap() + 1, u.as_str()))
        .collect();
    let cfg = Arc::new(config(dir.path(), &lists));
    let clock = TestClock::new(T0);
    let mut s = settings(&cfg, &clock);
    s.max_concurrent = 2;
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |_| server.request_count() >= 2).await;
    for _ in 0..20 {
        let st = r.status().unwrap();
        let fetching = st
            .lists
            .iter()
            .filter(|l| l.phase == RefreshPhase::Fetching)
            .count();
        assert!(fetching <= 2, "{fetching}");
        assert!(server.max_open.load(Ordering::SeqCst) <= 2);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(st_running(&r));
    assert!(r.shutdown(WAIT).await);
    assert_eq!(r.task_count(), 0);
}

fn st_running(r: &Refresher) -> bool {
    r.status().unwrap().schedule.running
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_a_running_fetch_in_time() {
    let dir = temp_dir();
    let server = serve(|_| Resp::hang()).await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    let mut s = settings(&cfg, &clock);
    s.limits.total_timeout = Duration::from_secs(60);
    s.limits.read_timeout = Duration::from_secs(60);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().phase == RefreshPhase::Fetching
    })
    .await;
    // The scheduler spawns the fetch task just after the `Start` step: wait for it.
    wait_for(&r, WAIT, |_| server.request_count() == 1).await;
    assert!(r.task_count() >= 3, "{}", r.task_count());
    let start = Instant::now();
    assert!(r.shutdown(Duration::from_secs(2)).await);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(r.task_count(), 0);
    // A second shutdown is fine.
    assert!(r.shutdown(Duration::from_millis(100)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_twice_is_an_error() {
    let dir = temp_dir();
    let cfg = Arc::new(config(dir.path(), &[]));
    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    r.start(test_lookup()).unwrap();
    assert!(r.start(test_lookup()).is_err());
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_config_follows_url_and_enabled_changes() {
    let dir = temp_dir();
    let server = serve(|req| {
        if req.path == "/new" {
            Resp::ok("new.example\n")
        } else {
            Resp::ok("old.example\n")
        }
    })
    .await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/old"))]));
    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
    assert!(blocked(&r.engine(), "old.example"));

    let cfg2 = Arc::new(config(dir.path(), &[(1, &server.url("/new"))]));
    r.set_config(Arc::clone(&cfg2)).unwrap();
    wait_for(&r, WAIT, |_| blocked(&r.engine(), "new.example")).await;
    assert!(!blocked(&r.engine(), "old.example"));

    let mut c3 = (*cfg2).clone();
    c3.lists.adlists[0].enabled = false;
    r.set_config(Arc::new(c3)).unwrap();
    wait_for(&r, WAIT, |_| !blocked(&r.engine(), "new.example")).await;
    let st = r.status().unwrap();
    assert_eq!(st.list(1).unwrap().phase, RefreshPhase::Disabled);
    assert!(!st.list(1).unwrap().in_engine);
    assert!(r.shutdown(WAIT).await);
}

/// A build hook that blocks the build on its blocking thread until the test releases it.
/// By default it blocks before the swap; with `before_read`, before the build reads a body;
/// with `body_stored`, in the store step after it wrote the files.
#[derive(Clone, Default)]
struct Gate {
    armed: Arc<AtomicBool>,
    before_read: Arc<AtomicBool>,
    body_stored: Arc<AtomicBool>,
    waiting: Arc<AtomicUsize>,
    open: Arc<Mutex<bool>>,
    cv: Arc<std::sync::Condvar>,
}

impl Gate {
    fn stage(&self) -> BuildStage {
        if self.body_stored.load(Ordering::SeqCst) {
            BuildStage::BodyStored
        } else if self.before_read.load(Ordering::SeqCst) {
            BuildStage::BeforeRead
        } else {
            BuildStage::BeforeSwap
        }
    }

    fn hook(&self) -> rusthole_lists::BuildHook {
        let g = self.clone();
        Arc::new(move |stage| {
            if stage != g.stage() || !g.armed.load(Ordering::SeqCst) {
                return;
            }
            g.waiting.fetch_add(1, Ordering::SeqCst);
            let open = g.open.lock().unwrap();
            // A time limit: a broken test must not hang forever.
            let _ =
                g.cv.wait_timeout_while(open, Duration::from_secs(20), |o| !*o)
                    .unwrap();
            g.waiting.fetch_sub(1, Ordering::SeqCst);
        })
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queries_use_the_old_engine_during_a_slow_build() {
    let dir = temp_dir();
    let v2 = Arc::new(AtomicBool::new(false));
    let v = Arc::clone(&v2);
    let server = serve(move |_| {
        if v.load(Ordering::SeqCst) {
            Resp::ok("old.example\nnew.example\n")
        } else {
            Resp::ok("old.example\n")
        }
    })
    .await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    let gate = Gate::default();
    let mut s = settings(&cfg, &clock);
    s.build_hook = Some(gate.hook());
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
    let engine = r.engine();
    let generation = engine.generation();

    // The next build blocks before its swap.
    gate.armed.store(true, Ordering::SeqCst);
    v2.store(true, Ordering::SeqCst);
    r.update_now(UpdateTarget::One(1)).unwrap();
    wait_for(&r, WAIT, |_| gate.waiting.load(Ordering::SeqCst) == 1).await;
    assert!(r.status().unwrap().engine.building);

    // Three more build requests during the build: they give one more build, not three.
    for _ in 0..3 {
        r.set_config(Arc::clone(&cfg)).unwrap();
    }

    // Queries get answers from the old engine while the build waits: 2000 checks end while
    // the gate is closed, so no check waits for the build.
    let worker = {
        let engine = engine.clone();
        std::thread::spawn(move || {
            for _ in 0..2000 {
                assert!(blocked(&engine, "old.example"));
                assert!(!blocked(&engine, "new.example"));
            }
        })
    };
    worker.join().unwrap();
    assert_eq!(gate.waiting.load(Ordering::SeqCst), 1);
    assert_eq!(engine.generation(), generation);

    gate.release();
    wait_for(&r, WAIT, |_| engine.generation() >= generation + 2).await;
    assert!(blocked(&engine, "new.example"));
    // No third build.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(engine.generation(), generation + 2);
    assert!(!r.status().unwrap().engine.building);
    assert!(r.shutdown(WAIT).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_during_a_build_never_swaps() {
    let dir = temp_dir();
    let server = serve(|_| Resp::ok("late.example\n")).await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    let gate = Gate::default();
    gate.armed.store(true, Ordering::SeqCst);
    let mut s = settings(&cfg, &clock);
    s.build_hook = Some(gate.hook());
    // The first build (at load) passes the gate: open it for the load only.
    gate.armed.store(false, Ordering::SeqCst);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    gate.armed.store(true, Ordering::SeqCst);
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |_| gate.waiting.load(Ordering::SeqCst) == 1).await;
    let engine = r.engine();
    let generation = engine.generation();
    let start = Instant::now();
    assert!(r.shutdown(Duration::from_secs(2)).await);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(r.task_count(), 0);
    gate.release();
    // The build thread ends; it must not swap after the stop.
    for _ in 0..50 {
        if gate.waiting.load(Ordering::SeqCst) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(engine.generation(), generation);
    assert!(!blocked(&engine, "late.example"));
}

fn requests_to(server: &common::TestServer, path: &str) -> usize {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|q| q.path == path)
        .count()
}

/// A fetch of a list that is disabled during the fetch still counts for the global limit,
/// and the list does not start a second fetch while the first one runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_of_a_disabled_list_still_counts() {
    let dir = temp_dir();
    let server = serve(|_| Resp::hang()).await;
    let urls: Vec<String> = (1..=3).map(|i| server.url(&format!("/l{i}"))).collect();
    let cfg = Arc::new(config(
        dir.path(),
        &[(1, &urls[0]), (2, &urls[1]), (3, &urls[2])],
    ));
    let clock = TestClock::new(T0);
    let mut s = settings(&cfg, &clock);
    s.max_concurrent = 2;
    s.limits.total_timeout = Duration::from_secs(60);
    s.limits.read_timeout = Duration::from_secs(60);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |_| server.request_count() == 2).await;
    assert_eq!(requests_to(&server, "/l1"), 1);
    assert_eq!(requests_to(&server, "/l2"), 1);

    // Disable list 1 during its fetch: the fetch still runs, so list 3 does not start.
    let mut off = (*cfg).clone();
    off.lists.adlists[0].enabled = false;
    r.set_config(Arc::new(off)).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(server.request_count(), 2);
    assert_eq!(
        r.status().unwrap().list(1).unwrap().phase,
        RefreshPhase::Disabled
    );

    // Enable it again: no second fetch of list 1 while the first one runs.
    r.set_config(Arc::clone(&cfg)).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(requests_to(&server, "/l1"), 1);
    assert_eq!(server.request_count(), 2);
    assert_eq!(
        r.status().unwrap().list(1).unwrap().phase,
        RefreshPhase::Due
    );
    assert!(r.shutdown(WAIT).await);
    assert_eq!(r.task_count(), 0);
}

/// The result of a fetch of a list that was disabled and enabled again during the fetch is
/// not used; the list is then fetched again. A removed list gets no cache file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_of_a_changed_list_is_not_used() {
    let dir = temp_dir();
    let server = serve(|req| {
        let name = req.path.trim_start_matches('/');
        Resp::ok(format!("{name}.example\n")).delayed(Duration::from_millis(500))
    })
    .await;
    let cfg = Arc::new(config(
        dir.path(),
        &[(1, &server.url("/one")), (2, &server.url("/two"))],
    ));
    let clock = TestClock::new(T0);
    let r = Refresher::load(Arc::clone(&cfg), settings(&cfg, &clock))
        .await
        .unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |_| server.request_count() == 2).await;

    // List 1: off and on again. List 2: removed.
    let mut off = (*cfg).clone();
    off.lists.adlists[0].enabled = false;
    off.lists.adlists.truncate(1);
    r.set_config(Arc::new(off)).unwrap();
    let mut on = (*cfg).clone();
    on.lists.adlists.truncate(1);
    r.set_config(Arc::new(on)).unwrap();

    // The first fetch of list 1 ends and is not used; a second fetch starts and is used.
    let st = wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
    assert_eq!(requests_to(&server, "/one"), 2);
    assert_eq!(st.list(1).unwrap().phase, RefreshPhase::Idle);
    assert_eq!(st.list(1).unwrap().failures, 0);
    assert!(st.list(2).is_none());
    assert!(blocked(&r.engine(), "one.example"));
    // The fetch of the removed list wrote no file.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!r.cache().body_path(2).exists());
    assert!(!r.cache().meta_path(2).exists());
    assert!(!blocked(&r.engine(), "two.example"));
    assert!(r.shutdown(WAIT).await);
}

/// A fetch that stores a new body while a build reads the bodies: the build reads the old
/// body (the store step waits for the work permit), so the list never leaves the engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_stored_during_a_build_keeps_the_list_in_the_engine() {
    let dir = temp_dir();
    let v2 = Arc::new(AtomicBool::new(false));
    let v = Arc::clone(&v2);
    let server = serve(move |_| {
        if v.load(Ordering::SeqCst) {
            Resp::ok("old.example\nnew.example\n")
        } else {
            Resp::ok("old.example\n")
        }
    })
    .await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    let gate = Gate::default();
    gate.before_read.store(true, Ordering::SeqCst);
    // Each build records a miss when the engine before it does not block old.example.
    let engine_cell: Arc<OnceLock<rusthole_lists::EngineHandle>> = Arc::default();
    let misses = Arc::new(AtomicUsize::new(0));
    let hook = {
        let gate_hook = gate.hook();
        let cell = Arc::clone(&engine_cell);
        let misses = Arc::clone(&misses);
        Arc::new(move |stage: BuildStage| {
            if stage == BuildStage::BeforeRead
                && let Some(e) = cell.get()
                && !blocked(e, "old.example")
            {
                misses.fetch_add(1, Ordering::SeqCst);
            }
            gate_hook(stage);
        })
    };
    let mut s = settings(&cfg, &clock);
    s.build_hook = Some(hook);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
    let engine = r.engine();
    assert!(engine_cell.set(engine.clone()).is_ok());
    let body = std::fs::read(r.cache().body_path(1)).unwrap();

    // A build stops before it reads the bodies.
    gate.armed.store(true, Ordering::SeqCst);
    r.set_config(Arc::clone(&cfg)).unwrap();
    wait_for(&r, WAIT, |_| gate.waiting.load(Ordering::SeqCst) == 1).await;
    // A fetch gets a new body during the build: its store step waits.
    v2.store(true, Ordering::SeqCst);
    r.update_now(UpdateTarget::One(1)).unwrap();
    wait_for(&r, WAIT, |_| server.request_count() == 2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(std::fs::read(r.cache().body_path(1)).unwrap(), body);
    assert_eq!(
        r.status().unwrap().list(1).unwrap().phase,
        RefreshPhase::Fetching
    );

    gate.armed.store(false, Ordering::SeqCst);
    gate.release();
    wait_for(&r, WAIT, |s| {
        blocked(&engine, "new.example")
            && s.list(1).unwrap().phase == RefreshPhase::Idle
            && !s.engine.building
    })
    .await;
    assert!(blocked(&engine, "old.example"));
    assert!(r.status().unwrap().list(1).unwrap().in_engine);
    assert_eq!(misses.load(Ordering::SeqCst), 0);
    assert!(r.shutdown(WAIT).await);
}

/// A build that takes longer than its limit keeps the work permit until it stops: the next
/// build never runs at the same time, and `building` stays true until the first one ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_build_that_took_too_long_blocks_the_next_build() {
    let dir = temp_dir();
    let server = serve(|_| Resp::ok("ads.example\n")).await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    let armed = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let hook = {
        let (armed, active, max_active, calls) = (
            Arc::clone(&armed),
            Arc::clone(&active),
            Arc::clone(&max_active),
            Arc::clone(&calls),
        );
        Arc::new(move |stage: BuildStage| {
            if stage != BuildStage::BeforeSwap || !armed.load(Ordering::SeqCst) {
                return;
            }
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            max_active.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1000));
            active.fetch_sub(1, Ordering::SeqCst);
            calls.fetch_add(1, Ordering::SeqCst);
        })
    };
    let mut s = settings(&cfg, &clock);
    s.build_hook = Some(hook);
    s.build_timeout = Duration::from_millis(300);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| s.list(1).unwrap().in_engine).await;
    let engine = r.engine();
    let generation = engine.generation();

    armed.store(true, Ordering::SeqCst);
    r.set_config(Arc::clone(&cfg)).unwrap();
    wait_for(&r, WAIT, |_| active.load(Ordering::SeqCst) == 1).await;
    // The first build is over its limit, but its thread still runs.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(r.status().unwrap().engine.building);
    r.set_config(Arc::clone(&cfg)).unwrap();
    wait_for(&r, WAIT, |s| {
        calls.load(Ordering::SeqCst) >= 1
            && active.load(Ordering::SeqCst) == 0
            && !s.engine.building
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(max_active.load(Ordering::SeqCst), 1);
    // The build that took too long did not swap.
    assert_eq!(engine.generation(), generation);

    // The next build works.
    armed.store(false, Ordering::SeqCst);
    r.set_config(Arc::clone(&cfg)).unwrap();
    wait_for(&r, WAIT, |_| engine.generation() == generation + 1).await;
    assert!(blocked(&engine, "ads.example"));
    assert!(r.shutdown(WAIT).await);
}

/// A list that is disabled and enabled again during its fetch does not start a second
/// fetch, also when a fetch slot is free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_never_has_two_fetches() {
    let dir = temp_dir();
    let server = serve(|_| Resp::hang()).await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l1"))]));
    let clock = TestClock::new(T0);
    let mut s = settings(&cfg, &clock);
    s.limits.total_timeout = Duration::from_secs(60);
    s.limits.read_timeout = Duration::from_secs(60);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |_| server.request_count() == 1).await;
    let mut off = (*cfg).clone();
    off.lists.adlists[0].enabled = false;
    r.set_config(Arc::new(off)).unwrap();
    r.set_config(Arc::clone(&cfg)).unwrap();
    r.update_now(UpdateTarget::One(1)).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(requests_to(&server, "/l1"), 1);
    assert_eq!(
        r.status().unwrap().list(1).unwrap().phase,
        RefreshPhase::Due
    );
    assert!(r.shutdown(WAIT).await);
}

/// The store step keeps the work permit until the new hash is in the state: a build that is
/// asked for between the body write and that step waits, so it never reads a new body with
/// an old hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_build_waits_until_a_stored_body_is_in_the_state() {
    let dir = temp_dir();
    let v2 = Arc::new(AtomicBool::new(false));
    let v = Arc::clone(&v2);
    let server = serve(move |_| {
        if v.load(Ordering::SeqCst) {
            Resp::ok(
                "old.example
new.example
",
            )
        } else {
            Resp::ok(
                "old.example
",
            )
        }
    })
    .await;
    let cfg = Arc::new(config(dir.path(), &[(1, &server.url("/l"))]));
    let clock = TestClock::new(T0);
    let gate = Gate::default();
    gate.body_stored.store(true, Ordering::SeqCst);
    // Each build records a miss when the engine before it does not block old.example.
    let engine_cell: Arc<OnceLock<rusthole_lists::EngineHandle>> = Arc::default();
    let misses = Arc::new(AtomicUsize::new(0));
    let hook = {
        let gate_hook = gate.hook();
        let cell = Arc::clone(&engine_cell);
        let misses = Arc::clone(&misses);
        Arc::new(move |stage: BuildStage| {
            if stage == BuildStage::BeforeRead
                && let Some(e) = cell.get()
                && !blocked(e, "old.example")
            {
                misses.fetch_add(1, Ordering::SeqCst);
            }
            gate_hook(stage);
        })
    };
    let mut s = settings(&cfg, &clock);
    s.build_hook = Some(hook);
    let r = Refresher::load(Arc::clone(&cfg), s).await.unwrap();
    r.start(test_lookup()).unwrap();
    wait_for(&r, WAIT, |s| {
        s.list(1).unwrap().in_engine && !s.engine.building
    })
    .await;
    let engine = r.engine();
    assert!(engine_cell.set(engine.clone()).is_ok());
    let generation = engine.generation();

    // The store step of a new body stops after its writes.
    gate.armed.store(true, Ordering::SeqCst);
    v2.store(true, Ordering::SeqCst);
    r.update_now(UpdateTarget::One(1)).unwrap();
    wait_for(&r, WAIT, |_| gate.waiting.load(Ordering::SeqCst) == 1).await;
    assert_eq!(
        std::fs::read(r.cache().body_path(1)).unwrap(),
        b"old.example
new.example
"
    );
    // A build request now: the build waits for the work permit.
    r.set_config(Arc::clone(&cfg)).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(engine.generation(), generation);
    assert!(blocked(&engine, "old.example"));

    gate.armed.store(false, Ordering::SeqCst);
    gate.release();
    wait_for(&r, WAIT, |s| {
        blocked(&engine, "new.example")
            && s.list(1).unwrap().phase == RefreshPhase::Idle
            && !s.engine.building
    })
    .await;
    assert!(blocked(&engine, "old.example"));
    assert!(r.status().unwrap().list(1).unwrap().in_engine);
    assert_eq!(misses.load(Ordering::SeqCst), 0);
    assert!(r.shutdown(WAIT).await);
}
