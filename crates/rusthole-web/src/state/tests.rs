use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;

use super::*;
use crate::config_edit::{FileWriter, write_atomic};

const TEXT: &str = "config_version = 1\n\n[blocking]\nenabled = true\n";

/// Counts the live applies.
#[derive(Debug, Default)]
struct CountApply(AtomicUsize, Option<Vec<(String, SocketAddr)>>);

impl LiveApply for CountApply {
    fn apply(&self, _old: &Config, _new: &Arc<Config>) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        false
    }

    fn listeners(&self) -> Option<Vec<(String, SocketAddr)>> {
        self.1.clone()
    }
}

fn state_with(store: ConfigStore, live: Arc<CountApply>) -> AppState {
    AppState::new(AdminDeps {
        config: Arc::new(store),
        clock: crate::clock::ManualClock::new(0),
        stats: None,
        lists: None,
        engine: rusthole_dns::engine_handle(PolicyEngine::default()),
        blocking: Arc::new(BlockingControl::new(true)),
        live,
        tls: None,
        system: SystemStatic::default(),
        interfaces: Arc::new(rusthole_dns::StaticInterfaces::default()),
        assets: Arc::new(crate::assets::PlaceholderAssets),
    })
}

/// A writer that tells `started` when it runs, then waits for `release` (at most 10 s), then
/// writes the file.
fn gated_writer(
    started: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
) -> FileWriter {
    let release = std::sync::Mutex::new(release);
    Arc::new(move |path: &Path, data: &[u8]| {
        let _ = started.send(());
        if let Ok(rx) = release.lock() {
            let _ = rx.recv_timeout(Duration::from_secs(10));
        }
        write_atomic(path, data)
    })
}

fn file_config(path: &Path) -> Config {
    let mut c = Config::from_toml_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    c.assign_ids();
    c
}

/// m15: a request that is dropped during the file write must not leave the new file on disk
/// and the old config in memory. The write, the memory state and the live apply run in one
/// task that the request cannot cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_write_request_keeps_the_file_and_the_memory_equal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, TEXT).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (store, _) = ConfigStore::open(&path).unwrap();
    let store = store.with_writer(gated_writer(started_tx, release_rx));
    let live = Arc::new(CountApply::default());
    let state = state_with(store, Arc::clone(&live));
    let mut fut = Box::pin(state.write(|c| {
        c.blocking.enabled = false;
        Ok(())
    }));
    // Poll the request until the writer runs, then drop the request.
    let wait_started = tokio::task::spawn_blocking(move || {
        started_rx.recv_timeout(Duration::from_secs(10)).is_ok()
    });
    tokio::select! {
        _ = &mut fut => panic!("the write must wait for the writer"),
        ok = wait_started => assert!(ok.unwrap(), "the writer did not start"),
    }
    drop(fut);
    release_tx.send(()).unwrap();
    // The file gets the change; the memory must get it too.
    let mut same = false;
    for _ in 0..500 {
        let disk = file_config(&path);
        if !disk.blocking.enabled && *state.config() == disk {
            same = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(same, "the memory state differs from the file");
    assert_eq!(live.0.load(Ordering::SeqCst), 1, "the live apply must run");
}

/// m15: a write that takes longer than the I/O limit and then ends must not leave the memory
/// state and the file different.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_write_keeps_the_file_and_the_memory_equal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, TEXT).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (store, _) = ConfigStore::open(&path).unwrap();
    let store = store
        .with_writer(gated_writer(started_tx, release_rx))
        .with_io_timeout(Duration::from_secs(1));
    let live = Arc::new(CountApply::default());
    let state = state_with(store, Arc::clone(&live));
    let release = tokio::task::spawn_blocking(move || {
        assert!(started_rx.recv_timeout(Duration::from_secs(10)).is_ok());
        // The write ends after the first time limit.
        std::thread::sleep(Duration::from_millis(1500));
        release_tx.send(()).unwrap();
    });
    let _ = state
        .write(|c| {
            c.blocking.enabled = false;
            Ok(())
        })
        .await;
    release.await.unwrap();
    // The late write lands. A read request after it (no write, no login) must see the same
    // state in memory as on disk.
    let mut disk = file_config(&path);
    for _ in 0..500 {
        if !disk.blocking.enabled {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        disk = file_config(&path);
    }
    assert!(!disk.blocking.enabled, "the late write did not land");
    assert_eq!(
        *state.config(),
        disk,
        "the memory state differs from the file"
    );
    assert_eq!(live.0.load(Ordering::SeqCst), 1);
}

/// m13: a login that read the credentials before a change gets no session.
#[tokio::test]
async fn a_login_that_read_old_credentials_gets_no_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rusthole.toml");
    std::fs::write(&path, TEXT).unwrap();
    let (store, _) = ConfigStore::open(&path).unwrap();
    let state = state_with(store, Arc::new(CountApply::default()));
    let before = state.0.auth.generation().unwrap();
    let old = state.config();
    let mut new = (*old).clone();
    new.admin.password_hash = "$argon2id$changed".to_owned();
    state.apply_config(&old, &Arc::new(new), None);
    assert!(crate::auth::new_session(&state, before).is_err());
    let now = state.0.auth.generation().unwrap();
    assert!(crate::auth::new_session(&state, now).is_ok());
}

/// m18: `GET /system` lists the DNS and DoH addresses of the live parts, read at request
/// time, and the bound admin addresses.
#[test]
fn system_listeners_are_read_now() {
    let a = |s: &str| s.parse::<SocketAddr>().unwrap();
    let live = vec![
        ("dns".to_owned(), a("192.0.2.2:53")),
        ("doh".to_owned(), a("192.0.2.2:443")),
    ];
    let store = ConfigStore::new(
        PathBuf::from("unused.toml"),
        TEXT.to_owned(),
        &Config::default(),
    );
    let state = state_with(
        store,
        Arc::new(CountApply(AtomicUsize::new(0), Some(live.clone()))),
    );
    state.set_admin_bound(&[a("192.0.2.2:8443")]);
    let mut want = live;
    want.push(("admin".to_owned(), a("192.0.2.2:8443")));
    assert_eq!(state.listeners(), want);
}
