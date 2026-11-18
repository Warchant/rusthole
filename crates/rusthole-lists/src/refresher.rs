//! The list refresher: the I/O shell around [`rusthole_core::refresh`].
//!
//! ```mermaid
//! sequenceDiagram
//!     participant B as binary
//!     participant R as Refresher
//!     participant D as disk cache
//!     participant E as EngineHandle
//!     B->>R: load(config, settings)
//!     R->>D: read metadata, read and parse each body (blocking thread)
//!     R->>E: first engine (swap)
//!     B->>B: start DNS with the engine handle
//!     B->>R: start(host lookup)
//!     loop scheduler (service loop)
//!         R->>R: Tick; start due lists (at most max_concurrent)
//!         R->>R: fetch -> store body (blocking) -> outcome event
//!         R->>E: build on a blocking thread, then swap (one build at a time)
//!     end
//!     B->>R: shutdown(deadline)
//! ```
//!
//! - Tasks: one scheduler, one builder, one task for each running fetch. All of them are in
//!   one `TaskTracker` and stop on one cancel token. [`Refresher::shutdown`] waits for them
//!   with a deadline.
//! - The state lock is held for short pure steps only, never across I/O or an `.await`.
//!   Each lock has a time limit ([`LOCK_TIMEOUT`]). The shell reads the monotonic time
//!   after it gets the lock, so the machines get their events in time order.
//! - Fetches: the state has a map of the running fetches (list id and fetch number). A list
//!   in the map does not start a second fetch, and the global limit counts the map. A fetch
//!   stays in the map until its task ends, also when the list is disabled, removed or gets a
//!   new URL. Such a fetch writes no file and does not change the machine.
//! - Heavy work: one work permit (a semaphore with one permit) for the store step of a new
//!   body (parse and write) and for the build (read, parse, build, swap). Thus at most one
//!   parse or build runs at a time. The blocking thread holds the permit until it ends, also
//!   after its async caller timed out. The store step puts the new hash in the state before
//!   it gives back the permit, and the build copies the hashes after it gets the permit. Thus
//!   a build never reads a body that does not agree with its copied hash.
//! - Builds: a request during a build makes one more build after it (`Notify` keeps one
//!   permit, so many requests give one build). The build reads and parses one list at a
//!   time from disk, largest first, and checks the body hash. A build that is cancelled or
//!   takes longer than its limit does not swap.
//!
//! ```mermaid
//! flowchart LR
//!     F[fetch: body in RAM] --> W{work permit}
//!     W --> S[store: parse, write body and metadata, new hash into the state]
//!     W --> B[build: copy hashes, read and parse bodies, build, swap]
//!     S -->|Updated| N[build request]
//!     N --> B
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, MutexGuard};
use rusthole_core::Config;
use rusthole_core::config::Adlist;
use rusthole_core::lists::{self, ListFormat, ParseLimits, ParsedList};
use rusthole_core::policy::{BuildReport, ListStatus as BuildListStatus};
use rusthole_core::refresh::{
    BodyFacts, EntryCounts, ListMeta, ListRefresh, MonoTime, RefreshEvent, RefreshPolicy,
    RefreshState, Validators, initial_due,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::engine::{EngineHandle, build_engine};
use crate::fetch::{FetchError, FetchLimits, FetchOutcome, Fetcher};
use crate::resolver::HostLookup;
use crate::status::{
    EngineStatus, ListState, ListStatus, ListsStatus, RefreshPhase, ScheduleStatus,
};
use crate::store::{DiskCache, MetaLoad, ReadError};

/// Time limit for the state lock. The lock is held for microseconds, so a wait this long
/// means a bug; the caller then skips the step and logs an ERROR.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
/// Default number of fetches that run at the same time.
pub const DEFAULT_MAX_CONCURRENT: usize = 3;
/// The highest allowed number of fetches at the same time.
pub const MAX_CONCURRENT: usize = 4;
/// Longest sleep of the scheduler. It looks at the lists at least this often.
pub const MAX_SLEEP: Duration = Duration::from_secs(60);
/// Default time limit for one engine build.
pub const BUILD_TIMEOUT: Duration = Duration::from_mins(10);
/// Time limit to read the metadata files at load.
const META_LOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// Time limit to store one fetched body (hash, parse, write).
const STORE_TIMEOUT: Duration = Duration::from_mins(5);

/// The wall clock in Unix seconds (an input, so that tests can fix it).
pub type WallClock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// A test hook: the build and the store step call it on their blocking threads at each
/// [`BuildStage`].
pub type BuildHook = Arc<dyn Fn(BuildStage) + Send + Sync>;

/// The points in a build at which the build calls the test hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildStage {
    /// The build has the work permit and copied the list hashes. It did not read a body.
    BeforeRead,
    /// The build made the new engine. It did not swap it in.
    BeforeSwap,
    /// The store step of a fetch with a body wrote its files. It did not put the result in
    /// the state, and it still has the work permit.
    BodyStored,
}

/// The system wall clock in Unix seconds.
pub fn system_wall_clock() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Settings of the refresher.
#[derive(Clone)]
pub struct ListsSettings {
    /// The data directory. The cache is in `<data_dir>/lists`.
    pub data_dir: PathBuf,
    /// Limits of one fetch.
    pub limits: FetchLimits,
    /// Limits of one list parse.
    pub parse_limits: ParseLimits,
    /// Fetches at the same time, `1..=MAX_CONCURRENT`.
    pub max_concurrent: usize,
    /// First retry delay after a failed fetch (at least one second).
    pub base_backoff: Duration,
    /// Longest sleep of the scheduler.
    pub max_sleep: Duration,
    /// Time limit for one engine build.
    pub build_timeout: Duration,
    /// The wall clock.
    pub wall_clock: WallClock,
    /// The TLS client config. `None`: the system roots (or the bundled roots) from
    /// `rusthole-tls`.
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// A test hook in each build (see [`BuildStage`]).
    pub build_hook: Option<BuildHook>,
}

impl fmt::Debug for ListsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListsSettings")
            .field("data_dir", &self.data_dir)
            .field("limits", &self.limits)
            .field("parse_limits", &self.parse_limits)
            .field("max_concurrent", &self.max_concurrent)
            .field("base_backoff", &self.base_backoff)
            .field("max_sleep", &self.max_sleep)
            .field("build_timeout", &self.build_timeout)
            .field("tls", &self.tls.is_some())
            .field("build_hook", &self.build_hook.is_some())
            .finish_non_exhaustive()
    }
}

impl ListsSettings {
    /// Default settings for the data directory of `config`.
    pub fn from_config(config: &Config) -> Self {
        Self {
            data_dir: PathBuf::from(&config.server.data_dir),
            limits: FetchLimits::default(),
            parse_limits: ParseLimits::default(),
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            base_backoff: rusthole_core::refresh::DEFAULT_BASE_BACKOFF,
            max_sleep: MAX_SLEEP,
            build_timeout: BUILD_TIMEOUT,
            wall_clock: Arc::new(system_wall_clock),
            tls: None,
            build_hook: None,
        }
    }
}

/// Which lists an "update now" applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateTarget {
    /// One list.
    One(u32),
    /// Each enabled list.
    All,
}

/// Why an "update now" was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    /// No list has this id.
    #[error("no list has the id {0}")]
    UnknownList(u32),
    /// The list is disabled.
    #[error("the list {0} is disabled")]
    Disabled(u32),
    /// The refresher is busy (the state lock timed out).
    #[error("the refresher is busy")]
    Busy,
}

/// Why the refresher did not load or start.
#[derive(Debug, thiserror::Error)]
pub enum RefresherError {
    /// A blocking task failed or timed out.
    #[error("the list cache cannot be read: {0}")]
    Load(String),
    /// The HTTP client cannot start.
    #[error("{0}")]
    Fetch(#[from] FetchError),
    /// The TLS client config cannot be made.
    #[error("TLS: {0}")]
    Tls(String),
    /// `start` was called before.
    #[error("the refresher already runs")]
    AlreadyStarted,
}

/// One list in the refresher.
#[derive(Debug, Clone)]
struct Slot {
    list: Adlist,
    machine: Option<ListRefresh>,
    /// The current metadata of the list (for its current URL).
    meta: ListMeta,
    /// The metadata on disk, as it was last read or written.
    disk_meta: Option<ListMeta>,
    /// The body on disk matches `meta` (checked by the last build, or written by a fetch).
    body_ok: bool,
    /// The current engine uses the list.
    in_engine: bool,
}

impl Slot {
    fn new(list: Adlist, disk_meta: Option<ListMeta>) -> Self {
        let meta = disk_meta
            .as_ref()
            .filter(|m| m.url == list.url)
            .cloned()
            .unwrap_or_else(|| ListMeta::new(&list.url));
        let body_ok = meta.has_body_for(&list.url);
        Self {
            list,
            machine: None,
            meta,
            disk_meta,
            body_ok,
            in_engine: false,
        }
    }

    /// The validators for a conditional GET: only when a good body is on disk.
    fn conditional(&self) -> Option<Validators> {
        (self.body_ok && self.meta.has_body_for(&self.list.url)).then(|| Validators {
            etag: self.meta.etag.clone(),
            last_modified: self.meta.last_modified.clone(),
        })
    }

    /// The last success, for the schedule: only with a good body on disk.
    fn last_success(&self) -> Option<i64> {
        (self.body_ok && self.meta.has_body_for(&self.list.url))
            .then_some(self.meta.last_success)
            .flatten()
    }
}

#[derive(Debug, Default)]
struct BuildState {
    running: bool,
    last_build: Option<i64>,
    unique_domains: usize,
    entries: usize,
    memory_bytes: usize,
    issues: usize,
    count: u64,
}

/// One running fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    /// The fetch number (one number for each `Start`).
    seq: u64,
    /// False when the list was disabled, removed or got a new URL during the fetch. The
    /// result of the fetch is then not used.
    live: bool,
}

#[derive(Debug)]
struct State {
    config: Arc<Config>,
    policy: RefreshPolicy,
    lists: BTreeMap<u32, Slot>,
    build: BuildState,
    /// The running fetches by list id. A list id is in the map from its `Start` until its
    /// fetch task ends. The map has at most `MAX_CONCURRENT` entries: only `tick` adds an
    /// entry, and it counts the map first.
    fetching: BTreeMap<u32, InFlight>,
    /// The number for the next fetch.
    next_fetch: u64,
}

impl State {
    /// Marks a running fetch of `id` as not used (see [`InFlight::live`]).
    fn orphan(&mut self, id: u32) {
        if let Some(f) = self.fetching.get_mut(&id) {
            f.live = false;
        }
    }
}

struct Inner {
    settings: ListsSettings,
    cache: DiskCache,
    engine: EngineHandle,
    state: Mutex<State>,
    origin: Instant,
    wake: Notify,
    build_wanted: Notify,
    /// The work permit for the heavy blocking work (store step of a new body, build).
    work: Arc<Semaphore>,
    tracker: TaskTracker,
    cancel: CancellationToken,
    fetcher: OnceLock<Fetcher>,
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner")
            .field("settings", &self.settings)
            .field("cache", &self.cache)
            .field("engine", &self.engine)
            .field("tasks", &self.tracker.len())
            .finish_non_exhaustive()
    }
}

/// The list refresher. Dropping it cancels all its tasks; prefer [`Refresher::shutdown`].
#[derive(Debug)]
pub struct Refresher {
    inner: Arc<Inner>,
}

impl Drop for Refresher {
    fn drop(&mut self) {
        self.inner.cancel.cancel();
        self.inner.tracker.close();
    }
}

/// One fetch to run.
#[derive(Debug, Clone)]
struct FetchJob {
    id: u32,
    /// The fetch number (see [`InFlight::seq`]).
    seq: u64,
    url: String,
    conditional: Option<Validators>,
    /// The metadata to merge the result into.
    base: ListMeta,
    /// The metadata on disk.
    disk: Option<ListMeta>,
    body_ok: bool,
}

/// What a fetch did, for the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Updated,
    NotModified,
    Failed,
}

/// The result of one fetch after the store step.
#[derive(Debug)]
struct Finished {
    outcome: Outcome,
    meta: ListMeta,
    /// The metadata on disk after the store step.
    disk: Option<ListMeta>,
    /// The body on disk is good for `meta`.
    body_ok: bool,
}

/// A list for a build.
#[derive(Debug, Clone)]
struct BuildInput {
    id: u32,
    hash: String,
    size: u64,
}

/// What a build found for one list body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyCheck {
    Ok,
    Bad(String),
}

#[derive(Debug)]
struct BuildOutput {
    report: BuildReport,
    checks: Vec<(u32, String, BodyCheck)>,
}

impl Refresher {
    /// Loads every list from the disk cache, builds the first engine and swaps it in. No
    /// network. A missing or corrupt cache file is a WARN; the list is then due at once.
    ///
    /// The builder task starts here. Call [`Refresher::start`] to start the downloads.
    pub async fn load(
        config: Arc<Config>,
        settings: ListsSettings,
    ) -> Result<Self, RefresherError> {
        let cache = DiskCache::new(&settings.data_dir);
        let ids: Vec<u32> = config.lists.adlists.iter().map(|l| l.id).collect();
        let c = cache.clone();
        let read = tokio::task::spawn_blocking(move || {
            if let Err(e) = c.ensure_dir() {
                tracing::warn!(dir = %c.dir().display(), error = %e, "cannot make the list cache directory");
            }
            ids.into_iter()
                .map(|id| (id, c.load_meta(id)))
                .collect::<Vec<_>>()
        });
        let metas = match tokio::time::timeout(META_LOAD_TIMEOUT, read).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => return Err(RefresherError::Load(e.to_string())),
            Err(_) => return Err(RefresherError::Load("timeout".to_owned())),
        };
        let mut disk: BTreeMap<u32, Option<ListMeta>> = BTreeMap::new();
        for (id, load) in metas {
            let meta = match load {
                MetaLoad::Found(m) => Some(m),
                MetaLoad::Missing => None,
                MetaLoad::Corrupt(e) => {
                    tracing::warn!(list = id, error = %e, "the list metadata file is not valid; the list is fetched again");
                    None
                }
            };
            disk.insert(id, meta);
        }
        let mut lists = BTreeMap::new();
        for adlist in &config.lists.adlists {
            let disk_meta = disk.get(&adlist.id).cloned().flatten();
            if disk_meta.as_ref().is_some_and(|m| m.url != adlist.url) {
                tracing::warn!(
                    list = adlist.id,
                    "the list cache is for another URL; the list is fetched again"
                );
            }
            lists.insert(adlist.id, Slot::new(adlist.clone(), disk_meta));
        }
        let policy = policy_for(&config, &settings);
        // The first handle has the rules of the config and no list, with a random seed. The
        // first build below replaces it with the cached lists.
        let engine = EngineHandle::new(build_engine(&config, std::iter::empty()).0);
        let inner = Arc::new(Inner {
            cache,
            engine,
            state: Mutex::new(State {
                config,
                policy,
                lists,
                build: BuildState::default(),
                fetching: BTreeMap::new(),
                next_fetch: 0,
            }),
            origin: Instant::now(),
            wake: Notify::new(),
            build_wanted: Notify::new(),
            work: Arc::new(Semaphore::new(1)),
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
            fetcher: OnceLock::new(),
            settings,
        });
        let refresher = Self {
            inner: Arc::clone(&inner),
        };
        inner.run_build().await;
        // The machines start after the first build: it found the bad bodies.
        let wall = (inner.settings.wall_clock)();
        if let Some((mut st, now)) = inner.lock() {
            let policy = st.policy;
            for slot in st.lists.values_mut() {
                if slot.list.enabled {
                    let due = initial_due(&policy, slot.list.id, now, wall, slot.last_success());
                    let mut machine = ListRefresh::new(slot.list.id, due);
                    // A list that is due at once shows as due before the start.
                    let _ = machine.step(&policy, RefreshEvent::Tick(now));
                    slot.machine = Some(machine);
                }
            }
        }
        let builder = Arc::clone(&inner);
        let cancel = inner.cancel.clone();
        inner.tracker.spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = builder.build_loop() => {}
            }
        });
        Ok(refresher)
    }

    /// Starts the downloads: the scheduler fetches due lists in the background. Names are
    /// looked up with `lookup` (production: the upstream pool of the DNS server).
    pub fn start(&self, lookup: Arc<dyn HostLookup>) -> Result<(), RefresherError> {
        let tls = match &self.inner.settings.tls {
            Some(t) => Arc::clone(t),
            None => {
                rusthole_tls::client_config(vec![b"http/1.1".to_vec()])
                    .map_err(|e| RefresherError::Tls(e.to_string()))?
                    .0
            }
        };
        let fetcher = Fetcher::new(self.inner.settings.limits, tls, lookup)?;
        self.inner
            .fetcher
            .set(fetcher)
            .map_err(|_| RefresherError::AlreadyStarted)?;
        let inner = Arc::clone(&self.inner);
        let cancel = self.inner.cancel.clone();
        self.inner.tracker.spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = inner.schedule_loop() => {}
            }
        });
        Ok(())
    }

    /// The engine handle for the DNS path.
    pub fn engine(&self) -> EngineHandle {
        self.inner.engine.clone()
    }

    /// The disk cache.
    pub fn cache(&self) -> &DiskCache {
        &self.inner.cache
    }

    /// Asks for an update of one list or of all enabled lists. Returns at once with the
    /// number of lists; [`Refresher::status`] shows the progress.
    pub fn update_now(&self, target: UpdateTarget) -> Result<usize, UpdateError> {
        self.inner.update_now(target)
    }

    /// Uses a new config: adds and removes lists, applies URL, kind, group and interval
    /// changes, and asks for a new build. A list with a new URL is fetched again.
    ///
    /// A fetch that runs for a list that this config disables, removes or gives a new URL
    /// is not used: it writes no file, and a new fetch of the list starts only after it ends.
    pub fn set_config(&self, config: Arc<Config>) -> Result<(), UpdateError> {
        let wall = (self.inner.settings.wall_clock)();
        let (mut guard, now) = self.inner.lock().ok_or(UpdateError::Busy)?;
        let st = &mut *guard;
        let policy = policy_for(&config, &self.inner.settings);
        let interval_changed = policy != st.policy;
        st.policy = policy;
        let mut old = std::mem::take(&mut st.lists);
        for adlist in &config.lists.adlists {
            let id = adlist.id;
            let mut slot = match old.remove(&id) {
                Some(mut s) if s.list.url == adlist.url => {
                    s.list = adlist.clone();
                    s
                }
                Some(s) => {
                    // A new URL: a new machine that is due now. A fetch of the old URL that
                    // still runs is not used.
                    st.orphan(id);
                    let mut fresh = Slot::new(adlist.clone(), s.disk_meta);
                    let mut machine = ListRefresh::new(id, Some(now));
                    let _ = machine.step(&policy, RefreshEvent::Tick(now));
                    fresh.machine = Some(machine);
                    fresh
                }
                None => Slot::new(adlist.clone(), None),
            };
            if !slot.list.enabled {
                st.orphan(id);
                slot.machine = None;
            } else if slot.machine.is_none()
                || (interval_changed
                    && slot
                        .machine
                        .is_some_and(|m| matches!(m.state(), RefreshState::Idle { .. })))
            {
                let due = initial_due(&policy, id, now, wall, slot.last_success());
                slot.machine = Some(ListRefresh::new(id, due));
            }
            st.lists.insert(id, slot);
        }
        // The lists that the new config does not have.
        for id in old.into_keys() {
            st.orphan(id);
        }
        st.config = config;
        drop(guard);
        self.inner.build_wanted.notify_one();
        self.inner.wake.notify_one();
        Ok(())
    }

    /// The status of all lists. `None` when the state lock timed out.
    pub fn status(&self) -> Option<ListsStatus> {
        self.inner.status()
    }

    /// Number of running tasks.
    pub fn task_count(&self) -> usize {
        self.inner.tracker.len()
    }

    /// Stops all tasks: cancels them and waits at most `deadline`. Returns true when all
    /// tasks ended in time. A build on a blocking thread cannot be stopped at once: it stops
    /// at the next list and never swaps after the cancel.
    pub async fn shutdown(&self, deadline: Duration) -> bool {
        self.inner.cancel.cancel();
        self.inner.tracker.close();
        let clean = tokio::time::timeout(deadline, self.inner.tracker.wait())
            .await
            .is_ok();
        if clean {
            tracing::info!("list refresher stopped");
        } else {
            tracing::error!(
                tasks = self.inner.tracker.len(),
                "list refresher tasks did not stop in time"
            );
        }
        clean
    }
}

fn policy_for(config: &Config, settings: &ListsSettings) -> RefreshPolicy {
    RefreshPolicy {
        base_backoff: settings.base_backoff,
        ..RefreshPolicy::from_hours(config.lists.refresh_interval_hours)
    }
}

impl Inner {
    fn now(&self) -> MonoTime {
        MonoTime::from_duration(self.origin.elapsed())
    }

    /// Gets the state lock and then reads the monotonic time. All machine steps use this
    /// time: a time read before the lock can be older than the time of a step that another
    /// thread did first, and the machine then refuses the event (time went back).
    fn lock(&self) -> Option<(MutexGuard<'_, State>, MonoTime)> {
        let Some(guard) = self.state.try_lock_for(LOCK_TIMEOUT) else {
            tracing::error!("the list refresher state lock timed out");
            return None;
        };
        let now = self.now();
        Some((guard, now))
    }

    /// Gets the work permit (see the module doc). `None` after `limit` or on cancel.
    async fn acquire_work(&self, limit: Duration) -> Option<OwnedSemaphorePermit> {
        tokio::select! {
            () = self.cancel.cancelled() => None,
            r = tokio::time::timeout(limit, Arc::clone(&self.work).acquire_owned()) => match r {
                Ok(Ok(permit)) => Some(permit),
                Ok(Err(_)) => {
                    tracing::error!("the work permit of the list refresher is closed");
                    None
                }
                Err(_) => None,
            },
        }
    }

    fn update_now(&self, target: UpdateTarget) -> Result<usize, UpdateError> {
        let (mut st, now) = self.lock().ok_or(UpdateError::Busy)?;
        let policy = st.policy;
        let mut count = 0;
        match target {
            UpdateTarget::One(id) => {
                let slot = st.lists.get_mut(&id).ok_or(UpdateError::UnknownList(id))?;
                let machine = slot.machine.as_mut().ok_or(UpdateError::Disabled(id))?;
                let _ = machine.step(&policy, RefreshEvent::UpdateNow(now));
                count = 1;
            }
            UpdateTarget::All => {
                for machine in st.lists.values_mut().filter_map(|s| s.machine.as_mut()) {
                    let _ = machine.step(&policy, RefreshEvent::UpdateNow(now));
                    count += 1;
                }
            }
        }
        drop(st);
        self.wake.notify_one();
        Ok(count)
    }

    /// The scheduler.
    ///
    /// Service loop: unbounded on purpose. It runs for the life of the refresher and ends
    /// when the cancel token is cancelled (the caller selects on it).
    async fn schedule_loop(self: Arc<Self>) {
        loop {
            let (jobs, wake_at, now) = self.tick();
            for job in jobs {
                self.spawn_fetch(job);
            }
            let sleep = wake_at
                .map_or(self.settings.max_sleep, |t| t.saturating_since(now))
                .min(self.settings.max_sleep);
            tokio::select! {
                () = self.cancel.cancelled() => break,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(sleep) => {}
            }
        }
    }

    /// One scheduler round: a `Tick` for each list, then a `Start` for due lists while a
    /// fetch slot is free. Returns the fetches to run, the next wake time and the time of
    /// the round.
    fn tick(&self) -> (Vec<FetchJob>, Option<MonoTime>, MonoTime) {
        let Some((mut guard, now)) = self.lock() else {
            return (Vec::new(), None, self.now());
        };
        let st = &mut *guard;
        let policy = st.policy;
        let max = self.settings.max_concurrent.clamp(1, MAX_CONCURRENT);
        for slot in st.lists.values_mut() {
            let id = slot.list.id;
            if let Some(m) = slot.machine.as_mut() {
                let _ = m.step(&policy, RefreshEvent::Tick(now));
                if m.is_fetching() && !st.fetching.contains_key(&id) {
                    // Not possible: a machine goes to `Fetching` only with an entry in the
                    // map. Go to a safe state: the fetch counts as failed.
                    tracing::error!(list = id, machine = ?m, "the list is fetching, but no fetch task runs; the fetch counts as failed");
                    let _ = m.step(&policy, RefreshEvent::Failed(now));
                }
            }
        }
        let mut jobs = Vec::new();
        for slot in st.lists.values_mut() {
            // The limit counts each running fetch, also a fetch that is not used.
            if st.fetching.len() >= max {
                break;
            }
            let id = slot.list.id;
            let Some(m) = slot.machine.as_mut() else {
                continue;
            };
            // One fetch at a time for each list: a fetch that is not used still runs.
            if !m.wants_fetch() || st.fetching.contains_key(&id) {
                continue;
            }
            if m.step(&policy, RefreshEvent::Start(now)).is_ok() {
                let seq = st.next_fetch;
                st.next_fetch = st.next_fetch.wrapping_add(1);
                st.fetching.insert(id, InFlight { seq, live: true });
                jobs.push(FetchJob {
                    id,
                    seq,
                    url: slot.list.url.clone(),
                    conditional: slot.conditional(),
                    base: slot.meta.clone(),
                    disk: slot.disk_meta.clone(),
                    body_ok: slot.body_ok,
                });
            }
        }
        let wake_at = st
            .lists
            .values()
            .filter_map(|s| s.machine.and_then(|m| m.wake_at()))
            .min();
        (jobs, wake_at, now)
    }

    /// True when the result of `job` is used: its fetch is the running fetch of the list,
    /// and the list was not disabled, removed or given a new URL during the fetch.
    fn is_live(&self, job: &FetchJob) -> bool {
        self.lock().is_some_and(|(st, _)| {
            st.fetching
                .get(&job.id)
                .is_some_and(|f| f.seq == job.seq && f.live)
        })
    }

    fn spawn_fetch(self: &Arc<Self>, job: FetchJob) {
        let Some(fetcher) = self.fetcher.get().cloned() else {
            tracing::error!(list = job.id, "a fetch was due before the start");
            let failed = Finished {
                outcome: Outcome::Failed,
                meta: job.base.clone(),
                disk: job.disk.clone(),
                body_ok: job.body_ok,
            };
            self.finish(&job, Some(failed));
            return;
        };
        let inner = Arc::clone(self);
        let cancel = self.cancel.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = inner.run_fetch(fetcher, job) => {}
            }
        });
    }

    async fn run_fetch(self: Arc<Self>, fetcher: Fetcher, job: FetchJob) {
        let result = fetcher.fetch(&job.url, job.conditional.as_ref()).await;
        if !self.is_live(&job) {
            tracing::info!(
                list = job.id,
                "the list was disabled, removed or changed during its fetch; the result is not used"
            );
            self.finish(&job, None);
            return;
        }
        let now_unix = (self.settings.wall_clock)();
        let finished = match result {
            Ok(FetchOutcome::NotModified(v)) => {
                tracing::debug!(list = job.id, "the list did not change (not modified)");
                let meta = job.base.after_not_modified(now_unix, v);
                let disk = self.persist_meta(job.id, &meta, job.disk.clone()).await;
                Finished {
                    outcome: Outcome::NotModified,
                    meta,
                    disk,
                    body_ok: job.body_ok,
                }
            }
            Ok(FetchOutcome::Body { bytes, validators }) => {
                // The store step calls `finish` itself, with the work permit.
                self.store_body(job, bytes, validators, now_unix).await;
                return;
            }
            Err(e) => {
                tracing::warn!(list = job.id, error = %e, "list fetch failed; the last good copy stays in use");
                let meta = job.base.after_failure(now_unix, &e.to_string());
                let disk = self.persist_meta(job.id, &meta, job.disk.clone()).await;
                Finished {
                    outcome: Outcome::Failed,
                    meta,
                    disk,
                    body_ok: job.body_ok,
                }
            }
        };
        self.finish(&job, Some(finished));
    }

    /// Writes `meta` when it differs from the file on disk. Returns the metadata on disk
    /// after the step.
    async fn persist_meta(
        &self,
        id: u32,
        meta: &ListMeta,
        disk: Option<ListMeta>,
    ) -> Option<ListMeta> {
        if disk.as_ref() == Some(meta) {
            return disk;
        }
        let cache = self.cache.clone();
        let m = meta.clone();
        let write = tokio::task::spawn_blocking(move || cache.write_meta(id, &m));
        match tokio::time::timeout(STORE_TIMEOUT, write).await {
            Ok(Ok(Ok(()))) => Some(meta.clone()),
            Ok(Ok(Err(e))) => {
                tracing::warn!(list = id, error = %e, "cannot write the list metadata");
                disk
            }
            Ok(Err(e)) => {
                tracing::error!(list = id, error = %e, "the metadata write task failed");
                disk
            }
            Err(_) => {
                tracing::error!(list = id, "the metadata write timed out");
                disk
            }
        }
    }

    /// The longest wait for the work permit in the store step: a build can hold it up to its
    /// own limit.
    fn store_wait(&self) -> Duration {
        self.settings.build_timeout.saturating_add(STORE_TIMEOUT)
    }

    /// Checks, parses and stores a new body on a blocking thread with the work permit, then
    /// calls `finish` before it gives back the permit.
    async fn store_body(
        self: &Arc<Self>,
        job: FetchJob,
        bytes: Vec<u8>,
        validators: Validators,
        now_unix: i64,
    ) {
        let Some(permit) = self.acquire_work(self.store_wait()).await else {
            // No file changed: the old copy stays good.
            tracing::error!(
                list = job.id,
                "the store step waited too long for the work permit"
            );
            let meta = job
                .base
                .after_failure(now_unix, "the refresher was busy for too long");
            let failed = Finished {
                outcome: Outcome::Failed,
                meta,
                disk: job.disk.clone(),
                body_ok: job.body_ok,
            };
            self.finish(&job, Some(failed));
            return;
        };
        let inner = Arc::clone(self);
        let limits = self.settings.parse_limits;
        let blocking_job = job.clone();
        let work = tokio::task::spawn_blocking(move || {
            // The permit is given back when this thread ends, also on a panic.
            let _permit = permit;
            let job = blocking_job;
            if !inner.is_live(&job) {
                inner.finish(&job, None);
                return;
            }
            let f = store_body_blocking(&inner.cache, &job, &bytes, validators, now_unix, &limits);
            drop(bytes);
            if let Some(h) = &inner.settings.build_hook {
                h(BuildStage::BodyStored);
            }
            inner.finish(&job, Some(f));
        });
        let error = match tokio::time::timeout(STORE_TIMEOUT, work).await {
            Ok(Ok(())) => return,
            Ok(Err(e)) => format!("the store task failed: {e}"),
            Err(_) => "the store step timed out".to_owned(),
        };
        // The blocking thread can still write. Its result is then not used (`finish` checks
        // the fetch number), and the body is checked again with a fetch.
        tracing::error!(list = job.id, error, "cannot store the list body");
        let abandoned = Finished {
            outcome: Outcome::Failed,
            meta: job.base.after_failure(now_unix, &error),
            disk: None,
            body_ok: false,
        };
        self.finish(&job, Some(abandoned));
    }

    /// Applies the result of a fetch to the state and the machine, and removes the fetch
    /// from the map of running fetches. `None`: the fetch wrote no file.
    ///
    /// - A result of a fetch that is not the running fetch of the list (a store step that
    ///   timed out) is not used.
    /// - A fetch that is not live (see [`InFlight::live`]) does not change the machine.
    fn finish(&self, job: &FetchJob, outcome: Option<Finished>) {
        let mut rebuild = false;
        if let Some((mut guard, now)) = self.lock() {
            let st = &mut *guard;
            match st.fetching.get(&job.id) {
                Some(f) if f.seq == job.seq => {}
                _ => {
                    tracing::debug!(list = job.id, "the result of an old fetch is not used");
                    return;
                }
            }
            let live = st.fetching.remove(&job.id).is_some_and(|f| f.live);
            let policy = st.policy;
            if let (Some(f), Some(slot)) = (outcome, st.lists.get_mut(&job.id)) {
                // The disk facts are true in all cases.
                slot.disk_meta = f.disk;
                if slot.list.url == job.url {
                    slot.meta = f.meta;
                    slot.body_ok = f.body_ok;
                    rebuild = f.outcome == Outcome::Updated
                        || (f.outcome == Outcome::NotModified && !slot.in_engine && slot.body_ok);
                }
                if live {
                    let event = match f.outcome {
                        Outcome::Updated => RefreshEvent::Updated(now),
                        Outcome::NotModified => RefreshEvent::NotModified(now),
                        Outcome::Failed => RefreshEvent::Failed(now),
                    };
                    // An event that the state does not expect logs at ERROR in `step`.
                    if let Some(m) = slot.machine.as_mut() {
                        let _ = m.step(&policy, event);
                    } else {
                        tracing::error!(
                            list = job.id,
                            ?event,
                            "a live fetch ended for a list with no machine"
                        );
                    }
                }
            }
        }
        if rebuild {
            self.build_wanted.notify_one();
        }
        self.wake.notify_one();
    }

    /// The builder: one build at a time; requests during a build give one more build.
    ///
    /// Service loop: unbounded on purpose. It runs for the life of the refresher and ends
    /// when the cancel token is cancelled (the caller selects on it).
    async fn build_loop(self: Arc<Self>) {
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => break,
                () = self.build_wanted.notified() => {}
            }
            self.run_build().await;
        }
    }

    /// Builds a new engine from the disk cache on a blocking thread and swaps it in.
    ///
    /// The blocking thread holds the work permit until it ends. Thus a build that took too
    /// long still blocks the next build until it stops (it never swaps after the stop).
    async fn run_build(self: &Arc<Self>) {
        let Some(permit) = self.acquire_work(self.settings.build_timeout).await else {
            if !self.cancel.is_cancelled() {
                tracing::error!(
                    "the engine build waited too long for the work permit; the old engine stays"
                );
            }
            return;
        };
        let stop = self.cancel.child_token();
        let job = {
            let inner = Arc::clone(self);
            let stop = stop.clone();
            tokio::task::spawn_blocking(move || {
                // The permit is given back when this thread ends, also on a panic.
                let _permit = permit;
                inner.build_blocking(&stop);
            })
        };
        let result = tokio::select! {
            () = self.cancel.cancelled() => {
                stop.cancel();
                return;
            }
            r = tokio::time::timeout(self.settings.build_timeout, job) => r,
        };
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!(error = %e, "the engine build task failed; the old engine stays");
            }
            Err(_) => {
                stop.cancel();
                tracing::error!(
                    "the engine build took too long; the old engine stays, and the next build waits until this build stops"
                );
            }
        }
    }

    /// The build on its blocking thread, with the work permit: copies the list hashes,
    /// builds, swaps and applies the result to the state.
    fn build_blocking(&self, stop: &CancellationToken) {
        if stop.is_cancelled() {
            return;
        }
        let (config, inputs) = {
            let Some((mut st, _)) = self.lock() else {
                return;
            };
            st.build.running = true;
            let inputs: Vec<BuildInput> = st
                .lists
                .values()
                .filter(|s| s.list.enabled && s.body_ok && s.meta.has_body_for(&s.list.url))
                .map(|s| BuildInput {
                    id: s.list.id,
                    hash: s.meta.body_hash.clone().unwrap_or_default(),
                    size: s.meta.size_bytes,
                })
                .collect();
            (Arc::clone(&st.config), inputs)
        };
        // `building` stays true until this thread ends, on each exit path.
        let _running = RunningFlag(self);
        let output = build_and_swap(
            &self.cache,
            &config,
            inputs,
            self.settings.limits.max_body,
            &self.settings.parse_limits,
            stop,
            self.settings.build_hook.as_ref(),
            &self.engine,
        );
        if let Some(out) = output {
            self.apply_build(out);
        }
    }

    /// Applies the result of a build to the state: which lists are in the engine, which
    /// bodies are bad (fetched again), and the build numbers.
    fn apply_build(&self, out: BuildOutput) {
        let wall = (self.settings.wall_clock)();
        let Some((mut st, now)) = self.lock() else {
            return;
        };
        let policy = st.policy;
        let used: std::collections::HashSet<u32> = out
            .report
            .lists
            .iter()
            .filter(|l| matches!(l.status, BuildListStatus::Used | BuildListStatus::SetFull))
            .map(|l| l.id)
            .collect();
        for slot in st.lists.values_mut() {
            slot.in_engine = used.contains(&slot.list.id);
        }
        for (id, hash, check) in out.checks {
            let BodyCheck::Bad(reason) = check else {
                continue;
            };
            let Some(slot) = st.lists.get_mut(&id) else {
                continue;
            };
            // A fetch can have written a new body during the build: only the checked body
            // is bad.
            if slot.meta.body_hash.as_deref() != Some(hash.as_str()) {
                continue;
            }
            tracing::warn!(
                list = id,
                reason,
                "the cached list body is not valid; the list is fetched again"
            );
            slot.body_ok = false;
            if let Some(m) = slot.machine.as_mut() {
                let _ = m.step(&policy, RefreshEvent::UpdateNow(now));
            }
        }
        for issue in &out.report.issues {
            tracing::warn!(path = %issue.path, message = %issue.message, "engine build issue");
        }
        st.build.count += 1;
        st.build.last_build = Some(wall);
        st.build.unique_domains = out.report.unique_domains;
        st.build.entries = out.report.entries;
        st.build.memory_bytes = out.report.memory_bytes;
        st.build.issues = out.report.issues.len();
        tracing::info!(
            unique_domains = out.report.unique_domains,
            entries = out.report.entries,
            memory_bytes = out.report.memory_bytes,
            peak_build_bytes = out.report.peak_build_bytes,
            "new policy engine in use"
        );
        drop(st);
        self.wake.notify_one();
    }

    fn status(&self) -> Option<ListsStatus> {
        let wall = (self.settings.wall_clock)();
        let (st, now) = self.lock()?;
        let to_wall = |t: MonoTime| {
            let ahead = t.saturating_since(now).as_secs();
            wall.saturating_add(i64::try_from(ahead).unwrap_or(i64::MAX))
        };
        let mut running = st.build.running;
        let mut next_run: Option<i64> = None;
        let lists: Vec<ListStatus> = st
            .lists
            .values()
            .map(|s| {
                let (phase, failures, next_due) = match s.machine {
                    None => (RefreshPhase::Disabled, 0, None),
                    Some(m) => {
                        let phase = match m.state() {
                            RefreshState::Idle { .. } => RefreshPhase::Idle,
                            RefreshState::Due { .. } => RefreshPhase::Due,
                            RefreshState::Fetching { .. } => RefreshPhase::Fetching,
                            RefreshState::Backoff { .. } => RefreshPhase::Backoff,
                        };
                        (phase, m.failures(), m.wake_at().map(to_wall))
                    }
                };
                if matches!(phase, RefreshPhase::Due | RefreshPhase::Fetching) {
                    running = true;
                }
                if let Some(d) = next_due {
                    next_run = Some(next_run.map_or(d, |n| n.min(d)));
                }
                let state = if matches!(phase, RefreshPhase::Due | RefreshPhase::Fetching) {
                    ListState::Updating
                } else if s.meta.last_error.is_some() {
                    ListState::Error
                } else if s.meta.last_success.is_some() {
                    ListState::Ok
                } else {
                    ListState::Never
                };
                let has_copy = s.body_ok && s.meta.has_body_for(&s.list.url);
                ListStatus {
                    id: s.list.id,
                    url: s.list.url.clone(),
                    kind: s.list.kind,
                    enabled: s.list.enabled,
                    groups: s.list.groups.clone(),
                    state,
                    phase,
                    failures,
                    last_update: s.meta.last_attempt,
                    last_success: s.meta.last_success,
                    last_error: s.meta.last_error.clone(),
                    entries: if has_copy {
                        s.meta.entries
                    } else {
                        EntryCounts::default()
                    },
                    size_bytes: if has_copy { s.meta.size_bytes } else { 0 },
                    next_due,
                    in_engine: s.in_engine,
                }
            })
            .collect();
        Some(ListsStatus {
            lists,
            schedule: ScheduleStatus {
                interval_hours: st.config.lists.refresh_interval_hours,
                next_run,
                running,
            },
            engine: EngineStatus {
                generation: self.engine.generation(),
                building: st.build.running,
                last_build: st.build.last_build,
                unique_domains: st.build.unique_domains,
                entries: st.build.entries,
                memory_bytes: st.build.memory_bytes,
                issues: st.build.issues,
            },
        })
    }
}

/// SHA-256 of `bytes` in lowercase hex.
pub fn body_hash(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for b in digest.as_ref() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The text of a body. Bytes that are not UTF-8 become U+FFFD (the line is then invalid).
fn body_text(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

fn counts(list: &ParsedList) -> EntryCounts {
    let s = &list.stats;
    EntryCounts {
        valid: s.valid as u64,
        invalid: s.invalid as u64,
        skipped: s.skipped.total() as u64,
    }
}

/// The store step of a fetch that gave a body (blocking).
///
/// - The same body as on disk (same hash): no body write; the metadata gets the new times
///   and validators, and is written only when it changed.
/// - A new body: parse it first. A parse error (too many entries, too large) is a failure,
///   and the old copy stays. Else write the body, then the metadata.
fn store_body_blocking(
    cache: &DiskCache,
    job: &FetchJob,
    bytes: &[u8],
    validators: Validators,
    now_unix: i64,
    limits: &ParseLimits,
) -> Finished {
    let hash = body_hash(bytes);
    let write_meta = |meta: &ListMeta| -> Option<ListMeta> {
        if job.disk.as_ref() == Some(meta) {
            return job.disk.clone();
        }
        match cache.write_meta(job.id, meta) {
            Ok(()) => Some(meta.clone()),
            Err(e) => {
                tracing::warn!(list = job.id, error = %e, "cannot write the list metadata");
                job.disk.clone()
            }
        }
    };
    let facts = |entries: EntryCounts| BodyFacts {
        hash: hash.clone(),
        size_bytes: bytes.len() as u64,
        entries,
    };
    if job.body_ok
        && job.base.has_body_for(&job.url)
        && job.base.body_hash.as_deref() == Some(hash.as_str())
    {
        tracing::debug!(list = job.id, "the list body did not change");
        let meta = job
            .base
            .after_body(&job.url, now_unix, validators, facts(job.base.entries));
        let disk = write_meta(&meta);
        return Finished {
            outcome: Outcome::NotModified,
            meta,
            disk,
            body_ok: true,
        };
    }
    let entries = {
        let text = body_text(bytes);
        match lists::parse(&text, ListFormat::Auto, limits) {
            Ok(parsed) => counts(&parsed),
            Err(e) => {
                tracing::warn!(list = job.id, error = %e, "the downloaded list is not usable; the last good copy stays in use");
                let meta = job.base.after_failure(now_unix, &e.to_string());
                let disk = write_meta(&meta);
                return Finished {
                    outcome: Outcome::Failed,
                    meta,
                    disk,
                    body_ok: job.body_ok,
                };
            }
        }
    };
    if let Err(e) = cache.write_body(job.id, bytes) {
        tracing::warn!(list = job.id, error = %e, "cannot write the list body");
        let meta = job
            .base
            .after_failure(now_unix, &format!("cannot write the cache: {e}"));
        let disk = write_meta(&meta);
        return Finished {
            outcome: Outcome::Failed,
            meta,
            disk,
            body_ok: job.body_ok,
        };
    }
    let meta = job
        .base
        .after_body(&job.url, now_unix, validators, facts(entries));
    let disk = write_meta(&meta);
    tracing::info!(
        list = job.id,
        bytes = bytes.len(),
        valid = entries.valid,
        "list updated"
    );
    Finished {
        outcome: Outcome::Updated,
        meta,
        disk,
        body_ok: true,
    }
}

/// Reads, checks and parses one cached body (blocking).
fn load_one(
    cache: &DiskCache,
    input: &BuildInput,
    max_body: u64,
    limits: &ParseLimits,
) -> Result<ParsedList, String> {
    let bytes = match cache.read_body(input.id, max_body) {
        Ok(Some(b)) => b,
        Ok(None) => return Err("the body file is missing".to_owned()),
        Err(ReadError::TooLarge) => return Err("the body file is too large".to_owned()),
        Err(ReadError::Io(e)) => return Err(e.to_string()),
    };
    if body_hash(&bytes) != input.hash {
        return Err("the body file does not match its hash".to_owned());
    }
    let text = body_text(&bytes);
    lists::parse(&text, ListFormat::Auto, limits).map_err(|e| e.to_string())
}

/// Sets `building` to false when the build thread ends (on each exit path).
struct RunningFlag<'a>(&'a Inner);

impl Drop for RunningFlag<'_> {
    fn drop(&mut self) {
        if let Some((mut st, _)) = self.0.lock() {
            st.build.running = false;
        }
    }
}

/// The build (blocking): reads one list at a time, largest first, builds the engine, calls
/// the test hook and swaps. Returns `None` when `stop` was cancelled (no swap).
#[allow(clippy::too_many_arguments)] // One call site; a struct would only rename the arguments.
fn build_and_swap(
    cache: &DiskCache,
    config: &Config,
    mut inputs: Vec<BuildInput>,
    max_body: u64,
    limits: &ParseLimits,
    stop: &CancellationToken,
    hook: Option<&BuildHook>,
    engine: &EngineHandle,
) -> Option<BuildOutput> {
    if let Some(h) = hook {
        h(BuildStage::BeforeRead);
    }
    inputs.sort_by(|a, b| b.size.cmp(&a.size).then(a.id.cmp(&b.id)));
    let mut checks = Vec::with_capacity(inputs.len());
    let lists = inputs.iter().filter_map(|input| {
        if stop.is_cancelled() {
            return None;
        }
        match load_one(cache, input, max_body, limits) {
            Ok(parsed) => {
                checks.push((input.id, input.hash.clone(), BodyCheck::Ok));
                Some((input.id, parsed))
            }
            Err(reason) => {
                checks.push((input.id, input.hash.clone(), BodyCheck::Bad(reason)));
                None
            }
        }
    });
    let (new_engine, report) = build_engine(config, lists);
    if stop.is_cancelled() {
        return None;
    }
    if let Some(h) = hook {
        h(BuildStage::BeforeSwap);
    }
    if stop.is_cancelled() {
        return None;
    }
    let old = engine.swap(new_engine);
    // Free the old engine here, on the blocking thread. A query that still holds it keeps
    // it alive until the query ends.
    drop(old);
    Some(BuildOutput { report, checks })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)] // Tests: a failure is a test failure.
mod tests {
    use super::*;
    use rusthole_core::config::ListKind;

    /// An "update now" that waits for the lock must not lose against an event that stepped
    /// the machine during the wait (finding: the time was read before the lock).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn update_now_reads_the_time_after_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.server.data_dir = dir.path().to_string_lossy().into_owned();
        config.lists.adlists = vec![Adlist {
            id: 1,
            url: "http://127.0.0.1:9/l".to_owned(),
            kind: ListKind::Block,
            enabled: true,
            groups: vec!["default".to_owned()],
            comment: None,
        }];
        let config = Arc::new(config);
        let r = Refresher::load(Arc::clone(&config), ListsSettings::from_config(&config))
            .await
            .unwrap();
        let inner = Arc::clone(&r.inner);
        let policy = {
            let (mut st, _) = inner.lock().unwrap();
            // An idle list that only an "update now" makes due.
            st.lists.get_mut(&1).unwrap().machine = Some(ListRefresh::new(1, None));
            st.policy
        };
        let worker = {
            let mut guard = inner.state.lock();
            let worker = {
                let inner = Arc::clone(&inner);
                std::thread::spawn(move || inner.update_now(UpdateTarget::One(1)))
            };
            std::thread::sleep(Duration::from_millis(50));
            // Another event steps the machine while the update waits for the lock.
            let t = inner.now();
            let machine = guard.lists.get_mut(&1).unwrap().machine.as_mut().unwrap();
            machine.step(&policy, RefreshEvent::Tick(t)).unwrap();
            worker
        };
        assert_eq!(worker.join().unwrap(), Ok(1));
        let machine = {
            let (st, _) = inner.lock().unwrap();
            st.lists[&1].machine.unwrap()
        };
        assert!(machine.wants_fetch(), "{machine:?}");
        assert!(r.shutdown(Duration::from_secs(5)).await);
    }

    #[test]
    fn hash_is_sha256_hex() {
        assert_eq!(
            body_hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
