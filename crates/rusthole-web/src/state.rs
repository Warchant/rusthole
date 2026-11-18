//! The shared state of the admin API and its dependencies.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rusthole_core::acl::{Acl, InterfaceNet};
use rusthole_core::blocking_state::MonoTime;
use rusthole_core::config::IdKind;
use rusthole_core::net::Cidr;
use rusthole_core::{Config, PolicyEngine};
use rusthole_dns::{BlockingControl, InterfaceSource};
use rusthole_lists::Refresher;
use rusthole_store::{NewAudit, Stats, StoreError};
use rusthole_tls::CertStore;

use crate::assets::AssetSource;
use crate::auth::Auth;
use crate::clock::Clock;
use crate::config_edit::{ConfigStore, WRITE_LOCK_TIMEOUT, WriteError, Written};
use crate::error::{ApiError, ApiResult};
use crate::host::HostAllow;

/// Time limit for one statistics query.
pub const STATS_TIMEOUT: Duration = Duration::from_secs(15);
/// Time limit for one audit write.
pub const AUDIT_TIMEOUT: Duration = Duration::from_secs(5);
/// The time that a request waits for its config write task. The task goes on after this
/// time; it is shorter than the request time limit, so the client gets a clear error.
pub const WRITE_TASK_WAIT: Duration = Duration::from_secs(25);

/// Waits for a config task with [`WRITE_TASK_WAIT`]. The task goes on when the wait ends.
async fn join_config_task<R>(task: tokio::task::JoinHandle<ApiResult<R>>) -> ApiResult<R> {
    match tokio::time::timeout(WRITE_TASK_WAIT, task).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "a config write task failed");
            Err(ApiError::internal())
        }
        Err(_) => Err(ApiError::unavailable(
            "The config write takes too long. It goes on in the background; load the data again.",
        )),
    }
}

/// What the bin applies after a config change (the DNS server, the client identity, the
/// statistics reason map). The web crate applies the list refresher itself.
pub trait LiveApply: Send + Sync + fmt::Debug {
    /// Applies a new, valid config. Returns true when a part of the change needs a restart.
    fn apply(&self, old: &Config, new: &Arc<Config>) -> bool;

    /// The DNS and DoH addresses that are bound now: kind (`dns`, `doh`) and address.
    /// `None`: use [`SystemStatic::listeners`] (tests, tools).
    fn listeners(&self) -> Option<Vec<(String, SocketAddr)>> {
        None
    }
}

/// A [`LiveApply`] that applies nothing (tests, tools).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLiveApply;

impl LiveApply for NoLiveApply {
    fn apply(&self, _old: &Config, _new: &Arc<Config>) -> bool {
        false
    }
}

/// True when a change touches a part that only a restart applies: listeners, upstreams,
/// statistics settings, TLS, or the data directory.
pub fn restart_fields_changed(old: &Config, new: &Config) -> bool {
    old.server != new.server
        || old.upstreams != new.upstreams
        || old.stats != new.stats
        || old.tls != new.tls
        || old.admin.tls_cert_path != new.admin.tls_cert_path
        || old.admin.tls_key_path != new.admin.tls_key_path
}

/// Facts for `GET /system` that do not change while the server runs.
#[derive(Debug, Clone, Default)]
pub struct SystemStatic {
    /// The version (`CARGO_PKG_VERSION` of the bin).
    pub version: String,
    /// The git commit, when the build knows it.
    pub commit: Option<String>,
    /// The start time, Unix seconds.
    pub started_at: i64,
    /// The config file path.
    pub config_path: String,
    /// The data directory.
    pub data_dir: String,
    /// The bound listeners: kind (`dns`, `doh`, `admin`) and address.
    pub listeners: Vec<(String, SocketAddr)>,
}

/// The dependencies of the admin API.
#[derive(Clone)]
pub struct AdminDeps {
    /// The config file and the config in memory.
    pub config: Arc<ConfigStore>,
    /// The clocks.
    pub clock: Arc<dyn Clock>,
    /// The statistics store. `None`: statistics endpoints answer 503.
    pub stats: Option<Stats>,
    /// The list refresher. `None`: list updates answer 503.
    pub lists: Option<Arc<Refresher>>,
    /// The current policy engine (for the domain search and the system facts).
    pub engine: rusthole_dns::EngineHandle,
    /// The blocking toggle.
    pub blocking: Arc<BlockingControl>,
    /// Live apply of the bin.
    pub live: Arc<dyn LiveApply>,
    /// The TLS certificate store.
    pub tls: Option<Arc<CertStore>>,
    /// Static system facts.
    pub system: SystemStatic,
    /// The local interfaces (for the ACL, the Host check and `acl.local_subnets`).
    pub interfaces: Arc<dyn InterfaceSource>,
    /// The UI files.
    pub assets: Arc<dyn AssetSource>,
}

impl fmt::Debug for AdminDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminDeps")
            .field("config", &self.config.path())
            .field("stats", &self.stats.is_some())
            .field("lists", &self.lists.is_some())
            .field("tls", &self.tls.is_some())
            .field("system", &self.system)
            .finish_non_exhaustive()
    }
}

/// The network facts that change with the interfaces and the config.
#[derive(Debug, Clone)]
pub struct NetView {
    /// The allowed `Host` values.
    pub hosts: HostAllow,
    /// The client ACL (decision D7).
    pub acl: Acl,
    /// The IPv4 subnets of the local interfaces.
    pub local_subnets: Vec<Cidr>,
}

pub(crate) struct Inner {
    pub(crate) deps: AdminDeps,
    /// The bound admin addresses (after the server started).
    pub(crate) bound: ArcSwap<Vec<SocketAddr>>,
    pub(crate) auth: Auth,
    pub(crate) net: ArcSwap<NetView>,
    pub(crate) restart_required: AtomicBool,
    /// The monotonic time (ms) of the last config refresh of a login.
    pub(crate) last_refresh_ms: std::sync::atomic::AtomicU64,
    pub(crate) id_high: Mutex<HashMap<IdKind, u32>>,
    pub(crate) started: MonoTime,
}

/// The state of the admin API. Cheap to clone.
#[derive(Clone)]
pub struct AppState(pub(crate) Arc<Inner>);

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("deps", &self.0.deps)
            .finish_non_exhaustive()
    }
}

/// The client address of a request. The server puts it into the request extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr(pub SocketAddr);

impl AppState {
    /// Makes the state. It scans the interfaces once.
    pub fn new(deps: AdminDeps) -> Self {
        let cfg = deps.config.get();
        let auth = Auth::new(&cfg);
        let started = deps.clock.mono();
        let net = build_net(&cfg, deps.interfaces.as_ref(), &deps.system.listeners, &[]);
        Self(Arc::new(Inner {
            deps,
            bound: ArcSwap::from_pointee(Vec::new()),
            auth,
            net: ArcSwap::from_pointee(net),
            restart_required: AtomicBool::new(false),
            last_refresh_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
            id_high: Mutex::new(HashMap::new()),
            started,
        }))
    }

    /// The dependencies.
    pub fn deps(&self) -> &AdminDeps {
        &self.0.deps
    }

    /// The config in memory.
    pub fn config(&self) -> Arc<Config> {
        self.0.deps.config.get()
    }

    /// The clock.
    pub fn clock(&self) -> &dyn Clock {
        self.0.deps.clock.as_ref()
    }

    /// The current engine.
    pub fn engine(&self) -> Arc<PolicyEngine> {
        self.0.deps.engine.load_full()
    }

    /// The network facts.
    pub fn net(&self) -> Arc<NetView> {
        self.0.net.load_full()
    }

    /// Scans the interfaces again and rebuilds the ACL and the Host list.
    pub fn refresh_net(&self) {
        let cfg = self.config();
        let bound = self.0.bound.load_full();
        let net = build_net(
            &cfg,
            self.0.deps.interfaces.as_ref(),
            &self.0.deps.system.listeners,
            &bound,
        );
        self.0.net.store(Arc::new(net));
    }

    /// Records the bound admin addresses: the `Host` check then uses their port and
    /// addresses (the config port can be 0 in tests).
    pub fn set_admin_bound(&self, bound: &[SocketAddr]) {
        self.0.bound.store(Arc::new(bound.to_vec()));
        self.refresh_net();
    }

    /// The listeners for `GET /system`, read now: the DNS and DoH addresses of
    /// [`LiveApply::listeners`], then the bound admin addresses (m18).
    pub(crate) fn listeners(&self) -> Vec<(String, SocketAddr)> {
        let fixed = &self.0.deps.system.listeners;
        let mut out = self.0.deps.live.listeners().unwrap_or_else(|| {
            fixed
                .iter()
                .filter(|(k, _)| k != "admin")
                .cloned()
                .collect()
        });
        let bound = self.0.bound.load();
        if bound.is_empty() {
            out.extend(fixed.iter().filter(|(k, _)| k == "admin").cloned());
        } else {
            out.extend(bound.iter().map(|a| ("admin".to_owned(), *a)));
        }
        out
    }

    /// True when a change since the start needs a restart.
    pub fn restart_required(&self) -> bool {
        self.0.restart_required.load(Ordering::Acquire)
    }

    /// Applies a new config to the running parts. Returns true when a restart is needed.
    /// `keep`: the session that made the change (see [`crate::auth::Auth::set_config`]).
    pub(crate) fn apply_config(
        &self,
        old: &Config,
        new: &Arc<Config>,
        keep: Option<[u8; 32]>,
    ) -> bool {
        if let Some(lists) = &self.0.deps.lists
            && let Err(e) = lists.set_config(Arc::clone(new))
        {
            tracing::error!(error = %e, "the list refresher did not take the new config");
        }
        self.0.auth.set_config(old, new, keep, self.clock().mono());
        self.refresh_net();
        let restart = self.0.deps.live.apply(old, new) || restart_fields_changed(old, new);
        if restart {
            self.0.restart_required.store(true, Ordering::Release);
        }
        restart
    }

    /// Changes the config and writes the file (see [`ConfigStore::update_and_apply`]), then
    /// applies the new config. A hand edit of the file gives 409 `config_conflict`.
    ///
    /// Cancel safe: the read, the change, the file write, the new config in memory and the
    /// live apply run in a spawned task that holds the writer lock. A dropped request does
    /// not stop it, so the file and the memory state cannot differ.
    pub(crate) async fn write<T: Send + 'static>(
        &self,
        change: impl FnOnce(&mut Config) -> Result<T, ApiError> + Send + 'static,
    ) -> ApiResult<(T, Arc<Config>, bool)> {
        self.write_keeping(None, change).await
    }

    /// Like [`AppState::write`]. When the change ends the sessions (a TOTP change), the
    /// session `keep` stays (see [`crate::auth::Auth::set_config`]).
    pub(crate) async fn write_keeping<T: Send + 'static>(
        &self,
        keep: Option<[u8; 32]>,
        change: impl FnOnce(&mut Config) -> Result<T, ApiError> + Send + 'static,
    ) -> ApiResult<(T, Arc<Config>, bool)> {
        let this = self.clone();
        let task = tokio::spawn(async move {
            let applier = this.clone();
            let result = this
                .0
                .deps
                .config
                .update_and_apply(WRITE_LOCK_TIMEOUT, change, move |old, new, ours| {
                    // A file that changed on disk keeps no session.
                    applier.apply_config(old, new, if ours { keep } else { None })
                })
                .await;
            match result {
                Ok(Written {
                    value,
                    new,
                    restart,
                    ..
                }) => Ok((value, new, restart)),
                Err(WriteError::Api(e)) => Err(e),
                Err(WriteError::Conflict { .. }) => Err(ApiError::config_conflict()),
            }
        });
        join_config_task(task).await
    }

    /// Reads the config file again when it changed on disk (for example after
    /// `rusthole passwd`), and applies it. Errors are logged. It runs in a spawned task, like
    /// [`AppState::write`]. `lock_wait` is the time limit for the writer lock; a write that
    /// runs reads the file itself.
    pub(crate) async fn refresh_config_with(&self, lock_wait: Duration) {
        let this = self.clone();
        let task = tokio::spawn(async move {
            let applier = this.clone();
            // An empty change: the store reads the file and compares the hash first.
            let result = this
                .0
                .deps
                .config
                .update_and_apply(
                    lock_wait,
                    |_| Err::<(), _>(ApiError::not_found()),
                    move |old, new, _ours| {
                        tracing::info!(
                            "the config file changed on disk; rusthole uses the new file"
                        );
                        applier.apply_config(old, new, None)
                    },
                )
                .await;
            match result {
                Err(WriteError::Api(_) | WriteError::Conflict { .. }) | Ok(_) => Ok(()),
            }
        });
        let _ = join_config_task(task).await;
    }

    /// Like [`AppState::refresh_config_with`], with the normal lock time limit.
    pub(crate) async fn refresh_config(&self) {
        self.refresh_config_with(WRITE_LOCK_TIMEOUT).await;
    }

    /// Like [`AppState::refresh_config`], at most once in 2 s (logins call it).
    pub(crate) async fn refresh_config_throttled(&self) {
        if self.refresh_due() {
            self.refresh_config().await;
        }
    }

    /// Like [`AppState::refresh_config_throttled`], but it does not wait for the writer
    /// lock: a write that runs reads the file itself. The auth middleware and the session
    /// probe call it before they check a session or a token.
    pub(crate) async fn refresh_config_soon(&self) {
        if self.refresh_due() {
            self.refresh_config_with(Duration::ZERO).await;
        }
    }

    /// True at most once in 2 s (monotonic clock): the next config refresh is due.
    fn refresh_due(&self) -> bool {
        let now = u64::try_from(self.clock().mono().as_duration().as_millis()).unwrap_or(u64::MAX);
        let last = self.0.last_refresh_ms.load(Ordering::Acquire);
        if last != u64::MAX && now.saturating_sub(last) < 2000 {
            return false;
        }
        // Only one caller gets the slot.
        self.0
            .last_refresh_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// The next id for a new item: one more than the highest id that the collection has or
    /// had since the start, so an id is not used again while the server runs.
    pub(crate) fn next_id(&self, kind: IdKind, cfg: &Config) -> ApiResult<u32> {
        let mut high = self
            .0
            .id_high
            .try_lock_for(Duration::from_secs(2))
            .ok_or_else(|| ApiError::unavailable("The server is busy. Try again."))?;
        let floor = 1;
        let used = cfg.ids_of(kind);
        let prev = high.get(&kind).copied();
        let id = rusthole_core::config::next_free_id(used.into_iter().chain(prev), floor)
            .ok_or_else(|| ApiError::conflict("No free id is left."))?;
        high.insert(kind, id);
        Ok(id)
    }

    /// Runs a statistics query on a blocking thread with a time limit.
    pub(crate) async fn stats<R: Send + 'static>(
        &self,
        f: impl FnOnce(&Stats) -> Result<R, StoreError> + Send + 'static,
    ) -> ApiResult<R> {
        let Some(stats) = self.0.deps.stats.clone() else {
            return Err(ApiError::unavailable("Statistics are not available."));
        };
        let task = tokio::task::spawn_blocking(move || f(&stats));
        match tokio::time::timeout(STATS_TIMEOUT, task).await {
            Ok(Ok(Ok(r))) => Ok(r),
            Ok(Ok(Err(e))) => Err(store_error(&e)),
            Ok(Err(e)) => {
                tracing::error!(error = %e, "a statistics task failed");
                Err(ApiError::internal())
            }
            Err(_) => Err(ApiError::unavailable(
                "The statistics query took too long. Try a shorter range.",
            )),
        }
    }

    /// Adds an audit line. Errors are logged; the request does not fail.
    pub(crate) async fn audit(&self, line: NewAudit) {
        let Some(stats) = self.0.deps.stats.clone() else {
            return;
        };
        let task = tokio::task::spawn_blocking(move || stats.append_audit(&line));
        match tokio::time::timeout(AUDIT_TIMEOUT, task).await {
            Ok(Ok(Ok(_))) => {}
            Ok(Ok(Err(e))) => tracing::error!(error = %e, "cannot write an audit line"),
            Ok(Err(e)) => tracing::error!(error = %e, "the audit task failed"),
            Err(_) => tracing::error!("the audit write timed out"),
        }
    }

    /// The uptime.
    pub fn uptime(&self) -> Duration {
        self.clock().mono().saturating_since(self.0.started)
    }
}

/// The API error for a store error.
pub(crate) fn store_error(e: &StoreError) -> ApiError {
    match e {
        StoreError::Busy => ApiError::unavailable("The statistics store is busy. Try again."),
        StoreError::TooLarge { .. } => ApiError::unavailable(e.to_string()),
        StoreError::Cursor(_) => ApiError::bad_request("The cursor is not valid."),
        other => {
            tracing::error!(error = %other, "statistics store error");
            ApiError::internal()
        }
    }
}

/// Builds the ACL, the Host list and the local subnets.
pub fn build_net(
    cfg: &Config,
    interfaces: &dyn InterfaceSource,
    listeners: &[(String, SocketAddr)],
    admin_bound: &[SocketAddr],
) -> NetView {
    let nets: Vec<InterfaceNet> = interfaces.scan().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "cannot read the network interfaces");
        Vec::new()
    });
    let allow: Vec<Cidr> = cfg
        .acl
        .allow
        .iter()
        .filter_map(|s| Cidr::parse(s).ok())
        .collect();
    let acl = Acl::build(cfg.acl.auto_local, &nets, &allow);
    let mut addrs: Vec<Ipv4Addr> = nets.iter().map(|n| n.addr).collect();
    for (_, a) in listeners {
        if let IpAddr::V4(v4) = a.ip()
            && !v4.is_unspecified()
        {
            addrs.push(v4);
        }
    }
    for s in &cfg.server.admin.listen {
        if let Ok(v4) = s.parse::<Ipv4Addr>() {
            addrs.push(v4);
        }
    }
    for a in admin_bound {
        if let IpAddr::V4(v4) = a.ip()
            && !v4.is_unspecified()
        {
            addrs.push(v4);
        }
    }
    let port = admin_bound
        .first()
        .map_or(cfg.server.admin.port, SocketAddr::port);
    let hosts = HostAllow::new(port, cfg.tls.names.iter().map(String::as_str), addrs);
    let mut local_subnets: Vec<Cidr> = nets
        .iter()
        .map(InterfaceNet::subnet)
        .filter(|c| !matches!(c.addr, IpAddr::V4(v) if v.is_loopback()))
        .collect();
    local_subnets.sort_by_key(|c| (c.addr, c.prefix));
    local_subnets.dedup();
    NetView {
        hosts,
        acl,
        local_subnets,
    }
}

#[cfg(test)]
mod tests;
