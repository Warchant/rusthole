//! The `run` command: load the config, start the list refresher, the policy, the DNS server
//! and the admin listener, wait for a stop signal, stop.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant M as main
//!     participant L as list refresher (P3b)
//!     participant P as policy (P3c)
//!     participant S as DNS server
//!     participant A as admin listener (P5)
//!     M->>M: load and validate config (exit 1 on a problem)
//!     M->>L: load: first engine from the disk cache (no network)
//!     M->>P: neighbor task, client resolver, filter with the refresher engine
//!     M->>S: start with the filter (bind, upstream pool, rescan)
//!     M->>L: start downloads (names through the upstream pool)
//!     M->>A: HTTPS listener, API (one TLS store with DoH; a failed start is an ERROR, DNS goes on)
//!     M->>M: certificate reload task (each minute: file stamps, new local addresses; each hour: renewal)
//!     M->>M: systemd READY=1 (notify.rs)
//!     M->>M: wait for SIGTERM / SIGINT / Ctrl+C
//!     M->>M: systemd STOPPING=1
//!     M->>M: stop the certificate reload task
//!     M->>A: shutdown (graceful, then hard stop)
//!     M->>L: shutdown (deadline)
//!     M->>S: shutdown (finish in-flight queries, hard stop after grace)
//!     M->>P: shutdown (neighbor and PTR tasks)
//!     M->>M: stop the runtime, then the statistics store (final flush)
//! ```
//!
//! Each exit path (a start error of any part, or the stop signal) stops the parts that
//! started before, in the reverse order. Tests prove both paths.

use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use parking_lot::Mutex;
use rusthole_core::Config;
use rusthole_core::clients::ClientTable;
use rusthole_dns::server::SHUTDOWN_GRACE;
use rusthole_dns::{
    BlockingControl, BoundListener, DnsServer, DnsSettings, EngineHandle, IdentityService,
    IdentitySettings, InterfaceSource, NeighborSource, PolicyFilter, ServerDeps, SystemInterfaces,
    SystemNeighbors,
};
use rusthole_lists::{ListsSettings, Refresher};
use rusthole_web::config_edit::ConfigStore;
use rusthole_web::{AdminDeps, AdminServer, AdminSettings, AppState, LiveApply, SystemStatic};
use tokio_util::sync::CancellationToken;

use crate::stats_observer::RuleIds;

/// Time limit for the runtime to stop after the server stopped.
const RUNTIME_STOP: Duration = Duration::from_secs(2);
/// Time limit for the list refresher to stop.
const LISTS_STOP: Duration = Duration::from_secs(5);
/// Time limit for the admin listener to stop gracefully.
const ADMIN_STOP: Duration = Duration::from_secs(3);
/// The period of the client identity sync (MAC and name into the statistics store).
const IDENTITY_SYNC: Duration = Duration::from_secs(60);
/// The largest number of clients that one identity sync updates.
const IDENTITY_SYNC_MAX: usize = 4096;
/// The period of the certificate check (M2): the file stamps (mode `file`) and the local
/// addresses (modes `self-signed` and `local-ca`).
pub(crate) const CERT_CHECK: Duration = Duration::from_secs(60);
/// A full certificate check (renewal) is due at least this often.
const CERT_RELOAD: Duration = Duration::from_secs(3600);
/// Time limit for one certificate check or open (it can make a new key).
const CERT_TIMEOUT: Duration = Duration::from_secs(60);
/// Time limit for a background task to stop.
const TASK_STOP: Duration = Duration::from_secs(2);

/// Runs the server until a stop signal.
pub(crate) fn run(path: &Path, out: &mut impl Write) -> anyhow::Result<ExitCode> {
    let Some((config, text)) = crate::load_config_text(path, out)? else {
        return Ok(ExitCode::FAILURE);
    };
    let (settings, warnings) = DnsSettings::from_config(&config)
        .with_context(|| format!("cannot use {}", path.display()))?;
    for w in &warnings {
        tracing::warn!("{w}");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rusthole")
        .build()
        .context("cannot start the async runtime")?;
    // The DoH listener (part P7) needs its TLS config before the start. The admin listener
    // uses the same certificate store (M2).
    let (certs, doh_tls) = crate::doh::server_tls(&config)?.unzip();
    let store = Arc::new(ConfigStore::new(path.to_path_buf(), text, &config));
    let cfg = store.get();
    // The statistics store (part P4). It stops after the DNS server, with a final flush.
    let stats = crate::stats_observer::start(&cfg);
    let rule_ids = RuleIds::new(&cfg);
    let deps = ServerDeps {
        observer: crate::stats_observer::observer(stats.as_ref(), rule_ids.clone()),
        doh_tls,
        ..ServerDeps::default()
    };
    let env = RunEnv {
        neighbors: Arc::new(SystemNeighbors),
        interfaces: Arc::new(SystemInterfaces),
        lists: ListsSettings::from_config(&cfg),
        admin_listen: None,
        stats: stats.as_ref().map(rusthole_store::StatsService::stats),
        rule_ids,
        config_path: path.display().to_string(),
        certs,
        cert_check: CERT_CHECK,
    };
    // systemd (`Type=notify`): READY=1 after all listeners are bound, STOPPING=1 at the stop
    // signal. Without NOTIFY_SOCKET both calls do nothing.
    let stop = async {
        stop_signal().await;
        crate::notify::notify(&[crate::notify::State::Stopping]);
    };
    let result = runtime.block_on(serve_all(store, settings, deps, env, stop, |r| {
        tracing::info!(dns = ?r.dns, admin = ?r.admin, "listeners are bound");
        crate::notify::notify(&[
            crate::notify::State::Ready,
            crate::notify::State::Status(ready_status(r.dns.len(), r.admin.len())),
        ]);
    }));
    runtime.shutdown_timeout(RUNTIME_STOP);
    crate::stats_observer::stop(stats);
    result?;
    Ok(ExitCode::SUCCESS)
}

/// The status text that `systemctl status` shows after the start.
fn ready_status(dns: usize, admin: usize) -> String {
    format!("running: DNS on {dns} address(es), admin UI on {admin} address(es)")
}

/// The parts of the process environment that tests replace.
pub(crate) struct RunEnv {
    pub(crate) neighbors: Arc<dyn NeighborSource>,
    pub(crate) interfaces: Arc<dyn InterfaceSource>,
    pub(crate) lists: ListsSettings,
    /// Admin listen addresses that replace the config (tests: `127.0.0.1:0`).
    pub(crate) admin_listen: Option<Vec<SocketAddr>>,
    pub(crate) stats: Option<rusthole_store::Stats>,
    pub(crate) rule_ids: RuleIds,
    pub(crate) config_path: String,
    /// The certificate store of the DoH listener. `None`: the admin listener opens it.
    pub(crate) certs: Option<Arc<rusthole_tls::CertStore>>,
    /// The period of the certificate check ([`CERT_CHECK`]; tests use less).
    pub(crate) cert_check: Duration,
}

/// The policy parts of a running server (part P3c): the client identity tasks and the
/// filter with the engine and the blocking toggle.
#[derive(Debug)]
pub(crate) struct Policy {
    identity: Arc<IdentityService>,
    filter: Arc<PolicyFilter>,
}

impl Policy {
    /// Starts the neighbor and PTR tasks and makes the filter with `engine` (the engine
    /// handle of the list refresher). Call it inside a tokio runtime.
    pub(crate) fn start(
        config: &Config,
        settings: &DnsSettings,
        engine: EngineHandle,
        neighbors: Arc<dyn NeighborSource>,
    ) -> anyhow::Result<Self> {
        let (table, issues) = ClientTable::from_config(config);
        for issue in &issues {
            tracing::warn!("clients: {issue}");
        }
        let identity = Arc::new(
            IdentityService::start(
                table,
                Arc::clone(&settings.local),
                neighbors,
                IdentitySettings::default(),
            )
            .context("cannot start the client identity tasks")?,
        );
        let filter = Arc::new(PolicyFilter::new(
            engine,
            Arc::new(BlockingControl::new(config.blocking.enabled)),
            identity.resolver(),
        ));
        Ok(Self { identity, filter })
    }

    /// The filter (the engine handle and the blocking toggle are in it).
    #[cfg(test)]
    pub(crate) fn filter(&self) -> &Arc<PolicyFilter> {
        &self.filter
    }

    /// The client identity service.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> &Arc<IdentityService> {
        &self.identity
    }
}

/// What the `ready` callback of [`serve_all`] sees.
pub(crate) struct Running<'a> {
    pub(crate) dns: Vec<BoundListener>,
    pub(crate) admin: Vec<SocketAddr>,
    /// Only tests read it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) policy: &'a Policy,
    /// Only tests read it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) refresher: &'a Arc<Refresher>,
    /// Only tests read it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) server: &'a Arc<DnsServer>,
}

/// The started parts. [`Parts::stop`] stops the parts that are there, in the reverse order
/// of the start.
#[derive(Default)]
struct Parts {
    refresher: Option<Arc<Refresher>>,
    policy: Option<Policy>,
    server: Option<Arc<DnsServer>>,
    admin: Option<AdminServer>,
    sync: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    certs: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
}

/// Cancels a background task and waits for its end, with a time limit.
async fn stop_task(task: Option<(CancellationToken, tokio::task::JoinHandle<()>)>, name: &str) {
    if let Some((cancel, task)) = task {
        cancel.cancel();
        if tokio::time::timeout(TASK_STOP, task).await.is_err() {
            tracing::warn!("the {name} task did not stop in time");
        }
    }
}

impl Parts {
    async fn stop(self) {
        stop_task(self.sync, "identity sync").await;
        stop_task(self.certs, "certificate reload").await;
        if let Some(admin) = &self.admin
            && !admin.shutdown(ADMIN_STOP).await
        {
            tracing::warn!("admin connections did not end in time");
        }
        if let Some(r) = &self.refresher
            && !r.shutdown(LISTS_STOP).await
        {
            tracing::warn!("list refresher tasks did not stop in time");
        }
        if let Some(s) = &self.server {
            s.shutdown(SHUTDOWN_GRACE).await;
        }
        if let Some(p) = &self.policy
            && !p.identity.shutdown(SHUTDOWN_GRACE).await
        {
            tracing::warn!("client identity tasks did not stop in time");
        }
    }
}

/// Starts all parts, gives them to `ready`, waits for `stop`, then stops all parts. Each
/// exit path stops every part that started.
pub(crate) async fn serve_all(
    store: Arc<ConfigStore>,
    settings: DnsSettings,
    base: ServerDeps,
    env: RunEnv,
    stop: impl Future<Output = ()>,
    ready: impl FnOnce(&Running<'_>),
) -> anyhow::Result<()> {
    let mut parts = Parts::default();
    let result = start_parts(&mut parts, &store, settings, base, env).await;
    if let Err(e) = result {
        parts.stop().await;
        return Err(e);
    }
    if let (Some(policy), Some(refresher), Some(server)) =
        (&parts.policy, &parts.refresher, &parts.server)
    {
        tracing::info!("rusthole is running");
        ready(&Running {
            dns: server.bound(),
            admin: parts
                .admin
                .as_ref()
                .map_or_else(Vec::new, |a| a.bound().to_vec()),
            policy,
            refresher,
            server,
        });
    }
    stop.await;
    tracing::info!("stop signal received; stopping");
    parts.stop().await;
    Ok(())
}

async fn start_parts(
    parts: &mut Parts,
    store: &Arc<ConfigStore>,
    settings: DnsSettings,
    base: ServerDeps,
    env: RunEnv,
) -> anyhow::Result<()> {
    let cfg = store.get();
    let refresher = Arc::new(
        Refresher::load(Arc::clone(&cfg), env.lists)
            .await
            .context("cannot load the lists")?,
    );
    parts.refresher = Some(Arc::clone(&refresher));
    let policy = Policy::start(&cfg, &settings, refresher.engine().shared(), env.neighbors)?;
    let filter = Arc::clone(&policy.filter);
    let resolver = policy.identity.resolver();
    parts.policy = Some(policy);
    let deps = ServerDeps {
        filter: Arc::clone(&filter) as Arc<dyn rusthole_dns::QueryFilter>,
        interfaces: Arc::clone(&env.interfaces),
        ..base
    };
    let server = Arc::new(
        rusthole_dns::start(settings.clone(), deps)
            .await
            .context("cannot start the DNS server")?,
    );
    parts.server = Some(Arc::clone(&server));
    refresher
        .start(Arc::new(server.host_resolver()))
        .context("cannot start the list downloads")?;
    if let Some(stats) = &env.stats {
        let cancel = CancellationToken::new();
        let task = tokio::spawn(identity_sync(
            stats.clone(),
            Arc::clone(&resolver),
            cancel.clone(),
        ));
        parts.sync = Some((cancel, task));
    }
    let mut certs = env.certs;
    if cfg.server.admin.enabled {
        let live = Arc::new(BinLive {
            server: Arc::clone(&server),
            resolver,
            current: Mutex::new(settings),
            rule_ids: env.rule_ids.clone(),
        });
        // m16: a failed admin start (TLS or bind) does not stop DNS (owner decision). The
        // admin UI is then not reachable until a restart.
        let started = async {
            let store_tls = match &certs {
                Some(c) => Arc::clone(c),
                None => open_certs(&cfg, Arc::clone(&env.interfaces)).await?,
            };
            certs = Some(Arc::clone(&store_tls));
            start_admin(
                store,
                &cfg,
                &env.interfaces,
                env.admin_listen,
                env.stats,
                &refresher,
                &filter,
                live,
                &server,
                env.config_path,
                store_tls,
            )
            .await
        };
        match started.await {
            Ok(admin) => parts.admin = Some(admin),
            Err(e) => tracing::error!(
                error = format!("{e:#}"),
                "the admin listener did not start; DNS runs without the admin UI"
            ),
        }
    }
    if let Some(c) = certs {
        let cancel = CancellationToken::new();
        let task = tokio::spawn(cert_reload(
            c,
            Arc::clone(&env.interfaces),
            env.cert_check,
            cancel.clone(),
        ));
        parts.certs = Some((cancel, task));
    }
    Ok(())
}

/// Opens the certificate store on a blocking thread, with a time limit.
async fn open_certs(
    cfg: &Config,
    interfaces: Arc<dyn InterfaceSource>,
) -> anyhow::Result<Arc<rusthole_tls::CertStore>> {
    let tls_settings = rusthole_tls::TlsSettings::from_config(cfg);
    let open = tokio::task::spawn_blocking(move || {
        let ips = crate::doh::local_ips(interfaces.as_ref());
        rusthole_tls::CertStore::open(tls_settings, &ips, rusthole_tls::now_unix())
    });
    let (certs, _notices) = tokio::time::timeout(CERT_TIMEOUT, open)
        .await
        .context("the TLS certificate setup timed out")?
        .context("the TLS certificate task failed")?
        .context("cannot set up the TLS certificate of the admin listener")?;
    Ok(certs)
}

/// True when a certificate check is due (M2). Pure.
///
/// - Mode `file`: at each round. The check only compares the size and the time stamp of
///   the two files, so a new certificate from an ACME client is used in one round.
/// - Other modes: when the local addresses changed (a new LAN address must get into the
///   certificate), and at least each [`CERT_RELOAD`] (renewal before the end of validity).
pub(crate) fn cert_check_due(file_mode: bool, addrs_changed: bool, since_last: Duration) -> bool {
    file_mode || addrs_changed || since_last >= CERT_RELOAD
}

/// Checks the certificate each `period` and uses a new one when necessary (M2). The admin
/// listener and the DoH listener read the store at each handshake, so a new certificate
/// applies to the next connection.
///
/// Service loop: unbounded on purpose. It runs for the life of the server and ends when
/// `cancel` is cancelled. Each check runs on a blocking thread with a time limit.
async fn cert_reload(
    certs: Arc<rusthole_tls::CertStore>,
    interfaces: Arc<dyn InterfaceSource>,
    period: Duration,
    cancel: CancellationToken,
) {
    let file_mode = certs.mode() == rusthole_core::config::TlsMode::File;
    let mut last_addrs: Option<Vec<IpAddr>> = None;
    let mut last_check = tokio::time::Instant::now();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(period) => {}
        }
        let c = Arc::clone(&certs);
        let ifs = Arc::clone(&interfaces);
        let prev = last_addrs.clone();
        let since = last_check.elapsed();
        let job = tokio::task::spawn_blocking(move || {
            let addrs = crate::doh::local_ips(ifs.as_ref());
            let changed = prev.as_ref() != Some(&addrs);
            let result = cert_check_due(file_mode, changed, since)
                .then(|| c.reload(&addrs, rusthole_tls::now_unix()));
            (addrs, result)
        });
        match tokio::time::timeout(CERT_TIMEOUT, job).await {
            Ok(Ok((addrs, result))) => {
                last_addrs = Some(addrs);
                match result {
                    None => {}
                    Some(Ok(outcome)) => {
                        last_check = tokio::time::Instant::now();
                        if matches!(outcome, rusthole_tls::ReloadOutcome::Reloaded(_)) {
                            tracing::info!("a new TLS certificate is in use for new connections");
                        }
                    }
                    Some(Err(e)) => {
                        last_check = tokio::time::Instant::now();
                        tracing::error!(error = %e, "the TLS certificate check failed; the current certificate stays");
                    }
                }
            }
            Ok(Err(e)) => tracing::error!(error = %e, "the TLS certificate task failed"),
            Err(_) => tracing::warn!("the TLS certificate check timed out; it runs again later"),
        }
    }
}

#[allow(clippy::too_many_arguments)] // The wiring of one listener; a struct would only rename the list.
async fn start_admin(
    store: &Arc<ConfigStore>,
    cfg: &Config,
    interfaces: &Arc<dyn InterfaceSource>,
    listen: Option<Vec<SocketAddr>>,
    stats: Option<rusthole_store::Stats>,
    refresher: &Arc<Refresher>,
    filter: &Arc<PolicyFilter>,
    live: Arc<BinLive>,
    server: &Arc<DnsServer>,
    config_path: String,
    certs: Arc<rusthole_tls::CertStore>,
) -> anyhow::Result<AdminServer> {
    let tls = rusthole_tls::admin_server_config(&certs).context("cannot make the TLS config")?;
    let listen = match listen {
        Some(l) => l,
        None => rusthole_web::listen_addrs(cfg, interfaces.as_ref())
            .context("cannot find the admin listen addresses")?,
    };
    let mut listeners: Vec<(String, SocketAddr)> = server
        .bound()
        .iter()
        .map(|b| ("dns".to_owned(), b.udp))
        .collect();
    listeners.extend(listen.iter().map(|a| ("admin".to_owned(), *a)));
    let deps = AdminDeps {
        config: Arc::clone(store),
        clock: Arc::new(rusthole_web::clock::SystemClock::new()),
        stats,
        lists: Some(Arc::clone(refresher)),
        engine: Arc::clone(filter.engine()),
        blocking: Arc::clone(filter.blocking()),
        live,
        tls: Some(certs),
        system: SystemStatic {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: option_env!("RUSTHOLE_COMMIT").map(str::to_owned),
            started_at: rusthole_store::wall_now(),
            config_path,
            data_dir: cfg.server.data_dir.clone(),
            listeners,
        },
        interfaces: Arc::clone(interfaces),
        assets: Arc::new(rusthole_web::assets::EmbeddedAssets),
        // The report asks the upstream pool directly, as the list downloads do.
        report: Some(rusthole_report::Reporter::new(rusthole_report::Sources {
            dns: Arc::new(server.host_resolver()),
        })),
    };
    let app = AppState::new(deps);
    rusthole_web::start(AdminSettings::new(listen), tls, app)
        .await
        .context("cannot start the admin listener")
}

/// Applies a config change of the API to the DNS server, the client identity and the
/// statistics reason map. The web crate applies the list refresher (lists, rules, groups,
/// blocking mode: one engine build).
struct BinLive {
    server: Arc<DnsServer>,
    resolver: Arc<rusthole_dns::ClientResolver>,
    current: Mutex<DnsSettings>,
    rule_ids: RuleIds,
}

impl std::fmt::Debug for BinLive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinLive").finish_non_exhaustive()
    }
}

impl LiveApply for BinLive {
    fn listeners(&self) -> Option<Vec<(String, SocketAddr)>> {
        Some(live_listeners(&self.server))
    }

    fn apply(&self, _old: &Config, new: &Arc<Config>) -> bool {
        self.rule_ids.set(new);
        let (settings, warnings) = match DnsSettings::from_config(new) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "the new config has no usable DNS settings; a restart is needed");
                return true;
            }
        };
        for w in &warnings {
            tracing::warn!("{w}");
        }
        let (table, issues) = ClientTable::from_config(new);
        for issue in &issues {
            tracing::warn!("clients: {issue}");
        }
        let mut restart = !self.resolver.set_config(table, Arc::clone(&settings.local));
        let Some(mut current) = self.current.try_lock_for(Duration::from_secs(2)) else {
            tracing::error!("the live settings lock timed out; a restart is needed");
            return true;
        };
        restart |= self.server.apply_live(&current, &settings);
        *current = settings;
        restart
    }
}

/// m18: the DNS and DoH addresses that are bound now, for `GET /system`.
pub(crate) fn live_listeners(server: &DnsServer) -> Vec<(String, SocketAddr)> {
    let mut out: Vec<(String, SocketAddr)> = server
        .bound()
        .iter()
        .map(|b| ("dns".to_owned(), b.udp))
        .collect();
    out.extend(
        server
            .doh_bound()
            .into_iter()
            .map(|a| ("doh".to_owned(), a)),
    );
    out
}

/// Copies the MAC address and the local name of each client address into the statistics
/// store, so that a client has its MAC as key (docs/API.md section 5.6). A service loop
/// until the stop.
///
/// m11: each round reads the local zone of the resolver now, so a live apply of new local
/// records reaches the statistics in one round. See [`next_identity`] for when a stored
/// name is cleared.
async fn identity_sync(
    stats: rusthole_store::Stats,
    resolver: Arc<rusthole_dns::ClientResolver>,
    cancel: CancellationToken,
) {
    // The zone of the last round: a stored name that came from it and that the new zone
    // does not give any more is cleared.
    let mut prev: Option<Arc<rusthole_core::localdns::LocalZone>> = None;
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(IDENTITY_SYNC) => {}
        }
        let s = stats.clone();
        let r = Arc::clone(&resolver);
        let p = prev.clone();
        let task = tokio::task::spawn_blocking(move || sync_once(&s, &r, p.as_deref()));
        match tokio::time::timeout(Duration::from_secs(30), task).await {
            // Only a full round moves `prev` on: else a removed name never clears.
            Ok(Ok(Some(zone))) => prev = Some(zone),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "the client identity sync task failed"),
            Err(_) => tracing::warn!("the client identity sync timed out"),
        }
    }
}

/// The identity to store for one client, or `None` when the stored one stays. Pure.
///
/// - The MAC address: the neighbor table now, else the stored MAC.
/// - The name: the local zone now, else the PTR cache, else the stored name. A stored name
///   that the last zone gave to this address (`was_local`) is cleared when the zone and the
///   PTR cache give no name now: the record was removed. A name from a PTR lookup stays
///   when its cache entry ends.
pub(crate) fn next_identity(
    stored: &rusthole_store::Identity,
    mac: Option<String>,
    name: Option<String>,
    was_local: bool,
) -> Option<rusthole_store::Identity> {
    let next = rusthole_store::Identity {
        mac: mac.or_else(|| stored.mac.clone()),
        name: name.or_else(|| if was_local { None } else { stored.name.clone() }),
    };
    (next != *stored).then_some(next)
}

/// One identity sync round with the local zone of the resolver now (m11). Returns that zone
/// when the round ended, or `None` when it stopped early (a store error).
pub(crate) fn sync_once(
    stats: &rusthole_store::Stats,
    resolver: &rusthole_dns::ClientResolver,
    prev: Option<&rusthole_core::localdns::LocalZone>,
) -> Option<Arc<rusthole_core::localdns::LocalZone>> {
    let zone = resolver.zone();
    let Ok(index) = stats.clients_index() else {
        return None;
    };
    for meta in index.all().take(IDENTITY_SYNC_MAX) {
        let mac = resolver.neighbors().get_ip(meta.ip).map(|m| m.to_string());
        let name = zone
            .names_of(meta.ip)
            .first()
            .cloned()
            .or_else(|| resolver.hostname_of(meta.ip))
            .map(|n| n.as_str().to_owned());
        let stored = rusthole_store::Identity {
            mac: meta.mac.clone(),
            name: meta.name.clone(),
        };
        let was_local = stored.name.as_deref().is_some_and(|n| {
            prev.is_some_and(|z| z.names_of(meta.ip).iter().any(|d| d.as_str() == n))
        });
        let Some(identity) = next_identity(&stored, mac, name, was_local) else {
            continue;
        };
        if let Err(e) = stats.set_client_identity(meta.ip, identity) {
            tracing::debug!(error = %e, "cannot record a client identity");
            return None;
        }
    }
    Some(zone)
}

/// Waits for SIGTERM or SIGINT (Unix), or Ctrl+C (all systems).
///
/// The wait has no time limit on purpose: the server runs until it gets a stop signal.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
                return;
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM or SIGINT; using Ctrl+C only");
            }
        }
    }
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %e, "cannot listen for Ctrl+C; stop the process with a kill");
        // No stop signal can come. The server runs until the process is killed.
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests;
