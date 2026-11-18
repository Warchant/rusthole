//! The DNS server: settings from the config, listeners, interface rescan and shutdown.
//!
//! ```mermaid
//! flowchart LR
//!     start[start] --> scan[scan interfaces] --> acl[build ACL]
//!     acl --> bind[bind UDP + TCP per address]
//!     bind --> tasks[UDP loops, TCP accept loops, rescan loop, prober]
//!     tasks --> stop[shutdown: stop accept, finish in-flight, hard stop after grace]
//! ```
//!
//! Every task goes through one [`Spawner`], so [`DnsServer::shutdown`] and `Drop` stop all
//! of them. A start error also stops the tasks that the start made.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use parking_lot::Mutex;
use rusthole_core::Config;
use rusthole_core::acl::{self, Acl, InterfaceNet};
use rusthole_core::cache::TtlPolicy;
use rusthole_core::config::AUTO;
use rusthole_core::net::{Cidr, Transport, UpstreamHost, UpstreamUrl};
use rusthole_core::ratelimit;
use rusthole_core::upstream_health::{HealthConfig, HealthState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::filter::{AllowAll, ClientTransport, NoopObserver, QueryFilter, QueryObserver};
use crate::handler::{Handler, HandlerSettings};
use crate::interfaces::{self, InterfaceSource, SystemInterfaces};
use crate::resolve::HostResolver;
use crate::sync::{Clock, LOCK_TIMEOUT, Spawner};
use crate::upstream::{self, Pool, PoolSettings, UpstreamProto, UpstreamServer};
use crate::wire::{self, HEADER_LEN, RawHeader};

/// Default period of the interface rescan (amendment A5).
pub const RESCAN_INTERVAL: Duration = Duration::from_secs(30);
/// Default time that shutdown gives in-flight queries.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Client UDP queries in handling at the same time, at most. More are dropped.
pub const MAX_UDP_INFLIGHT: usize = 1024;
/// The largest UDP query that rusthole reads.
const MAX_UDP_QUERY: usize = 4096;
/// Time limit for one UDP reply send.
const UDP_SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// Time that the hard stop waits for the tasks.
const HARD_STOP_WAIT: Duration = Duration::from_secs(2);
/// A pause after an accept or receive error, so a lasting error does not spin the CPU.
const ERROR_PAUSE: Duration = Duration::from_millis(5);
/// Open TCP connections from off-net clients, at most. They have their own pool, so they
/// cannot use the connection slots of LAN clients.
pub const MAX_OFFNET_TCP: usize = 16;
/// Time limit for the full exchange with an off-net TCP client (read one query, write
/// REFUSED). Then the connection closes.
pub const OFFNET_TCP_TIMEOUT: Duration = Duration::from_secs(1);
/// Tries to find a port that is free for UDP and TCP (port 0 in the settings).
const PORT_PAIR_TRIES: usize = 128;

/// Where to listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenMode {
    /// Each IPv4 address of each local interface. rusthole rebinds when they change.
    Auto,
    /// These addresses only.
    Addrs(Vec<IpAddr>),
}

/// Limits of the TCP listener (RFC 7766).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpLimits {
    /// Open client connections, at most.
    pub max_connections: usize,
    /// Open connections from one client address, at most.
    pub max_per_client: usize,
    /// A connection with no query for this time closes.
    pub idle_timeout: Duration,
    /// Time limit to read the rest of a query, or to write a reply.
    pub io_timeout: Duration,
    /// Queries on one connection, at most. Then the connection closes.
    pub max_queries_per_connection: usize,
    /// The largest query in bytes. A longer query closes the connection.
    pub max_query_len: usize,
}

impl Default for TcpLimits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_per_client: 16,
            idle_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(5),
            max_queries_per_connection: 100,
            max_query_len: 4096,
        }
    }
}

/// All settings of the DNS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    /// Listen addresses.
    pub listen: ListenMode,
    /// Port for UDP and TCP. 0 (tests only; config validation refuses it) picks a random
    /// port that is free for UDP and TCP on each address.
    pub port: u16,
    /// Allow loopback and each local interface subnet.
    pub acl_auto_local: bool,
    /// More allowed networks.
    pub acl_allow: Vec<Cidr>,
    /// Pipeline settings.
    pub handler: HandlerSettings,
    /// Upstream pool settings.
    pub pool: PoolSettings,
    /// Period of the interface rescan.
    pub rescan_interval: Duration,
    /// TCP listener limits.
    pub tcp: TcpLimits,
}

/// Why the config cannot give DNS settings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    /// A config value does not parse. `Config::validate` reports this first.
    #[error("{path}: {message}")]
    BadValue {
        /// The TOML path.
        path: String,
        /// The problem.
        message: String,
    },
    /// No upstream that this version can use.
    #[error(
        "no plain DNS upstream (udp:// or tcp://) in upstreams.servers; \
         DoT and DoH upstreams come in a later version"
    )]
    NoUpstream,
}

impl DnsSettings {
    /// Makes the DNS settings from a validated config. Also returns warnings to log (for
    /// example a DoT or DoH upstream that this version skips).
    pub fn from_config(cfg: &Config) -> Result<(Self, Vec<String>), SettingsError> {
        let mut warnings = Vec::new();
        let bad = |path: String, message: String| SettingsError::BadValue { path, message };
        let listen = if cfg.server.dns_listen.iter().any(|s| s.trim() == AUTO) {
            ListenMode::Auto
        } else {
            let mut addrs = Vec::new();
            for (i, s) in cfg.server.dns_listen.iter().enumerate() {
                let ip: IpAddr = s.trim().parse().map_err(|_| {
                    bad(
                        format!("server.dns_listen[{i}]"),
                        "not an IP address".to_owned(),
                    )
                })?;
                addrs.push(ip);
            }
            ListenMode::Addrs(addrs)
        };
        let mut acl_allow = Vec::new();
        for (i, s) in cfg.acl.allow.iter().enumerate() {
            acl_allow
                .push(Cidr::parse(s).map_err(|e| bad(format!("acl.allow[{i}]"), e.to_string()))?);
        }
        let mut servers = Vec::new();
        for (i, up) in cfg.upstreams.servers.iter().enumerate() {
            let url = UpstreamUrl::parse(&up.url)
                .map_err(|e| bad(format!("upstreams.servers[{i}].url"), e.to_string()))?;
            match (url.transport, &url.host) {
                (Transport::Udp | Transport::Tcp, UpstreamHost::Ip(ip)) => {
                    servers.push(UpstreamServer {
                        addr: SocketAddr::new(*ip, url.port),
                        proto: if url.transport == Transport::Udp {
                            UpstreamProto::Udp
                        } else {
                            UpstreamProto::Tcp
                        },
                    });
                }
                _ => warnings.push(format!(
                    "upstreams.servers[{i}]: DoT and DoH upstreams come in a later version; \
                     this upstream is skipped"
                )),
            }
        }
        if servers.is_empty() {
            return Err(SettingsError::NoUpstream);
        }
        let settings = Self {
            listen,
            port: cfg.server.dns_port,
            acl_auto_local: cfg.acl.auto_local,
            acl_allow,
            handler: HandlerSettings {
                ttl: TtlPolicy {
                    min_ttl: cfg.cache.min_ttl,
                    max_ttl: cfg.cache.max_ttl,
                    negative_ttl: cfg.cache.negative_ttl,
                },
                cache_entries: usize::try_from(cfg.cache.max_entries).unwrap_or(usize::MAX),
                rate_queries: cfg.rate_limit.queries,
                rate_interval_seconds: cfg.rate_limit.interval_seconds,
                rate_max_clients: ratelimit::MAX_CLIENTS,
            },
            pool: PoolSettings {
                servers,
                timeout: Duration::from_millis(u64::from(cfg.upstreams.timeout_ms.max(1))),
                max_attempts: upstream::MAX_ATTEMPTS,
                max_inflight: upstream::MAX_INFLIGHT,
                health: HealthConfig::default(),
            },
            rescan_interval: RESCAN_INTERVAL,
            tcp: TcpLimits::default(),
        };
        Ok((settings, warnings))
    }

    fn needs_scan(&self) -> bool {
        self.listen == ListenMode::Auto || self.acl_auto_local
    }
}

/// The hooks of the server.
#[derive(Debug, Clone)]
pub struct ServerDeps {
    /// The interface list.
    pub interfaces: Arc<dyn InterfaceSource>,
    /// The policy hook.
    pub filter: Arc<dyn QueryFilter>,
    /// The statistics hook.
    pub observer: Arc<dyn QueryObserver>,
}

impl Default for ServerDeps {
    fn default() -> Self {
        Self {
            interfaces: Arc::new(SystemInterfaces),
            filter: Arc::new(AllowAll),
            observer: Arc::new(NoopObserver),
        }
    }
}

/// Why the server did not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The interface list cannot be read, and `dns_listen` is `auto`.
    #[error("cannot read the network interfaces: {0}")]
    Interfaces(#[source] io::Error),
    /// An explicit listen address cannot be bound.
    #[error("cannot listen on {addr}: {source}")]
    Bind {
        /// The address and port.
        addr: SocketAddr,
        /// The OS error.
        #[source]
        source: io::Error,
    },
    /// No address could be bound.
    #[error("no DNS listen address could be bound")]
    NoListener,
}

/// The UDP and TCP addresses of one bound listen address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundListener {
    /// The UDP socket address.
    pub udp: SocketAddr,
    /// The TCP socket address.
    pub tcp: SocketAddr,
}

#[derive(Debug)]
struct ActiveListener {
    bound: BoundListener,
    cancel: CancellationToken,
}

#[derive(Debug)]
struct Shared {
    settings: DnsSettings,
    interfaces: Arc<dyn InterfaceSource>,
    handler: Arc<Handler>,
    pool: Pool,
    spawner: Spawner,
    root: CancellationToken,
    listeners: Mutex<BTreeMap<IpAddr, ActiveListener>>,
    warned_public: Mutex<HashSet<Cidr>>,
    udp_permits: Arc<Semaphore>,
    tcp: TcpAdmission,
}

/// A running DNS server. Dropping it stops all tasks without a wait; prefer
/// [`DnsServer::shutdown`].
#[derive(Debug)]
pub struct DnsServer {
    shared: Arc<Shared>,
}

/// Starts the DNS server.
pub async fn start(settings: DnsSettings, deps: ServerDeps) -> Result<DnsServer, StartError> {
    let clock = Clock::new();
    let spawner = Spawner::new();
    let nets = if settings.needs_scan() {
        match deps.interfaces.scan() {
            Ok(n) => n,
            Err(e) if settings.listen == ListenMode::Auto => return Err(StartError::Interfaces(e)),
            Err(e) => {
                tracing::warn!(error = %e, "cannot read the network interfaces; the ACL allows loopback and acl.allow only");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let acl = Acl::build(settings.acl_auto_local, &nets, &settings.acl_allow);
    let handler = Arc::new(Handler::new(
        &settings.handler,
        acl,
        deps.filter,
        deps.observer,
        clock,
    ));
    let pool = Pool::new(settings.pool.clone(), clock, spawner.clone());
    let tcp = TcpAdmission::new(&settings.tcp);
    let shared = Arc::new(Shared {
        settings,
        interfaces: deps.interfaces,
        handler,
        pool,
        spawner,
        root: CancellationToken::new(),
        listeners: Mutex::new(BTreeMap::new()),
        warned_public: Mutex::new(HashSet::new()),
        udp_permits: Arc::new(Semaphore::new(MAX_UDP_INFLIGHT)),
        tcp,
    });
    // From here, each error path stops the tasks through `server`.
    let server = DnsServer {
        shared: Arc::clone(&shared),
    };
    shared.warn_public(&nets);
    match shared.start_listeners(&nets).await {
        Ok(()) => {}
        Err(e) => {
            server.shutdown(Duration::from_millis(500)).await;
            return Err(e);
        }
    }
    if shared.settings.needs_scan() {
        let sh = Arc::clone(&shared);
        let cancel = shared.root.clone();
        shared
            .spawner
            .spawn(async move { sh.rescan_loop(cancel).await });
    }
    let pool = shared.pool.clone();
    let cancel = shared.root.clone();
    shared
        .spawner
        .spawn(async move { pool.run_prober(cancel).await });
    Ok(server)
}

impl DnsServer {
    /// The bound listeners.
    pub fn bound(&self) -> Vec<BoundListener> {
        self.shared
            .listeners
            .try_lock_for(LOCK_TIMEOUT)
            .map_or_else(Vec::new, |m| m.values().map(|l| l.bound).collect())
    }

    /// The current ACL. `None` when its lock timed out.
    pub fn acl(&self) -> Option<Arc<Acl>> {
        self.shared.handler.acl()
    }

    /// Number of running tasks.
    pub fn task_count(&self) -> usize {
        self.shared.spawner.len()
    }

    /// The health of each upstream, in config order.
    pub fn upstream_health(&self) -> Vec<HealthState> {
        self.shared.pool.health()
    }

    /// Number of cache entries.
    pub fn cache_len(&self) -> usize {
        self.shared.handler.cache_len()
    }

    /// Number of coalesced upstream queries in flight.
    pub fn inflight_upstream(&self) -> usize {
        self.shared.pool.inflight_len()
    }

    /// A host name lookup through the upstream pool of this server (no ACL, no filter, no
    /// cache). The list refresher uses it for its downloads (part P3b).
    pub fn host_resolver(&self) -> HostResolver {
        HostResolver::new(self.shared.pool.clone(), self.shared.root.clone())
    }

    /// Scans the interfaces now: updates the ACL and (with `auto`) the listeners.
    pub async fn rescan(&self) {
        self.shared.rescan().await;
    }

    /// Stops the server: stops accept and receive, gives in-flight queries `grace` to end,
    /// then stops all tasks. Returns true when all tasks ended in `grace`.
    pub async fn shutdown(&self, grace: Duration) -> bool {
        self.shared.root.cancel();
        let clean = self.shared.spawner.stop(grace, HARD_STOP_WAIT).await;
        if let Some(mut m) = self.shared.listeners.try_lock_for(LOCK_TIMEOUT) {
            m.clear();
        }
        if clean {
            tracing::info!("DNS server stopped");
        } else {
            tracing::warn!("DNS server stopped; some queries did not end in time");
        }
        clean
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.shared.root.cancel();
        self.shared.spawner.hard_stop();
    }
}

impl Shared {
    /// Logs a warning once for each interface subnet that is not private (amendment A8).
    fn warn_public(&self, nets: &[InterfaceNet]) {
        if !self.settings.acl_auto_local {
            return;
        }
        let Some(mut warned) = self.warned_public.try_lock_for(LOCK_TIMEOUT) else {
            return;
        };
        for net in acl::public_subnets(nets) {
            // The set holds interface subnets only, so it stays small; cap it anyway.
            if warned.len() < 1024 && warned.insert(net) {
                tracing::warn!(
                    subnet = %net,
                    "a local interface subnet is not private; with acl.auto_local, clients \
                     from this network can use rusthole"
                );
            }
        }
    }

    async fn start_listeners(self: &Arc<Self>, nets: &[InterfaceNet]) -> Result<(), StartError> {
        match &self.settings.listen {
            ListenMode::Addrs(addrs) => {
                for ip in addrs {
                    self.bind(*ip).await.map_err(|source| StartError::Bind {
                        addr: SocketAddr::new(*ip, self.settings.port),
                        source,
                    })?;
                }
            }
            ListenMode::Auto => {
                if !cfg!(target_os = "linux") {
                    tracing::info!(
                        "development mode: on this OS, dns_listen = \"auto\" binds 127.0.0.1 only"
                    );
                }
                for ip in auto_listen_addrs(nets) {
                    if let Err(e) = self.bind(ip).await {
                        tracing::warn!(addr = %ip, error = %e, "cannot listen; retry at the next interface scan");
                    }
                }
            }
        }
        if self
            .listeners
            .try_lock_for(LOCK_TIMEOUT)
            .is_none_or(|m| m.is_empty())
        {
            return Err(StartError::NoListener);
        }
        Ok(())
    }

    /// Binds UDP and TCP on `ip` and starts their loops.
    async fn bind(self: &Arc<Self>, ip: IpAddr) -> io::Result<()> {
        let (udp, tcp) = bind_pair(ip, self.settings.port).await?;
        let bound = BoundListener {
            udp: udp.local_addr()?,
            tcp: tcp.local_addr()?,
        };
        let cancel = self.root.child_token();
        let Some(mut map) = self.listeners.try_lock_for(LOCK_TIMEOUT) else {
            return Err(io::Error::other("the listener map lock timed out"));
        };
        if let Some(old) = map.insert(
            ip,
            ActiveListener {
                bound,
                cancel: cancel.clone(),
            },
        ) {
            old.cancel.cancel();
        }
        drop(map);
        let udp = Arc::new(udp);
        {
            let sh = Arc::clone(self);
            let c = cancel.clone();
            self.spawner
                .spawn(async move { sh.serve_udp(udp, c).await });
        }
        {
            let sh = Arc::clone(self);
            let c = cancel.clone();
            self.spawner
                .spawn(async move { sh.serve_tcp(tcp, c).await });
        }
        tracing::info!(udp = %bound.udp, tcp = %bound.tcp, "DNS listening");
        Ok(())
    }

    /// Rescans the interfaces on a period.
    ///
    /// Service loop: unbounded on purpose. It runs for the life of the server and ends when
    /// `cancel` is cancelled.
    async fn rescan_loop(self: Arc<Self>, cancel: CancellationToken) {
        let mut tick = tokio::time::interval(self.settings.rescan_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is at once; the start did the first scan.
        tick.tick().await;
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = tick.tick() => self.rescan().await,
            }
        }
    }

    async fn rescan(self: &Arc<Self>) {
        let nets = match self.interfaces.scan() {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "cannot read the network interfaces; keeping the old state");
                return;
            }
        };
        self.handler.set_acl(Acl::build(
            self.settings.acl_auto_local,
            &nets,
            &self.settings.acl_allow,
        ));
        self.warn_public(&nets);
        if self.settings.listen != ListenMode::Auto || self.root.is_cancelled() {
            return;
        }
        let want: Vec<IpAddr> = auto_listen_addrs(&nets);
        let have: Vec<IpAddr> = {
            let Some(mut map) = self.listeners.try_lock_for(LOCK_TIMEOUT) else {
                tracing::error!("cannot update the listeners: the lock timed out");
                return;
            };
            let gone: Vec<IpAddr> = map
                .keys()
                .filter(|ip| !want.contains(ip))
                .copied()
                .collect();
            for ip in gone {
                if let Some(l) = map.remove(&ip) {
                    l.cancel.cancel();
                    tracing::info!(udp = %l.bound.udp, tcp = %l.bound.tcp, "DNS stopped listening (address removed)");
                }
            }
            map.keys().copied().collect()
        };
        for ip in want.into_iter().filter(|ip| !have.contains(ip)) {
            if let Err(e) = self.bind(ip).await {
                tracing::warn!(addr = %ip, error = %e, "cannot listen; retry at the next interface scan");
            }
        }
    }

    /// Receives UDP queries and spawns one task for each.
    ///
    /// Service loop: unbounded on purpose. It runs while the address is bound and ends when
    /// `cancel` is cancelled.
    async fn serve_udp(self: Arc<Self>, sock: Arc<UdpSocket>, cancel: CancellationToken) {
        let mut buf = vec![0u8; MAX_UDP_QUERY];
        loop {
            let received = tokio::select! {
                () = cancel.cancelled() => break,
                r = sock.recv_from(&mut buf) => r,
            };
            let (n, peer) = match received {
                Ok(v) => v,
                Err(e) => {
                    // Windows reports an ICMP "port unreachable" from an earlier send as
                    // `ConnectionReset`. The socket still works.
                    if e.kind() != io::ErrorKind::ConnectionReset {
                        tracing::debug!(error = %e, "UDP receive error");
                        tokio::time::sleep(ERROR_PAUSE).await;
                    }
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&self.udp_permits).try_acquire_owned() else {
                tracing::debug!(%peer, "too many UDP queries in flight; query dropped");
                continue;
            };
            let Some(data) = buf.get(..n).map(<[u8]>::to_vec) else {
                continue;
            };
            let sh = Arc::clone(&self);
            let sock = Arc::clone(&sock);
            self.spawner.spawn(async move {
                let _permit = permit;
                if let Some(reply) = sh
                    .handler
                    .handle(&sh.pool, &data, peer, ClientTransport::Udp)
                    .await
                {
                    let _ =
                        tokio::time::timeout(UDP_SEND_TIMEOUT, sock.send_to(&reply.bytes, peer))
                            .await;
                }
            });
        }
    }

    /// Accepts TCP connections within the connection limits.
    ///
    /// Service loop: unbounded on purpose. It runs while the address is bound and ends when
    /// `cancel` is cancelled.
    async fn serve_tcp(self: Arc<Self>, listener: TcpListener, cancel: CancellationToken) {
        loop {
            let accepted = tokio::select! {
                () = cancel.cancelled() => break,
                r = listener.accept() => r,
            };
            let (stream, peer) = match accepted {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "TCP accept error");
                    tokio::time::sleep(ERROR_PAUSE).await;
                    continue;
                }
            };
            // The ACL check is here, before a slot is taken, so off-net clients cannot use
            // the slots of LAN clients. `front` checks the ACL again for each query, because
            // the ACL can change while a connection is open.
            let allowed = self.handler.allowed(peer.ip());
            match self.tcp.admit(allowed, peer.ip()) {
                Admit::Lan(permit, slot) => {
                    let sh = Arc::clone(&self);
                    let c = cancel.clone();
                    self.spawner.spawn(async move {
                        let _permit = permit;
                        let _slot = slot;
                        sh.serve_conn(stream, peer, c).await;
                    });
                }
                Admit::OffNet(permit) => {
                    let sh = Arc::clone(&self);
                    let c = cancel.clone();
                    self.spawner.spawn(async move {
                        let _permit = permit;
                        sh.serve_offnet(stream, c).await;
                    });
                }
                Admit::Reject(reason) => {
                    tracing::debug!(%peer, reason, "TCP connection closed");
                }
            }
        }
    }

    /// Serves one off-net TCP connection: reads one query and answers REFUSED (amendment
    /// A8), then closes. The full exchange has one time limit, [`OFFNET_TCP_TIMEOUT`], so a
    /// slow sender cannot keep the slot.
    async fn serve_offnet(&self, mut stream: TcpStream, cancel: CancellationToken) {
        let max_query_len = self.settings.tcp.max_query_len;
        let exchange = async {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.ok()?;
            let n = usize::from(u16::from_be_bytes(len_buf));
            if n < HEADER_LEN || n > max_query_len {
                return None;
            }
            let mut buf = vec![0u8; n];
            stream.read_exact(&mut buf).await.ok()?;
            let h = RawHeader::parse(&buf)?;
            if h.qr {
                // Never answer a response.
                return None;
            }
            let reply = wire::header_reply(&h, ResponseCode::Refused);
            let len = u16::try_from(reply.len()).ok()?;
            let mut out = Vec::with_capacity(reply.len() + 2);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&reply);
            stream.write_all(&out).await.ok()
        };
        tokio::select! {
            () = cancel.cancelled() => {}
            _ = tokio::time::timeout(OFFNET_TCP_TIMEOUT, exchange) => {}
        }
        let _ = tokio::time::timeout(OFFNET_TCP_TIMEOUT, stream.shutdown()).await;
    }

    /// Serves one TCP connection: at most `max_queries_per_connection` queries, one at a
    /// time. The loop is bounded by that number.
    async fn serve_conn(&self, mut stream: TcpStream, peer: SocketAddr, cancel: CancellationToken) {
        let limits = self.settings.tcp;
        for _ in 0..limits.max_queries_per_connection {
            let mut len_buf = [0u8; 2];
            let read = tokio::select! {
                () = cancel.cancelled() => break,
                r = tokio::time::timeout(limits.idle_timeout, stream.read_exact(&mut len_buf)) => r,
            };
            if !matches!(read, Ok(Ok(_))) {
                break;
            }
            let n = usize::from(u16::from_be_bytes(len_buf));
            if n < HEADER_LEN || n > limits.max_query_len {
                break;
            }
            let mut buf = vec![0u8; n];
            let read = tokio::time::timeout(limits.io_timeout, stream.read_exact(&mut buf)).await;
            if !matches!(read, Ok(Ok(_))) {
                break;
            }
            // An in-flight query ends even during shutdown (the hard stop has a limit).
            let Some(reply) = self
                .handler
                .handle(&self.pool, &buf, peer, ClientTransport::Tcp)
                .await
            else {
                break;
            };
            let Ok(len) = u16::try_from(reply.bytes.len()) else {
                break;
            };
            let mut out = Vec::with_capacity(reply.bytes.len() + 2);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&reply.bytes);
            let wrote = tokio::time::timeout(limits.io_timeout, stream.write_all(&out)).await;
            if !matches!(wrote, Ok(Ok(()))) || reply.close {
                break;
            }
        }
        let _ = tokio::time::timeout(limits.io_timeout, stream.shutdown()).await;
    }
}

/// The addresses for `dns_listen = "auto"`. On Linux: each IPv4 interface address. On other
/// systems (development only): `127.0.0.1` only, so a development host binds no LAN address.
fn auto_listen_addrs(nets: &[InterfaceNet]) -> Vec<IpAddr> {
    if cfg!(target_os = "linux") {
        interfaces::listen_addrs(nets)
    } else {
        vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
    }
}

/// Binds UDP and TCP on the same port. Port 0 (tests only) tries random ports from the OS
/// CSPRNG until one is free for both, at most [`PORT_PAIR_TRIES`] times.
///
/// The ports are random, not from the OS: on Windows, the OS gives TCP ports in sequence,
/// and a full sequence can be in a UDP excluded port range.
async fn bind_pair(ip: IpAddr, port: u16) -> io::Result<(UdpSocket, TcpListener)> {
    if port != 0 {
        let udp = UdpSocket::bind(SocketAddr::new(ip, port)).await?;
        let tcp = TcpListener::bind(SocketAddr::new(ip, port)).await?;
        return Ok((udp, tcp));
    }
    let mut last = io::Error::new(io::ErrorKind::AddrInUse, "no free port");
    for _ in 0..PORT_PAIR_TRIES {
        let p = upstream::random_port().map_err(|e| io::Error::other(e.to_string()))?;
        let addr = SocketAddr::new(ip, p);
        let failed = match UdpSocket::bind(addr).await {
            Ok(udp) => match TcpListener::bind(addr).await {
                Ok(tcp) => return Ok((udp, tcp)),
                Err(e) => e,
            },
            Err(e) => e,
        };
        if !matches!(
            failed.kind(),
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
        ) {
            return Err(failed);
        }
        last = failed;
    }
    Err(last)
}

/// How the accept loop admits a TCP connection.
enum Admit {
    /// An allowed client: a slot in the main pool and in the per-client count.
    Lan(OwnedSemaphorePermit, ClientSlot),
    /// An off-net client: a slot in the small off-net pool.
    OffNet(OwnedSemaphorePermit),
    /// No free slot: close the connection at once.
    Reject(&'static str),
}

/// The TCP connection limits: a main pool with a per-client count for allowed clients, and
/// a separate small pool for off-net clients.
#[derive(Debug)]
struct TcpAdmission {
    lan: Arc<Semaphore>,
    offnet: Arc<Semaphore>,
    per_client: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_client: usize,
}

impl TcpAdmission {
    fn new(limits: &TcpLimits) -> Self {
        Self {
            lan: Arc::new(Semaphore::new(limits.max_connections.max(1))),
            offnet: Arc::new(Semaphore::new(MAX_OFFNET_TCP)),
            per_client: Arc::new(Mutex::new(HashMap::new())),
            max_per_client: limits.max_per_client,
        }
    }

    /// Admits a connection from `ip`. `allowed` is the ACL decision for `ip`.
    fn admit(&self, allowed: bool, ip: IpAddr) -> Admit {
        if !allowed {
            return Arc::clone(&self.offnet).try_acquire_owned().map_or(
                Admit::Reject("too many off-net TCP connections"),
                Admit::OffNet,
            );
        }
        let Ok(permit) = Arc::clone(&self.lan).try_acquire_owned() else {
            return Admit::Reject("too many TCP connections");
        };
        match ClientSlot::acquire(&self.per_client, ip, self.max_per_client) {
            Some(slot) => Admit::Lan(permit, slot),
            None => Admit::Reject("too many TCP connections from this client"),
        }
    }
}

/// A slot in the per-client TCP connection count. The map holds only clients with an open
/// connection, so its size is at most `max_connections`.
struct ClientSlot {
    map: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl ClientSlot {
    fn acquire(map: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr, max: usize) -> Option<Self> {
        let mut m = map.try_lock_for(LOCK_TIMEOUT)?;
        let count = m.entry(ip).or_insert(0);
        if *count >= max {
            if *count == 0 {
                m.remove(&ip);
            }
            return None;
        }
        *count += 1;
        Some(Self {
            map: Arc::clone(map),
            ip,
        })
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let Some(mut m) = self.map.try_lock_for(LOCK_TIMEOUT) else {
            tracing::error!("cannot release a TCP client slot: the lock timed out");
            return;
        };
        if let Some(c) = m.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_from_default_config() {
        let cfg = Config::default();
        let (s, warnings) = DnsSettings::from_config(&cfg).unwrap();
        assert_eq!(s.listen, ListenMode::Auto);
        assert_eq!(s.port, 53);
        assert_eq!(s.pool.servers.len(), 2);
        assert_eq!(s.pool.timeout, Duration::from_millis(2000));
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn settings_skip_encrypted_upstreams() {
        let text = r#"
config_version = 1
[server]
dns_listen = ["192.0.2.1"]
dns_port = 5353
[acl]
auto_local = false
allow = ["198.51.100.0/24"]
[upstreams]
timeout_ms = 300
[[upstreams.servers]]
url = "tcp://192.0.2.53"
[[upstreams.servers]]
url = "tls://dns.example:853"
bootstrap = ["192.0.2.80"]
"#;
        let cfg = Config::from_toml_str(text).unwrap();
        assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
        let (s, warnings) = DnsSettings::from_config(&cfg).unwrap();
        assert_eq!(
            s.listen,
            ListenMode::Addrs(vec!["192.0.2.1".parse().unwrap()])
        );
        assert_eq!(
            s.pool.servers,
            vec![UpstreamServer {
                addr: "192.0.2.53:53".parse().unwrap(),
                proto: UpstreamProto::Tcp
            }]
        );
        assert_eq!(warnings.len(), 1);
        assert!(!s.acl_auto_local);
        assert_eq!(s.acl_allow, vec![Cidr::parse("198.51.100.0/24").unwrap()]);
    }

    #[test]
    fn settings_need_a_plain_upstream() {
        let text = r#"
config_version = 1
[[upstreams.servers]]
url = "https://doh.example/dns-query"
bootstrap = ["192.0.2.81"]
"#;
        let cfg = Config::from_toml_str(text).unwrap();
        assert_eq!(
            DnsSettings::from_config(&cfg).unwrap_err(),
            SettingsError::NoUpstream
        );
    }

    #[test]
    fn off_net_tcp_clients_cannot_use_the_lan_slots() {
        let limits = TcpLimits {
            max_connections: 2,
            max_per_client: 1,
            ..TcpLimits::default()
        };
        let adm = TcpAdmission::new(&limits);
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        // Fill the off-net pool from many off-net addresses, then try more.
        let mut held = Vec::new();
        for i in 0..(MAX_OFFNET_TCP + 8) {
            match adm.admit(false, ip(&format!("198.51.100.{i}"))) {
                Admit::OffNet(p) => held.push(p),
                Admit::Reject(_) => {}
                Admit::Lan(..) => panic!("an off-net client got a LAN slot"),
            }
        }
        assert_eq!(held.len(), MAX_OFFNET_TCP);
        assert_eq!(adm.lan.available_permits(), 2);
        assert!(adm.per_client.lock().is_empty());
        // LAN clients still get their slots.
        let a = adm.admit(true, ip("192.0.2.7"));
        assert!(matches!(a, Admit::Lan(..)));
        // The per-client limit applies.
        assert!(matches!(adm.admit(true, ip("192.0.2.7")), Admit::Reject(_)));
        let b = adm.admit(true, ip("192.0.2.8"));
        assert!(matches!(b, Admit::Lan(..)));
        // The main pool is full.
        assert!(matches!(adm.admit(true, ip("192.0.2.9")), Admit::Reject(_)));
        // An off-net slot comes back when its connection closes.
        drop(held.pop());
        assert!(matches!(
            adm.admit(false, ip("198.51.100.200")),
            Admit::OffNet(_)
        ));
        drop((a, b));
        assert_eq!(adm.lan.available_permits(), 2);
        assert!(adm.per_client.lock().is_empty());
    }

    #[test]
    fn client_slots_are_bounded_and_released() {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        let a = ClientSlot::acquire(&map, ip, 2).unwrap();
        let b = ClientSlot::acquire(&map, ip, 2).unwrap();
        assert!(ClientSlot::acquire(&map, ip, 2).is_none());
        drop(a);
        let c = ClientSlot::acquire(&map, ip, 2).unwrap();
        drop(b);
        drop(c);
        assert_eq!(map.lock().len(), 0);
        assert!(ClientSlot::acquire(&map, ip, 0).is_none());
        assert_eq!(map.lock().len(), 0);
    }
}
