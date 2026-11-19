//! The admin listener: TCP accept, client ACL, connection limits, TLS, HTTP/1.1 and HTTP/2,
//! time limits and graceful shutdown.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant C as client
//!     participant A as accept loop
//!     participant T as connection task
//!     C->>A: TCP connect
//!     A->>A: ACL (off-net: close at once), limits (total, per address)
//!     A->>T: spawn
//!     T->>C: TLS handshake (time limit)
//!     T->>C: HTTP/1.1 or HTTP/2 (header time limit, idle limit, request time limit)
//!     Note over A,T: shutdown: stop accept, graceful close, hard stop after the grace time
//! ```

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use parking_lot::Mutex;
use rusthole_core::Config;
use rusthole_core::config::AUTO;
use rusthole_dns::InterfaceSource;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::ServiceExt;

use crate::redirect::{self, FirstByte};
use crate::state::{AppState, ClientAddr};

/// Limits and time limits of the admin listener.
#[derive(Debug, Clone)]
pub struct AdminSettings {
    /// The addresses to bind.
    pub listen: Vec<SocketAddr>,
    /// Time limit of the TLS handshake.
    pub handshake_timeout: Duration,
    /// Time limit to read the request header (HTTP/1.1). It is also the idle limit of a
    /// connection (all protocols): a connection with no request in flight and no activity
    /// for this time is closed.
    pub header_timeout: Duration,
    /// The stall limit of a connection with a request in flight: with no activity for this
    /// time (no response data sent), the connection is closed. It must be longer than the
    /// request time limit ([`crate::router::REQUEST_TIMEOUT`]).
    pub stall_timeout: Duration,
    /// Open connections, at most.
    pub max_connections: usize,
    /// Open connections from one client address, at most.
    pub max_per_client: usize,
    /// HTTP/2 streams on one connection, at most.
    pub max_streams: u32,
    /// The period of the interface scan (ACL and Host list).
    pub net_refresh: Duration,
}

impl AdminSettings {
    /// Default limits for `listen`.
    pub fn new(listen: Vec<SocketAddr>) -> Self {
        Self {
            listen,
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            stall_timeout: crate::router::REQUEST_TIMEOUT + Duration::from_secs(10),
            max_connections: 256,
            max_per_client: 32,
            max_streams: 64,
            net_refresh: Duration::from_secs(30),
        }
    }
}

/// The admin listen addresses of a config. `"auto"` is each IPv4 address of each local
/// interface on Linux, and `127.0.0.1` on other systems (development mode, see
/// docs/ENGINEERING.md "Network in tests").
pub fn listen_addrs(cfg: &Config, interfaces: &dyn InterfaceSource) -> io::Result<Vec<SocketAddr>> {
    let port = cfg.server.admin.port;
    let mut out = Vec::new();
    if cfg.server.admin.listen.iter().any(|s| s.trim() == AUTO) {
        if cfg!(target_os = "linux") {
            for n in interfaces.scan()? {
                out.push(SocketAddr::new(IpAddr::V4(n.addr), port));
            }
        } else {
            tracing::info!(
                "admin listen \"auto\" binds 127.0.0.1 only on this OS (development mode)"
            );
            out.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }
    } else {
        for s in &cfg.server.admin.listen {
            let ip: Ipv4Addr = s.trim().parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "server.admin.listen: not an IPv4 address",
                )
            })?;
            out.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The running admin listener. Dropping it stops all tasks without a wait; prefer
/// [`AdminServer::shutdown`].
#[derive(Debug)]
pub struct AdminServer {
    bound: Vec<SocketAddr>,
    cancel: CancellationToken,
    hard: CancellationToken,
    tracker: TaskTracker,
}

impl Drop for AdminServer {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.hard.cancel();
        self.tracker.close();
    }
}

/// Counts the open connections of each address. Every key has at least one connection, so
/// the map has at most `max_connections` keys.
#[derive(Debug, Default)]
struct PerClient {
    open: Mutex<HashMap<IpAddr, usize>>,
}

/// One admitted connection. Dropping it frees its slots.
struct Slot {
    per: Arc<PerClient>,
    ip: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut m = self.per.open.lock();
        if let Some(n) = m.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

fn admit(
    per: &Arc<PerClient>,
    total: &Arc<Semaphore>,
    ip: IpAddr,
    max_per_client: usize,
) -> Option<Slot> {
    let permit = Arc::clone(total).try_acquire_owned().ok()?;
    let mut m = per.open.try_lock_for(Duration::from_millis(100))?;
    let n = m.entry(ip).or_insert(0);
    if *n >= max_per_client {
        if *n == 0 {
            m.remove(&ip);
        }
        return None;
    }
    *n += 1;
    drop(m);
    Some(Slot {
        per: Arc::clone(per),
        ip,
        _permit: permit,
    })
}

/// Binds the listeners and starts the accept loops.
///
/// An address that cannot be bound is logged at ERROR, and the listener runs on the other
/// addresses (m16). The function fails only when no address is bound. The listener binds
/// once: it does not bind again when the interfaces change (docs/SECURITY.md).
pub async fn start(
    settings: AdminSettings,
    tls: Arc<rustls::ServerConfig>,
    state: AppState,
) -> io::Result<AdminServer> {
    let mut listeners = Vec::new();
    let mut first_error = None;
    for addr in &settings.listen {
        match TcpListener::bind(addr).await {
            Ok(l) => listeners.push(l),
            Err(e) => {
                tracing::error!(address = %addr, error = %e, "cannot listen on an admin address; the admin listener uses the other addresses");
                first_error.get_or_insert_with(|| {
                    io::Error::new(e.kind(), format!("cannot listen on {addr} (admin): {e}"))
                });
            }
        }
    }
    if listeners.is_empty() {
        return Err(first_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no admin listen address")
        }));
    }
    let bound: Vec<SocketAddr> = listeners
        .iter()
        .filter_map(|l| l.local_addr().ok())
        .collect();
    let server = AdminServer {
        bound: bound.clone(),
        cancel: CancellationToken::new(),
        hard: CancellationToken::new(),
        tracker: TaskTracker::new(),
    };
    state.set_admin_bound(&bound);
    let app = crate::router::build(state.clone());
    let acceptor = TlsAcceptor::from(tls);
    let per = Arc::new(PerClient::default());
    let total = Arc::new(Semaphore::new(settings.max_connections.max(1)));
    for listener in listeners {
        let ctx = AcceptCtx {
            settings: settings.clone(),
            state: state.clone(),
            app: app.clone(),
            acceptor: acceptor.clone(),
            per: Arc::clone(&per),
            total: Arc::clone(&total),
            cancel: server.cancel.clone(),
            hard: server.hard.clone(),
            tracker: server.tracker.clone(),
        };
        server.tracker.spawn(accept_loop(listener, ctx));
    }
    // The interface scan: a service loop until the stop.
    let refresh_state = state.clone();
    let cancel = server.cancel.clone();
    let period = settings.net_refresh;
    server.tracker.spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(period) => {
                    let st = refresh_state.clone();
                    // The scan reads the OS interface list; run it on a blocking thread.
                    let _ = tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || st.refresh_net())).await;
                }
            }
        }
    });
    for a in &bound {
        tracing::info!(address = %a, "admin listener (HTTPS) is running");
    }
    Ok(server)
}

#[derive(Clone)]
struct AcceptCtx {
    settings: AdminSettings,
    state: AppState,
    app: axum::Router,
    acceptor: TlsAcceptor,
    per: Arc<PerClient>,
    total: Arc<Semaphore>,
    cancel: CancellationToken,
    hard: CancellationToken,
    tracker: TaskTracker,
}

/// The accept loop of one listener. It runs until the stop: a service loop, unbounded on
/// purpose.
async fn accept_loop(listener: TcpListener, ctx: AcceptCtx) {
    loop {
        let accepted = tokio::select! {
            () = ctx.cancel.cancelled() => break,
            r = listener.accept() => r,
        };
        let (tcp, peer) = match accepted {
            Ok(x) => x,
            Err(e) => {
                // For example too many open files. Wait a little, then go on.
                tracing::warn!(error = %e, "admin accept failed");
                tokio::select! {
                    () = ctx.cancel.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_millis(100)) => continue,
                }
            }
        };
        // Decision D7: an off-net client is closed at once.
        if !ctx.state.net().acl.allows(peer.ip()) {
            tracing::debug!(%peer, "admin connection from outside the ACL closed");
            drop(tcp);
            continue;
        }
        let Some(slot) = admit(&ctx.per, &ctx.total, peer.ip(), ctx.settings.max_per_client) else {
            tracing::debug!(%peer, "admin connection limit reached; connection closed");
            drop(tcp);
            continue;
        };
        let c = ctx.clone();
        ctx.tracker.spawn(serve_conn(tcp, peer, slot, c));
    }
}

/// After the idle limit, a graceful close has this time. Then the connection is dropped
/// (a silent HTTP/2 peer can keep a graceful close open).
const IDLE_GRACE: Duration = Duration::from_secs(1);

/// The activity of one connection: the time of the last activity and the requests in
/// flight. The idle watchdog reads it.
#[derive(Debug)]
struct Activity {
    start: tokio::time::Instant,
    /// Milliseconds from `start` to the last activity.
    last_ms: AtomicU64,
    in_flight: AtomicUsize,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
        })
    }

    fn now_ms(&self) -> u64 {
        millis(self.start.elapsed())
    }

    fn touch(&self) {
        self.last_ms.fetch_max(self.now_ms(), Ordering::AcqRel);
    }

    /// A request starts. The guard ends it when it drops (also when the request is
    /// cancelled).
    fn enter(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        self.touch();
        InFlight(Arc::clone(self))
    }
}

/// One request in flight. It lives until the response body is sent or dropped.
struct InFlight(Arc<Activity>);

impl InFlight {
    /// The response made progress.
    fn touch(&self) {
        self.0.touch();
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The idle decision (pure). Returns `None` when the connection must close. Else returns
/// the time to wait before the next check (at least 1 ms).
///
/// - No request in flight: close after `idle_limit` with no activity.
/// - A request in flight: close after `stall_limit` with no activity. The handler has the
///   request time limit, and each frame of the response body is activity. So only a
///   stalled response (for example a peer that never reads, or an HTTP/2 send window of
///   0) reaches this limit.
fn idle_wait(
    in_flight: usize,
    last_ms: u64,
    now_ms: u64,
    idle_limit: Duration,
    stall_limit: Duration,
) -> Option<Duration> {
    let min = Duration::from_millis(1);
    let limit = if in_flight > 0 {
        stall_limit
    } else {
        idle_limit
    };
    let idle = Duration::from_millis(now_ms.saturating_sub(last_ms));
    if idle >= limit {
        None
    } else {
        Some(limit.saturating_sub(idle).max(min))
    }
}

/// Completes when the connection must close (see [`idle_wait`]). The loop runs for the
/// life of the connection, so it is unbounded on purpose. The connection task drops it
/// when the connection ends. Each step sleeps at least 1 ms.
async fn idle_watchdog(act: Arc<Activity>, idle_limit: Duration, stall_limit: Duration) {
    loop {
        let wait = idle_wait(
            act.in_flight.load(Ordering::Acquire),
            act.last_ms.load(Ordering::Acquire),
            act.now_ms(),
            idle_limit,
            stall_limit,
        );
        match wait {
            None => return,
            Some(d) => tokio::time::sleep(d).await,
        }
    }
}

/// The first byte of a connection, without reading it. `None` at EOF.
async fn first_byte(tcp: &TcpStream) -> std::io::Result<Option<u8>> {
    let mut b = [0u8; 1];
    let n = tcp.peek(&mut b).await?;
    Ok(if n == 1 { b.first().copied() } else { None })
}

/// Reads a plain HTTP request head (at most [`redirect::MAX_HEAD`] bytes) and writes the
/// redirect answer. The caller gives the time limit.
async fn plain_redirect(mut tcp: TcpStream, ctx: &AcceptCtx) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    // Bounded: each pass reads at least one byte, and the head has at most MAX_HEAD bytes.
    for _ in 0..redirect::MAX_HEAD {
        if redirect::head_complete(&head) || head.len() >= redirect::MAX_HEAD {
            break;
        }
        match tcp.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(chunk.get(..n).unwrap_or_default()),
        }
    }
    head.truncate(redirect::MAX_HEAD);
    let answer = redirect::answer(&head, &ctx.state.net().hosts);
    let _ = tcp.write_all(&answer).await;
    let _ = tcp.shutdown().await;
}

/// Looks at the first byte of a connection: TLS goes on (`Some`); plain HTTP gets a
/// redirect answer and the connection ends (`None`); other bytes close it.
async fn tls_or_redirect(tcp: TcpStream, peer: SocketAddr, ctx: &AcceptCtx) -> Option<TcpStream> {
    let first = tokio::select! {
        () = ctx.hard.cancelled() => return None,
        () = ctx.cancel.cancelled() => return None,
        r = tokio::time::timeout(ctx.settings.handshake_timeout, first_byte(&tcp)) => r,
    };
    match first {
        Ok(Ok(Some(b))) => match redirect::classify(b) {
            FirstByte::Tls => Some(tcp),
            FirstByte::Http => {
                tokio::select! {
                    () = ctx.hard.cancelled() => {}
                    () = ctx.cancel.cancelled() => {}
                    r = tokio::time::timeout(ctx.settings.handshake_timeout, plain_redirect(tcp, ctx)) => {
                        if r.is_err() {
                            tracing::debug!(%peer, "plain HTTP request head timed out");
                        }
                    }
                }
                None
            }
            FirstByte::Other => {
                tracing::debug!(%peer, "admin connection is not TLS or HTTP; closed");
                None
            }
        },
        // EOF, an error or the time limit: close.
        _ => None,
    }
}

async fn serve_conn(tcp: TcpStream, peer: SocketAddr, slot: Slot, ctx: AcceptCtx) {
    let _slot = slot;
    let _ = tcp.set_nodelay(true);
    // Plain HTTP on the TLS port gets a redirect to HTTPS (docs/SECURITY.md section 2).
    let Some(tcp) = tls_or_redirect(tcp, peer, &ctx).await else {
        return;
    };
    let handshake = tokio::select! {
        () = ctx.hard.cancelled() => return,
        () = ctx.cancel.cancelled() => return,
        r = tokio::time::timeout(ctx.settings.handshake_timeout, ctx.acceptor.accept(tcp)) => r,
    };
    let stream = match handshake {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(%peer, error = %e, "admin TLS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "admin TLS handshake timed out");
            return;
        }
    };
    // The end of the handshake counts as activity.
    let act = Activity::new();
    let app = ctx.app.clone();
    let req_act = Arc::clone(&act);
    let svc = tower::service_fn(move |mut req: Request<Incoming>| {
        let guard = req_act.enter();
        req.extensions_mut().insert(ClientAddr(peer));
        let app = app.clone();
        async move {
            let resp = app.oneshot(req.map(Body::new)).await?;
            // The guard lives until the body is sent or dropped. Each frame is activity.
            Ok::<_, std::convert::Infallible>(resp.map(move |b| {
                Body::new(b.map_frame(move |f| {
                    guard.touch();
                    f
                }))
            }))
        }
    });
    let svc = TowerToHyperService::new(svc);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(ctx.settings.header_timeout)
        .keep_alive(true)
        .max_buf_size(64 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(ctx.settings.max_streams)
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10));
    let conn = builder.serve_connection(TokioIo::new(stream), svc);
    tokio::pin!(conn);
    // The version check of hyper-util has no time limit, HTTP/2 has no idle limit, and a
    // response body can stall. The watchdog closes such a connection.
    let idle = idle_watchdog(
        Arc::clone(&act),
        ctx.settings.header_timeout,
        ctx.settings.stall_timeout,
    );
    tokio::pin!(idle);
    tokio::select! {
        r = conn.as_mut() => {
            if let Err(e) = r {
                tracing::debug!(%peer, error = %e, "admin connection ended with an error");
            }
        }
        () = ctx.cancel.cancelled() => {
            conn.as_mut().graceful_shutdown();
            tokio::select! {
                _ = conn.as_mut() => {}
                () = ctx.hard.cancelled() => {}
            }
        }
        () = idle.as_mut() => {
            tracing::debug!(%peer, "admin connection idle or stalled; closed");
            conn.as_mut().graceful_shutdown();
            tokio::select! {
                _ = conn.as_mut() => {}
                () = tokio::time::sleep(IDLE_GRACE) => {}
                () = ctx.hard.cancelled() => {}
            }
        }
    }
}

impl AdminServer {
    /// The bound addresses.
    pub fn bound(&self) -> &[SocketAddr] {
        &self.bound
    }

    /// Running tasks (accept loops, connections, the interface scan).
    pub fn task_count(&self) -> usize {
        self.tracker.len()
    }

    /// Stops the listener: stops accept, closes the connections gracefully, and after
    /// `grace` stops the rest. Returns true when all tasks ended in `grace`.
    pub async fn shutdown(&self, grace: Duration) -> bool {
        self.cancel.cancel();
        self.tracker.close();
        let clean = tokio::time::timeout(grace, self.tracker.wait())
            .await
            .is_ok();
        if !clean {
            self.hard.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(1), self.tracker.wait()).await;
            tracing::warn!(
                tasks = self.tracker.len(),
                "admin connections did not end in time; stopped them"
            );
        }
        tracing::info!("admin listener stopped");
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_limits() {
        let per = Arc::new(PerClient::default());
        let total = Arc::new(Semaphore::new(3));
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let s1 = admit(&per, &total, a, 2).unwrap();
        let s2 = admit(&per, &total, a, 2).unwrap();
        assert!(admit(&per, &total, a, 2).is_none(), "per-client limit");
        let s3 = admit(&per, &total, b, 2).unwrap();
        assert!(admit(&per, &total, b, 2).is_none(), "total limit");
        drop(s1);
        drop(s3);
        assert_eq!(per.open.lock().len(), 1);
        drop(s2);
        assert!(per.open.lock().is_empty());
        assert_eq!(total.available_permits(), 3);
    }

    #[test]
    fn idle_decision() {
        let idle = Duration::from_millis(500);
        let stall = Duration::from_millis(5000);
        let ms = Duration::from_millis;
        // No request: wait for the rest of the idle limit, then close.
        assert_eq!(idle_wait(0, 100, 300, idle, stall), Some(ms(300)));
        assert_eq!(idle_wait(0, 100, 599, idle, stall), Some(ms(1)));
        assert_eq!(idle_wait(0, 100, 600, idle, stall), None);
        assert_eq!(idle_wait(0, 0, u64::MAX, idle, stall), None);
        // A request in flight is not idle after the idle limit; it closes only after the
        // stall limit with no activity.
        assert_eq!(idle_wait(1, 100, 600, idle, stall), Some(ms(4500)));
        assert_eq!(idle_wait(2, 100, 5099, idle, stall), Some(ms(1)));
        assert_eq!(idle_wait(1, 100, 5100, idle, stall), None);
        assert_eq!(idle_wait(1, 0, u64::MAX, idle, stall), None);
        // A last time after now (a race between threads) is not idle.
        assert_eq!(idle_wait(0, 900, 800, idle, stall), Some(idle));
        // A zero limit closes at once; the wait is never shorter than 1 ms.
        assert_eq!(idle_wait(1, 0, 0, Duration::ZERO, Duration::ZERO), None);
        assert_eq!(
            idle_wait(0, 0, 1, Duration::from_micros(1500), stall),
            Some(ms(1))
        );
    }

    #[test]
    fn default_stall_limit_is_longer_than_the_request_limit() {
        let s = AdminSettings::new(Vec::new());
        assert!(s.stall_timeout > crate::router::REQUEST_TIMEOUT);
        assert!(s.stall_timeout > s.header_timeout);
    }

    #[tokio::test]
    async fn in_flight_guard_counts() {
        let act = Activity::new();
        let g1 = act.enter();
        let g2 = act.enter();
        assert_eq!(act.in_flight.load(Ordering::Acquire), 2);
        drop(g1);
        assert_eq!(act.in_flight.load(Ordering::Acquire), 1);
        drop(g2);
        assert_eq!(act.in_flight.load(Ordering::Acquire), 0);
    }

    #[test]
    fn auto_is_loopback_off_linux() {
        let cfg = Config::default();
        let ifs = rusthole_dns::StaticInterfaces::default();
        let addrs = listen_addrs(&cfg, &ifs).unwrap();
        if !cfg!(target_os = "linux") {
            assert_eq!(addrs, [SocketAddr::from(([127, 0, 0, 1], 8443))]);
        }
    }
}
