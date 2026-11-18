//! The DoH listener (RFC 8484): HTTPS on its own port, path `/dns-query`.
//!
//! ```mermaid
//! flowchart TD
//!     acc[TCP accept] --> acl{ACL allows the TCP peer?}
//!     acl -->|no| close[close at once, no TLS]
//!     acl --> slot{connection slot: total and per client?}
//!     slot -->|no| close
//!     slot --> tls[TLS handshake, time limit, ALPN h2 or http/1.1]
//!     tls --> http[HTTP/2 or HTTP/1.1 connection]
//!     http --> req[request: decode GET or POST, time limit]
//!     req -->|bad| status[404, 405, 413, 414, 415 or 400]
//!     req --> pipe[DNS pipeline: rate limit, filter, cache, upstreams, observer]
//!     pipe --> ok[200 application/dns-message, Cache-Control max-age = lowest TTL]
//! ```
//!
//! - The client of a DoH query is the TCP peer address. rusthole does not read
//!   `X-Forwarded-For` or `Forwarded`: a client can write any header, and the ACL and the
//!   rate limit must use an address that the client cannot choose.
//! - The ACL check is at accept, before the TLS handshake, so an off-net client costs no
//!   TLS work. The pipeline checks the ACL again for each query, because the ACL can change
//!   while a connection is open.
//! - A query over the rate limit gets a DNS REFUSED reply (status 200), and the connection
//!   closes after it.
//! - Limits ([`DohLimits`]): TLS handshake time, header read time (HTTP/1.1), request time,
//!   idle time, connections in total and per client, HTTP/2 streams per connection, and
//!   requests per connection.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::header::{ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use parking_lot::Mutex;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::doh_wire::{self, DNS_MESSAGE, DohError, DohHead, MAX_BODY};
use crate::filter::ClientTransport;
use crate::handler::Handler;
use crate::server::ClientSlot;
use crate::sync::{Clock, LOCK_TIMEOUT, Spawner};
use crate::tls_upstream::HyperExec;
use crate::upstream::Pool;

/// A pause after an accept error, so a lasting error does not spin the CPU.
const ERROR_PAUSE: Duration = Duration::from_millis(5);
/// Time that a connection gets to end its open requests after a graceful shutdown starts.
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// The largest HTTP/1.1 read buffer (request line and headers).
const MAX_H1_BUF: usize = 16 * 1024;
/// The largest HTTP/2 header list.
const MAX_H2_HEADERS: u32 = 16 * 1024;
/// HTTP/2 keep-alive ping interval and time limit.
const H2_KEEP_ALIVE: Duration = Duration::from_secs(20);

/// The limits of the DoH listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DohLimits {
    /// Time limit for the TLS handshake.
    pub handshake_timeout: Duration,
    /// Time limit to read the request headers (HTTP/1.1).
    pub header_timeout: Duration,
    /// Time limit for one request: the body read and the DNS answer.
    pub request_timeout: Duration,
    /// A connection with no open request closes after this time.
    pub idle_timeout: Duration,
    /// Open connections, at most.
    pub max_connections: usize,
    /// Open connections from one client address, at most.
    pub max_per_client: usize,
    /// Open HTTP/2 streams on one connection, at most.
    pub max_streams: u32,
    /// Requests on one connection, at most. Then the connection closes.
    pub max_requests_per_connection: usize,
}

impl Default for DohLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(20),
            idle_timeout: Duration::from_secs(30),
            max_connections: 128,
            max_per_client: 16,
            max_streams: 16,
            max_requests_per_connection: 1000,
        }
    }
}

/// The settings of the DoH listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohSettings {
    /// Listen addresses (IPv4 only, amendment A11).
    pub listen: crate::server::ListenMode,
    /// The port. 0 (tests only) lets the OS pick a port.
    pub port: u16,
    /// The limits.
    pub limits: DohLimits,
}

#[derive(Debug)]
struct ActiveDoh {
    addr: SocketAddr,
    cancel: CancellationToken,
}

/// The DoH listeners and their shared state.
pub(crate) struct DohService {
    settings: DohSettings,
    handler: Arc<Handler>,
    pool: Pool,
    spawner: Spawner,
    clock: Clock,
    acceptor: TlsAcceptor,
    conns: Arc<Semaphore>,
    per_client: Arc<Mutex<HashMap<IpAddr, usize>>>,
    listeners: Mutex<BTreeMap<IpAddr, ActiveDoh>>,
}

impl std::fmt::Debug for DohService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohService")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The state of one connection that the request handler and the connection driver share.
#[derive(Debug)]
struct ConnCtl {
    requests: AtomicUsize,
    open: AtomicUsize,
    last_ms: AtomicU64,
    close: Notify,
}

/// Counts an open request while it lives.
struct OpenRequest<'a>(&'a ConnCtl, Clock);

impl<'a> OpenRequest<'a> {
    fn new(ctl: &'a ConnCtl, clock: Clock) -> Self {
        ctl.open.fetch_add(1, Ordering::AcqRel);
        ctl.last_ms.store(clock.now_ms(), Ordering::Release);
        Self(ctl, clock)
    }
}

impl Drop for OpenRequest<'_> {
    fn drop(&mut self) {
        self.0.last_ms.store(self.1.now_ms(), Ordering::Release);
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}

type Body = Full<Bytes>;

impl DohService {
    pub(crate) fn new(
        settings: DohSettings,
        handler: Arc<Handler>,
        pool: Pool,
        spawner: Spawner,
        clock: Clock,
        tls: Arc<ServerConfig>,
    ) -> Self {
        let conns = Arc::new(Semaphore::new(settings.limits.max_connections.max(1)));
        Self {
            settings,
            handler,
            pool,
            spawner,
            clock,
            acceptor: TlsAcceptor::from(tls),
            conns,
            per_client: Arc::new(Mutex::new(HashMap::new())),
            listeners: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn settings(&self) -> &DohSettings {
        &self.settings
    }

    /// The bound addresses.
    pub(crate) fn bound(&self) -> Vec<SocketAddr> {
        self.listeners
            .try_lock_for(LOCK_TIMEOUT)
            .map_or_else(Vec::new, |m| m.values().map(|l| l.addr).collect())
    }

    /// The addresses that have a listener.
    pub(crate) fn bound_ips(&self) -> Vec<IpAddr> {
        self.listeners
            .try_lock_for(LOCK_TIMEOUT)
            .map_or_else(Vec::new, |m| m.keys().copied().collect())
    }

    /// Open connections.
    pub(crate) fn open_connections(&self) -> usize {
        self.settings
            .limits
            .max_connections
            .max(1)
            .saturating_sub(self.conns.available_permits())
    }

    /// Stops the listener on `ip`.
    pub(crate) fn unbind(&self, ip: IpAddr) {
        if let Some(mut m) = self.listeners.try_lock_for(LOCK_TIMEOUT)
            && let Some(l) = m.remove(&ip)
        {
            l.cancel.cancel();
            tracing::info!(addr = %l.addr, "DoH stopped listening (address removed)");
        }
    }

    /// Forgets all listeners (after shutdown).
    pub(crate) fn clear(&self) {
        if let Some(mut m) = self.listeners.try_lock_for(LOCK_TIMEOUT) {
            for (_, l) in std::mem::take(&mut *m) {
                l.cancel.cancel();
            }
        }
    }

    /// Binds TCP on `ip` and starts the accept loop. `root` is the server stop token.
    pub(crate) async fn bind(
        self: &Arc<Self>,
        ip: IpAddr,
        root: &CancellationToken,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(SocketAddr::new(ip, self.settings.port)).await?;
        let addr = listener.local_addr()?;
        let cancel = root.child_token();
        let Some(mut map) = self.listeners.try_lock_for(LOCK_TIMEOUT) else {
            return Err(io::Error::other("the DoH listener map lock timed out"));
        };
        if let Some(old) = map.insert(
            ip,
            ActiveDoh {
                addr,
                cancel: cancel.clone(),
            },
        ) {
            old.cancel.cancel();
        }
        drop(map);
        let me = Arc::clone(self);
        self.spawner
            .spawn(async move { me.accept_loop(listener, cancel).await });
        tracing::info!(%addr, "DoH listening (https://.../dns-query)");
        Ok(())
    }

    /// Accepts connections within the limits.
    ///
    /// Service loop: unbounded on purpose. It runs while the address is bound and ends when
    /// `cancel` is cancelled.
    async fn accept_loop(self: Arc<Self>, listener: TcpListener, cancel: CancellationToken) {
        loop {
            let accepted = tokio::select! {
                () = cancel.cancelled() => break,
                r = listener.accept() => r,
            };
            let (stream, peer) = match accepted {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "DoH accept error");
                    tokio::time::sleep(ERROR_PAUSE).await;
                    continue;
                }
            };
            // The ACL uses the TCP peer address (no X-Forwarded-For). An off-net client
            // gets no TLS handshake.
            if !self.handler.allowed(peer.ip()) {
                tracing::debug!(%peer, "DoH connection from an off-net client closed");
                continue;
            }
            let Some((permit, slot)) = self.admit(peer.ip()) else {
                tracing::debug!(%peer, "DoH connection limit reached; connection closed");
                continue;
            };
            let me = Arc::clone(&self);
            let c = cancel.clone();
            self.spawner.spawn(async move {
                let _permit = permit;
                let _slot = slot;
                me.serve_conn(stream, peer, c).await;
            });
        }
    }

    fn admit(&self, ip: IpAddr) -> Option<(OwnedSemaphorePermit, ClientSlot)> {
        let permit = Arc::clone(&self.conns).try_acquire_owned().ok()?;
        let slot = ClientSlot::acquire(&self.per_client, ip, self.settings.limits.max_per_client)?;
        Some((permit, slot))
    }

    /// Serves one connection: TLS, then HTTP/2 or HTTP/1.1 by ALPN.
    async fn serve_conn(
        self: Arc<Self>,
        tcp: TcpStream,
        peer: SocketAddr,
        cancel: CancellationToken,
    ) {
        let limits = self.settings.limits;
        let _ = tcp.set_nodelay(true);
        let tls = tokio::select! {
            () = cancel.cancelled() => return,
            r = tokio::time::timeout(limits.handshake_timeout, self.acceptor.accept(tcp)) => match r {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "DoH TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "DoH TLS handshake timed out");
                    return;
                }
            },
        };
        let h2 = tls.get_ref().1.alpn_protocol() == Some(rusthole_tls::ALPN_H2);
        let ctl = Arc::new(ConnCtl {
            requests: AtomicUsize::new(0),
            open: AtomicUsize::new(0),
            last_ms: AtomicU64::new(self.clock.now_ms()),
            close: Notify::new(),
        });
        let svc = {
            let me = Arc::clone(&self);
            let ctl = Arc::clone(&ctl);
            service_fn(move |req: Request<Incoming>| {
                let me = Arc::clone(&me);
                let ctl = Arc::clone(&ctl);
                async move { Ok::<_, Infallible>(me.request(req, peer, &ctl).await) }
            })
        };
        let io = TokioIo::new(tls);
        if h2 {
            let mut b = hyper::server::conn::http2::Builder::new(HyperExec(self.spawner.clone()));
            b.timer(TokioTimer::new())
                .max_concurrent_streams(limits.max_streams)
                .max_header_list_size(MAX_H2_HEADERS)
                .keep_alive_interval(H2_KEEP_ALIVE)
                .keep_alive_timeout(H2_KEEP_ALIVE)
                .max_pending_accept_reset_streams(16)
                .max_local_error_reset_streams(64);
            let conn = b.serve_connection(io, svc);
            self.drive(
                conn,
                hyper::server::conn::http2::Connection::graceful_shutdown,
                &ctl,
                &cancel,
                peer,
            )
            .await;
        } else {
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(TokioTimer::new())
                .header_read_timeout(limits.header_timeout)
                .max_buf_size(MAX_H1_BUF)
                .keep_alive(true);
            let conn = b.serve_connection(io, svc);
            self.drive(
                conn,
                hyper::server::conn::http1::Connection::graceful_shutdown,
                &ctl,
                &cancel,
                peer,
            )
            .await;
        }
    }

    /// Drives one HTTP connection until it ends. A graceful shutdown starts on server
    /// shutdown, on the request limit, on a close request of the pipeline, or when the
    /// connection is idle. Then the connection gets [`CLOSE_GRACE`] to end, and drops.
    ///
    /// The loop ends: the request limit and the idle limit start the graceful shutdown,
    /// and the grace time ends it.
    async fn drive<C, G>(
        &self,
        conn: C,
        graceful: G,
        ctl: &ConnCtl,
        cancel: &CancellationToken,
        peer: SocketAddr,
    ) where
        C: std::future::Future<Output = Result<(), hyper::Error>>,
        G: Fn(Pin<&mut C>),
    {
        let idle_ms =
            u64::try_from(self.settings.limits.idle_timeout.as_millis()).unwrap_or(u64::MAX);
        let check = (self.settings.limits.idle_timeout / 4)
            .clamp(Duration::from_millis(20), Duration::from_secs(1));
        tokio::pin!(conn);
        let mut tick = tokio::time::interval(check);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut close_by: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                r = &mut conn => {
                    if let Err(e) = r {
                        tracing::debug!(%peer, error = %e, "DoH connection ended with an error");
                    }
                    break;
                }
                () = cancel.cancelled(), if close_by.is_none() => {
                    graceful(conn.as_mut());
                    close_by = Some(tokio::time::Instant::now() + CLOSE_GRACE);
                }
                () = ctl.close.notified(), if close_by.is_none() => {
                    graceful(conn.as_mut());
                    close_by = Some(tokio::time::Instant::now() + CLOSE_GRACE);
                }
                _ = tick.tick() => {
                    let now = tokio::time::Instant::now();
                    if close_by.is_some_and(|d| now >= d) {
                        tracing::debug!(%peer, "DoH connection did not end in the grace time; closing it");
                        break;
                    }
                    let idle = ctl.open.load(Ordering::Acquire) == 0
                        && self.clock.now_ms().saturating_sub(ctl.last_ms.load(Ordering::Acquire)) >= idle_ms;
                    if idle && close_by.is_none() {
                        graceful(conn.as_mut());
                        close_by = Some(now + CLOSE_GRACE);
                    }
                }
            }
        }
    }

    /// Handles one HTTP request.
    async fn request(
        &self,
        req: Request<Incoming>,
        peer: SocketAddr,
        ctl: &ConnCtl,
    ) -> Response<Body> {
        let _open = OpenRequest::new(ctl, self.clock);
        let n = ctl
            .requests
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let max = self.settings.limits.max_requests_per_connection.max(1);
        if n >= max {
            // The last request: the connection closes after it.
            ctl.close.notify_one();
        }
        if n > max {
            return status_response(StatusCode::SERVICE_UNAVAILABLE);
        }
        match tokio::time::timeout(
            self.settings.limits.request_timeout,
            self.answer(req, peer, ctl),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => status_response(StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    async fn answer(
        &self,
        req: Request<Incoming>,
        peer: SocketAddr,
        ctl: &ConnCtl,
    ) -> Response<Body> {
        let head = {
            let headers = req.headers();
            doh_wire::decode_head(
                req.method().as_str(),
                req.uri().path(),
                req.uri().query(),
                headers.get(CONTENT_TYPE).map(HeaderValue::as_bytes),
                headers.get(CONTENT_LENGTH).map(HeaderValue::as_bytes),
            )
        };
        let msg = match head {
            Err(e) => return error_response(e),
            Ok(DohHead::Get(msg)) => msg,
            Ok(DohHead::Post) => match Limited::new(req.into_body(), MAX_BODY).collect().await {
                Ok(body) => match doh_wire::decode_body(&body.to_bytes()) {
                    Ok(m) => m,
                    Err(e) => return error_response(e),
                },
                Err(e) => {
                    let e = if e.is::<http_body_util::LengthLimitError>() {
                        DohError::PayloadTooLarge
                    } else {
                        DohError::BadRequest
                    };
                    return error_response(e);
                }
            },
        };
        let Some(reply) = self
            .handler
            .handle(&self.pool, &msg, peer, ClientTransport::Https)
            .await
        else {
            // A message that the pipeline drops (for example a response, not a query).
            return error_response(DohError::BadRequest);
        };
        if reply.close {
            // REFUSED for an off-net or rate-limited client: close the connection after it.
            ctl.close.notify_one();
        }
        dns_response(reply.bytes)
    }
}

/// A 200 reply with the DNS message.
fn dns_response(bytes: Vec<u8>) -> Response<Body> {
    let max_age = doh_wire::reply_max_age(&bytes);
    let mut resp = Response::new(Full::new(Bytes::from(bytes)));
    let h = resp.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE));
    if let Ok(v) = HeaderValue::from_str(&format!("max-age={max_age}")) {
        h.insert(CACHE_CONTROL, v);
    }
    resp
}

fn status_response(status: StatusCode) -> Response<Body> {
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = status;
    resp
}

fn error_response(e: DohError) -> Response<Body> {
    let status = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut resp = status_response(status);
    if e == DohError::MethodNotAllowed {
        resp.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, POST"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_statuses() {
        assert_eq!(error_response(DohError::NotFound).status(), 404);
        let r = error_response(DohError::MethodNotAllowed);
        assert_eq!(r.status(), 405);
        assert_eq!(r.headers()[ALLOW], "GET, POST");
        assert_eq!(error_response(DohError::UriTooLong).status(), 414);
    }

    #[test]
    fn dns_response_headers() {
        let r = dns_response(vec![0; 12]);
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()[CONTENT_TYPE], DNS_MESSAGE);
        assert_eq!(r.headers()[CACHE_CONTROL], "max-age=0");
    }
}
