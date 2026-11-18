//! DNS over HTTPS upstream (RFC 8484) over HTTP/2.
//!
//! - rusthole connects to a bootstrap address, makes the TLS handshake with SNI = the host
//!   name of the URL and ALPN `h2`, and refuses a server without HTTP/2.
//! - One HTTP/2 connection per upstream carries all queries (streams). It closes after
//!   [`IDLE_TIMEOUT`] with no query.
//! - Each query is a POST with `application/dns-message` and ID 0 on the wire (RFC 8484
//!   section 4.1). The pipeline gives the client its own ID in the reply.
//! - The reply must have status 200, the content type `application/dns-message`, a body of
//!   at most [`MAX_REPLY`] bytes, ID 0 and the same question.
//! - Connect, handshake, request and body read each have a time limit: the query deadline.
//! - A query that gets a connection error on a reused connection gets one retry on a new
//!   connection. A timeout is not retried: the pool sends the query to the next upstream at
//!   once. The connection stays in use when a reply came on it after the query was sent.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, Query};
use http::header::{ACCEPT, CONTENT_TYPE};
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioIo, TokioTimer};
use parking_lot::Mutex;
use rustls::ClientConfig;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::doh_wire::DNS_MESSAGE;
use crate::sync::{Clock, LOCK_TIMEOUT, Spawner};
use crate::tls_upstream::{self, HyperExec, TlsTarget};
use crate::upstream::UpstreamError;
use crate::wire;

/// An HTTP/2 connection with no query closes after this time.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest reply body in bytes.
pub const MAX_REPLY: usize = 65_535;
/// HTTP/2 keep-alive ping interval while queries are open.
const KEEP_ALIVE: Duration = Duration::from_secs(10);
/// How often the connection task checks the idle time.
const IDLE_CHECK: Duration = Duration::from_secs(1);

/// A live HTTP/2 connection.
#[derive(Clone)]
struct H2Conn {
    send: SendRequest<Full<Bytes>>,
    addr: SocketAddr,
    activity: Arc<Activity>,
}

/// When a connection was used last, how many queries are open on it, and how many replies
/// came on it.
#[derive(Debug)]
struct Activity {
    last_ms: AtomicU64,
    open: AtomicUsize,
    /// Reply heads received. A timeout with no reply after the query was sent means that
    /// the connection is dead.
    replies: AtomicU64,
}

/// Counts an open query while it lives.
struct OpenGuard<'a>(&'a Activity, Clock);

impl<'a> OpenGuard<'a> {
    fn new(a: &'a Activity, clock: Clock) -> Self {
        a.open.fetch_add(1, Ordering::AcqRel);
        a.last_ms.store(clock.now_ms(), Ordering::Release);
        Self(a, clock)
    }
}

impl Drop for OpenGuard<'_> {
    fn drop(&mut self) {
        self.0.last_ms.store(self.1.now_ms(), Ordering::Release);
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The DoH client of one upstream.
pub(crate) struct DohClient {
    target: Arc<TlsTarget>,
    config: Arc<ClientConfig>,
    uri: String,
    conn: Mutex<Option<H2Conn>>,
    /// Only one connect at a time, so a burst of queries opens one connection.
    open_lock: tokio::sync::Mutex<()>,
    preferred: AtomicUsize,
    spawner: Spawner,
    stop: CancellationToken,
    clock: Clock,
    idle_timeout: Duration,
}

impl std::fmt::Debug for DohClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohClient")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl DohClient {
    pub(crate) fn new(
        target: Arc<TlsTarget>,
        config: Arc<ClientConfig>,
        spawner: Spawner,
        stop: CancellationToken,
        clock: Clock,
    ) -> Self {
        let uri = format!("https://{}{}", target.authority(), target.path);
        Self {
            target,
            config,
            uri,
            conn: Mutex::new(None),
            open_lock: tokio::sync::Mutex::new(()),
            preferred: AtomicUsize::new(0),
            spawner,
            stop,
            clock,
            idle_timeout: IDLE_TIMEOUT,
        }
    }

    /// True when a live connection exists.
    pub(crate) fn has_conn(&self) -> bool {
        self.conn
            .try_lock_for(LOCK_TIMEOUT)
            .is_some_and(|c| c.as_ref().is_some_and(|c| !c.send.is_closed()))
    }

    /// One query with the time limit `timeout`. Only a connection error on a reused
    /// connection gives one more try on a new connection (a connection error comes before
    /// the deadline). A timeout, an HTTP status or a wrong reply goes back to the pool at
    /// once, so the next upstream answers after one `timeout`.
    pub(crate) async fn exchange(
        &self,
        query: &Query,
        dnssec_ok: bool,
        timeout: Duration,
    ) -> Result<(Message, SocketAddr), UpstreamError> {
        let body =
            Bytes::from(wire::upstream_query(0, query, dnssec_ok).ok_or(UpstreamError::Encode)?);
        if let Some(conn) = self.reusable() {
            let deadline = Instant::now() + timeout;
            let replies = conn.activity.replies.load(Ordering::Acquire);
            match self.request(&conn, body.clone(), query, deadline).await {
                Ok(msg) => return Ok((msg, conn.addr)),
                Err(e @ UpstreamError::Io(_)) => {
                    tracing::debug!(upstream = %conn.addr, error = %e, "DoH connection error on a reused connection; retrying on a new connection");
                    self.forget(&conn);
                }
                Err(e) => {
                    self.after_failure(&conn, e, replies);
                    return Err(e);
                }
            }
        }
        let deadline = Instant::now() + timeout;
        let conn = self.open(deadline).await?;
        let replies = conn.activity.replies.load(Ordering::Acquire);
        match self.request(&conn, body, query, deadline).await {
            Ok(msg) => Ok((msg, conn.addr)),
            Err(e) => {
                self.after_failure(&conn, e, replies);
                Err(e)
            }
        }
    }

    /// Forgets `conn` after the failure `e` when the connection is not good.
    /// `replies_before` is the reply count of the connection before the query was sent.
    fn after_failure(&self, conn: &H2Conn, e: UpstreamError, replies_before: u64) {
        let now = conn.activity.replies.load(Ordering::Acquire);
        if !tls_upstream::keeps_conn(e, replies_before, now) {
            tracing::debug!(upstream = %conn.addr, error = %e, "DoH connection removed");
            self.forget(conn);
        }
    }

    fn reusable(&self) -> Option<H2Conn> {
        let mut slot = self.conn.try_lock_for(LOCK_TIMEOUT)?;
        if slot.as_ref().is_some_and(|c| c.send.is_closed()) {
            *slot = None;
        }
        slot.clone()
    }

    fn forget(&self, conn: &H2Conn) {
        if let Some(mut slot) = self.conn.try_lock_for(LOCK_TIMEOUT)
            && slot
                .as_ref()
                .is_some_and(|c| Arc::ptr_eq(&c.activity, &conn.activity))
        {
            *slot = None;
        }
    }

    /// Opens a new HTTP/2 connection and starts its task. One connect runs at a time. A
    /// query that waited for the connect of another query uses that connection.
    async fn open(&self, deadline: Instant) -> Result<H2Conn, UpstreamError> {
        if self.stop.is_cancelled() {
            return Err(UpstreamError::Stopped);
        }
        let Ok(_guard) = timeout_at(deadline, self.open_lock.lock()).await else {
            return Err(UpstreamError::Timeout);
        };
        if let Some(conn) = self.reusable() {
            return Ok(conn);
        }
        let start = self.preferred.load(Ordering::Relaxed);
        let (tls, idx) = tls_upstream::connect(&self.target, &self.config, start, deadline)
            .await
            .inspect_err(|_| {
                self.preferred
                    .store(start.wrapping_add(1), Ordering::Relaxed);
            })?;
        self.preferred.store(idx, Ordering::Relaxed);
        let addr = self
            .target
            .addrs
            .get(idx)
            .copied()
            .ok_or(UpstreamError::NoUpstream)?;
        if tls.get_ref().1.alpn_protocol() != Some(rusthole_tls::ALPN_H2) {
            tracing::warn!(upstream = %addr, name = %self.target.name, "the DoH upstream does not offer HTTP/2");
            return Err(UpstreamError::Tls);
        }
        let mut builder = hyper::client::conn::http2::Builder::new(HyperExec(self.spawner.clone()));
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(KEEP_ALIVE)
            .keep_alive_timeout(KEEP_ALIVE)
            .max_header_list_size(16 * 1024)
            .max_concurrent_reset_streams(32);
        let (send, conn) = match timeout_at(deadline, builder.handshake(TokioIo::new(tls))).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::debug!(upstream = %addr, error = %e, "HTTP/2 handshake failed");
                return Err(UpstreamError::Io(std::io::ErrorKind::ConnectionAborted));
            }
            Err(_) => return Err(UpstreamError::Timeout),
        };
        let activity = Arc::new(Activity {
            last_ms: AtomicU64::new(self.clock.now_ms()),
            open: AtomicUsize::new(0),
            replies: AtomicU64::new(0),
        });
        let h2 = H2Conn {
            send,
            addr,
            activity: Arc::clone(&activity),
        };
        if let Some(mut slot) = self.conn.try_lock_for(LOCK_TIMEOUT) {
            *slot = Some(h2.clone());
        }
        let stop = self.stop.clone();
        let clock = self.clock;
        let idle_ms = u64::try_from(self.idle_timeout.as_millis()).unwrap_or(u64::MAX);
        self.spawner.spawn(async move {
            drive(conn, activity, clock, idle_ms, stop, addr).await;
        });
        Ok(h2)
    }

    /// Sends one POST on `conn` and checks the reply.
    async fn request(
        &self,
        conn: &H2Conn,
        body: Bytes,
        query: &Query,
        deadline: Instant,
    ) -> Result<Message, UpstreamError> {
        let _open = OpenGuard::new(&conn.activity, self.clock);
        let mut send = conn.send.clone();
        let closed = || UpstreamError::Io(std::io::ErrorKind::ConnectionAborted);
        timeout_at(deadline, send.ready())
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|_| closed())?;
        let req = http::Request::post(self.uri.as_str())
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(Full::new(body))
            .map_err(|_| UpstreamError::Encode)?;
        let resp = timeout_at(deadline, send.send_request(req))
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|_| closed())?;
        // A reply head came: the connection lives.
        conn.activity.replies.fetch_add(1, Ordering::AcqRel);
        let status = resp.status().as_u16();
        if status != 200 {
            tracing::debug!(upstream = %conn.addr, status, "DoH upstream answered with an HTTP error");
            return Err(UpstreamError::Http(status));
        }
        let ct_ok = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case(DNS_MESSAGE)
            });
        if !ct_ok {
            return Err(UpstreamError::BadReply);
        }
        let collected = timeout_at(
            deadline,
            Limited::new(resp.into_body(), MAX_REPLY).collect(),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(|_| UpstreamError::BadReply)?;
        let bytes = collected.to_bytes();
        wire::check_upstream_reply(&bytes, 0, query).map_err(|reason| {
            tracing::debug!(upstream = %conn.addr, %reason, "ignored a DoH reply");
            UpstreamError::BadReply
        })
    }
}

/// Drives one HTTP/2 connection until it closes, it is idle for `idle_ms`, or shutdown.
/// On shutdown, the open streams get a graceful end (GOAWAY) with the hard stop of the
/// spawner as the limit.
///
/// Service loop: unbounded on purpose. It runs while the connection lives; the idle limit,
/// the peer and shutdown end it.
async fn drive<C>(
    conn: C,
    activity: Arc<Activity>,
    clock: Clock,
    idle_ms: u64,
    stop: CancellationToken,
    addr: SocketAddr,
) where
    C: std::future::Future<Output = Result<(), hyper::Error>>,
{
    tokio::pin!(conn);
    let mut tick = tokio::time::interval(IDLE_CHECK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = &mut conn => {
                if let Err(e) = r {
                    tracing::debug!(upstream = %addr, error = %e, "DoH connection ended");
                }
                return;
            }
            () = stop.cancelled() => break,
            _ = tick.tick() => {
                let idle = activity.open.load(Ordering::Acquire) == 0
                    && clock.now_ms().saturating_sub(activity.last_ms.load(Ordering::Acquire)) >= idle_ms;
                if idle {
                    tracing::debug!(upstream = %addr, "DoH connection idle; closing it");
                    return;
                }
            }
        }
    }
    // Shutdown: let the open streams end, with a limit.
    let wait_open = async {
        for _ in 0..50 {
            if activity.open.load(Ordering::Acquire) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::select! {
        _ = &mut conn => {}
        () = wait_open => {}
    }
}
