//! DNS over TLS upstream (RFC 7858).
//!
//! ```mermaid
//! flowchart LR
//!     q[query] --> pick{live connection with room?}
//!     pick -->|yes| job[send job to connection task]
//!     pick -->|no| conn[connect to bootstrap address, TLS with SNI = name] --> job
//!     job --> task[connection task: write frame, read frames, match ID and question]
//!     task --> reply[answer to the waiting query]
//!     task -->|idle timeout, error, shutdown| close[close the connection]
//! ```
//!
//! - Each upstream keeps at most [`MAX_CONNS`] connections. A connection closes after
//!   [`IDLE_TIMEOUT`] with no query.
//! - One connection carries up to [`MAX_PIPELINE`] queries at the same time (pipelining).
//!   Each query gets a random ID that no other open query on the connection has.
//! - A reply counts only when its ID belongs to an open query and its question is the same
//!   question (the checks of amendment A5). Other frames are ignored, at most
//!   [`MAX_IGNORED_FRAMES`] on one connection; then the connection closes.
//! - Connect, handshake, write and read each have a time limit: the query deadline.
//! - A query that gets a connection error on a reused connection (the server closed it, or
//!   a write failed) gets one retry on a new connection. A server can close an idle
//!   connection at any time, and that is not an upstream failure.
//! - A timeout is not retried: the pool sends the query to the next upstream at once. The
//!   connection stays in use when it read data after the query was sent (the upstream is
//!   slow for this name only). Else it is removed (it is dead).
//! - At [`MAX_CONN_EVENTS`] minus [`DRAIN_EVENTS`], a connection takes no new query and
//!   closes when its open queries end. The full bound is a fault guard only.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use parking_lot::Mutex;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::dot_frame::{self, FrameReader, MAX_CHUNK};
use crate::sync::{LOCK_TIMEOUT, Spawner};
use crate::tls_upstream::{self, TlsTarget};
use crate::upstream::{self, UpstreamError};
use crate::wire::{self, RawHeader};

/// Connections to one DoT upstream, at most.
pub const MAX_CONNS: usize = 2;
/// Open queries on one connection, at most.
pub const MAX_PIPELINE: usize = 32;
/// A connection with no open query closes after this time.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
/// Frames with an unknown ID or a wrong question on one connection, at most. Then the
/// connection closes.
pub const MAX_IGNORED_FRAMES: usize = 64;
/// Events (jobs, reads, timer ticks) that one connection task handles, at most. This bounds
/// the task loop. At [`MAX_CONN_EVENTS`] minus [`DRAIN_EVENTS`] the connection takes no new
/// query and closes when its open queries end (a usual end). The full bound is a fault
/// guard: it is logged at ERROR.
pub const MAX_CONN_EVENTS: usize = 100_000;
/// Events kept for the drain of the open queries after the soft event limit.
pub const DRAIN_EVENTS: usize = 2 * MAX_PIPELINE;
/// Tries to find a query ID that no open query on the connection has.
const ID_TRIES: usize = 16;

/// One query for a connection task.
struct Job {
    query: Query,
    dnssec_ok: bool,
    deadline: Instant,
    reply: oneshot::Sender<Result<Message, UpstreamError>>,
}

/// A query that waits for its reply on a connection.
struct Open {
    query: Query,
    deadline: Instant,
    reply: oneshot::Sender<Result<Message, UpstreamError>>,
}

/// A handle to a live connection task.
#[derive(Clone)]
struct ConnHandle {
    tx: mpsc::Sender<Job>,
    addr: SocketAddr,
    /// Reads with data on the connection. A timeout with no read after the query was sent
    /// means that the connection is dead.
    reads: Arc<AtomicU64>,
}

/// The settings of one connection task.
struct ConnCfg {
    addr: SocketAddr,
    idle_timeout: Duration,
    /// The hard event bound of the task loop.
    max_events: usize,
    reads: Arc<AtomicU64>,
}

/// The DoT client of one upstream.
pub(crate) struct DotClient {
    target: Arc<TlsTarget>,
    config: Arc<ClientConfig>,
    conns: Mutex<Vec<ConnHandle>>,
    /// Only one connect at a time, so a burst of queries opens one connection, not one
    /// for each query.
    open_lock: tokio::sync::Mutex<()>,
    /// The index of the bootstrap address that worked last.
    preferred: AtomicUsize,
    spawner: Spawner,
    stop: CancellationToken,
    idle_timeout: Duration,
}

impl std::fmt::Debug for DotClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotClient")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl DotClient {
    pub(crate) fn new(
        target: Arc<TlsTarget>,
        config: Arc<ClientConfig>,
        spawner: Spawner,
        stop: CancellationToken,
    ) -> Self {
        Self {
            target,
            config,
            conns: Mutex::new(Vec::new()),
            open_lock: tokio::sync::Mutex::new(()),
            preferred: AtomicUsize::new(0),
            spawner,
            stop,
            idle_timeout: IDLE_TIMEOUT,
        }
    }

    /// Number of live connections.
    pub(crate) fn conn_count(&self) -> usize {
        self.conns.try_lock_for(LOCK_TIMEOUT).map_or(0, |mut c| {
            c.retain(|h| !h.tx.is_closed());
            c.len()
        })
    }

    /// One query with the time limit `timeout`. Only a connection error on a reused
    /// connection gives one more try on a new connection (a connection error comes before
    /// the deadline, so the total time stays near `timeout`). A timeout goes back to the
    /// pool at once, so the next upstream answers after one `timeout`.
    pub(crate) async fn exchange(
        &self,
        query: &Query,
        dnssec_ok: bool,
        timeout: Duration,
    ) -> Result<(Message, SocketAddr), UpstreamError> {
        if let Some(conn) = self.reusable() {
            let deadline = Instant::now() + timeout;
            let reads = conn.reads.load(Ordering::Acquire);
            match send(&conn, query, dnssec_ok, deadline).await {
                Ok(msg) => return Ok((msg, conn.addr)),
                Err(UpstreamError::Overloaded) => {}
                Err(e @ UpstreamError::Io(_)) => {
                    tracing::debug!(upstream = %conn.addr, error = %e, "DoT connection error on a reused connection; retrying on a new connection");
                    self.evict(&conn);
                }
                Err(e) => {
                    self.after_failure(&conn, e, reads);
                    return Err(e);
                }
            }
        }
        let deadline = Instant::now() + timeout;
        let conn = self.open(deadline).await?;
        let reads = conn.reads.load(Ordering::Acquire);
        match send(&conn, query, dnssec_ok, deadline).await {
            Ok(msg) => Ok((msg, conn.addr)),
            Err(e) => {
                self.after_failure(&conn, e, reads);
                Err(e)
            }
        }
    }

    /// Removes `conn` from the pool after the failure `e` when the connection is not good.
    /// `reads_before` is the read count of the connection before the query was sent.
    fn after_failure(&self, conn: &ConnHandle, e: UpstreamError, reads_before: u64) {
        if !tls_upstream::keeps_conn(e, reads_before, conn.reads.load(Ordering::Acquire)) {
            tracing::debug!(upstream = %conn.addr, error = %e, "DoT connection removed from the pool");
            self.evict(conn);
        }
    }

    /// Removes `conn` from the pool. Its task ends when its open queries end.
    fn evict(&self, conn: &ConnHandle) {
        if let Some(mut conns) = self.conns.try_lock_for(LOCK_TIMEOUT) {
            conns.retain(|h| !h.tx.same_channel(&conn.tx) && !h.tx.is_closed());
        }
    }

    /// A live connection with room for one more query.
    fn reusable(&self) -> Option<ConnHandle> {
        let mut conns = self.conns.try_lock_for(LOCK_TIMEOUT)?;
        conns.retain(|h| !h.tx.is_closed());
        conns.iter().find(|h| h.tx.capacity() > 0).cloned()
    }

    /// Opens a new connection and starts its task. One connect runs at a time. A query that
    /// waited for the connect of another query uses that connection. With
    /// [`MAX_CONNS`] connections and no room on them, the query gets
    /// [`UpstreamError::Overloaded`] (it goes to the next upstream).
    async fn open(&self, deadline: Instant) -> Result<ConnHandle, UpstreamError> {
        if self.stop.is_cancelled() {
            return Err(UpstreamError::Stopped);
        }
        let Ok(_guard) = timeout_at(deadline, self.open_lock.lock()).await else {
            return Err(UpstreamError::Timeout);
        };
        if let Some(conn) = self.reusable() {
            return Ok(conn);
        }
        if self.conn_count() >= MAX_CONNS {
            return Err(UpstreamError::Overloaded);
        }
        let start = self.preferred.load(Ordering::Relaxed);
        let (stream, idx) = tls_upstream::connect(&self.target, &self.config, start, deadline)
            .await
            .inspect_err(|_| {
                // The next try starts at the next address.
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
        let (tx, rx) = mpsc::channel(MAX_PIPELINE);
        let reads = Arc::new(AtomicU64::new(0));
        let handle = ConnHandle {
            tx,
            addr,
            reads: Arc::clone(&reads),
        };
        if let Some(mut conns) = self.conns.try_lock_for(LOCK_TIMEOUT) {
            conns.retain(|h| !h.tx.is_closed());
            // The open lock and the check above keep the pool at MAX_CONNS.
            conns.push(handle.clone());
        }
        let stop = self.stop.clone();
        let cfg = ConnCfg {
            addr,
            idle_timeout: self.idle_timeout,
            max_events: MAX_CONN_EVENTS,
            reads,
        };
        self.spawner.spawn(async move {
            run_conn(stream, rx, cfg, stop).await;
        });
        Ok(handle)
    }

    /// Test helper: a client with a short idle timeout.
    #[cfg(test)]
    fn with_idle_timeout(mut self, idle: Duration) -> Self {
        self.idle_timeout = idle;
        self
    }
}

/// Sends one job to a connection task and waits for the reply.
async fn send(
    conn: &ConnHandle,
    query: &Query,
    dnssec_ok: bool,
    deadline: Instant,
) -> Result<Message, UpstreamError> {
    let (reply, rx) = oneshot::channel();
    let job = Job {
        query: query.clone(),
        dnssec_ok,
        deadline,
        reply,
    };
    match conn.tx.try_send(job) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => return Err(UpstreamError::Overloaded),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            return Err(UpstreamError::Io(io::ErrorKind::ConnectionAborted));
        }
    }
    match timeout_at(deadline, rx).await {
        Ok(Ok(result)) => result,
        // The task stopped without an answer: the connection closed.
        Ok(Err(_)) => Err(UpstreamError::Io(io::ErrorKind::ConnectionAborted)),
        Err(_) => Err(UpstreamError::Timeout),
    }
}

/// Why a connection task stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnEnd {
    Idle,
    Closed,
    Error,
    Stopped,
    TooManyIgnored,
    EventBound,
}

/// The connection task. The loop is bounded by `cfg.max_events` (in production
/// [`MAX_CONN_EVENTS`]). At `cfg.max_events - DRAIN_EVENTS` the task takes no new job and
/// ends when its open queries end.
async fn run_conn<S>(
    stream: S,
    mut rx: mpsc::Receiver<Job>,
    cfg: ConnCfg,
    stop: CancellationToken,
) -> ConnEnd
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ConnCfg {
        addr,
        idle_timeout,
        max_events,
        reads,
    } = cfg;
    let soft_limit = max_events.saturating_sub(DRAIN_EVENTS);
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut reader = FrameReader::new();
    let mut open: HashMap<u16, Open> = HashMap::new();
    let mut buf = vec![0u8; MAX_CHUNK];
    let mut ignored = 0usize;
    let mut idle_at = Instant::now() + idle_timeout;
    let mut draining = false;
    let mut end = ConnEnd::EventBound;
    for step in 0..max_events {
        if !draining && step >= soft_limit {
            tracing::debug!(upstream = %addr, step, "DoT connection reached its soft event limit; it takes no new query");
            draining = true;
            close_jobs(&mut rx);
        }
        expire(&mut open, Instant::now());
        if draining && open.is_empty() {
            end = ConnEnd::Stopped;
            break;
        }
        // With open queries, wake at the first deadline only. The idle time applies only
        // with no open query (a wake at a past idle time would make the loop spin).
        let wake = open.values().map(|o| o.deadline).min().unwrap_or(idle_at);
        tokio::select! {
            () = stop.cancelled(), if !draining => {
                // Shutdown: no new job; the open queries end by reply or deadline.
                draining = true;
                close_jobs(&mut rx);
            }
            job = rx.recv(), if !draining && open.len() < MAX_PIPELINE => {
                let Some(job) = job else {
                    // The client is gone. Finish the open queries.
                    draining = true;
                    continue;
                };
                idle_at = Instant::now() + idle_timeout;
                if let Err(e) = start_job(&mut wr, &mut open, job).await {
                    tracing::debug!(upstream = %addr, error = %e, "DoT write failed");
                    end = ConnEnd::Error;
                    break;
                }
            }
            r = rd.read(&mut buf) => {
                let n = match r {
                    Ok(0) => { end = ConnEnd::Closed; break; }
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(upstream = %addr, error = %e, "DoT read failed");
                        end = ConnEnd::Error;
                        break;
                    }
                };
                reads.fetch_add(1, Ordering::AcqRel);
                idle_at = Instant::now() + idle_timeout;
                let Some(data) = buf.get(..n) else { continue };
                match take_frames(&mut reader, data, &mut open, addr) {
                    Ok(bad) => ignored += bad,
                    Err(e) => {
                        tracing::debug!(upstream = %addr, error = %e, "DoT stream error");
                        end = ConnEnd::Error;
                        break;
                    }
                }
                if ignored > MAX_IGNORED_FRAMES {
                    tracing::warn!(upstream = %addr, "too many wrong DoT replies; closing the connection");
                    end = ConnEnd::TooManyIgnored;
                    break;
                }
            }
            () = sleep_until(wake) => {
                if open.is_empty() && !draining && Instant::now() >= idle_at {
                    end = ConnEnd::Idle;
                    break;
                }
            }
        }
    }
    if end == ConnEnd::EventBound {
        tracing::error!(upstream = %addr, bound = max_events, open = open.len(), "DoT connection reached its event bound; closing it");
    }
    rx.close();
    for (_, o) in open.drain() {
        let _ = o
            .reply
            .send(Err(UpstreamError::Io(io::ErrorKind::ConnectionAborted)));
    }
    // A close_notify, with a short limit. The stream drops after it.
    let _ = tokio::time::timeout(Duration::from_millis(200), wr.shutdown()).await;
    tracing::debug!(upstream = %addr, ?end, "DoT connection closed");
    end
}

/// Closes the job channel and fails the jobs in it with a connection error, so that they
/// retry on a new connection at once. The channel holds at most [`MAX_PIPELINE`] jobs, and a
/// closed channel takes no new job, so the loop is bounded.
fn close_jobs(rx: &mut mpsc::Receiver<Job>) {
    rx.close();
    for _ in 0..MAX_PIPELINE {
        let Ok(job) = rx.try_recv() else {
            break;
        };
        let _ = job
            .reply
            .send(Err(UpstreamError::Io(io::ErrorKind::ConnectionAborted)));
    }
}

/// Removes the open queries whose deadline passed and gives their waiters a timeout. (A
/// dropped reply would look like a closed connection.)
fn expire(open: &mut HashMap<u16, Open>, now: Instant) {
    let late: Vec<u16> = open
        .iter()
        .filter(|(_, o)| o.deadline <= now || o.reply.is_closed())
        .map(|(id, _)| *id)
        .collect();
    for id in late {
        if let Some(o) = open.remove(&id) {
            let _ = o.reply.send(Err(UpstreamError::Timeout));
        }
    }
}

/// Writes one job and records it as open.
async fn start_job<W: AsyncWrite + Unpin>(
    wr: &mut W,
    open: &mut HashMap<u16, Open>,
    job: Job,
) -> Result<(), UpstreamError> {
    if job.deadline <= Instant::now() || job.reply.is_closed() {
        let _ = job.reply.send(Err(UpstreamError::Timeout));
        return Ok(());
    }
    let mut id = None;
    for _ in 0..ID_TRIES {
        let candidate = upstream::random_id()?;
        if !open.contains_key(&candidate) {
            id = Some(candidate);
            break;
        }
    }
    let Some(id) = id else {
        let _ = job.reply.send(Err(UpstreamError::Overloaded));
        return Ok(());
    };
    let Some(framed) = wire::upstream_query(id, &job.query, job.dnssec_ok)
        .as_deref()
        .and_then(dot_frame::frame)
    else {
        let _ = job.reply.send(Err(UpstreamError::Encode));
        return Ok(());
    };
    match timeout_at(job.deadline, wr.write_all(&framed)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = job.reply.send(Err(UpstreamError::Io(e.kind())));
            return Err(UpstreamError::Io(e.kind()));
        }
        Err(_) => {
            let _ = job.reply.send(Err(UpstreamError::Timeout));
            return Err(UpstreamError::Timeout);
        }
    }
    match timeout_at(job.deadline, wr.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = job.reply.send(Err(UpstreamError::Io(e.kind())));
            return Err(UpstreamError::Io(e.kind()));
        }
        Err(_) => {
            let _ = job.reply.send(Err(UpstreamError::Timeout));
            return Err(UpstreamError::Timeout);
        }
    }
    open.insert(
        id,
        Open {
            query: job.query,
            deadline: job.deadline,
            reply: job.reply,
        },
    );
    Ok(())
}

/// Feeds `data` to the frame reader and answers the open queries. Gives the number of
/// ignored frames. The inner loop is bounded: each frame takes at least 14 bytes, so one
/// chunk gives at most `MAX_BUFFER / 14` frames.
fn take_frames(
    reader: &mut FrameReader,
    data: &[u8],
    open: &mut HashMap<u16, Open>,
    addr: SocketAddr,
) -> Result<usize, dot_frame::FrameError> {
    reader.push(data)?;
    let mut ignored = 0;
    for _ in 0..=dot_frame::MAX_BUFFER / (wire::HEADER_LEN + 2) {
        let Some(frame) = reader.next_frame()? else {
            break;
        };
        if !answer_frame(&frame, open, addr) {
            ignored += 1;
        }
    }
    Ok(ignored)
}

/// Gives a frame to the open query with its ID and question. False when no open query
/// matches.
fn answer_frame(frame: &[u8], open: &mut HashMap<u16, Open>, addr: SocketAddr) -> bool {
    let Some(h) = RawHeader::parse(frame) else {
        return false;
    };
    let Some(o) = open.get(&h.id) else {
        tracing::debug!(upstream = %addr, id = h.id, "ignored a DoT reply with an unknown ID");
        return false;
    };
    match wire::check_upstream_reply(frame, h.id, &o.query) {
        Ok(msg) => {
            if let Some(o) = open.remove(&h.id) {
                let _ = o.reply.send(Ok(msg));
            }
            true
        }
        Err(reason) => {
            tracing::debug!(upstream = %addr, %reason, "ignored a DoT reply");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::io::DuplexStream;

    fn q(name: &str) -> Query {
        Query::query(Name::from_ascii(name).unwrap(), RecordType::A)
    }

    fn reply_for(req: &[u8], name: Option<&str>, id_delta: u16) -> Vec<u8> {
        let m = Message::from_vec(req).unwrap();
        let mut r = Message::new(
            m.metadata.id.wrapping_add(id_delta),
            MessageType::Response,
            OpCode::Query,
        );
        let query = name.map_or_else(|| m.queries[0].clone(), q);
        r.answers.push(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A::new(192, 0, 2, 9)),
        ));
        r.queries = vec![query];
        dot_frame::frame(&r.to_vec().unwrap()).unwrap()
    }

    async fn read_frame(s: &mut DuplexStream) -> Vec<u8> {
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.unwrap();
        let mut b = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut b).await.unwrap();
        b
    }

    fn spawn_conn(
        client: DuplexStream,
        idle: Duration,
    ) -> (
        mpsc::Sender<Job>,
        tokio::task::JoinHandle<ConnEnd>,
        CancellationToken,
    ) {
        spawn_conn_bounded(client, idle, MAX_CONN_EVENTS)
    }

    fn spawn_conn_bounded(
        client: DuplexStream,
        idle: Duration,
        max_events: usize,
    ) -> (
        mpsc::Sender<Job>,
        tokio::task::JoinHandle<ConnEnd>,
        CancellationToken,
    ) {
        let (tx, rx) = mpsc::channel(MAX_PIPELINE);
        let stop = CancellationToken::new();
        let s = stop.clone();
        let cfg = ConnCfg {
            addr: "127.0.0.1:853".parse().unwrap(),
            idle_timeout: idle,
            max_events,
            reads: Arc::new(AtomicU64::new(0)),
        };
        let h = tokio::spawn(async move { run_conn(client, rx, cfg, s).await });
        (tx, h, stop)
    }

    async fn join(h: tokio::task::JoinHandle<ConnEnd>) -> ConnEnd {
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap()
    }

    /// A query timeout longer than the idle timeout: the task waits for the deadline of the
    /// open query. It does not spin to its event bound when the idle time passes.
    #[tokio::test]
    async fn long_query_timeout_does_not_spin() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (tx, h, _stop) = spawn_conn(client, Duration::from_millis(50));
        let start = Instant::now();
        let (j, r) = job("slow.example.", Duration::from_millis(300));
        tx.send(j).await.unwrap();
        let _ = read_frame(&mut server).await;
        let res = tokio::time::timeout(Duration::from_secs(5), r)
            .await
            .unwrap()
            .unwrap();
        let waited = start.elapsed();
        assert_eq!(res.unwrap_err(), UpstreamError::Timeout);
        assert!(waited >= Duration::from_millis(250), "{waited:?}");
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        // With no open query, the idle time applies again.
        assert_eq!(join(h).await, ConnEnd::Idle);
    }

    /// At the soft event limit, the connection takes no new job, and its open query still
    /// gets its answer: a usual end, not the event bound.
    #[tokio::test]
    async fn soft_event_limit_drains_the_open_queries() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        // The soft limit is 1: the first event (the job) is the last new job.
        let (tx, h, _stop) = spawn_conn_bounded(client, Duration::from_secs(30), DRAIN_EVENTS + 1);
        let (j, r) = job("one.example.", Duration::from_secs(5));
        tx.send(j).await.unwrap();
        let a = read_frame(&mut server).await;
        assert!(
            eventually_closed(&tx).await,
            "no new job after the soft limit"
        );
        server.write_all(&reply_for(&a, None, 0)).await.unwrap();
        assert!(r.await.unwrap().is_ok(), "the open query is not aborted");
        assert_eq!(join(h).await, ConnEnd::Stopped);
    }

    /// A server that sends one byte at a time and never ends a frame: the task stops at its
    /// hard event bound and fails the open query.
    #[tokio::test]
    async fn hard_event_bound_stops_the_task() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let max_events = DRAIN_EVENTS + 2;
        let (tx, h, _stop) = spawn_conn_bounded(client, Duration::from_secs(30), max_events);
        let (j, r) = job("one.example.", Duration::from_secs(20));
        tx.send(j).await.unwrap();
        let _ = read_frame(&mut server).await;
        // A frame of 1000 bytes, sent one byte at a time.
        let writer = tokio::spawn(async move {
            let mut bytes = vec![0x03, 0xE8];
            bytes.resize(1002, 0);
            for b in bytes {
                if server.write_all(&[b]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });
        assert_eq!(join(h).await, ConnEnd::EventBound);
        assert_eq!(
            r.await.unwrap().unwrap_err(),
            UpstreamError::Io(io::ErrorKind::ConnectionAborted)
        );
        writer.abort();
    }

    /// Waits until the job channel is closed, at most 5 s.
    async fn eventually_closed(tx: &mpsc::Sender<Job>) -> bool {
        for _ in 0..500 {
            if tx.is_closed() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// Jobs that wait in the channel when the connection stops taking jobs get a connection
    /// error at once (they retry on a new connection), not at their deadline.
    #[tokio::test]
    async fn queued_jobs_fail_at_once_on_shutdown() {
        let (tx, rx) = mpsc::channel(MAX_PIPELINE);
        let (j, r) = job("one.example.", Duration::from_secs(30));
        tx.send(j).await.unwrap();
        let mut rx = rx;
        close_jobs(&mut rx);
        assert_eq!(
            r.await.unwrap().unwrap_err(),
            UpstreamError::Io(io::ErrorKind::ConnectionAborted)
        );
        assert!(tx.is_closed());
    }

    fn job(name: &str, wait: Duration) -> (Job, oneshot::Receiver<Result<Message, UpstreamError>>) {
        let (reply, rx) = oneshot::channel();
        (
            Job {
                query: q(name),
                dnssec_ok: false,
                deadline: Instant::now() + wait,
                reply,
            },
            rx,
        )
    }

    /// Two pipelined queries; the server answers in the reverse order, and sends a wrong
    /// ID and a wrong question first. Each query gets its own answer.
    #[tokio::test]
    async fn pipelined_replies_match_by_id_and_question() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let (tx, h, _stop) = spawn_conn(client, Duration::from_secs(5));
        let (j1, r1) = job("one.example.", Duration::from_secs(5));
        let (j2, r2) = job("two.example.", Duration::from_secs(5));
        tx.send(j1).await.unwrap();
        tx.send(j2).await.unwrap();
        let a = read_frame(&mut server).await;
        let b = read_frame(&mut server).await;
        assert_ne!(a[..2], b[..2], "pipelined queries have different IDs");
        server.write_all(&reply_for(&b, None, 1)).await.unwrap();
        server
            .write_all(&reply_for(&b, Some("other.example."), 0))
            .await
            .unwrap();
        server.write_all(&reply_for(&b, None, 0)).await.unwrap();
        server.write_all(&reply_for(&a, None, 0)).await.unwrap();
        let m1 = r1.await.unwrap().unwrap();
        let m2 = r2.await.unwrap().unwrap();
        assert_eq!(m1.queries[0].name().to_ascii(), "one.example.");
        assert_eq!(m2.queries[0].name().to_ascii(), "two.example.");
        drop(tx);
        let end = tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end, ConnEnd::Stopped);
    }

    #[tokio::test]
    async fn idle_connection_closes() {
        let (client, _server) = tokio::io::duplex(1024);
        let (_tx, h, _stop) = spawn_conn(client, Duration::from_millis(50));
        let end = tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end, ConnEnd::Idle);
    }

    #[tokio::test]
    async fn server_close_fails_open_queries() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (tx, h, _stop) = spawn_conn(client, Duration::from_secs(5));
        let (j, r) = job("one.example.", Duration::from_secs(5));
        tx.send(j).await.unwrap();
        let _ = read_frame(&mut server).await;
        drop(server);
        assert!(matches!(r.await.unwrap(), Err(UpstreamError::Io(_))));
        let end = tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end, ConnEnd::Closed);
    }

    #[tokio::test]
    async fn too_many_wrong_frames_close_the_connection() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let (tx, h, _stop) = spawn_conn(client, Duration::from_secs(5));
        let (j, r) = job("one.example.", Duration::from_secs(5));
        tx.send(j).await.unwrap();
        let a = read_frame(&mut server).await;
        for _ in 0..=MAX_IGNORED_FRAMES {
            if server.write_all(&reply_for(&a, None, 1)).await.is_err() {
                break;
            }
        }
        let end = tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end, ConnEnd::TooManyIgnored);
        assert!(r.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn shutdown_drains_then_stops() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (tx, h, stop) = spawn_conn(client, Duration::from_secs(30));
        let (j, r) = job("one.example.", Duration::from_secs(5));
        tx.send(j).await.unwrap();
        let a = read_frame(&mut server).await;
        stop.cancel();
        // The open query still gets its answer.
        server.write_all(&reply_for(&a, None, 0)).await.unwrap();
        assert!(r.await.unwrap().is_ok());
        let end = tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end, ConnEnd::Stopped);
        // No new job after the stop.
        let (j, _r) = job("two.example.", Duration::from_secs(5));
        assert!(tx.send(j).await.is_err());
    }

    #[tokio::test]
    async fn a_late_query_expires() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (tx, _h, _stop) = spawn_conn(client, Duration::from_secs(30));
        let (j, r) = job("one.example.", Duration::from_millis(100));
        tx.send(j).await.unwrap();
        let _ = read_frame(&mut server).await;
        // The task gives the waiter a timeout at the deadline.
        let res = tokio::time::timeout(Duration::from_secs(5), r)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(res.unwrap_err(), UpstreamError::Timeout);
    }

    #[test]
    fn idle_setter() {
        let t = Arc::new(TlsTarget {
            name: "dns.example".to_owned(),
            addrs: vec!["127.0.0.1:853".parse().unwrap()],
            port: 853,
            path: String::new(),
        });
        let cfg = crate::tls_upstream::UpstreamTls::with_roots(rustls::RootCertStore::empty())
            .unwrap()
            .dot;
        let c = DotClient::new(t, cfg, Spawner::new(), CancellationToken::new())
            .with_idle_timeout(Duration::from_millis(5));
        assert_eq!(c.idle_timeout, Duration::from_millis(5));
        assert_eq!(c.conn_count(), 0);
    }
}
