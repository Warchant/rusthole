//! Upstream pool: plain DNS over UDP and TCP, with failover, health, coalescing and the
//! hardening of amendment A5.
//!
//! For each upstream query:
//!
//! - a new UDP socket on a random source port (CSPRNG), connected to the upstream;
//! - a random query ID (CSPRNG);
//! - a reply counts only when it comes from the upstream address and port, has the same ID,
//!   and has the same question. Other packets are ignored, and the wait goes on until the
//!   time limit (at most [`MAX_IGNORED_REPLIES`] packets);
//! - a reply with the TC bit makes a retry over TCP;
//! - a timeout, an I/O error or SERVFAIL makes the query go to the next upstream, at most
//!   [`PoolSettings::max_attempts`] upstreams.
//!
//! Identical queries in flight (same cache key) share one upstream query. A semaphore
//! limits the upstream queries in flight.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use parking_lot::Mutex;
use rusthole_core::cache::CacheKey;
use rusthole_core::upstream_health::{self, HealthConfig, HealthEvent, HealthState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::sync::{Clock, LOCK_TIMEOUT, Spawner};
use crate::wire::{self, ReplyReject};

/// Upstreams tried for one query, at most.
pub const MAX_ATTEMPTS: usize = 3;
/// Upstream queries in flight, at most. Also the size limit of the coalescing map.
pub const MAX_INFLIGHT: usize = 512;
/// Wrong packets that one UDP upstream query ignores before it gives up.
pub const MAX_IGNORED_REPLIES: usize = 64;
/// Random source ports to try before the OS picks one.
const PORT_TRIES: usize = 8;
/// Receive buffer for a UDP upstream reply. We ask for 1232 bytes; this leaves room.
const UDP_RECV_BUF: usize = 4096;
/// How often the prober looks for a `Down` upstream with a due probe.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// The transport of a plain upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProto {
    /// UDP, with a TCP retry on truncation.
    Udp,
    /// TCP only.
    Tcp,
}

/// One plain upstream server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamServer {
    /// The address and port.
    pub addr: SocketAddr,
    /// UDP or TCP.
    pub proto: UpstreamProto,
}

/// Settings of the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSettings {
    /// The servers, in config order.
    pub servers: Vec<UpstreamServer>,
    /// Time limit for one exchange with one upstream (the TCP retry gets its own limit).
    pub timeout: Duration,
    /// Upstreams tried for one query, at most.
    pub max_attempts: usize,
    /// Upstream queries in flight, at most.
    pub max_inflight: usize,
    /// Settings of the health state machine.
    pub health: HealthConfig,
}

impl PoolSettings {
    /// The longest time that one query can take in the pool: each attempt can use the UDP
    /// time limit and the TCP time limit, plus the wait for a semaphore permit.
    pub fn query_budget(&self) -> Duration {
        let attempts = u32::try_from(self.max_attempts.max(1)).unwrap_or(u32::MAX);
        self.timeout
            .saturating_mul(2)
            .saturating_mul(attempts)
            .saturating_add(self.timeout)
            .saturating_add(Duration::from_millis(500))
    }
}

/// Why the pool has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// No reply came in the time limit.
    #[error("timeout")]
    Timeout,
    /// A socket error.
    #[error("I/O error: {0:?}")]
    Io(io::ErrorKind),
    /// Only wrong replies came.
    #[error("no valid reply")]
    BadReply,
    /// The OS random source failed.
    #[error("no random data")]
    NoRandom,
    /// The query could not be encoded.
    #[error("the query cannot be encoded")]
    Encode,
    /// Too many queries in flight.
    #[error("too many queries in flight")]
    Overloaded,
    /// The pool has no upstream.
    #[error("no upstream")]
    NoUpstream,
    /// The upstream task stopped (shutdown).
    #[error("the upstream query stopped")]
    Stopped,
}

/// A valid upstream answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAnswer {
    /// The answer. It passed [`wire::check_upstream_reply`].
    pub message: Message,
    /// The upstream that sent it.
    pub upstream: SocketAddr,
}

type Shared = Arc<Result<UpstreamAnswer, UpstreamError>>;

/// The upstream pool. Cheap to clone.
#[derive(Debug, Clone)]
pub(crate) struct Pool {
    inner: Arc<PoolInner>,
}

#[derive(Debug)]
struct PoolInner {
    settings: PoolSettings,
    health: Mutex<Vec<HealthState>>,
    permits: Arc<Semaphore>,
    inflight: Mutex<HashMap<CacheKey, watch::Receiver<Option<Shared>>>>,
    clock: Clock,
    spawner: Spawner,
}

/// Removes the coalescing entry when the leader task ends, also on cancel.
struct InflightGuard {
    inner: Arc<PoolInner>,
    key: CacheKey,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Some(mut map) = self.inner.inflight.try_lock_for(LOCK_TIMEOUT) {
            map.remove(&self.key);
        } else {
            // A later query sees the closed channel and replaces the entry.
            tracing::error!("cannot remove an in-flight query: the lock timed out");
        }
    }
}

impl Pool {
    pub(crate) fn new(settings: PoolSettings, clock: Clock, spawner: Spawner) -> Self {
        let n = settings.servers.len();
        let permits = Arc::new(Semaphore::new(settings.max_inflight.max(1)));
        Self {
            inner: Arc::new(PoolInner {
                settings,
                health: Mutex::new(vec![HealthState::Healthy; n]),
                permits,
                inflight: Mutex::new(HashMap::new()),
                clock,
                spawner,
            }),
        }
    }

    /// The health of each upstream, in config order.
    pub(crate) fn health(&self) -> Vec<HealthState> {
        self.inner
            .health
            .try_lock_for(LOCK_TIMEOUT)
            .map_or_else(Vec::new, |g| g.clone())
    }

    /// Number of coalesced queries in flight.
    pub(crate) fn inflight_len(&self) -> usize {
        self.inner
            .inflight
            .try_lock_for(LOCK_TIMEOUT)
            .map_or(0, |g| g.len())
    }

    /// Resolves `query` through the upstreams. Identical queries in flight share one
    /// upstream query.
    pub(crate) async fn resolve(
        &self,
        key: &CacheKey,
        query: &Query,
        dnssec_ok: bool,
    ) -> Result<UpstreamAnswer, UpstreamError> {
        let mut rx = self.join_or_lead(key, query, dnssec_ok)?;
        let budget = self.inner.settings.query_budget();
        let shared = match tokio::time::timeout(budget, rx.wait_for(Option::is_some)).await {
            Ok(Ok(value)) => value.clone(),
            Ok(Err(_)) => return Err(UpstreamError::Stopped),
            Err(_) => return Err(UpstreamError::Timeout),
        };
        match shared {
            Some(result) => (*result).clone(),
            None => Err(UpstreamError::Stopped),
        }
    }

    fn join_or_lead(
        &self,
        key: &CacheKey,
        query: &Query,
        dnssec_ok: bool,
    ) -> Result<watch::Receiver<Option<Shared>>, UpstreamError> {
        let mut map = self
            .inner
            .inflight
            .try_lock_for(LOCK_TIMEOUT)
            .ok_or(UpstreamError::Overloaded)?;
        if let Some(rx) = map.get(key) {
            // A closed channel means that the leader stopped without an answer.
            if rx.has_changed().is_ok() {
                return Ok(rx.clone());
            }
            map.remove(key);
        }
        if map.len() >= self.inner.settings.max_inflight.max(1) {
            return Err(UpstreamError::Overloaded);
        }
        let (tx, rx) = watch::channel(None);
        map.insert(key.clone(), rx.clone());
        drop(map);

        let guard = InflightGuard {
            inner: Arc::clone(&self.inner),
            key: key.clone(),
        };
        let inner = Arc::clone(&self.inner);
        let query = query.clone();
        // The leader runs in its own task: when the first client goes away, the other
        // clients still get the answer.
        self.inner.spawner.spawn(async move {
            let _guard = guard;
            let result = inner.lead(&query, dnssec_ok).await;
            // No receiver left is not an error.
            let _ = tx.send(Some(Arc::new(result)));
        });
        Ok(rx)
    }

    /// Probes each `Down` upstream when its probe is due.
    ///
    /// Service loop: unbounded on purpose. It runs for the life of the server and ends when
    /// `cancel` is cancelled.
    pub(crate) async fn run_prober(self, cancel: CancellationToken) {
        let mut tick = tokio::time::interval(PROBE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = tick.tick() => {}
            }
            for idx in self.inner.start_due_probes() {
                let inner = Arc::clone(&self.inner);
                self.inner.spawner.spawn(async move {
                    inner.probe(idx).await;
                });
            }
        }
    }
}

impl PoolInner {
    /// Queries the upstreams in health order until one gives a valid answer that is not
    /// SERVFAIL. The loop is bounded by `max_attempts`.
    async fn lead(&self, query: &Query, dnssec_ok: bool) -> Result<UpstreamAnswer, UpstreamError> {
        let deadline = Instant::now() + self.settings.timeout;
        let Ok(Ok(_permit)) = timeout_at(deadline, Arc::clone(&self.permits).acquire_owned()).await
        else {
            return Err(UpstreamError::Overloaded);
        };
        let order = match self.health.try_lock_for(LOCK_TIMEOUT) {
            Some(states) => upstream_health::plan(&states, self.settings.max_attempts),
            None => (0..self.settings.servers.len().min(self.settings.max_attempts)).collect(),
        };
        let mut last: Result<UpstreamAnswer, UpstreamError> = Err(UpstreamError::NoUpstream);
        for idx in order {
            let Some(server) = self.settings.servers.get(idx).copied() else {
                continue;
            };
            match exchange(server, query, dnssec_ok, self.settings.timeout).await {
                Ok(message) => {
                    self.report(idx, true);
                    let answer = UpstreamAnswer {
                        message,
                        upstream: server.addr,
                    };
                    if !wire::is_server_failure(&answer.message) {
                        return Ok(answer);
                    }
                    tracing::debug!(upstream = %server.addr, "upstream answered SERVFAIL; trying the next one");
                    last = Ok(answer);
                }
                Err(e) => {
                    self.report(idx, false);
                    tracing::debug!(upstream = %server.addr, error = %e, "upstream query failed");
                    if last.is_err() {
                        last = Err(e);
                    }
                }
            }
        }
        last
    }

    /// Feeds a result to the health machine of upstream `idx`.
    fn report(&self, idx: usize, success: bool) {
        let now_ms = self.clock.now_ms();
        let event = if success {
            HealthEvent::Success { now_ms }
        } else {
            HealthEvent::Failure { now_ms }
        };
        self.apply(idx, event);
    }

    fn apply(&self, idx: usize, event: HealthEvent) {
        let Some(mut states) = self.health.try_lock_for(LOCK_TIMEOUT) else {
            tracing::error!("cannot update upstream health: the lock timed out");
            return;
        };
        self.step_locked(&mut states, idx, event);
    }

    /// Applies `event` to upstream `idx`. The caller holds the health lock.
    fn step_locked(&self, states: &mut [HealthState], idx: usize, event: HealthEvent) {
        let Some(state) = states.get_mut(idx) else {
            return;
        };
        let addr = self.settings.servers.get(idx).map(|s| s.addr);
        let old = *state;
        let step = upstream_health::step(&self.settings.health, old, event);
        if let Some(invalid) = step.invalid {
            tracing::error!(
                upstream = ?addr,
                state = ?invalid.state,
                event = ?invalid.event,
                next = ?step.state,
                "invalid upstream health transition; going to the safe state"
            );
        }
        match (old, step.state) {
            (HealthState::Down { .. } | HealthState::Probing { .. }, HealthState::Healthy) => {
                tracing::info!(upstream = ?addr, "upstream is up again");
            }
            (HealthState::Healthy | HealthState::Suspect { .. }, HealthState::Down { .. }) => {
                tracing::warn!(upstream = ?addr, "upstream is down");
            }
            _ => {}
        }
        *state = step.state;
    }

    /// Moves each `Down` upstream with a due probe to `Probing`. Returns their indexes.
    /// The check and the step use one lock hold, so a late result cannot come between them.
    fn start_due_probes(&self) -> Vec<usize> {
        let now_ms = self.clock.now_ms();
        let Some(mut states) = self.health.try_lock_for(LOCK_TIMEOUT) else {
            return Vec::new();
        };
        let due: Vec<usize> = states
            .iter()
            .enumerate()
            .filter(|(_, s)| upstream_health::probe_due(s, now_ms))
            .map(|(i, _)| i)
            .collect();
        for &idx in &due {
            self.step_locked(&mut states, idx, HealthEvent::ProbeStart { now_ms });
        }
        due
    }

    /// Sends a probe query (`. NS`) to upstream `idx`. Any valid answer is a success.
    async fn probe(&self, idx: usize) {
        let Some(server) = self.settings.servers.get(idx).copied() else {
            return;
        };
        let query = Query::query(Name::root(), RecordType::NS);
        let ok = exchange(server, &query, false, self.settings.timeout)
            .await
            .is_ok();
        tracing::debug!(upstream = %server.addr, ok, "upstream probe done");
        self.report(idx, ok);
    }
}

/// One exchange with one upstream: UDP with a TCP retry on truncation, or TCP.
async fn exchange(
    server: UpstreamServer,
    query: &Query,
    dnssec_ok: bool,
    timeout: Duration,
) -> Result<Message, UpstreamError> {
    match server.proto {
        UpstreamProto::Tcp => tcp_exchange(server.addr, query, dnssec_ok, timeout).await,
        UpstreamProto::Udp => {
            let msg = udp_exchange(server.addr, query, dnssec_ok, timeout).await?;
            if msg.metadata.truncation {
                tracing::debug!(upstream = %server.addr, "truncated reply; retrying over TCP");
                tcp_exchange(server.addr, query, dnssec_ok, timeout).await
            } else {
                Ok(msg)
            }
        }
    }
}

/// A random value from the OS CSPRNG.
fn random_u32() -> Result<u32, UpstreamError> {
    getrandom::u32().map_err(|_| UpstreamError::NoRandom)
}

/// A random query ID.
pub(crate) fn random_id() -> Result<u16, UpstreamError> {
    let [a, b, _, _] = random_u32()?.to_be_bytes();
    Ok(u16::from_be_bytes([a, b]))
}

/// A random port in `1024..=65535` from the OS CSPRNG.
pub(crate) fn random_port() -> Result<u16, UpstreamError> {
    Ok(1024 + u16::try_from(random_u32()? % 64_512).unwrap_or(0))
}

/// The local address for a socket that talks to `peer`: loopback for a loopback peer (no
/// firewall prompt on a development host), else the wildcard address of the peer family.
pub(crate) fn local_bind_ip(peer: SocketAddr) -> IpAddr {
    match peer.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_loopback() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// A UDP socket on a random source port in `1024..=65535`. After [`PORT_TRIES`] busy ports,
/// the OS picks the port. The local address comes from [`local_bind_ip`].
async fn bind_random(peer: SocketAddr) -> Result<UdpSocket, UpstreamError> {
    let any = local_bind_ip(peer);
    for _ in 0..PORT_TRIES {
        let port = random_port()?;
        match UdpSocket::bind(SocketAddr::new(any, port)).await {
            Ok(s) => return Ok(s),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) => {}
            Err(e) => return Err(UpstreamError::Io(e.kind())),
        }
    }
    UdpSocket::bind(SocketAddr::new(any, 0))
        .await
        .map_err(|e| UpstreamError::Io(e.kind()))
}

/// One UDP exchange. Ignores packets from another address, with another ID or with
/// another question, until the time limit.
async fn udp_exchange(
    addr: SocketAddr,
    query: &Query,
    dnssec_ok: bool,
    timeout: Duration,
) -> Result<Message, UpstreamError> {
    let deadline = Instant::now() + timeout;
    let id = random_id()?;
    let bytes = wire::upstream_query(id, query, dnssec_ok).ok_or(UpstreamError::Encode)?;
    let sock = bind_random(addr).await?;
    sock.connect(addr)
        .await
        .map_err(|e| UpstreamError::Io(e.kind()))?;
    match timeout_at(deadline, sock.send(&bytes)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(UpstreamError::Io(e.kind())),
        Err(_) => return Err(UpstreamError::Timeout),
    }
    let mut buf = vec![0u8; UDP_RECV_BUF];
    for _ in 0..=MAX_IGNORED_REPLIES {
        let (n, from) = match timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            // On Windows an ICMP "port unreachable" gives `ConnectionReset` here.
            Ok(Err(e)) => return Err(UpstreamError::Io(e.kind())),
            Err(_) => return Err(UpstreamError::Timeout),
        };
        if from != addr {
            tracing::debug!(%from, upstream = %addr, "ignored a reply from another address");
            continue;
        }
        let Some(data) = buf.get(..n) else {
            continue;
        };
        match wire::check_upstream_reply(data, id, query) {
            Ok(msg) => return Ok(msg),
            Err(reason) => log_reject(addr, reason),
        }
    }
    Err(UpstreamError::BadReply)
}

fn log_reject(addr: SocketAddr, reason: ReplyReject) {
    tracing::debug!(upstream = %addr, %reason, "ignored an upstream reply");
}

/// One TCP exchange with the 2-byte length prefix (RFC 1035 section 4.2.2).
async fn tcp_exchange(
    addr: SocketAddr,
    query: &Query,
    dnssec_ok: bool,
    timeout: Duration,
) -> Result<Message, UpstreamError> {
    let deadline = Instant::now() + timeout;
    let id = random_id()?;
    let bytes = wire::upstream_query(id, query, dnssec_ok).ok_or(UpstreamError::Encode)?;
    let len = u16::try_from(bytes.len()).map_err(|_| UpstreamError::Encode)?;
    let io_err = |e: io::Error| UpstreamError::Io(e.kind());
    let mut stream = timeout_at(deadline, TcpStream::connect(addr))
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(io_err)?;
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&bytes);
    timeout_at(deadline, stream.write_all(&framed))
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(io_err)?;
    let mut len_buf = [0u8; 2];
    timeout_at(deadline, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(io_err)?;
    let n = usize::from(u16::from_be_bytes(len_buf));
    if n < wire::HEADER_LEN {
        return Err(UpstreamError::BadReply);
    }
    let mut buf = vec![0u8; n];
    timeout_at(deadline, stream.read_exact(&mut buf))
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(io_err)?;
    wire::check_upstream_reply(&buf, id, query).map_err(|reason| {
        log_reject(addr, reason);
        UpstreamError::BadReply
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_covers_all_attempts() {
        let s = PoolSettings {
            servers: Vec::new(),
            timeout: Duration::from_millis(100),
            max_attempts: 3,
            max_inflight: 4,
            health: HealthConfig::default(),
        };
        assert_eq!(s.query_budget(), Duration::from_millis(100 * 6 + 100 + 500));
    }

    #[test]
    fn random_ids_differ() {
        let ids: Vec<u16> = (0..64).map(|_| random_id().unwrap()).collect();
        let mut uniq = ids.clone();
        uniq.sort_unstable();
        uniq.dedup();
        // 64 random 16-bit values: a few collisions are possible, many are not.
        assert!(uniq.len() > 50, "{ids:?}");
    }

    /// A flood of wrong replies ends the wait after `MAX_IGNORED_REPLIES + 1` packets,
    /// long before the time limit: the loop is bounded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ignored_reply_loop_is_bounded() {
        let fake = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = fake.local_addr().unwrap();
        let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&sent);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let (n, peer) = fake.recv_from(&mut buf).await.unwrap();
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut wrong = Message::new(
                q.metadata.id.wrapping_add(1),
                hickory_proto::op::MessageType::Response,
                hickory_proto::op::OpCode::Query,
            );
            wrong.queries.clone_from(&q.queries);
            let bytes = wrong.to_vec().unwrap();
            for _ in 0..(MAX_IGNORED_REPLIES * 3) {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if fake.send_to(&bytes, peer).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        let query = Query::query(Name::from_ascii("flood.example.").unwrap(), RecordType::A);
        let start = Instant::now();
        let r = udp_exchange(addr, &query, false, Duration::from_secs(20)).await;
        assert_eq!(r.unwrap_err(), UpstreamError::BadReply);
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(sent.load(std::sync::atomic::Ordering::SeqCst) > MAX_IGNORED_REPLIES);
    }

    #[test]
    fn bind_address_follows_the_peer_address() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let peer = |s: &str| -> SocketAddr { s.parse().unwrap() };
        assert_eq!(local_bind_ip(peer("127.0.0.1:53")), ip("127.0.0.1"));
        assert_eq!(local_bind_ip(peer("192.0.2.53:53")), ip("0.0.0.0"));
        assert_eq!(local_bind_ip(peer("[::1]:53")), ip("::1"));
        assert_eq!(local_bind_ip(peer("[2001:db8::1]:53")), ip("::"));
    }

    #[tokio::test]
    async fn random_source_ports_differ() {
        let peer: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let mut ports = Vec::new();
        for _ in 0..8 {
            let s = bind_random(peer).await.unwrap();
            ports.push(s.local_addr().unwrap().port());
        }
        ports.sort_unstable();
        ports.dedup();
        assert!(ports.len() >= 6, "{ports:?}");
        assert!(ports.iter().all(|p| *p >= 1024));
        // A loopback upstream gets a loopback source address.
        let s = bind_random(peer).await.unwrap();
        assert!(s.local_addr().unwrap().ip().is_loopback());
    }
}
