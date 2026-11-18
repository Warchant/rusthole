//! Upstream pool: plain DNS over UDP and TCP, DNS over TLS ([`crate::dot`]) and DNS over
//! HTTPS ([`crate::doh_client`]), with failover, health, coalescing and the hardening of
//! amendment A5.
//!
//! The pool holds the servers of `upstreams.servers` (in config order) and then the servers
//! of `upstreams.fallback_plain`. Each server has its own health state. The clock mode
//! ([`crate::clock`]) selects which servers a query can use: while the wall clock is not
//! plausible, the DoT and DoH servers are skipped (no query, no probe, no health change) and
//! the fallback servers are used. The same occurs while each DoT and DoH server fails its
//! handshake with a certificate date error (review item m1, [`clock::date_step`]). An
//! answer from a fallback server has [`UpstreamAnswer::fallback`] set, and the cache keeps
//! it for a short time only (review item m3).
//!
//! For each plain upstream query:
//!
//! - a new UDP socket on a random source port (CSPRNG), connected to the upstream;
//! - a random query ID (CSPRNG);
//! - a reply counts only when it comes from the upstream address and port, has the same ID,
//!   and has the same question. Other packets are ignored, and the wait goes on until the
//!   time limit (at most [`MAX_IGNORED_REPLIES`] packets);
//! - a reply with the TC bit makes a retry over TCP;
//! - a timeout, an I/O error, SERVFAIL or REFUSED makes the query go to the next upstream,
//!   at most [`PoolSettings::max_attempts`] upstreams. When no upstream gives a better
//!   answer, the client gets the last SERVFAIL or REFUSED answer.
//!
//! Health: a timeout or an I/O error is a failure. Each valid answer is a success, also
//! SERVFAIL and REFUSED. Reason: an upstream can refuse or fail one name only (for example
//! its own block list, or a broken zone). If such an answer were a failure, a client could
//! take a good upstream `Down` with a few names that it refuses.
//!
//! Identical queries in flight (same cache key) share one upstream query. A semaphore
//! limits the upstream queries in flight.
//!
//! In-flight share (review item m2): each requester (a client address, or the local host
//! resolver) can lead at most [`PoolSettings::max_inflight_per_client`] upstream queries at
//! the same time (coalesced queries and conditional forwards). A query that joins a query in
//! flight takes no slot. So one client cannot take all [`PoolSettings::max_inflight`] slots.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

use crate::clock::{
    self, DateEvent, DateState, HandshakeClass, ModeCell, ServerRole, UpstreamMode,
};
use crate::doh_client::DohClient;
use crate::dot::DotClient;
use crate::sync::{Clock, LOCK_TIMEOUT, Spawner};
use crate::tls_upstream::{TlsTarget, UpstreamTls};
use crate::wire::{self, ReplyReject};

/// Upstreams tried for one query, at most.
pub const MAX_ATTEMPTS: usize = 3;
/// Upstream queries in flight, at most. Also the size limit of the coalescing map.
pub const MAX_INFLIGHT: usize = 512;
/// Upstream queries in flight that one requester can lead, at most (review item m2).
pub const MAX_INFLIGHT_PER_CLIENT: usize = 64;
/// Wrong packets that one UDP upstream query ignores before it gives up.
pub const MAX_IGNORED_REPLIES: usize = 64;
/// Random source ports to try before the OS picks one.
const PORT_TRIES: usize = 8;
/// Receive buffer for a UDP upstream reply. We ask for 1232 bytes; this leaves room.
const UDP_RECV_BUF: usize = 4096;
/// How often the prober looks for a `Down` upstream with a due probe.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// The transport of an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamProto {
    /// UDP, with a TCP retry on truncation.
    Udp,
    /// TCP only.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls(Arc<TlsTarget>),
    /// DNS over HTTPS (RFC 8484) over HTTP/2.
    Https(Arc<TlsTarget>),
}

impl UpstreamProto {
    /// True for DoT and DoH.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Tls(_) | Self::Https(_))
    }
}

/// One upstream server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamServer {
    /// The address and port. For DoT and DoH: the first bootstrap address (logs and
    /// statistics show the address that answered).
    pub addr: SocketAddr,
    /// The transport.
    pub proto: UpstreamProto,
}

/// Settings of the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSettings {
    /// The servers, in config order.
    pub servers: Vec<UpstreamServer>,
    /// Plain servers for the time when the wall clock is not plausible
    /// (`upstreams.fallback_plain`). Only UDP and TCP servers are used here.
    pub fallback: Vec<UpstreamServer>,
    /// Time limit for one exchange with one upstream (the TCP retry gets its own limit).
    pub timeout: Duration,
    /// Upstreams tried for one query, at most.
    pub max_attempts: usize,
    /// Upstream queries in flight, at most.
    pub max_inflight: usize,
    /// Upstream queries in flight that one requester (a client address) can lead, at most.
    pub max_inflight_per_client: usize,
    /// Settings of the health state machine.
    pub health: HealthConfig,
}

impl PoolSettings {
    /// The longest time that one query can take in the pool: each attempt can use two time
    /// limits (UDP and the TCP retry, or a reused DoT/DoH connection and a new one), plus
    /// the wait for a semaphore permit.
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
    /// The TLS handshake failed (for example a certificate for another name), or a DoH
    /// server has no HTTP/2.
    #[error("TLS handshake failed")]
    Tls,
    /// The TLS handshake failed because the certificate is not yet valid or expired. A
    /// wrong system clock can cause this (review item m1).
    #[error("TLS handshake failed: the certificate is not yet valid or expired")]
    CertDate,
    /// A DoH server answered with an HTTP status that is not 200.
    #[error("HTTP status {0}")]
    Http(u16),
}

/// A valid upstream answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAnswer {
    /// The answer. It passed [`wire::check_upstream_reply`].
    pub message: Message,
    /// The upstream that sent it.
    pub upstream: SocketAddr,
    /// True when a `upstreams.fallback_plain` server sent the answer. The cache keeps such
    /// an answer for a short time only (review item m3).
    pub fallback: bool,
}

type Shared = Arc<Result<UpstreamAnswer, UpstreamError>>;

/// Who asks the pool for an upstream query. Each requester has its own share of the
/// in-flight slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Requester {
    /// A DNS client.
    Client(IpAddr),
    /// The host resolver of rusthole itself (list downloads).
    Local,
}

/// True when a requester that leads `in_use` upstream queries now can lead one more, with
/// `share` slots for each requester. Pure.
pub(crate) fn share_allows(in_use: usize, share: usize) -> bool {
    in_use < share.max(1)
}

/// A slot of the in-flight share of one requester. The slot is free again when the value
/// is dropped (also on cancel or panic): the count is the strong count of the `Arc`, so no
/// lock is needed to give the slot back, and the count cannot leak.
#[derive(Debug)]
pub(crate) struct ShareSlot {
    _token: Arc<()>,
}

/// The upstream pool. Cheap to clone.
#[derive(Debug, Clone)]
pub(crate) struct Pool {
    inner: Arc<PoolInner>,
}

/// The client of one encrypted upstream.
#[derive(Debug)]
enum EncClient {
    Dot(DotClient),
    Doh(DohClient),
}

#[derive(Debug)]
struct PoolInner {
    settings: PoolSettings,
    /// `settings.servers`, then `settings.fallback`.
    all: Vec<UpstreamServer>,
    roles: Vec<ServerRole>,
    /// The DoT or DoH client of each server in `all` (`None` for a plain server).
    clients: Vec<Option<EncClient>>,
    /// The clock mode ([`clock::clock_step`]).
    mode: ModeCell,
    /// The certificate date state (review item m1). The flag is true for
    /// [`DateState::DateFallback`]; [`PoolInner::note_handshake`] sets it under the `dates`
    /// lock.
    date_fallback: AtomicBool,
    /// The last counted handshake result of each server (by index into `all`).
    dates: Mutex<Vec<Option<HandshakeClass>>>,
    health: Mutex<Vec<HealthState>>,
    permits: Arc<Semaphore>,
    inflight: Mutex<HashMap<CacheKey, watch::Receiver<Option<Shared>>>>,
    /// One token for each requester with a slot in use. The strong count of a token minus
    /// one is the number of slots in use ([`ShareSlot`]). At most `max_inflight` + 1 entries
    /// stay: free tokens are removed when the map is larger.
    shares: Mutex<HashMap<Requester, Arc<()>>>,
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
    /// Makes the pool. `tls` must be set when a server is DoT or DoH; without it, such a
    /// server fails each query with [`UpstreamError::Tls`]. `stop` ends the DoT and DoH
    /// connection tasks at shutdown.
    pub(crate) fn new(
        settings: PoolSettings,
        clock: Clock,
        spawner: Spawner,
        tls: Option<&UpstreamTls>,
        stop: &CancellationToken,
    ) -> Self {
        let mut all = settings.servers.clone();
        let mut roles: Vec<ServerRole> = settings
            .servers
            .iter()
            .map(|s| {
                if s.proto.is_encrypted() {
                    ServerRole::Encrypted
                } else {
                    ServerRole::Plain
                }
            })
            .collect();
        for s in &settings.fallback {
            if s.proto.is_encrypted() {
                tracing::error!(upstream = %s.addr, "a fallback server must be plain DNS; it is skipped");
                continue;
            }
            all.push(s.clone());
            roles.push(ServerRole::Fallback);
        }
        let clients = all
            .iter()
            .map(|s| match (&s.proto, tls) {
                (UpstreamProto::Tls(t), Some(tls)) => Some(EncClient::Dot(DotClient::new(
                    Arc::clone(t),
                    Arc::clone(&tls.dot),
                    spawner.clone(),
                    stop.clone(),
                ))),
                (UpstreamProto::Https(t), Some(tls)) => Some(EncClient::Doh(DohClient::new(
                    Arc::clone(t),
                    Arc::clone(&tls.doh),
                    spawner.clone(),
                    stop.clone(),
                    clock,
                ))),
                _ => None,
            })
            .collect();
        let n = all.len();
        let permits = Arc::new(Semaphore::new(settings.max_inflight.max(1)));
        Self {
            inner: Arc::new(PoolInner {
                settings,
                all,
                roles,
                clients,
                mode: ModeCell::new(UpstreamMode::Encrypted),
                date_fallback: AtomicBool::new(false),
                dates: Mutex::new(vec![None; n]),
                health: Mutex::new(vec![HealthState::Healthy; n]),
                permits,
                inflight: Mutex::new(HashMap::new()),
                shares: Mutex::new(HashMap::new()),
                clock,
                spawner,
            }),
        }
    }

    /// True when a server is DoT or DoH.
    pub(crate) fn has_encrypted(&self) -> bool {
        self.inner.roles.contains(&ServerRole::Encrypted)
    }

    /// True when the pool has a fallback server.
    pub(crate) fn has_fallback(&self) -> bool {
        self.inner.roles.contains(&ServerRole::Fallback)
    }

    /// The mode that the pool uses: the clock mode and the certificate date state
    /// ([`clock::effective_mode`]).
    pub(crate) fn mode(&self) -> UpstreamMode {
        self.inner.effective_mode()
    }

    /// The clock mode only (the input of the next clock check).
    pub(crate) fn clock_mode(&self) -> UpstreamMode {
        self.inner.mode.get()
    }

    /// Sets the clock mode.
    pub(crate) fn set_mode(&self, mode: UpstreamMode) {
        self.inner.mode.set(mode);
    }

    /// True while the pool uses the fallback because of certificate date errors.
    pub(crate) fn in_date_fallback(&self) -> bool {
        self.inner.date_fallback.load(Ordering::Acquire)
    }

    /// In the certificate date fallback, tries one exchange (`. NS`) with each encrypted
    /// upstream, in order, until one passes. A passed exchange ends the fallback
    /// ([`PoolInner::note_handshake`]). Does nothing in the other states.
    ///
    /// Bounded: one exchange for each server, each with the query timeout. The health
    /// state does not change (the clock mode skips these servers).
    pub(crate) async fn date_probe(&self) {
        if !self.in_date_fallback() {
            return;
        }
        let query = Query::query(Name::root(), RecordType::NS);
        for idx in 0..self.inner.all.len() {
            if self.inner.roles.get(idx) != Some(&ServerRole::Encrypted) {
                continue;
            }
            let r = self.inner.exchange_idx(idx, &query, false).await;
            tracing::debug!(upstream = ?self.inner.all.get(idx).map(|s| s.addr), ok = r.is_ok(), "certificate date probe done");
            self.inner
                .note_handshake(idx, r.as_ref().map(|_| ()).map_err(|e| *e));
            if !self.in_date_fallback() {
                return;
            }
        }
    }

    /// Live DoT connections and DoH connections of all upstreams.
    pub(crate) fn tls_conns(&self) -> usize {
        self.inner
            .clients
            .iter()
            .map(|c| match c {
                Some(EncClient::Dot(d)) => d.conn_count(),
                Some(EncClient::Doh(d)) => usize::from(d.has_conn()),
                None => 0,
            })
            .sum()
    }

    /// The health of each upstream: `upstreams.servers` in config order, then
    /// `upstreams.fallback_plain`.
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

    /// Resolves `query` through the upstreams for `who`. Identical queries in flight share
    /// one upstream query.
    pub(crate) async fn resolve(
        &self,
        key: &CacheKey,
        query: &Query,
        dnssec_ok: bool,
        who: Requester,
    ) -> Result<UpstreamAnswer, UpstreamError> {
        let mut rx = self.join_or_lead(key, query, dnssec_ok, who)?;
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

    /// Takes one slot of the in-flight share of `who`, or gives
    /// [`UpstreamError::Overloaded`] when `who` uses all its slots.
    fn take_share(&self, who: Requester) -> Result<ShareSlot, UpstreamError> {
        let mut shares = self
            .inner
            .shares
            .try_lock_for(LOCK_TIMEOUT)
            .ok_or(UpstreamError::Overloaded)?;
        if shares.len() > self.inner.settings.max_inflight {
            // Bounded: one pass over at most max_inflight + 1 entries.
            shares.retain(|_, token| Arc::strong_count(token) > 1);
        }
        let token = shares.entry(who).or_default();
        let in_use = Arc::strong_count(token).saturating_sub(1);
        if !share_allows(in_use, self.inner.settings.max_inflight_per_client) {
            tracing::debug!(requester = ?who, in_use, "the requester uses all its in-flight slots");
            return Err(UpstreamError::Overloaded);
        }
        Ok(ShareSlot {
            _token: Arc::clone(token),
        })
    }

    /// The number of in-flight slots that `who` uses now. For tests.
    #[cfg(test)]
    fn share_in_use(&self, who: Requester) -> usize {
        self.inner
            .shares
            .try_lock_for(LOCK_TIMEOUT)
            .and_then(|s| s.get(&who).map(|t| Arc::strong_count(t).saturating_sub(1)))
            .unwrap_or(0)
    }

    fn join_or_lead(
        &self,
        key: &CacheKey,
        query: &Query,
        dnssec_ok: bool,
        who: Requester,
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
        let slot = self.take_share(who)?;
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
            // The slot is free again here, or when a cancel drops this task.
            drop(slot);
        });
        Ok(rx)
    }

    /// Sends `query` to a conditional forwarding server (part P3c), over UDP with a TCP retry
    /// on truncation, with the same hardening as a public upstream query. There is no
    /// coalescing, no health state and no fallback to the public upstreams: a failure gives
    /// an error (the client gets SERVFAIL). The query holds a permit of the in-flight limit
    /// and a slot of the in-flight share of `who`.
    pub(crate) async fn forward(
        &self,
        server: SocketAddr,
        query: &Query,
        dnssec_ok: bool,
        who: Requester,
    ) -> Result<UpstreamAnswer, UpstreamError> {
        let _slot = self.take_share(who)?;
        let timeout = self.inner.settings.timeout;
        let Ok(Ok(_permit)) =
            tokio::time::timeout(timeout, Arc::clone(&self.inner.permits).acquire_owned()).await
        else {
            return Err(UpstreamError::Overloaded);
        };
        let budget = self.inner.settings.query_budget();
        let message = tokio::time::timeout(
            budget,
            exchange_plain(server, false, query, dnssec_ok, timeout),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)??;
        Ok(UpstreamAnswer {
            message,
            upstream: server,
            fallback: false,
        })
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
    /// SERVFAIL or REFUSED. The loop is bounded by `max_attempts`.
    async fn lead(&self, query: &Query, dnssec_ok: bool) -> Result<UpstreamAnswer, UpstreamError> {
        let deadline = Instant::now() + self.settings.timeout;
        let Ok(Ok(_permit)) = timeout_at(deadline, Arc::clone(&self.permits).acquire_owned()).await
        else {
            return Err(UpstreamError::Overloaded);
        };
        let order = self.order();
        let mut last: Result<UpstreamAnswer, UpstreamError> = Err(UpstreamError::NoUpstream);
        for idx in order {
            let Some(server_addr) = self.all.get(idx).map(|s| s.addr) else {
                continue;
            };
            let result = self.exchange_idx(idx, query, dnssec_ok).await;
            self.note_handshake(idx, result.as_ref().map(|_| ()).map_err(|e| *e));
            match result {
                Ok((message, from)) => {
                    self.report(idx, true);
                    let answer = UpstreamAnswer {
                        message,
                        upstream: from,
                        fallback: self.roles.get(idx) == Some(&ServerRole::Fallback),
                    };
                    if !wire::is_server_failure(&answer.message) {
                        return Ok(answer);
                    }
                    tracing::debug!(upstream = %from, rcode = %answer.message.metadata.response_code, "upstream answered SERVFAIL or REFUSED; trying the next one");
                    last = Ok(answer);
                }
                Err(e) => {
                    if is_upstream_fault(e) {
                        self.report(idx, false);
                    }
                    tracing::debug!(upstream = %server_addr, error = %e, "upstream query failed");
                    if last.is_err() {
                        last = Err(e);
                    }
                }
            }
        }
        last
    }

    /// The servers that the current mode allows, as indexes into `all`.
    fn eligible(&self) -> Vec<usize> {
        clock::eligible(&self.roles, self.effective_mode())
    }

    /// The clock mode and the certificate date state together.
    fn effective_mode(&self) -> UpstreamMode {
        let date = if self.date_fallback.load(Ordering::Acquire) {
            DateState::DateFallback
        } else {
            DateState::Normal
        };
        clock::effective_mode(self.mode.get(), date)
    }

    /// Feeds the result of one exchange with server `idx` to the certificate date machine
    /// (review item m1). Only encrypted servers count. A passed exchange is
    /// [`HandshakeClass::Passed`], [`UpstreamError::CertDate`] is
    /// [`HandshakeClass::DateError`]; other errors do not change the class.
    fn note_handshake(&self, idx: usize, result: Result<(), UpstreamError>) {
        if self.roles.get(idx) != Some(&ServerRole::Encrypted) {
            return;
        }
        let class = match result {
            Ok(()) => HandshakeClass::Passed,
            Err(UpstreamError::CertDate) => HandshakeClass::DateError,
            Err(_) => return,
        };
        let Some(mut dates) = self.dates.try_lock_for(LOCK_TIMEOUT) else {
            tracing::error!("cannot update the certificate date state: the lock timed out");
            return;
        };
        if let Some(slot) = dates.get_mut(idx) {
            *slot = Some(class);
        }
        let event = match class {
            HandshakeClass::Passed => DateEvent::HandshakePassed,
            HandshakeClass::DateError if clock::all_date_errors(&self.roles, &dates) => {
                DateEvent::AllDateErrors
            }
            HandshakeClass::DateError => return,
        };
        let prev = if self.date_fallback.load(Ordering::Acquire) {
            DateState::DateFallback
        } else {
            DateState::Normal
        };
        let has_fallback = self.roles.contains(&ServerRole::Fallback);
        let step = clock::date_step(prev, event, has_fallback);
        if let Some(invalid) = step.invalid {
            tracing::error!(
                state = ?invalid.state,
                event = ?invalid.event,
                has_fallback = invalid.has_fallback,
                next = ?step.state,
                "invalid certificate date transition; going to the safe state"
            );
        }
        if let Some(notice) = step.notice {
            clock::log_date_notice(notice);
        }
        self.date_fallback
            .store(step.state == DateState::DateFallback, Ordering::Release);
    }

    /// The order of servers for one query: the eligible servers by health, then in order,
    /// at most `max_attempts`.
    fn order(&self) -> Vec<usize> {
        let eligible = self.eligible();
        let max = self.settings.max_attempts;
        let Some(states) = self.health.try_lock_for(LOCK_TIMEOUT) else {
            return eligible.into_iter().take(max).collect();
        };
        let sub: Vec<HealthState> = eligible
            .iter()
            .filter_map(|&i| states.get(i).copied())
            .collect();
        drop(states);
        upstream_health::plan(&sub, max)
            .into_iter()
            .filter_map(|j| eligible.get(j).copied())
            .collect()
    }

    /// One exchange with server `idx`. Gives the answer and the address that sent it.
    async fn exchange_idx(
        &self,
        idx: usize,
        query: &Query,
        dnssec_ok: bool,
    ) -> Result<(Message, SocketAddr), UpstreamError> {
        let server = self.all.get(idx).ok_or(UpstreamError::NoUpstream)?;
        let timeout = self.settings.timeout;
        match (
            &server.proto,
            self.clients.get(idx).and_then(Option::as_ref),
        ) {
            (UpstreamProto::Udp, _) => {
                exchange_plain(server.addr, false, query, dnssec_ok, timeout)
                    .await
                    .map(|m| (m, server.addr))
            }
            (UpstreamProto::Tcp, _) => exchange_plain(server.addr, true, query, dnssec_ok, timeout)
                .await
                .map(|m| (m, server.addr)),
            (UpstreamProto::Tls(_), Some(EncClient::Dot(c))) => {
                c.exchange(query, dnssec_ok, timeout).await
            }
            (UpstreamProto::Https(_), Some(EncClient::Doh(c))) => {
                c.exchange(query, dnssec_ok, timeout).await
            }
            (UpstreamProto::Tls(_) | UpstreamProto::Https(_), _) => Err(UpstreamError::Tls),
        }
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
        let addr = self.all.get(idx).map(|s| s.addr);
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
        // A server that the clock mode skips gets no probe, so its health does not change.
        let due: Vec<usize> = self
            .eligible()
            .into_iter()
            .filter(|&i| {
                states
                    .get(i)
                    .is_some_and(|s| upstream_health::probe_due(s, now_ms))
            })
            .collect();
        for &idx in &due {
            self.step_locked(&mut states, idx, HealthEvent::ProbeStart { now_ms });
        }
        due
    }

    /// Sends a probe query (`. NS`) to upstream `idx`. Any valid answer is a success.
    async fn probe(&self, idx: usize) {
        let Some(addr) = self.all.get(idx).map(|s| s.addr) else {
            return;
        };
        let query = Query::query(Name::root(), RecordType::NS);
        let result = self.exchange_idx(idx, &query, false).await;
        self.note_handshake(idx, result.as_ref().map(|_| ()).map_err(|e| *e));
        let ok = result.is_ok();
        tracing::debug!(upstream = %addr, ok, "upstream probe done");
        self.report(idx, ok);
    }
}

/// True when a failed query is a fault of the upstream and goes to its health machine.
/// [`UpstreamError::Overloaded`] is a local limit (for example all DoT connections of the
/// upstream are full), so the query goes to the next upstream with no health change.
///
/// A probe reports each failure, also this one: a skipped report would keep the upstream in
/// `Probing` with no next probe.
pub(crate) fn is_upstream_fault(e: UpstreamError) -> bool {
    e != UpstreamError::Overloaded
}

/// One exchange with one plain upstream: UDP with a TCP retry on truncation, or TCP. A DoT
/// or DoH server needs the pool; here it gives [`UpstreamError::Tls`].
pub(crate) async fn exchange(
    server: UpstreamServer,
    query: &Query,
    dnssec_ok: bool,
    timeout: Duration,
) -> Result<Message, UpstreamError> {
    match server.proto {
        UpstreamProto::Tcp => tcp_exchange(server.addr, query, dnssec_ok, timeout).await,
        UpstreamProto::Udp => exchange_plain(server.addr, false, query, dnssec_ok, timeout).await,
        UpstreamProto::Tls(_) | UpstreamProto::Https(_) => Err(UpstreamError::Tls),
    }
}

/// One plain exchange: TCP when `tcp_only`, else UDP with a TCP retry on truncation.
async fn exchange_plain(
    addr: SocketAddr,
    tcp_only: bool,
    query: &Query,
    dnssec_ok: bool,
    timeout: Duration,
) -> Result<Message, UpstreamError> {
    if tcp_only {
        return tcp_exchange(addr, query, dnssec_ok, timeout).await;
    }
    let msg = udp_exchange(addr, query, dnssec_ok, timeout).await?;
    if msg.metadata.truncation {
        tracing::debug!(upstream = %addr, "truncated reply; retrying over TCP");
        tcp_exchange(addr, query, dnssec_ok, timeout).await
    } else {
        Ok(msg)
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
    fn overloaded_is_not_an_upstream_fault() {
        assert!(!is_upstream_fault(UpstreamError::Overloaded));
        for e in [
            UpstreamError::Timeout,
            UpstreamError::Io(io::ErrorKind::ConnectionReset),
            UpstreamError::BadReply,
            UpstreamError::Tls,
            UpstreamError::CertDate,
            UpstreamError::Http(502),
        ] {
            assert!(is_upstream_fault(e), "{e}");
        }
    }

    #[test]
    fn share_rule() {
        assert!(share_allows(0, 64));
        assert!(share_allows(63, 64));
        assert!(!share_allows(64, 64));
        assert!(!share_allows(65, 64));
        // A share of 0 still allows one query.
        assert!(share_allows(0, 0));
        assert!(!share_allows(1, 0));
    }

    proptest::proptest! {
        /// The rule allows exactly `max(share, 1)` slots.
        #[test]
        fn share_rule_counts(in_use in 0usize..2000, share in 0usize..1000) {
            proptest::prop_assert_eq!(share_allows(in_use, share), in_use < share.max(1));
        }
    }

    fn pool_with(server: SocketAddr, max_inflight: usize, share: usize) -> Pool {
        Pool::new(
            PoolSettings {
                servers: vec![UpstreamServer {
                    addr: server,
                    proto: UpstreamProto::Udp,
                }],
                fallback: Vec::new(),
                timeout: Duration::from_secs(5),
                max_attempts: 1,
                max_inflight,
                max_inflight_per_client: share,
                health: HealthConfig::default(),
            },
            Clock::new(),
            Spawner::new(),
            None,
            &CancellationToken::new(),
        )
    }

    fn key_q(name: &str) -> (CacheKey, Query) {
        let q = Query::query(Name::from_ascii(name).unwrap(), RecordType::A);
        (CacheKey::new(name, 1, 1, false), q)
    }

    /// m2: a requester leads at most its share; another requester still gets a slot; a
    /// query that joins a query in flight takes no slot; a slot is free again when its
    /// leader ends (here: the pool stops it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_requester_has_its_own_share() {
        // An upstream that never answers.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = pool_with(silent.local_addr().unwrap(), 16, 3);
        let a = Requester::Client("192.0.2.1".parse().unwrap());
        let b = Requester::Client("192.0.2.2".parse().unwrap());
        let mut rxs = Vec::new();
        for i in 0..3 {
            let (k, q) = key_q(&format!("a{i}.example."));
            rxs.push(pool.join_or_lead(&k, &q, false, a).unwrap());
        }
        assert_eq!(pool.share_in_use(a), 3);
        let (k, q) = key_q("a3.example.");
        assert_eq!(
            pool.join_or_lead(&k, &q, false, a).unwrap_err(),
            UpstreamError::Overloaded
        );
        // Joining a query in flight is free, also for a full requester.
        let (k0, q0) = key_q("a0.example.");
        rxs.push(pool.join_or_lead(&k0, &q0, false, a).unwrap());
        rxs.push(pool.join_or_lead(&k0, &q0, false, b).unwrap());
        assert_eq!(pool.share_in_use(a), 3);
        assert_eq!(pool.share_in_use(b), 0);
        // Another requester and the local resolver have their own shares.
        let (k, q) = key_q("b0.example.");
        rxs.push(pool.join_or_lead(&k, &q, false, b).unwrap());
        let (k, q) = key_q("local.example.");
        rxs.push(pool.join_or_lead(&k, &q, false, Requester::Local).unwrap());
        assert_eq!(pool.inflight_len(), 5);
        // A hard stop of the leader tasks (the upstream never answers) gives the slots
        // back: the cleanup path of a cancelled leader.
        let clean = pool
            .inner
            .spawner
            .stop(Duration::from_millis(50), Duration::from_secs(2))
            .await;
        assert!(!clean);
        assert_eq!(pool.inner.spawner.len(), 0);
        assert_eq!(pool.share_in_use(a), 0);
        assert_eq!(pool.share_in_use(b), 0);
        assert_eq!(pool.inflight_len(), 0);
    }

    #[test]
    fn budget_covers_all_attempts() {
        let s = PoolSettings {
            servers: Vec::new(),
            fallback: Vec::new(),
            timeout: Duration::from_millis(100),
            max_attempts: 3,
            max_inflight: 4,
            max_inflight_per_client: 2,
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
