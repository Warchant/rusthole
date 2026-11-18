//! Client identity (part P3c): the I/O shell around [`rusthole_core::clients`].
//!
//! [`ClientResolver::identify`] runs on each query. It reads only memory: a short-lived
//! cache for each client address, the latest neighbor snapshot and the PTR cache. It never
//! waits for the network.
//!
//! Host-name clients: when the config has a client entry with a host name, the resolver
//! needs the name of each client address. It asks a background task through a bounded
//! queue. The task finds the name in the local records (the reverse map), or asks the
//! conditional forwarding server of the address (time limit). It never asks the public
//! upstreams. Until the name is known, the client gets the groups of its other matches (or
//! `default`), and the result is not cached, so the name applies at once when it comes.
//!
//! ```mermaid
//! flowchart LR
//!     q[query] --> id[identify]
//!     id --> cc{client cache}
//!     cc -->|hit| out[ClientInfo]
//!     cc -->|miss| nb[neighbor snapshot: MAC]
//!     nb --> ptr{PTR cache}
//!     ptr -->|miss| queue[(bounded queue)] --> task[PTR task:<br/>local records, then<br/>conditional forward]
//!     task --> ptr
//!     ptr --> res[ClientTable::resolve] --> out
//! ```
//!
//! [`IdentityService`] owns the neighbor refresh task and the PTR task. Its shutdown stops
//! both.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use parking_lot::Mutex;
use rusthole_core::DomainName;
use rusthole_core::clients::{
    CLIENT_CACHE_ENTRIES, CLIENT_CACHE_TTL_MS, ClientFacts, ClientTable, MatchedBy, TtlLru,
};
use rusthole_core::localdns::{LocalAnswer, LocalData, LocalZone, qtype, reverse_name};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::filter::ClientInfo;
use crate::local::dns_name;
use crate::neighbors::{self, NEIGHBOR_REFRESH, NeighborSource, NeighborTable};
use crate::sync::{Clock, LOCK_TIMEOUT, Spawner};
use crate::upstream::{self, UpstreamProto, UpstreamServer};

/// Time that [`IdentityService::shutdown`] waits after the grace time, at most.
const HARD_STOP_WAIT: Duration = Duration::from_secs(2);

/// Settings of the client identity. The defaults suit a home network; the config has no
/// keys for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentitySettings {
    /// Period of the neighbor table refresh.
    pub neighbor_refresh: Duration,
    /// Entries in the client cache, at most.
    pub client_cache_entries: usize,
    /// Time to live of one client cache entry.
    pub client_cache_ttl: Duration,
    /// Time limit for one PTR exchange with a conditional forwarding server.
    pub ptr_timeout: Duration,
    /// Client addresses that wait for a PTR lookup, at most. More are dropped and asked
    /// again later.
    pub ptr_queue: usize,
    /// Entries in the PTR cache, at most.
    pub ptr_cache_entries: usize,
    /// A lookup that did not end in this time is asked again.
    pub ptr_pending_ttl: Duration,
    /// Time to keep "no name" (no record, NXDOMAIN, or no server for the address).
    pub ptr_negative_ttl: Duration,
    /// Time to keep "no name" after a timeout or an I/O error.
    pub ptr_error_ttl: Duration,
    /// The lowest time to keep a name.
    pub ptr_min_ttl: Duration,
    /// The highest time to keep a name.
    pub ptr_max_ttl: Duration,
}

impl Default for IdentitySettings {
    fn default() -> Self {
        Self {
            neighbor_refresh: NEIGHBOR_REFRESH,
            client_cache_entries: CLIENT_CACHE_ENTRIES,
            client_cache_ttl: Duration::from_millis(CLIENT_CACHE_TTL_MS),
            ptr_timeout: Duration::from_secs(1),
            ptr_queue: 256,
            ptr_cache_entries: 4096,
            ptr_pending_ttl: Duration::from_secs(5),
            ptr_negative_ttl: Duration::from_secs(300),
            ptr_error_ttl: Duration::from_secs(30),
            ptr_min_ttl: Duration::from_secs(60),
            ptr_max_ttl: Duration::from_secs(3600),
        }
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The state of a PTR lookup for one client address.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PtrEntry {
    /// A lookup is queued or running.
    Pending,
    /// The name.
    Known(DomainName),
    /// No name.
    Unknown,
}

#[derive(Debug)]
struct PtrState {
    cache: Mutex<TtlLru<IpAddr, PtrEntry>>,
    tx: mpsc::Sender<IpAddr>,
    rx: Mutex<Option<mpsc::Receiver<IpAddr>>>,
}

/// Finds the MAC address and the groups of a client. See the module documentation.
#[derive(Debug)]
pub struct ClientResolver {
    table: ArcSwap<ClientTable>,
    zone: ArcSwap<LocalZone>,
    neighbors: Arc<NeighborTable>,
    cache: Mutex<TtlLru<IpAddr, ClientInfo>>,
    ptr: Option<PtrState>,
    settings: IdentitySettings,
    clock: Clock,
}

impl ClientResolver {
    /// Makes a resolver. It has a PTR queue only when `table` has a host-name client; the
    /// PTR task of [`IdentityService`] takes the queue.
    pub fn new(
        table: ClientTable,
        zone: Arc<LocalZone>,
        neighbors: Arc<NeighborTable>,
        settings: IdentitySettings,
    ) -> Self {
        let ptr = table.has_hostnames().then(|| {
            let (tx, rx) = mpsc::channel(settings.ptr_queue.max(1));
            PtrState {
                cache: Mutex::new(TtlLru::new(settings.ptr_cache_entries)),
                tx,
                rx: Mutex::new(Some(rx)),
            }
        });
        Self {
            table: ArcSwap::from_pointee(table),
            zone: ArcSwap::new(zone),
            neighbors,
            cache: Mutex::new(TtlLru::new(settings.client_cache_entries)),
            ptr,
            settings,
            clock: Clock::new(),
        }
    }

    /// Uses a new client table and local zone after a config change (part P5), and clears
    /// the client cache. Returns false when the new table has host-name clients but the
    /// resolver has no PTR task: those clients need a restart.
    pub fn set_config(&self, table: ClientTable, zone: Arc<LocalZone>) -> bool {
        let needs_ptr = table.has_hostnames() && self.ptr.is_none();
        self.table.store(Arc::new(table));
        self.zone.store(zone);
        if let Some(mut c) = self.cache.try_lock_for(LOCK_TIMEOUT) {
            c.clear();
        } else {
            tracing::warn!("the client cache lock timed out; old client facts stay for up to 10 s");
        }
        !needs_ptr
    }

    /// The neighbor table that the resolver reads.
    pub fn neighbors(&self) -> &Arc<NeighborTable> {
        &self.neighbors
    }

    /// The MAC address and the groups of the client `ip`. It reads only memory.
    pub fn identify(&self, ip: IpAddr) -> ClientInfo {
        let now = self.clock.now_ms();
        if let Some(mut c) = self.cache.try_lock_for(LOCK_TIMEOUT)
            && let Some(info) = c.get(&ip, now)
        {
            return info.clone();
        }
        let mac = self.neighbors.get_ip(ip);
        let mut facts = ClientFacts {
            ip,
            mac,
            hostname: None,
        };
        let table = self.table.load();
        let mut resolved = table.resolve(&facts);
        let mut settled = true;
        let host;
        // A host name can only change the result when no IP or MAC entry matched.
        if !matches!(resolved.matched, MatchedBy::Ip | MatchedBy::Mac) {
            let (name, done) = self.hostname_state(ip, now);
            settled = done;
            host = name;
            if host.is_some() {
                facts.hostname = host.as_ref();
                resolved = table.resolve(&facts);
            }
        }
        let info = ClientInfo {
            mac,
            groups: resolved.groups,
            matched: Some(resolved.matched),
        };
        if settled && let Some(mut c) = self.cache.try_lock_for(LOCK_TIMEOUT) {
            c.insert(ip, info.clone(), ms(self.settings.client_cache_ttl), now);
        }
        info
    }

    /// The known host name of a client address, if any. It starts no lookup.
    pub fn hostname_of(&self, ip: IpAddr) -> Option<DomainName> {
        let ptr = self.ptr.as_ref()?;
        let mut c = ptr.cache.try_lock_for(LOCK_TIMEOUT)?;
        match c.get(&ip, self.clock.now_ms()) {
            Some(PtrEntry::Known(n)) => Some(n.clone()),
            _ => None,
        }
    }

    /// The host name state: the name, and true when the state is final (not pending). A
    /// new address is queued for the PTR task; a full queue drops it, and the pending entry
    /// expires, so the address is asked again later.
    fn hostname_state(&self, ip: IpAddr, now: u64) -> (Option<DomainName>, bool) {
        let Some(ptr) = &self.ptr else {
            return (None, true);
        };
        let Some(mut c) = ptr.cache.try_lock_for(LOCK_TIMEOUT) else {
            return (None, false);
        };
        match c.get(&ip, now) {
            Some(PtrEntry::Known(n)) => (Some(n.clone()), true),
            Some(PtrEntry::Unknown) => (None, true),
            Some(PtrEntry::Pending) => (None, false),
            None => {
                c.insert(
                    ip,
                    PtrEntry::Pending,
                    ms(self.settings.ptr_pending_ttl),
                    now,
                );
                drop(c);
                if ptr.tx.try_send(ip).is_err() {
                    tracing::debug!(%ip, "the PTR queue is full; the lookup comes later");
                }
                (None, false)
            }
        }
    }

    /// Stores the result of a PTR lookup and drops the cached client result.
    fn store_ptr(&self, ip: IpAddr, entry: PtrEntry, ttl: Duration) {
        let now = self.clock.now_ms();
        if let Some(ptr) = &self.ptr
            && let Some(mut c) = ptr.cache.try_lock_for(LOCK_TIMEOUT)
        {
            c.insert(ip, entry, ms(ttl), now);
        }
        if let Some(mut c) = self.cache.try_lock_for(LOCK_TIMEOUT) {
            c.remove(&ip);
        }
    }

    /// Finds the host name of `ip`: the local reverse map, else the conditional forwarding
    /// server of its reverse zone. Never the public upstreams. Returns the entry and its
    /// time to live.
    async fn lookup_ptr(&self, ip: IpAddr) -> (PtrEntry, Duration) {
        let s = &self.settings;
        if let Some(name) = self.zone.load().names_of(ip).first() {
            return (PtrEntry::Known(name.clone()), s.ptr_max_ttl);
        }
        let Some(rev) = reverse_name(ip) else {
            return (PtrEntry::Unknown, s.ptr_negative_ttl);
        };
        let server = match self.zone.load().lookup(&rev, qtype::PTR) {
            LocalAnswer::Answer(records) => {
                let name = records.into_iter().find_map(|r| match r.data {
                    LocalData::Ptr(n) => Some(n),
                    _ => None,
                });
                return match name {
                    Some(n) => (PtrEntry::Known(n), s.ptr_max_ttl),
                    None => (PtrEntry::Unknown, s.ptr_negative_ttl),
                };
            }
            LocalAnswer::Forward { server, .. } => server,
            LocalAnswer::PrivateReverse | LocalAnswer::NotLocal => {
                return (PtrEntry::Unknown, s.ptr_negative_ttl);
            }
        };
        let Some(qname) = dns_name(&rev) else {
            return (PtrEntry::Unknown, s.ptr_negative_ttl);
        };
        let query = Query::query(qname, RecordType::PTR);
        let up = UpstreamServer {
            addr: server,
            proto: UpstreamProto::Udp,
        };
        // UDP and the TCP retry each have `ptr_timeout`; this is the limit for both.
        let limit = s.ptr_timeout.saturating_mul(2);
        let msg =
            match tokio::time::timeout(limit, upstream::exchange(up, &query, false, s.ptr_timeout))
                .await
            {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    tracing::debug!(%ip, %server, error = %e, "PTR lookup for a client failed");
                    return (PtrEntry::Unknown, s.ptr_error_ttl);
                }
                Err(_) => return (PtrEntry::Unknown, s.ptr_error_ttl),
            };
        if msg.metadata.response_code != ResponseCode::NoError {
            return (PtrEntry::Unknown, s.ptr_negative_ttl);
        }
        let found = msg.answers.iter().find_map(|r| match &r.data {
            RData::PTR(p) => DomainName::parse(&p.0.to_ascii()).ok().map(|n| (n, r.ttl)),
            _ => None,
        });
        match found {
            Some((name, ttl)) => {
                let ttl = Duration::from_secs(u64::from(ttl)).clamp(s.ptr_min_ttl, s.ptr_max_ttl);
                (PtrEntry::Known(name), ttl)
            }
            None => (PtrEntry::Unknown, s.ptr_negative_ttl),
        }
    }
}

/// Answers PTR requests from the queue.
///
/// Service loop: unbounded on purpose. It runs for the life of the server and ends when
/// `cancel` is cancelled or the queue closes. Each lookup has a time limit.
async fn ptr_worker(
    resolver: Arc<ClientResolver>,
    mut rx: mpsc::Receiver<IpAddr>,
    cancel: CancellationToken,
) {
    loop {
        let ip = tokio::select! {
            () = cancel.cancelled() => break,
            r = rx.recv() => match r {
                Some(ip) => ip,
                None => break,
            },
        };
        let (entry, ttl) = resolver.lookup_ptr(ip).await;
        tracing::debug!(%ip, ?entry, "client name lookup done");
        resolver.store_ptr(ip, entry, ttl);
    }
}

/// The background tasks of the client identity: the neighbor refresh and the PTR task.
/// Dropping it stops the tasks without a wait; prefer [`IdentityService::shutdown`].
#[derive(Debug)]
pub struct IdentityService {
    resolver: Arc<ClientResolver>,
    spawner: Spawner,
    cancel: CancellationToken,
}

impl IdentityService {
    /// Reads the neighbor table once, then starts the tasks. It needs a tokio runtime: with
    /// no current runtime it returns an error and starts nothing.
    pub fn start(
        table: ClientTable,
        zone: Arc<LocalZone>,
        source: Arc<dyn NeighborSource>,
        settings: IdentitySettings,
    ) -> Result<Self, tokio::runtime::TryCurrentError> {
        tokio::runtime::Handle::try_current()?;
        let neighbors = Arc::new(NeighborTable::new());
        if let Err(e) = neighbors.refresh_now(source.as_ref()) {
            tracing::warn!(error = %e, "cannot read the neighbor table; MAC clients are not known yet");
        }
        let resolver = Arc::new(ClientResolver::new(
            table,
            zone,
            Arc::clone(&neighbors),
            settings,
        ));
        let spawner = Spawner::new();
        let cancel = CancellationToken::new();
        {
            let c = cancel.clone();
            spawner.spawn(neighbors::refresh_loop(
                source,
                neighbors,
                settings.neighbor_refresh,
                c,
            ));
        }
        let rx = resolver
            .ptr
            .as_ref()
            .and_then(|p| p.rx.try_lock_for(LOCK_TIMEOUT).and_then(|mut g| g.take()));
        if let Some(rx) = rx {
            let r = Arc::clone(&resolver);
            let c = cancel.clone();
            spawner.spawn(ptr_worker(r, rx, c));
        }
        Ok(Self {
            resolver,
            spawner,
            cancel,
        })
    }

    /// The resolver for the filter.
    pub fn resolver(&self) -> Arc<ClientResolver> {
        Arc::clone(&self.resolver)
    }

    /// Number of running tasks.
    pub fn task_count(&self) -> usize {
        self.spawner.len()
    }

    /// Stops the tasks: a wait of `grace`, then a hard stop. Returns true when all tasks
    /// ended in `grace`.
    pub async fn shutdown(&self, grace: Duration) -> bool {
        self.cancel.cancel();
        self.spawner.stop(grace, HARD_STOP_WAIT).await
    }
}

impl Drop for IdentityService {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.spawner.hard_stop();
    }
}

#[cfg(test)]
mod tests;
