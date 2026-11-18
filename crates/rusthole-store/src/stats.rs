//! The [`Stats`] handle: the query functions for the admin API, and the apply and flush
//! steps that the worker thread calls.
//!
//! Each query reads the database and the RAM aggregate (the data that is not flushed yet)
//! and merges them, so the results are current. The query holds the database lock while it
//! reads both. A flush also holds the database lock from the moment it takes the RAM data
//! until the commit (or until it puts the data back after an error). So a query never sees
//! the same data two times, and never misses data that a flush is writing.
//!
//! All functions block. Part P5 calls them from `spawn_blocking`. Each lock has a time
//! limit; a lock that is not free in time gives [`StoreError::Busy`].

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, MutexGuard};
use rusthole_core::stats::agg::Aggregator;
use rusthole_core::stats::page::{MAX_LIMIT, Page, SortKey, paginate};
use rusthole_core::stats::policy::{day_of, retention_cutoff_hour, retention_due};
use rusthole_core::stats::query::{
    self, ClientListParams, ClientMeta, ClientRow, Clients, DomainDetail, DomainGroup, DomainRow,
    DomainSearchParams, Filter, GroupParams, HourMap, Hours, NameFilter, PairMap, Range, RangeSpec,
    ReasonMap, ReasonRow, Summary, Timeline, TimelineMap, TopClient, TopDomain, TypeMap, TypeRow,
    UpstreamMap, UpstreamRow, merge_btree, merge_hash,
};
use rusthole_core::stats::recent::{RecentFilter, RecentRing};
use rusthole_core::stats::{Counts, HOUR_SECONDS, StatsEvent, Status, TEN_MINUTES};

use crate::audit::{AuditEntry, AuditParams, NewAudit, RamAudit, audit_limit, cursor_id, page_of};
use crate::db::{Db, FlushReport};
use crate::{Identity, StatsSettings, StoreError};

/// Time limit for the RAM lock. The lock is held for microseconds to milliseconds.
pub(crate) const STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
/// Time limit for the database lock of a query (a flush can hold it for some time).
pub(crate) const DB_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// Time limit for the database lock of a flush (a long query can hold it).
pub(crate) const FLUSH_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest number of client identities in RAM.
pub(crate) const MAX_IDENTITIES: usize = 4096;

/// The RAM state.
#[derive(Debug)]
pub(crate) struct State {
    pub(crate) agg: Aggregator,
    pub(crate) recent: RecentRing,
    identities: HashMap<IpAddr, Identity>,
    identities_dirty: bool,
    ram_audit: RamAudit,
    last_ram_retention_day: Option<i64>,
}

#[derive(Debug, Default)]
struct Counters {
    flushes: AtomicU64,
    flush_failures: AtomicU64,
    lost_events: AtomicU64,
    last_flush_us: AtomicU64,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    db: Option<Mutex<Db>>,
    retention_days: u32,
    counters: Counters,
    dropped: Arc<AtomicU64>,
}

/// The statistics store handle. It is cheap to clone.
#[derive(Debug, Clone)]
pub struct Stats {
    inner: Arc<Inner>,
}

/// Health counters of the store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreCounters {
    /// Keys in RAM now.
    pub ram_keys: usize,
    /// The key bound.
    pub max_keys: usize,
    /// Hour buckets that were evicted from RAM (bound or RAM-only retention).
    pub evicted_buckets: u64,
    /// Events in the evicted buckets.
    pub evicted_events: u64,
    /// Events that the DNS path dropped because the channel was full.
    pub dropped_events: u64,
    /// Events lost because a lock was not free in time.
    pub lost_events: u64,
    /// Flushes that committed.
    pub flushes: u64,
    /// Flushes that failed (the data went back to RAM).
    pub flush_failures: u64,
    /// The duration of the last flush, in microseconds.
    pub last_flush_us: u64,
    /// Committed write transactions since the start, or `None` in RAM-only mode.
    pub db_writes: Option<u64>,
    /// Events in the recent-query ring.
    pub recent_len: usize,
}

/// Filters of `GET /stats/hours`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HoursFilter {
    /// A client key.
    pub client: Option<String>,
    /// An exact name.
    pub domain: Option<String>,
    /// A registrable domain. `domain` wins when both are given (P5 rejects that with 400).
    pub base: Option<String>,
}

/// One client with its hour histogram (`GET /stats/clients/{key}`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClientDetail {
    /// The client.
    pub row: ClientRow,
    /// The hour-of-day histogram of the client.
    pub hours: Hours,
}

/// One name with its hour histogram (`GET /stats/domains/{name}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDetailHours {
    /// The name.
    pub detail: DomainDetail,
    /// The hour-of-day histogram of the name.
    pub hours: Hours,
}

/// A client from `GET /clients/seen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenClient {
    /// What the store knows about the address.
    pub meta: ClientMeta,
    /// Queries in the last 30 days.
    pub queries: u64,
}

/// Parameters of `GET /queries/recent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecentParams {
    /// The largest number of items (1 to 1000).
    pub limit: usize,
    /// A client key.
    pub client: Option<String>,
    /// A status.
    pub status: Option<Status>,
    /// A part of a name.
    pub q: Option<String>,
}

/// Which parts a query reads.
#[derive(Debug, Default)]
struct Need {
    pairs: Option<Filter>,
    hours: Option<Filter>,
    types: Option<(i64, i64)>,
    upstreams: Option<(i64, i64)>,
    reasons: Option<(i64, i64)>,
    timeline: Option<(i64, i64)>,
    /// A filter on the 10-minute pair buckets (bounds in bucket numbers).
    pair_timeline: Option<Filter>,
    clients: bool,
    /// A name whose first query in all stored data (database and RAM) is needed.
    first_seen_of: Option<String>,
}

/// The merged parts of a query.
#[derive(Debug, Default)]
struct Parts {
    pairs: PairMap,
    hours: HourMap,
    types: TypeMap,
    upstreams: UpstreamMap,
    reasons: ReasonMap,
    timeline: TimelineMap,
    clients: Clients,
    first_seen: Option<i64>,
}

impl Stats {
    /// Makes the store. With a database path, it makes the directory, opens the file and
    /// runs the migrations. Without one (RAM-only mode) it opens no file.
    pub fn open(settings: &StatsSettings, dropped: Arc<AtomicU64>) -> Result<Self, StoreError> {
        let db = match &settings.db_path {
            Some(path) => {
                if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                    make_private_dir(dir)?;
                }
                Some(Mutex::new(Db::open(path)?))
            }
            None => None,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    agg: Aggregator::new(settings.max_keys),
                    recent: RecentRing::new(settings.recent_queries),
                    identities: HashMap::new(),
                    identities_dirty: false,
                    ram_audit: RamAudit::default(),
                    last_ram_retention_day: None,
                }),
                db,
                retention_days: settings.retention_days,
                counters: Counters::default(),
                dropped,
            }),
        })
    }

    /// True in RAM-only mode.
    pub fn is_ram_only(&self) -> bool {
        self.inner.db.is_none()
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, State>, StoreError> {
        self.inner
            .state
            .try_lock_for(STATE_LOCK_TIMEOUT)
            .ok_or(StoreError::Busy)
    }

    fn lock_db(&self, timeout: Duration) -> Result<Option<MutexGuard<'_, Db>>, StoreError> {
        match &self.inner.db {
            Some(m) => m.try_lock_for(timeout).map(Some).ok_or(StoreError::Busy),
            None => Ok(None),
        }
    }

    // -----------------------------------------------------------------------------------
    // Steps of the worker thread
    // -----------------------------------------------------------------------------------

    /// Counts the events (the worker calls it with each batch). On a lock timeout the
    /// events are lost and counted.
    pub fn apply(&self, events: &mut Vec<StatsEvent>) -> Result<(), StoreError> {
        let Ok(mut st) = self.lock_state() else {
            let n = u64::try_from(events.len()).unwrap_or(u64::MAX);
            self.inner
                .counters
                .lost_events
                .fetch_add(n, Ordering::Relaxed);
            events.clear();
            return Err(StoreError::Busy);
        };
        for e in events.drain(..) {
            st.agg.apply(&e);
            st.recent.push(e);
        }
        Ok(())
    }

    /// True when the RAM aggregate is near its key bound.
    pub fn near_full(&self) -> bool {
        self.lock_state().is_ok_and(|st| st.agg.near_full())
    }

    /// The RAM-only retention: once a day, evicts the hours older than the retention.
    /// It does nothing when a database is open (the flush runs the retention there).
    pub fn tick(&self, now: i64) {
        if !self.is_ram_only() {
            return;
        }
        if let Ok(mut st) = self.lock_state()
            && retention_due(st.last_ram_retention_day, now)
        {
            let cutoff = retention_cutoff_hour(now, self.inner.retention_days);
            let n = st.agg.evict_before(cutoff);
            st.last_ram_retention_day = Some(day_of(now));
            if n > 0 {
                tracing::info!(
                    buckets = n,
                    "statistics retention evicted old hours from RAM"
                );
            }
        }
    }

    /// Writes the RAM data to the database in one transaction. Returns `None` in RAM-only
    /// mode and when there is nothing to write (no disk write then). On an error, the data
    /// goes back to RAM.
    pub fn flush(&self, now: i64) -> Result<Option<FlushReport>, StoreError> {
        self.flush_with_timeout(now, FLUSH_LOCK_TIMEOUT)
    }

    pub(crate) fn flush_with_timeout(
        &self,
        now: i64,
        timeout: Duration,
    ) -> Result<Option<FlushReport>, StoreError> {
        let Some(mut db) = self.lock_db(timeout)? else {
            return Ok(None);
        };
        let (snap, identities, was_dirty) = {
            let mut st = self.lock_state()?;
            let was_dirty = st.identities_dirty;
            if st.agg.is_empty() && !was_dirty && !db.retention_due(now) {
                return Ok(None);
            }
            st.identities_dirty = false;
            let snap = st.agg.take();
            // All identities when one changed. Else the identities of the addresses in the
            // snapshot: a new `clients` row then gets the MAC and the name even when the
            // identity came before the first flush of the address.
            let identities: HashMap<IpAddr, Identity> = if was_dirty {
                st.identities.clone()
            } else {
                snap.hours
                    .values()
                    .flat_map(|b| b.pairs.keys())
                    .filter_map(|ip| st.identities.get(ip).map(|i| (*ip, i.clone())))
                    .collect()
            };
            (snap, identities, was_dirty)
        };
        let started = Instant::now();
        match db.flush(&snap, &identities, now, self.inner.retention_days) {
            Ok(report) => {
                let c = &self.inner.counters;
                c.flushes.fetch_add(1, Ordering::Relaxed);
                let us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                c.last_flush_us.store(us, Ordering::Relaxed);
                Ok(Some(report))
            }
            Err(e) => {
                self.inner
                    .counters
                    .flush_failures
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(error = %e, "statistics flush failed; the data stays in RAM");
                if let Ok(mut st) = self.lock_state() {
                    st.agg.restore(snap);
                    if was_dirty {
                        st.identities_dirty = true;
                    }
                } else {
                    self.inner
                        .counters
                        .lost_events
                        .fetch_add(snap.total_events(), Ordering::Relaxed);
                    tracing::error!("cannot put the statistics back into RAM; data lost");
                }
                Err(e)
            }
        }
    }

    /// Records what other parts know about a client address. The next flush writes it.
    pub fn set_client_identity(&self, ip: IpAddr, identity: Identity) -> Result<(), StoreError> {
        let mut st = self.lock_state()?;
        if st.identities.get(&ip) == Some(&identity) {
            return Ok(());
        }
        if st.identities.len() >= MAX_IDENTITIES
            && !st.identities.contains_key(&ip)
            && let Some(old) = st.identities.keys().next().copied()
        {
            st.identities.remove(&old);
        }
        st.identities.insert(ip, identity);
        st.identities_dirty = true;
        Ok(())
    }

    /// The health counters.
    pub fn counters(&self) -> StoreCounters {
        let c = &self.inner.counters;
        let mut out = StoreCounters {
            dropped_events: self.inner.dropped.load(Ordering::Relaxed),
            lost_events: c.lost_events.load(Ordering::Relaxed),
            flushes: c.flushes.load(Ordering::Relaxed),
            flush_failures: c.flush_failures.load(Ordering::Relaxed),
            last_flush_us: c.last_flush_us.load(Ordering::Relaxed),
            ..StoreCounters::default()
        };
        if let Ok(st) = self.lock_state() {
            out.ram_keys = st.agg.keys();
            out.max_keys = st.agg.max_keys();
            out.evicted_buckets = st.agg.evicted_buckets();
            out.evicted_events = st.agg.evicted_events();
            out.recent_len = st.recent.len();
        }
        if let Ok(Some(db)) = self.lock_db(DB_LOCK_TIMEOUT) {
            out.db_writes = Some(db.writes());
        }
        out
    }

    /// The number of committed write transactions and the number of rows that SQLite
    /// changed, or `None` in RAM-only mode (for tests).
    pub fn db_write_counters(&self) -> Result<Option<(u64, u64)>, StoreError> {
        Ok(self
            .lock_db(DB_LOCK_TIMEOUT)?
            .map(|db| (db.writes(), db.total_changes())))
    }

    /// Runs `f` with the database (for tests and the size report). `None` in RAM-only mode.
    pub fn with_db<R>(&self, f: impl FnOnce(&Db) -> R) -> Result<Option<R>, StoreError> {
        Ok(self.lock_db(DB_LOCK_TIMEOUT)?.map(|db| f(&db)))
    }

    // -----------------------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------------------

    fn parts(&self, need: &Need) -> Result<Parts, StoreError> {
        let db = self.lock_db(DB_LOCK_TIMEOUT)?;
        let mut p = Parts::default();
        let mut metas = Vec::new();
        if let Some(db) = db.as_deref() {
            if let Some(f) = &need.pairs {
                p.pairs = db.pairs(f)?;
            }
            if let Some(f) = &need.hours {
                p.hours = db.hour_counts(f)?;
            }
            if let Some((a, b)) = need.types {
                p.types = db.types(a, b)?;
            }
            if let Some((a, b)) = need.upstreams {
                p.upstreams = db.upstreams(a, b)?;
            }
            if let Some((a, b)) = need.reasons {
                p.reasons = db.reasons(a, b)?;
            }
            if let Some((a, b)) = need.timeline {
                p.timeline = db.timeline(a, b)?;
            }
            if let Some(f) = &need.pair_timeline {
                p.timeline = db.pair_timeline(f)?;
            }
            if need.clients {
                metas = db.clients()?;
            }
            if let Some(name) = &need.first_seen_of {
                p.first_seen = db.domain_first_seen(name)?;
            }
        }
        // The database lock is still held here, so no flush runs between the two reads.
        let st = self.lock_state()?;
        if let Some(f) = &need.pairs {
            merge_hash(&mut p.pairs, st.agg.pairs(f));
        }
        if let Some(f) = &need.hours {
            merge_btree(&mut p.hours, st.agg.hour_counts(f));
        }
        if let Some((a, b)) = need.types {
            merge_btree(&mut p.types, st.agg.types(a, b));
        }
        if let Some((a, b)) = need.upstreams {
            merge_btree(&mut p.upstreams, st.agg.upstreams(a, b));
        }
        if let Some((a, b)) = need.reasons {
            merge_btree(&mut p.reasons, st.agg.reasons(a, b));
        }
        if let Some((a, b)) = need.timeline {
            merge_btree(&mut p.timeline, st.agg.timeline(a, b));
        }
        if let Some(f) = &need.pair_timeline {
            merge_btree(&mut p.timeline, st.agg.pair_timeline(f));
        }
        if let Some(name) = &need.first_seen_of {
            let all = Filter {
                name: Some(NameFilter::Exact(name.clone())),
                ..Filter::hours(i64::MIN, i64::MAX)
            };
            let ram = st.agg.pairs(&all).values().map(|t| t.first_seen).min();
            p.first_seen = match (p.first_seen, ram) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        if need.clients {
            for (ip, (first, last)) in st.agg.client_seen() {
                metas.push(ClientMeta {
                    ip,
                    mac: None,
                    name: None,
                    first_seen: first,
                    last_seen: last,
                });
            }
            for m in &mut metas {
                if let Some(id) = st.identities.get(&m.ip) {
                    if id.mac.is_some() {
                        m.mac.clone_from(&id.mac);
                    }
                    if id.name.is_some() {
                        m.name.clone_from(&id.name);
                    }
                }
            }
            p.clients = Clients::new(metas);
        }
        drop(st);
        drop(db);
        Ok(p)
    }

    /// All known clients (database and RAM).
    pub fn clients_index(&self) -> Result<Clients, StoreError> {
        Ok(self
            .parts(&Need {
                clients: true,
                ..Need::default()
            })?
            .clients)
    }

    /// The addresses of a client key.
    fn ips_of(&self, key: &str) -> Result<BTreeSet<IpAddr>, StoreError> {
        Ok(self.clients_index()?.ips_of(key))
    }

    fn filter_for(
        &self,
        spec: &RangeSpec,
        client: Option<&str>,
        name: Option<NameFilter>,
    ) -> Result<Filter, StoreError> {
        let mut f = spec.filter();
        if let Some(key) = client {
            f.clients = Some(self.ips_of(key)?);
        }
        f.name = name;
        Ok(f)
    }

    /// `GET /stats/summary`.
    pub fn summary(&self, range: Range, now: i64) -> Result<Summary, StoreError> {
        let spec = RangeSpec::new(range, now);
        let p = self.parts(&Need {
            pairs: Some(spec.filter()),
            clients: true,
            ..Need::default()
        })?;
        Ok(query::summary(&p.pairs, &p.clients))
    }

    /// `GET /stats/timeline`. The 24 h range has 144 buckets of 10 minutes, also with a
    /// client or name filter (from the 10-minute pair buckets, docs/STATS.md section 2).
    pub fn timeline(
        &self,
        range: Range,
        now: i64,
        client: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Timeline, StoreError> {
        if range == Range::Day && client.is_none() && domain.is_none() {
            let spec = RangeSpec::new(range, now);
            let p = self.parts(&Need {
                timeline: Some(spec.ten_minutes()),
                ..Need::default()
            })?;
            return Ok(query::timeline(&spec, &p.timeline, TEN_MINUTES));
        }
        if range == Range::Day {
            let spec = RangeSpec::new(range, now);
            let mut f = self.filter_for(
                &spec,
                client,
                domain.map(|d| NameFilter::Exact(d.to_owned())),
            )?;
            let (from, to) = spec.ten_minutes();
            f.from_hour = from;
            f.to_hour = to;
            let p = self.parts(&Need {
                pair_timeline: Some(f),
                ..Need::default()
            })?;
            return Ok(query::timeline(&spec, &p.timeline, TEN_MINUTES));
        }
        let spec = RangeSpec::new(range, now);
        let f = self.filter_for(
            &spec,
            client,
            domain.map(|d| NameFilter::Exact(d.to_owned())),
        )?;
        let p = self.parts(&Need {
            hours: Some(f),
            ..Need::default()
        })?;
        Ok(query::timeline(&spec, &p.hours, HOUR_SECONDS))
    }

    /// `GET /stats/hours`.
    pub fn hours(
        &self,
        range: Range,
        now: i64,
        filter: &HoursFilter,
        utc_offset_minutes: i32,
    ) -> Result<Hours, StoreError> {
        let spec = RangeSpec::new(range, now);
        let name = match (&filter.domain, &filter.base) {
            (Some(d), _) => Some(NameFilter::Exact(d.clone())),
            (None, Some(b)) => Some(NameFilter::Base(b.clone())),
            (None, None) => None,
        };
        let f = self.filter_for(&spec, filter.client.as_deref(), name)?;
        let p = self.parts(&Need {
            hours: Some(f),
            ..Need::default()
        })?;
        Ok(query::hours(&p.hours, utc_offset_minutes))
    }

    /// `GET /stats/top/domains` (`blocked = false`) and `GET /stats/top/blocked`.
    pub fn top_domains(
        &self,
        range: Range,
        now: i64,
        client: Option<&str>,
        limit: usize,
        blocked: bool,
    ) -> Result<Vec<TopDomain>, StoreError> {
        let f = self.filter_for(&RangeSpec::new(range, now), client, None)?;
        let p = self.parts(&Need {
            pairs: Some(f),
            ..Need::default()
        })?;
        Ok(query::top_domains(&p.pairs, limit, blocked))
    }

    /// `GET /stats/top/clients`.
    pub fn top_clients(
        &self,
        range: Range,
        now: i64,
        limit: usize,
    ) -> Result<Vec<TopClient>, StoreError> {
        let spec = RangeSpec::new(range, now);
        let p = self.parts(&Need {
            pairs: Some(spec.filter()),
            clients: true,
            ..Need::default()
        })?;
        Ok(query::top_clients(&p.pairs, &p.clients, limit))
    }

    /// `GET /stats/query-types`.
    pub fn query_types(&self, range: Range, now: i64) -> Result<Vec<TypeRow>, StoreError> {
        let p = self.parts(&Need {
            types: Some(RangeSpec::new(range, now).hours()),
            ..Need::default()
        })?;
        Ok(query::query_types(&p.types))
    }

    /// `GET /stats/upstreams`.
    pub fn upstreams(&self, range: Range, now: i64) -> Result<Vec<UpstreamRow>, StoreError> {
        let spec = RangeSpec::new(range, now);
        let p = self.parts(&Need {
            upstreams: Some(spec.hours()),
            hours: Some(spec.filter()),
            ..Need::default()
        })?;
        let mut totals = Counts::default();
        for c in p.hours.values() {
            totals.add(c);
        }
        Ok(query::upstream_share(&p.upstreams, &totals))
    }

    /// The top reasons of blocked queries (top blocking lists and rules).
    pub fn top_reasons(
        &self,
        range: Range,
        now: i64,
        limit: usize,
    ) -> Result<Vec<ReasonRow>, StoreError> {
        let p = self.parts(&Need {
            reasons: Some(RangeSpec::new(range, now).hours()),
            ..Need::default()
        })?;
        Ok(query::top_reasons(&p.reasons, limit))
    }

    /// `GET /stats/clients`.
    pub fn clients(
        &self,
        range: Range,
        now: i64,
        params: &ClientListParams,
    ) -> Result<Page<ClientRow>, StoreError> {
        let spec = RangeSpec::new(range, now);
        let p = self.parts(&Need {
            pairs: Some(spec.filter()),
            clients: true,
            ..Need::default()
        })?;
        Ok(query::client_list(&p.pairs, &p.clients, params)?)
    }

    /// `GET /stats/clients/{key}`.
    pub fn client(
        &self,
        key: &str,
        range: Range,
        now: i64,
        utc_offset_minutes: i32,
    ) -> Result<ClientDetail, StoreError> {
        let f = self.filter_for(&RangeSpec::new(range, now), Some(key), None)?;
        let p = self.parts(&Need {
            pairs: Some(f.clone()),
            hours: Some(f),
            clients: true,
            ..Need::default()
        })?;
        Ok(ClientDetail {
            row: query::client_detail(&p.pairs, &p.clients, key),
            hours: query::hours(&p.hours, utc_offset_minutes),
        })
    }

    /// `GET /stats/clients/{key}/domains`.
    pub fn client_domains(
        &self,
        key: &str,
        range: Range,
        now: i64,
        params: &GroupParams,
    ) -> Result<Page<DomainGroup>, StoreError> {
        let f = self.filter_for(&RangeSpec::new(range, now), Some(key), None)?;
        let p = self.parts(&Need {
            pairs: Some(f),
            ..Need::default()
        })?;
        Ok(query::domain_groups(&p.pairs, params)?)
    }

    /// `GET /stats/domains`.
    pub fn domains(
        &self,
        range: Range,
        now: i64,
        params: &DomainSearchParams,
    ) -> Result<Page<DomainRow>, StoreError> {
        let spec = RangeSpec::new(range, now);
        let p = self.parts(&Need {
            pairs: Some(spec.filter()),
            clients: true,
            ..Need::default()
        })?;
        Ok(query::domain_search(&p.pairs, &p.clients, params)?)
    }

    /// `GET /stats/domains/{name}`.
    pub fn domain(
        &self,
        name: &str,
        range: Range,
        now: i64,
        utc_offset_minutes: i32,
    ) -> Result<DomainDetailHours, StoreError> {
        let f = self.filter_for(
            &RangeSpec::new(range, now),
            None,
            Some(NameFilter::Exact(name.to_owned())),
        )?;
        let p = self.parts(&Need {
            pairs: Some(f.clone()),
            hours: Some(f),
            clients: true,
            first_seen_of: Some(name.to_owned()),
            ..Need::default()
        })?;
        Ok(DomainDetailHours {
            detail: query::domain_detail(&p.pairs, &p.clients, name, p.first_seen),
            hours: query::hours(&p.hours, utc_offset_minutes),
        })
    }

    /// `GET /clients/seen`: the clients that sent queries, the latest first.
    pub fn seen_clients(
        &self,
        now: i64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<SeenClient>, StoreError> {
        let spec = RangeSpec::new(Range::Month, now);
        let p = self.parts(&Need {
            pairs: Some(spec.filter()),
            clients: true,
            ..Need::default()
        })?;
        let mut queries: HashMap<IpAddr, u64> = HashMap::new();
        for (k, t) in &p.pairs {
            let e = queries.entry(k.client).or_default();
            *e = e.saturating_add(t.counts.total);
        }
        let items: Vec<(SortKey, SeenClient)> = p
            .clients
            .all()
            .map(|m| {
                let key = SortKey {
                    num: m.last_seen.saturating_neg(),
                    text: String::new(),
                    tie: m.ip.to_string(),
                };
                let seen = SeenClient {
                    queries: queries.get(&m.ip).copied().unwrap_or(0),
                    meta: m.clone(),
                };
                (key, seen)
            })
            .collect();
        Ok(paginate(items, cursor, limit.min(MAX_LIMIT))?)
    }

    /// `GET /queries/recent`: newest first, from RAM only.
    pub fn recent(&self, params: &RecentParams) -> Result<Vec<StatsEvent>, StoreError> {
        let clients = match &params.client {
            Some(key) => Some(self.ips_of(key)?),
            None => None,
        };
        let st = self.lock_state()?;
        Ok(st.recent.query(&RecentFilter {
            limit: params.limit,
            clients,
            status: params.status,
            q: params.q.clone(),
        }))
    }

    // -----------------------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------------------

    /// Adds an audit line. With a database, the line is written at once (see
    /// [`crate::audit`]). Returns the id.
    pub fn append_audit(&self, line: &NewAudit) -> Result<i64, StoreError> {
        match self.lock_db(DB_LOCK_TIMEOUT)? {
            Some(mut db) => db.append_audit(line),
            None => Ok(self.lock_state()?.ram_audit.append(line)),
        }
    }

    /// `GET /audit`: newest first, one page.
    pub fn audit(&self, params: &AuditParams) -> Result<Page<AuditEntry>, StoreError> {
        let before = cursor_id(params.cursor.as_deref())?;
        let limit = audit_limit(params.limit);
        let prefix = params.action_prefix.as_deref();
        let lines = match self.lock_db(DB_LOCK_TIMEOUT)? {
            Some(db) => db.audit(before, prefix, limit + 1)?,
            None => self
                .lock_state()?
                .ram_audit
                .query(before, prefix, limit + 1),
        };
        Ok(page_of(lines, limit))
    }
}

impl Db {
    /// True when the next flush runs the retention.
    pub(crate) fn retention_due(&self, now: i64) -> bool {
        retention_due(self.last_retention_day(), now)
    }
}

/// Makes the data directory (and its missing parents). On Unix a new directory gets mode
/// 0700, so other local users cannot list or read the statistics files.
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// Opens the store at a path with default settings (for tools and tests).
pub fn open_at(path: &Path) -> Result<Stats, StoreError> {
    let settings = StatsSettings {
        db_path: Some(path.to_path_buf()),
        ..StatsSettings::ram_only()
    };
    Stats::open(&settings, Arc::new(AtomicU64::new(0)))
}
