//! The RAM aggregate of query events, with a bound on the number of keys.
//!
//! The aggregate holds one [`HourBucket`] for each UTC hour that has events, and a small
//! timeline of 10-minute buckets. The store takes a [`Snapshot`] at each flush and writes it
//! to the database; after that the RAM is empty again.
//!
//! The bound: the aggregate counts its keys (one key for each (client, name) pair, query
//! type, upstream and reason in each hour). The store flushes early when
//! [`Aggregator::near_full`] is true. When an event needs a new key and the bound is reached,
//! the aggregate evicts the oldest hour bucket and counts the eviction. In RAM-only mode this
//! is the normal way to stay in the bound.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use super::query::{Filter, HourMap, PairMap, ReasonMap, TimelineMap, TypeMap, UpstreamMap, span};
use super::{Counts, PairKey, StatsEvent, Tally, UpstreamTally, hour_of, ten_minutes_of};

/// The default bound on the number of keys in RAM between two flushes.
pub const DEFAULT_MAX_KEYS: usize = 100_000;
/// The smallest key bound. A smaller value is changed to this value.
pub const MIN_MAX_KEYS: usize = 64;
/// The largest number of 10-minute buckets in RAM (a little more than 24 hours).
pub const MAX_TIMELINE_BUCKETS: usize = 160;

/// All counters of one UTC hour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HourBucket {
    /// Client address, then full name, then the tally.
    pub pairs: HashMap<IpAddr, HashMap<Box<str>, Tally>>,
    /// Query type, then the count.
    pub types: HashMap<u16, u64>,
    /// Upstream, then the answers.
    pub upstreams: HashMap<Box<str>, UpstreamTally>,
    /// Reason (for example `list:3`), then the count.
    pub reasons: HashMap<Box<str>, u64>,
}

impl HourBucket {
    /// The number of keys in the bucket.
    pub fn keys(&self) -> usize {
        let pairs: usize = self.pairs.values().map(HashMap::len).sum();
        pairs + self.types.len() + self.upstreams.len() + self.reasons.len()
    }

    /// All queries in the bucket.
    pub fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for names in self.pairs.values() {
            for t in names.values() {
                c.add(&t.counts);
            }
        }
        c
    }

    /// Adds `other` to `self`.
    pub fn merge(&mut self, other: HourBucket) {
        for (client, names) in other.pairs {
            let mine = self.pairs.entry(client).or_default();
            for (name, t) in names {
                mine.entry(name).and_modify(|m| m.add(&t)).or_insert(t);
            }
        }
        for (k, v) in other.types {
            let e = self.types.entry(k).or_default();
            *e = e.saturating_add(v);
        }
        for (k, v) in other.upstreams {
            self.upstreams.entry(k).or_default().add(&v);
        }
        for (k, v) in other.reasons {
            let e = self.reasons.entry(k).or_default();
            *e = e.saturating_add(v);
        }
    }

    /// The number of new keys that `ev` adds to this bucket.
    fn new_keys(&self, ev: &StatsEvent) -> usize {
        let pair_new = self
            .pairs
            .get(&ev.client)
            .is_none_or(|names| !names.contains_key(ev.name.as_str()));
        let type_new = !self.types.contains_key(&ev.qtype);
        let up_new = ev
            .upstream
            .as_deref()
            .is_some_and(|u| !self.upstreams.contains_key(u));
        let reason_new = ev
            .reason
            .as_deref()
            .is_some_and(|r| !self.reasons.contains_key(r));
        usize::from(pair_new)
            + usize::from(type_new)
            + usize::from(up_new)
            + usize::from(reason_new)
    }

    /// Counts `ev`. Returns the number of new keys.
    fn apply(&mut self, ev: &StatsEvent) -> usize {
        let mut added = 0;
        let names = self.pairs.entry(ev.client).or_default();
        if let Some(t) = names.get_mut(ev.name.as_str()) {
            t.add(&Tally::one(ev.at, ev.status));
        } else {
            names.insert(ev.name.as_str().into(), Tally::one(ev.at, ev.status));
            added += 1;
        }
        let e = self.types.entry(ev.qtype).or_insert_with(|| {
            added += 1;
            0
        });
        *e = e.saturating_add(1);
        if let Some(up) = ev.upstream.as_deref() {
            let tally = UpstreamTally {
                count: 1,
                sum_us: ev.duration_us,
            };
            if let Some(t) = self.upstreams.get_mut(up) {
                t.add(&tally);
            } else {
                self.upstreams.insert(up.into(), tally);
                added += 1;
            }
        }
        if let Some(reason) = ev.reason.as_deref() {
            if let Some(c) = self.reasons.get_mut(reason) {
                *c = c.saturating_add(1);
            } else {
                self.reasons.insert(reason.into(), 1);
                added += 1;
            }
        }
        added
    }
}

/// The data that the store takes from RAM at a flush.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Hour buckets by UTC hour.
    pub hours: BTreeMap<i64, HourBucket>,
    /// 10-minute buckets by bucket number (Unix seconds / 600).
    pub timeline: BTreeMap<i64, Counts>,
}

impl Snapshot {
    /// True when the snapshot has no data.
    pub fn is_empty(&self) -> bool {
        self.hours.is_empty() && self.timeline.is_empty()
    }

    /// The number of events in the hour buckets.
    pub fn total_events(&self) -> u64 {
        self.hours
            .values()
            .map(|b| b.counts().total)
            .fold(0, u64::saturating_add)
    }
}

/// The RAM aggregate. See the module documentation.
#[derive(Debug, Clone)]
pub struct Aggregator {
    hours: BTreeMap<i64, HourBucket>,
    timeline: BTreeMap<i64, Counts>,
    keys: usize,
    max_keys: usize,
    evicted_buckets: u64,
    evicted_events: u64,
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_KEYS)
    }
}

impl Aggregator {
    /// An empty aggregate with a bound of `max_keys` keys (at least [`MIN_MAX_KEYS`]).
    pub fn new(max_keys: usize) -> Self {
        Self {
            hours: BTreeMap::new(),
            timeline: BTreeMap::new(),
            keys: 0,
            max_keys: max_keys.max(MIN_MAX_KEYS),
            evicted_buckets: 0,
            evicted_events: 0,
        }
    }

    /// The number of keys now.
    pub fn keys(&self) -> usize {
        self.keys
    }

    /// The key bound.
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }

    /// True when the keys use 3/4 of the bound or more. Then the store flushes early.
    pub fn near_full(&self) -> bool {
        self.keys >= self.max_keys / 4 * 3
    }

    /// True when there is no data.
    pub fn is_empty(&self) -> bool {
        self.hours.is_empty() && self.timeline.is_empty()
    }

    /// The number of hour buckets that were evicted.
    pub fn evicted_buckets(&self) -> u64 {
        self.evicted_buckets
    }

    /// The number of events in the evicted hour buckets (data that is lost).
    pub fn evicted_events(&self) -> u64 {
        self.evicted_events
    }

    /// The number of events in RAM.
    pub fn total_events(&self) -> u64 {
        self.hours
            .values()
            .map(|b| b.counts().total)
            .fold(0, u64::saturating_add)
    }

    /// The hour buckets (read only).
    pub fn hours(&self) -> &BTreeMap<i64, HourBucket> {
        &self.hours
    }

    /// Counts one event.
    pub fn apply(&mut self, ev: &StatsEvent) {
        let hour = hour_of(ev.at);
        // Make room. Each step evicts one bucket or stops, so the loop has at most
        // `hours.len() + 1` steps.
        for _ in 0..=self.hours.len() {
            let new = self.hours.get(&hour).map_or(
                // A new bucket: all keys of the event are new.
                4,
                |b| b.new_keys(ev),
            );
            if self.keys.saturating_add(new) <= self.max_keys || !self.evict_oldest() {
                break;
            }
        }
        let added = self.hours.entry(hour).or_default().apply(ev);
        self.keys = self.keys.saturating_add(added);
        self.timeline
            .entry(ten_minutes_of(ev.at))
            .or_default()
            .add_status(ev.status);
        while self.timeline.len() > MAX_TIMELINE_BUCKETS {
            self.timeline.pop_first();
        }
    }

    /// Takes all data out of RAM for a flush.
    pub fn take(&mut self) -> Snapshot {
        self.keys = 0;
        Snapshot {
            hours: std::mem::take(&mut self.hours),
            timeline: std::mem::take(&mut self.timeline),
        }
    }

    /// Puts a snapshot back after a failed flush. The key bound still holds: the oldest
    /// buckets are evicted when needed.
    pub fn restore(&mut self, snap: Snapshot) {
        for (hour, bucket) in snap.hours {
            match self.hours.get_mut(&hour) {
                Some(mine) => mine.merge(bucket),
                None => {
                    self.hours.insert(hour, bucket);
                }
            }
        }
        for (k, c) in snap.timeline {
            self.timeline.entry(k).or_default().add(&c);
        }
        while self.timeline.len() > MAX_TIMELINE_BUCKETS {
            self.timeline.pop_first();
        }
        self.keys = self.hours.values().map(HourBucket::keys).sum();
        for _ in 0..=self.hours.len() {
            if self.keys <= self.max_keys || !self.evict_oldest() {
                break;
            }
        }
    }

    /// Evicts all hour buckets before `first_hour` (the retention in RAM-only mode), and the
    /// 10-minute buckets before it. Returns the number of evicted hour buckets.
    pub fn evict_before(&mut self, first_hour: i64) -> u64 {
        let kept = self.hours.split_off(&first_hour);
        let old = std::mem::replace(&mut self.hours, kept);
        let mut n = 0u64;
        for bucket in old.into_values() {
            self.count_eviction(&bucket);
            n += 1;
        }
        let kept = self.timeline.split_off(&first_hour.saturating_mul(6));
        self.timeline = kept;
        n
    }

    /// Evicts the oldest hour bucket. Returns false when there is none.
    fn evict_oldest(&mut self) -> bool {
        match self.hours.pop_first() {
            Some((_, bucket)) => {
                self.count_eviction(&bucket);
                true
            }
            None => false,
        }
    }

    fn count_eviction(&mut self, bucket: &HourBucket) {
        self.keys = self.keys.saturating_sub(bucket.keys());
        self.evicted_buckets = self.evicted_buckets.saturating_add(1);
        self.evicted_events = self.evicted_events.saturating_add(bucket.counts().total);
    }

    /// The pairs in the filter, added up over the hours.
    pub fn pairs(&self, f: &Filter) -> PairMap {
        pairs_of(&self.hours, f)
    }

    /// Counts by hour in the filter.
    pub fn hour_counts(&self, f: &Filter) -> HourMap {
        let mut out = HourMap::new();
        for (&hour, b) in self.hours.range(f.span()) {
            let mut c = Counts::default();
            for (client, names) in &b.pairs {
                if !f.matches_client(*client) {
                    continue;
                }
                for (name, t) in names {
                    if f.matches_name(name) {
                        c.add(&t.counts);
                    }
                }
            }
            if c.total > 0 {
                out.entry(hour).or_default().add(&c);
            }
        }
        out
    }

    /// Query types in the hours `from..=to`.
    pub fn types(&self, from: i64, to: i64) -> TypeMap {
        let mut out = TypeMap::new();
        for b in self.hours.range(span(from, to)).map(|(_, b)| b) {
            for (&k, &v) in &b.types {
                let e = out.entry(k).or_default();
                *e = e.saturating_add(v);
            }
        }
        out
    }

    /// Upstream answers in the hours `from..=to`.
    pub fn upstreams(&self, from: i64, to: i64) -> UpstreamMap {
        let mut out = UpstreamMap::new();
        for b in self.hours.range(span(from, to)).map(|(_, b)| b) {
            for (k, v) in &b.upstreams {
                out.entry(k.to_string()).or_default().add(v);
            }
        }
        out
    }

    /// Reasons in the hours `from..=to`.
    pub fn reasons(&self, from: i64, to: i64) -> ReasonMap {
        let mut out = ReasonMap::new();
        for b in self.hours.range(span(from, to)).map(|(_, b)| b) {
            for (k, &v) in &b.reasons {
                let e = out.entry(k.to_string()).or_default();
                *e = e.saturating_add(v);
            }
        }
        out
    }

    /// 10-minute buckets `from..=to`.
    pub fn timeline(&self, from: i64, to: i64) -> TimelineMap {
        self.timeline
            .range(span(from, to))
            .map(|(&k, &v)| (k, v))
            .collect()
    }

    /// The first and the last query of each client in RAM (all hours).
    pub fn client_seen(&self) -> HashMap<IpAddr, (i64, i64)> {
        let mut out: HashMap<IpAddr, (i64, i64)> = HashMap::new();
        for b in self.hours.values() {
            for (client, names) in &b.pairs {
                for t in names.values() {
                    out.entry(*client)
                        .and_modify(|(f, l)| {
                            *f = (*f).min(t.first_seen);
                            *l = (*l).max(t.last_seen);
                        })
                        .or_insert((t.first_seen, t.last_seen));
                }
            }
        }
        out
    }
}

/// The pairs of `hours` in the filter, added up over the hours.
pub fn pairs_of(hours: &BTreeMap<i64, HourBucket>, f: &Filter) -> PairMap {
    let mut out = PairMap::new();
    for b in hours.range(f.span()).map(|(_, b)| b) {
        for (client, names) in &b.pairs {
            if !f.matches_client(*client) {
                continue;
            }
            for (name, t) in names {
                if !f.matches_name(name) {
                    continue;
                }
                let key = PairKey {
                    client: *client,
                    name: name.clone(),
                };
                out.entry(key).and_modify(|m| m.add(t)).or_insert(*t);
            }
        }
    }
    out
}
