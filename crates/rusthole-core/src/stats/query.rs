//! Pure query functions for the admin API (docs/API.md section 5).
//!
//! A query has two steps:
//!
//! 1. The store reads "parts" for a [`Filter`]: a [`PairMap`] (counts for each client and
//!    full name, added up over the hours), an [`HourMap`], a [`TypeMap`] and so on. It reads
//!    them from the database and from the RAM aggregate (data that is not flushed yet), and
//!    merges the two with [`merge_hash`] and [`merge_btree`].
//! 2. A function of this module makes the answer from the merged parts: totals, top lists,
//!    groups by registrable domain, hour histograms, pages.
//!
//! The functions return plain structs. Part P5 changes them to the JSON shapes of
//! docs/API.md.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::ops::Bound;

use super::base::registrable;
use super::page::{CursorError, Page, SortKey, paginate};
use super::policy::{effective_utc_offset, hour_of_day};
use super::{
    Counts, HOUR_SECONDS, PairKey, TEN_MINUTES, Tally, UpstreamTally, hour_of, qtype_name,
};

/// Counts for each (client, full name), added up over the hours of a filter.
pub type PairMap = HashMap<PairKey, Tally>;
/// Counts by UTC hour bucket.
pub type HourMap = BTreeMap<i64, Counts>;
/// Counts by query type.
pub type TypeMap = BTreeMap<u16, u64>;
/// Answers by upstream.
pub type UpstreamMap = BTreeMap<String, UpstreamTally>;
/// Counts by reason.
pub type ReasonMap = BTreeMap<String, u64>;
/// Counts by 10-minute bucket.
pub type TimelineMap = BTreeMap<i64, Counts>;

/// The largest `limit` of the top lists.
pub const MAX_TOP_LIMIT: usize = 100;
/// The largest number of clients in [`DomainDetail::clients`].
pub const MAX_DOMAIN_CLIENTS: usize = 100;
/// The largest `names_limit` of [`GroupParams`].
pub const MAX_NAMES_LIMIT: usize = 200;

// ---------------------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------------------

/// A value that can be added to a value of the same type.
pub trait AddTo {
    /// Adds `other` to `self`.
    fn add_to(&mut self, other: &Self);
}

impl AddTo for Counts {
    fn add_to(&mut self, other: &Self) {
        self.add(other);
    }
}

impl AddTo for Tally {
    fn add_to(&mut self, other: &Self) {
        self.add(other);
    }
}

impl AddTo for UpstreamTally {
    fn add_to(&mut self, other: &Self) {
        self.add(other);
    }
}

impl AddTo for u64 {
    fn add_to(&mut self, other: &Self) {
        *self = self.saturating_add(*other);
    }
}

/// Adds all values of `from` into `into`.
pub fn merge_hash<K: Eq + Hash, V: AddTo, S: BuildHasher>(
    into: &mut HashMap<K, V, S>,
    from: HashMap<K, V, S>,
) {
    for (k, v) in from {
        match into.get_mut(&k) {
            Some(mine) => mine.add_to(&v),
            None => {
                into.insert(k, v);
            }
        }
    }
}

/// Adds all values of `from` into `into`.
pub fn merge_btree<K: Ord, V: AddTo>(into: &mut BTreeMap<K, V>, from: BTreeMap<K, V>) {
    for (k, v) in from {
        match into.get_mut(&k) {
            Some(mine) => mine.add_to(&v),
            None => {
                into.insert(k, v);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Filter and range
// ---------------------------------------------------------------------------------------

/// A filter on full names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameFilter {
    /// One full name.
    Exact(String),
    /// All names with this registrable domain.
    Base(String),
}

impl NameFilter {
    /// True when `name` is in the filter.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            NameFilter::Exact(n) => name == n,
            NameFilter::Base(b) => registrable(name) == b,
        }
    }
}

/// What a store reads: hours, clients and names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// The first hour bucket.
    pub from_hour: i64,
    /// The last hour bucket (included). A value below `from_hour` gives no data.
    pub to_hour: i64,
    /// Only these client addresses.
    pub clients: Option<BTreeSet<IpAddr>>,
    /// Only these names.
    pub name: Option<NameFilter>,
}

impl Filter {
    /// A filter on hours only.
    pub fn hours(from_hour: i64, to_hour: i64) -> Self {
        Self {
            from_hour,
            to_hour,
            clients: None,
            name: None,
        }
    }

    /// True when the client is in the filter.
    pub fn matches_client(&self, client: IpAddr) -> bool {
        self.clients.as_ref().is_none_or(|c| c.contains(&client))
    }

    /// True when the name is in the filter.
    pub fn matches_name(&self, name: &str) -> bool {
        self.name.as_ref().is_none_or(|n| n.matches(name))
    }

    /// The hour range as map bounds. See [`span`].
    pub fn span(&self) -> (Bound<i64>, Bound<i64>) {
        span(self.from_hour, self.to_hour)
    }
}

/// Map bounds for `from..=to`. When `to < from`, the bounds give an empty range (a
/// `BTreeMap` panics on a reversed range, so never pass one).
pub fn span(from: i64, to: i64) -> (Bound<i64>, Bound<i64>) {
    if from <= to {
        (Bound::Included(from), Bound::Included(to))
    } else {
        (Bound::Included(from), Bound::Excluded(from))
    }
}

/// The time range of a statistics request (docs/API.md section 1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// The last 24 hours, 10-minute buckets.
    Day,
    /// The last 7 days, 1-hour buckets.
    Week,
    /// The last 30 days, 4-hour buckets.
    Month,
}

impl Range {
    /// Parses `24h`, `7d` or `30d`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "24h" => Some(Range::Day),
            "7d" => Some(Range::Week),
            "30d" => Some(Range::Month),
            _ => None,
        }
    }

    /// The API name.
    pub fn as_str(self) -> &'static str {
        match self {
            Range::Day => "24h",
            Range::Week => "7d",
            Range::Month => "30d",
        }
    }

    /// Seconds in one timeline bucket.
    pub fn bucket_seconds(self) -> i64 {
        match self {
            Range::Day => TEN_MINUTES,
            Range::Week => HOUR_SECONDS,
            Range::Month => 4 * HOUR_SECONDS,
        }
    }

    /// The number of timeline buckets.
    pub fn buckets(self) -> usize {
        match self {
            Range::Day => 144,
            Range::Week => 168,
            Range::Month => 180,
        }
    }
}

/// A range aligned to its buckets at a given `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeSpec {
    /// The range.
    pub range: Range,
    /// The start of the first bucket, Unix seconds.
    pub from: i64,
    /// The end of the last bucket (the current, partial bucket), Unix seconds.
    pub to: i64,
    /// Seconds in one bucket.
    pub bucket_seconds: i64,
    /// The number of buckets.
    pub buckets: usize,
}

impl RangeSpec {
    /// The range for `now` (Unix seconds).
    pub fn new(range: Range, now: i64) -> Self {
        Self::with_buckets(range, now, range.bucket_seconds(), range.buckets())
    }

    /// The 24 h range with 1-hour buckets. A timeline with a client or name filter uses
    /// it, because the database keeps these counts by hour only.
    pub fn day_by_hour(now: i64) -> Self {
        Self::with_buckets(Range::Day, now, HOUR_SECONDS, 24)
    }

    fn with_buckets(range: Range, now: i64, bucket_seconds: i64, buckets: usize) -> Self {
        let n = i64::try_from(buckets).unwrap_or(1);
        let last = now.div_euclid(bucket_seconds);
        let first = last.saturating_sub(n.saturating_sub(1));
        Self {
            range,
            from: first.saturating_mul(bucket_seconds),
            to: last.saturating_add(1).saturating_mul(bucket_seconds),
            bucket_seconds,
            buckets,
        }
    }

    /// The hour buckets of the range: the hours that start in `from..to`. The first hour is
    /// the first full hour at or after `from`. The last hour is the hour that holds `to - 1`
    /// (the current, partial hour). The statistics other than the timeline use whole hours.
    ///
    /// The 24 h range thus gives exactly 24 distinct hours, so the hour-of-day histogram
    /// counts each hour of the day one time. The 7 d and 30 d ranges start on an hour, so
    /// the rounding does not change them.
    pub fn hours(&self) -> (i64, i64) {
        (
            hour_of(self.from.saturating_add(HOUR_SECONDS - 1)),
            hour_of(self.to.saturating_sub(1)),
        )
    }

    /// The 10-minute buckets of the range.
    pub fn ten_minutes(&self) -> (i64, i64) {
        (
            self.from.div_euclid(TEN_MINUTES),
            self.to.saturating_sub(1).div_euclid(TEN_MINUTES),
        )
    }

    /// A filter on the hours of the range.
    pub fn filter(&self) -> Filter {
        let (from, to) = self.hours();
        Filter::hours(from, to)
    }
}

// ---------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------

/// What the store knows about one client address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMeta {
    /// The address.
    pub ip: IpAddr,
    /// The MAC address (lower case, colon form), when known.
    pub mac: Option<String>,
    /// A name (from the config, conditional forwarding or local records), when known.
    pub name: Option<String>,
    /// The first query in the stored data, Unix seconds.
    pub first_seen: i64,
    /// The last query in the stored data, Unix seconds.
    pub last_seen: i64,
}

/// The key of a client (docs/API.md section 5.6): the MAC address when known, else the IP
/// address.
pub fn client_key(ip: IpAddr, mac: Option<&str>) -> String {
    match mac {
        Some(m) if !m.is_empty() => m.to_ascii_lowercase(),
        _ => ip.to_string(),
    }
}

/// All known clients, by address.
#[derive(Debug, Clone, Default)]
pub struct Clients {
    by_ip: HashMap<IpAddr, ClientMeta>,
}

impl Clients {
    /// Makes the index. When two items have the same address, the times are merged and the
    /// later item gives the MAC and the name.
    pub fn new(metas: impl IntoIterator<Item = ClientMeta>) -> Self {
        let mut by_ip: HashMap<IpAddr, ClientMeta> = HashMap::new();
        for m in metas {
            match by_ip.get_mut(&m.ip) {
                Some(old) => {
                    old.first_seen = old.first_seen.min(m.first_seen);
                    old.last_seen = old.last_seen.max(m.last_seen);
                    if m.mac.is_some() {
                        old.mac = m.mac;
                    }
                    if m.name.is_some() {
                        old.name = m.name;
                    }
                }
                None => {
                    by_ip.insert(m.ip, m);
                }
            }
        }
        Self { by_ip }
    }

    /// The metadata of an address.
    pub fn get(&self, ip: IpAddr) -> Option<&ClientMeta> {
        self.by_ip.get(&ip)
    }

    /// All metadata.
    pub fn all(&self) -> impl Iterator<Item = &ClientMeta> {
        self.by_ip.values()
    }

    /// The key of an address.
    pub fn key_of(&self, ip: IpAddr) -> String {
        client_key(ip, self.by_ip.get(&ip).and_then(|m| m.mac.as_deref()))
    }

    /// All addresses of a key. A key that is an IP address always includes this address.
    pub fn ips_of(&self, key: &str) -> BTreeSet<IpAddr> {
        let mut out: BTreeSet<IpAddr> = self
            .by_ip
            .values()
            .filter(|m| client_key(m.ip, m.mac.as_deref()) == key)
            .map(|m| m.ip)
            .collect();
        if let Ok(ip) = key.parse::<IpAddr>() {
            out.insert(ip);
        }
        out
    }

    /// The name of a key: the name of the address with the latest query.
    pub fn name_of(&self, key: &str) -> Option<String> {
        self.by_ip
            .values()
            .filter(|m| m.name.is_some() && client_key(m.ip, m.mac.as_deref()) == key)
            .max_by_key(|m| (m.last_seen, m.ip))
            .and_then(|m| m.name.clone())
    }

    /// The MAC of a key.
    pub fn mac_of(&self, key: &str) -> Option<String> {
        self.by_ip
            .values()
            .find(|m| m.mac.is_some() && client_key(m.ip, m.mac.as_deref()) == key)
            .and_then(|m| m.mac.clone())
    }

    /// The first and last query of a key in the stored data.
    pub fn seen_of(&self, key: &str) -> Option<(i64, i64)> {
        self.by_ip
            .values()
            .filter(|m| client_key(m.ip, m.mac.as_deref()) == key)
            .map(|m| (m.first_seen, m.last_seen))
            .reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)))
    }
}

// ---------------------------------------------------------------------------------------
// Totals and timeline
// ---------------------------------------------------------------------------------------

/// `part / whole` in percent, rounded to 2 decimals. 0 when `whole` is 0.
#[allow(clippy::cast_precision_loss)] // Counts far below 2^52: the loss does not matter.
pub fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 * 10_000.0 / whole as f64).round() / 100.0
}

fn signed(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// The answer of `GET /stats/summary`.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    /// The counts.
    pub counts: Counts,
    /// Blocked queries in percent of all queries.
    pub blocked_percent: f64,
    /// Distinct full names.
    pub unique_domains: u64,
    /// Distinct client keys.
    pub unique_clients: u64,
}

/// Totals over all pairs.
pub fn summary(pairs: &PairMap, clients: &Clients) -> Summary {
    let mut counts = Counts::default();
    let mut names: HashSet<&str> = HashSet::new();
    let mut keys: HashSet<String> = HashSet::new();
    let mut ips: HashSet<IpAddr> = HashSet::new();
    for (k, t) in pairs {
        counts.add(&t.counts);
        names.insert(&k.name);
        if ips.insert(k.client) {
            keys.insert(clients.key_of(k.client));
        }
    }
    Summary {
        counts,
        blocked_percent: percent(counts.blocked, counts.total),
        unique_domains: names.len() as u64,
        unique_clients: keys.len() as u64,
    }
}

/// Totals over all pairs, with no client index (each address is one client).
pub fn totals(pairs: &PairMap) -> Counts {
    let mut counts = Counts::default();
    for t in pairs.values() {
        counts.add(&t.counts);
    }
    counts
}

/// The answer of `GET /stats/timeline`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeline {
    /// The start of the first bucket, Unix seconds.
    pub from: i64,
    /// The end of the last bucket, Unix seconds.
    pub to: i64,
    /// Seconds in one bucket.
    pub bucket_seconds: i64,
    /// All queries in each bucket.
    pub queries: Vec<u64>,
    /// Blocked queries in each bucket.
    pub blocked: Vec<u64>,
    /// Cached queries in each bucket.
    pub cached: Vec<u64>,
    /// Forwarded queries in each bucket.
    pub forwarded: Vec<u64>,
}

/// A timeline from a map of source buckets with `source_seconds` seconds each (600 for
/// the 10-minute map, 3600 for the hour map). A source bucket goes to the timeline bucket
/// that holds its start.
pub fn timeline(spec: &RangeSpec, source: &BTreeMap<i64, Counts>, source_seconds: i64) -> Timeline {
    let n = spec.buckets;
    let mut t = Timeline {
        from: spec.from,
        to: spec.to,
        bucket_seconds: spec.bucket_seconds,
        queries: vec![0; n],
        blocked: vec![0; n],
        cached: vec![0; n],
        forwarded: vec![0; n],
    };
    if source_seconds <= 0 || spec.bucket_seconds <= 0 {
        return t;
    }
    let first = spec.from.div_euclid(source_seconds);
    let last = spec.to.saturating_sub(1).div_euclid(source_seconds);
    for (&k, c) in source.range(span(first, last)) {
        let start = k.saturating_mul(source_seconds);
        let Ok(i) = usize::try_from(start.saturating_sub(spec.from) / spec.bucket_seconds) else {
            continue;
        };
        if let (Some(q), Some(b), Some(ca), Some(f)) = (
            t.queries.get_mut(i),
            t.blocked.get_mut(i),
            t.cached.get_mut(i),
            t.forwarded.get_mut(i),
        ) {
            *q = q.saturating_add(c.total);
            *b = b.saturating_add(c.blocked);
            *ca = ca.saturating_add(c.cached);
            *f = f.saturating_add(c.forwarded);
        }
    }
    t
}

/// The answer of `GET /stats/hours`: an hour-of-day histogram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hours {
    /// The offset that the server really used (whole hours), in minutes.
    pub utc_offset_minutes: i32,
    /// All queries in each hour of the day.
    pub queries: [u64; 24],
    /// Blocked queries in each hour of the day.
    pub blocked: [u64; 24],
}

/// The hour-of-day histogram of an hour map, with the UTC offset rule of docs/API.md
/// section 1.4.
pub fn hours(map: &HourMap, utc_offset_minutes: i32) -> Hours {
    let offset = effective_utc_offset(utc_offset_minutes);
    let mut h = Hours {
        utc_offset_minutes: offset,
        queries: [0; 24],
        blocked: [0; 24],
    };
    for (&hour, c) in map {
        let i = hour_of_day(hour, offset);
        if let (Some(q), Some(b)) = (h.queries.get_mut(i), h.blocked.get_mut(i)) {
            *q = q.saturating_add(c.total);
            *b = b.saturating_add(c.blocked);
        }
    }
    h
}

// ---------------------------------------------------------------------------------------
// Top lists, types, upstreams, reasons
// ---------------------------------------------------------------------------------------

/// One item of a domain top list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopDomain {
    /// The full name.
    pub name: String,
    /// The registrable domain.
    pub base: String,
    /// The count.
    pub count: u64,
}

fn by_name(pairs: &PairMap) -> HashMap<&str, Tally> {
    let mut out: HashMap<&str, Tally> = HashMap::new();
    for (k, t) in pairs {
        out.entry(&k.name).and_modify(|m| m.add(t)).or_insert(*t);
    }
    out
}

/// The most queried names. With `blocked`, the count is the blocked queries; else it is
/// the queries that were not blocked. Names with a count of 0 are not in the list.
pub fn top_domains(pairs: &PairMap, limit: usize, blocked: bool) -> Vec<TopDomain> {
    let mut items: Vec<TopDomain> = by_name(pairs)
        .into_iter()
        .map(|(name, t)| {
            let count = if blocked {
                t.counts.blocked
            } else {
                t.counts.total.saturating_sub(t.counts.blocked)
            };
            TopDomain {
                name: name.to_owned(),
                base: registrable(name).to_owned(),
                count,
            }
        })
        .filter(|d| d.count > 0)
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    items.truncate(limit.clamp(1, MAX_TOP_LIMIT));
    items
}

/// One item of the client top list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopClient {
    /// The client key.
    pub key: String,
    /// The client name.
    pub name: Option<String>,
    /// The address with the latest query.
    pub ip: IpAddr,
    /// All queries.
    pub count: u64,
    /// Blocked queries.
    pub blocked: u64,
}

/// The clients with the most queries.
pub fn top_clients(pairs: &PairMap, clients: &Clients, limit: usize) -> Vec<TopClient> {
    let mut items: Vec<TopClient> = by_key(pairs, clients)
        .into_iter()
        .map(|(key, a)| TopClient {
            name: clients.name_of(&key),
            ip: a.latest_ip(),
            count: a.tally.counts.total,
            blocked: a.tally.counts.blocked,
            key,
        })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    items.truncate(limit.clamp(1, MAX_TOP_LIMIT));
    items
}

/// One item of `GET /stats/query-types`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRow {
    /// The type number.
    pub qtype: u16,
    /// The type name, for example `A` or `TYPE65280`.
    pub name: String,
    /// The count.
    pub count: u64,
}

/// Query types, the most frequent first.
pub fn query_types(map: &TypeMap) -> Vec<TypeRow> {
    let mut items: Vec<TypeRow> = map
        .iter()
        .filter(|(_, c)| **c > 0)
        .map(|(&qtype, &count)| TypeRow {
            qtype,
            name: qtype_name(qtype),
            count,
        })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.qtype.cmp(&b.qtype)));
    items
}

/// Where answers came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// An upstream server.
    Upstream,
    /// The cache.
    Cache,
    /// A block reply.
    Blocked,
    /// A local record.
    Local,
}

impl SourceKind {
    /// The API name.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Upstream => "upstream",
            SourceKind::Cache => "cache",
            SourceKind::Blocked => "blocked",
            SourceKind::Local => "local",
        }
    }
}

/// One item of `GET /stats/upstreams`.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamRow {
    /// The upstream address, or `cache`, `blocked`, `local`.
    pub name: String,
    /// The kind.
    pub kind: SourceKind,
    /// The count.
    pub count: u64,
    /// The mean answer time of an upstream in milliseconds (1 decimal), else `None`.
    pub avg_ms: Option<f64>,
}

/// The upstream share: each upstream (the most answers first), then the cache, the block
/// replies and the local answers.
#[allow(clippy::cast_precision_loss)] // Sums far below 2^52: the loss does not matter.
pub fn upstream_share(map: &UpstreamMap, totals: &Counts) -> Vec<UpstreamRow> {
    let mut items: Vec<UpstreamRow> = map
        .iter()
        .filter(|(_, t)| t.count > 0)
        .map(|(name, t)| UpstreamRow {
            name: name.clone(),
            kind: SourceKind::Upstream,
            count: t.count,
            avg_ms: Some((t.sum_us as f64 / t.count as f64 / 100.0).round() / 10.0),
        })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    for (kind, count) in [
        (SourceKind::Cache, totals.cached),
        (SourceKind::Blocked, totals.blocked),
        (SourceKind::Local, totals.local),
    ] {
        items.push(UpstreamRow {
            name: kind.as_str().to_owned(),
            kind,
            count,
            avg_ms: None,
        });
    }
    items
}

/// One reason with its count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonRow {
    /// The reason, for example `list:3`.
    pub reason: String,
    /// The count.
    pub count: u64,
}

/// The most frequent reasons (top blocking lists and rules).
pub fn top_reasons(map: &ReasonMap, limit: usize) -> Vec<ReasonRow> {
    let mut items: Vec<ReasonRow> = map
        .iter()
        .filter(|(_, c)| **c > 0)
        .map(|(r, &count)| ReasonRow {
            reason: r.clone(),
            count,
        })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
    items.truncate(limit.clamp(1, MAX_TOP_LIMIT));
    items
}

// ---------------------------------------------------------------------------------------
// Clients in statistics
// ---------------------------------------------------------------------------------------

/// The sort order of a long collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// Most queries first.
    #[default]
    Queries,
    /// Most blocked queries first.
    Blocked,
    /// Latest query first.
    LastSeen,
    /// By name, A to Z.
    Name,
}

impl Sort {
    /// Parses `queries`, `blocked`, `last_seen` or `name`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "queries" => Some(Sort::Queries),
            "blocked" => Some(Sort::Blocked),
            "last_seen" => Some(Sort::LastSeen),
            "name" => Some(Sort::Name),
            _ => None,
        }
    }

    fn key(self, t: &Tally, name: Option<&str>, tie: &str) -> SortKey {
        let (num, text) = match self {
            Sort::Queries => (-signed(t.counts.total), String::new()),
            Sort::Blocked => (-signed(t.counts.blocked), String::new()),
            Sort::LastSeen => (t.last_seen.saturating_neg(), String::new()),
            Sort::Name => match name {
                Some(n) => (0, n.to_owned()),
                None => (1, String::new()),
            },
        };
        SortKey {
            num,
            text,
            tie: tie.to_owned(),
        }
    }
}

#[derive(Debug)]
struct KeyAgg<'a> {
    tally: Tally,
    ips: BTreeMap<IpAddr, i64>,
    names: HashSet<&'a str>,
}

impl KeyAgg<'_> {
    fn latest_ip(&self) -> IpAddr {
        self.ips
            .iter()
            .max_by_key(|(ip, last)| (**last, **ip))
            .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |(ip, _)| *ip)
    }
}

fn by_key<'a>(pairs: &'a PairMap, clients: &Clients) -> HashMap<String, KeyAgg<'a>> {
    let mut keys_of: HashMap<IpAddr, String> = HashMap::new();
    let mut out: HashMap<String, KeyAgg<'a>> = HashMap::new();
    for (k, t) in pairs {
        let key = keys_of
            .entry(k.client)
            .or_insert_with(|| clients.key_of(k.client))
            .clone();
        let a = out.entry(key).or_insert_with(|| KeyAgg {
            tally: *t,
            ips: BTreeMap::new(),
            names: HashSet::new(),
        });
        if !a.names.is_empty() || !a.ips.is_empty() {
            a.tally.add(t);
        }
        let last = a.ips.entry(k.client).or_insert(t.last_seen);
        *last = (*last).max(t.last_seen);
        a.names.insert(&k.name);
    }
    out
}

/// One client in statistics (`GET /stats/clients` and `GET /stats/clients/{key}`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClientRow {
    /// The client key.
    pub key: String,
    /// The client name.
    pub name: Option<String>,
    /// The address with the latest query.
    pub ip: Option<IpAddr>,
    /// All addresses that the client used in the range.
    pub ips: Vec<IpAddr>,
    /// The MAC address.
    pub mac: Option<String>,
    /// The counts in the range.
    pub counts: Counts,
    /// Blocked queries in percent.
    pub blocked_percent: f64,
    /// Distinct full names in the range.
    pub unique_domains: u64,
    /// Distinct registrable domains in the range.
    pub unique_bases: u64,
    /// The first query in the stored data (not only in the range), Unix seconds.
    pub first_seen: Option<i64>,
    /// The last query, Unix seconds.
    pub last_seen: Option<i64>,
}

fn client_row(key: String, a: Option<&KeyAgg<'_>>, clients: &Clients) -> ClientRow {
    let seen = clients.seen_of(&key);
    let range_seen = a.map(|a| (a.tally.first_seen, a.tally.last_seen));
    let first_seen = match (seen, range_seen) {
        (Some(s), Some(r)) => Some(s.0.min(r.0)),
        (Some(s), None) => Some(s.0),
        (None, Some(r)) => Some(r.0),
        (None, None) => None,
    };
    let last_seen = match (seen, range_seen) {
        (Some(s), Some(r)) => Some(s.1.max(r.1)),
        (Some(s), None) => Some(s.1),
        (None, Some(r)) => Some(r.1),
        (None, None) => None,
    };
    let counts = a.map_or_default(|a| a.tally.counts);
    let bases: HashSet<&str> =
        a.map_or_default(|a| a.names.iter().map(|n| registrable(n)).collect());
    ClientRow {
        name: clients.name_of(&key),
        ip: a
            .map(KeyAgg::latest_ip)
            .or_else(|| key.parse::<IpAddr>().ok()),
        ips: a.map_or_default(|a| a.ips.keys().copied().collect()),
        mac: clients.mac_of(&key),
        blocked_percent: percent(counts.blocked, counts.total),
        unique_domains: a.map_or(0, |a| a.names.len() as u64),
        unique_bases: bases.len() as u64,
        counts,
        first_seen,
        last_seen,
        key,
    }
}

/// Parameters of `GET /stats/clients`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientListParams {
    /// Only clients whose key, name, IP or MAC has this text (case-insensitive).
    pub q: Option<String>,
    /// The order.
    pub sort: Sort,
    /// The cursor from the previous page.
    pub cursor: Option<String>,
    /// The page size.
    pub limit: usize,
}

/// The clients with queries in the range, one page.
pub fn client_list(
    pairs: &PairMap,
    clients: &Clients,
    p: &ClientListParams,
) -> Result<Page<ClientRow>, CursorError> {
    let q = p.q.as_deref().map(str::to_ascii_lowercase);
    let items: Vec<(SortKey, ClientRow)> = by_key(pairs, clients)
        .into_iter()
        .map(|(key, a)| client_row(key, Some(&a), clients))
        .filter(|row| {
            q.as_deref().is_none_or(|q| {
                row.key.contains(q)
                    || row.ips.iter().any(|ip| ip.to_string().contains(q))
                    || row.mac.as_deref().is_some_and(|m| m.contains(q))
                    || row
                        .name
                        .as_deref()
                        .is_some_and(|n| n.to_ascii_lowercase().contains(q))
            })
        })
        .map(|row| {
            let t = Tally {
                counts: row.counts,
                first_seen: row.first_seen.unwrap_or(0),
                last_seen: row.last_seen.unwrap_or(0),
            };
            (p.sort.key(&t, row.name.as_deref(), &row.key), row)
        })
        .collect();
    paginate(items, p.cursor.as_deref(), p.limit)
}

/// One client with its counts in the range. `pairs` must hold the pairs of this client
/// only (the store filters by [`Clients::ips_of`]). A client with no queries gives zero
/// counts.
pub fn client_detail(pairs: &PairMap, clients: &Clients, key: &str) -> ClientRow {
    let mut aggs = by_key(pairs, clients);
    let a = aggs.remove(key);
    client_row(key.to_owned(), a.as_ref(), clients)
}

// ---------------------------------------------------------------------------------------
// Names grouped by registrable domain
// ---------------------------------------------------------------------------------------

/// One full name in a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRow {
    /// The full name.
    pub name: String,
    /// All queries.
    pub queries: u64,
    /// Blocked queries.
    pub blocked: u64,
    /// The first query in the range, Unix seconds.
    pub first_seen: i64,
    /// The last query in the range, Unix seconds.
    pub last_seen: i64,
}

/// One registrable domain with its names (`GET /stats/clients/{key}/domains`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainGroup {
    /// The registrable domain.
    pub base: String,
    /// All queries of the names in the group.
    pub queries: u64,
    /// Blocked queries of the names in the group.
    pub blocked: u64,
    /// The first query, Unix seconds.
    pub first_seen: i64,
    /// The last query, Unix seconds.
    pub last_seen: i64,
    /// The number of names in the group.
    pub names_total: usize,
    /// The first `names_limit` names, most queries first.
    pub names: Vec<NameRow>,
}

/// Parameters of `GET /stats/clients/{key}/domains`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupParams {
    /// Only groups whose base has this text (all names), or names that have it.
    pub q: Option<String>,
    /// The order of the groups.
    pub sort: Sort,
    /// The largest number of names in each group, clamped to `1..=MAX_NAMES_LIMIT`.
    pub names_limit: usize,
    /// Only names with blocked queries.
    pub blocked_only: bool,
    /// The cursor from the previous page.
    pub cursor: Option<String>,
    /// Groups per page.
    pub limit: usize,
}

/// Groups all names of `pairs` by registrable domain, one page of groups. A group is never
/// split between pages. `pairs` usually holds the pairs of one client.
pub fn domain_groups(pairs: &PairMap, p: &GroupParams) -> Result<Page<DomainGroup>, CursorError> {
    let q = p.q.as_deref().map(str::to_ascii_lowercase);
    let names_limit = p.names_limit.clamp(1, MAX_NAMES_LIMIT);
    let mut groups: BTreeMap<&str, Vec<(&str, Tally)>> = BTreeMap::new();
    for (name, t) in by_name(pairs) {
        if p.blocked_only && t.counts.blocked == 0 {
            continue;
        }
        let base = registrable(name);
        let keep = q
            .as_deref()
            .is_none_or(|q| base.contains(q) || name.contains(q));
        if keep {
            groups.entry(base).or_default().push((name, t));
        }
    }
    let items: Vec<(SortKey, DomainGroup)> = groups
        .into_iter()
        .filter_map(|(base, mut names)| {
            // With `q`, a base that does not have `q` keeps only the names that have it.
            if let Some(q) = q.as_deref()
                && !base.contains(q)
            {
                names.retain(|(n, _)| n.contains(q));
            }
            let mut total = names.first().map(|(_, t)| *t)?;
            for (_, t) in names.iter().skip(1) {
                total.add(t);
            }
            names.sort_by(|a, b| {
                b.1.counts
                    .total
                    .cmp(&a.1.counts.total)
                    .then_with(|| a.0.cmp(b.0))
            });
            let group = DomainGroup {
                base: base.to_owned(),
                queries: total.counts.total,
                blocked: total.counts.blocked,
                first_seen: total.first_seen,
                last_seen: total.last_seen,
                names_total: names.len(),
                names: names
                    .iter()
                    .take(names_limit)
                    .map(|(n, t)| NameRow {
                        name: (*n).to_owned(),
                        queries: t.counts.total,
                        blocked: t.counts.blocked,
                        first_seen: t.first_seen,
                        last_seen: t.last_seen,
                    })
                    .collect(),
            };
            Some((p.sort.key(&total, Some(base), base), group))
        })
        .collect();
    paginate(items, p.cursor.as_deref(), p.limit)
}

// ---------------------------------------------------------------------------------------
// Domains in statistics
// ---------------------------------------------------------------------------------------

/// One name in a domain search (`GET /stats/domains`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRow {
    /// The full name.
    pub name: String,
    /// The registrable domain.
    pub base: String,
    /// All queries.
    pub queries: u64,
    /// Blocked queries.
    pub blocked: u64,
    /// Distinct client keys.
    pub clients: u64,
    /// The last query, Unix seconds.
    pub last_seen: i64,
}

/// Parameters of `GET /stats/domains`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainSearchParams {
    /// Only names that have this text (case-insensitive).
    pub q: String,
    /// Only names with blocked queries.
    pub blocked_only: bool,
    /// The cursor from the previous page.
    pub cursor: Option<String>,
    /// The page size.
    pub limit: usize,
}

/// Names that have `q`, most queries first, one page.
pub fn domain_search(
    pairs: &PairMap,
    clients: &Clients,
    p: &DomainSearchParams,
) -> Result<Page<DomainRow>, CursorError> {
    let q = p.q.to_ascii_lowercase();
    let mut rows: HashMap<&str, (Tally, HashSet<String>)> = HashMap::new();
    for (k, t) in pairs {
        if !k.name.contains(q.as_str()) {
            continue;
        }
        let e = rows.entry(&k.name).or_insert_with(|| (*t, HashSet::new()));
        if !e.1.is_empty() {
            e.0.add(t);
        }
        e.1.insert(clients.key_of(k.client));
    }
    let items: Vec<(SortKey, DomainRow)> = rows
        .into_iter()
        .filter(|(_, (t, _))| !p.blocked_only || t.counts.blocked > 0)
        .map(|(name, (t, keys))| {
            let row = DomainRow {
                name: name.to_owned(),
                base: registrable(name).to_owned(),
                queries: t.counts.total,
                blocked: t.counts.blocked,
                clients: keys.len() as u64,
                last_seen: t.last_seen,
            };
            (Sort::Queries.key(&t, None, name), row)
        })
        .collect();
    paginate(items, p.cursor.as_deref(), p.limit)
}

/// One client of a name (`GET /stats/domains/{name}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainClient {
    /// The client key.
    pub key: String,
    /// The client name.
    pub name: Option<String>,
    /// The address with the latest query.
    pub ip: IpAddr,
    /// All queries.
    pub queries: u64,
    /// Blocked queries.
    pub blocked: u64,
    /// The last query, Unix seconds.
    pub last_seen: i64,
}

/// One name with its clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDetail {
    /// The full name.
    pub name: String,
    /// The registrable domain.
    pub base: String,
    /// The counts in the range.
    pub counts: Counts,
    /// The first query in the stored data (not only in the range), Unix seconds
    /// (docs/API.md section 5.7).
    pub first_seen: Option<i64>,
    /// The last query in the range, Unix seconds.
    pub last_seen: Option<i64>,
    /// At most [`MAX_DOMAIN_CLIENTS`] clients, most queries first.
    pub clients: Vec<DomainClient>,
}

/// One name with its counts and clients. Pairs of other names are ignored. A name with no
/// queries gives zero counts and no clients.
///
/// `stored_first_seen` is the first query of the name in all stored data (the store reads
/// it from the `domains` table and the RAM buckets). `first_seen` is the earlier of it and
/// the first query in `pairs`.
pub fn domain_detail(
    pairs: &PairMap,
    clients: &Clients,
    name: &str,
    stored_first_seen: Option<i64>,
) -> DomainDetail {
    let only: PairMap = pairs
        .iter()
        .filter(|(k, _)| &*k.name == name)
        .map(|(k, t)| (k.clone(), *t))
        .collect();
    let mut total: Option<Tally> = None;
    for t in only.values() {
        match total.as_mut() {
            Some(m) => m.add(t),
            None => total = Some(*t),
        }
    }
    let mut list: Vec<DomainClient> = by_key(&only, clients)
        .into_iter()
        .map(|(key, a)| DomainClient {
            name: clients.name_of(&key),
            ip: a.latest_ip(),
            queries: a.tally.counts.total,
            blocked: a.tally.counts.blocked,
            last_seen: a.tally.last_seen,
            key,
        })
        .collect();
    list.sort_by(|a, b| b.queries.cmp(&a.queries).then_with(|| a.key.cmp(&b.key)));
    list.truncate(MAX_DOMAIN_CLIENTS);
    DomainDetail {
        name: name.to_owned(),
        base: registrable(name).to_owned(),
        counts: total.map_or_default(|t| t.counts),
        first_seen: match (total.map(|t| t.first_seen), stored_first_seen) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        },
        last_seen: total.map(|t| t.last_seen),
        clients: list,
    }
}
