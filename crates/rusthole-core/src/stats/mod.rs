//! Statistics: the pure core of part P4.
//!
//! The DNS path gives one [`StatsEvent`] for each answered query. This module adds the events
//! up in RAM and answers the questions of the admin API. It does no I/O and reads no clock:
//! each event has its wall-clock time, and each function that needs the time gets `now`.
//!
//! ```mermaid
//! flowchart LR
//!     EV[StatsEvent] --> AGG[agg::Aggregator<br/>hour buckets in RAM]
//!     EV --> RING[recent::RecentRing]
//!     AGG -->|take| SNAP[agg::Snapshot] -->|flush| DB[(SQLite: rusthole-store)]
//!     AGG -->|extract| PARTS[query parts]
//!     DB -->|read| PARTS
//!     PARTS -->|merge| Q[query: summary, top lists,<br/>groups, histograms, pages]
//! ```
//!
//! - [`agg`]: the RAM aggregate with a bound on the number of keys.
//! - [`base`]: the registrable domain (eTLD+1) from the Public Suffix List.
//! - [`query`]: pure query functions over merged parts (RAM plus database).
//! - [`page`]: the keyset cursor for long collections.
//! - [`recent`]: the ring buffer of recent queries (RAM only).
//! - [`policy`]: when to flush, when to run the retention, when to log a WARN.

pub mod agg;
pub mod base;
pub mod page;
pub mod policy;
pub mod query;
pub mod recent;

#[cfg(test)]
mod tests;

use std::net::IpAddr;

/// Seconds in one hour bucket.
pub const HOUR_SECONDS: i64 = 3600;
/// Seconds in one bucket of the 24 h timeline.
pub const TEN_MINUTES: i64 = 600;

/// The status of one query (docs/API.md section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    /// Sent to an upstream server.
    Forwarded,
    /// Answered from the cache.
    Cached,
    /// Blocked by a list, a rule, a special domain or a CNAME check.
    Blocked,
    /// Answered from a local record.
    Local,
    /// Refused (rate limit).
    Refused,
    /// No answer from the upstreams (SERVFAIL).
    Error,
}

impl Status {
    /// All statuses.
    pub const ALL: [Status; 6] = [
        Status::Forwarded,
        Status::Cached,
        Status::Blocked,
        Status::Local,
        Status::Refused,
        Status::Error,
    ];

    /// The API name of the status.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Forwarded => "forwarded",
            Status::Cached => "cached",
            Status::Blocked => "blocked",
            Status::Local => "local",
            Status::Refused => "refused",
            Status::Error => "error",
        }
    }

    /// Parses an API name. An unknown name gives `None`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|st| st.as_str() == s)
    }
}

/// One answered query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsEvent {
    /// Wall-clock time of the answer, in Unix seconds (UTC). It can jump (no RTC on a Pi).
    pub at: i64,
    /// The client address.
    pub client: IpAddr,
    /// The query name in lowercase text form, without the trailing dot.
    pub name: String,
    /// The query type (for example 1 for A).
    pub qtype: u16,
    /// The status.
    pub status: Status,
    /// Why the query has this status (`list:{id}`, `rule:{id}`, `special`, `cname:{name}`,
    /// `local:{id}`), when the DNS path knows it.
    pub reason: Option<String>,
    /// The upstream that answered (for example `192.0.2.53:53`).
    pub upstream: Option<String>,
    /// Time from the start of the handling to the reply, in microseconds.
    pub duration_us: u64,
}

/// Query counts by status. All additions saturate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// All queries.
    pub total: u64,
    /// Blocked queries.
    pub blocked: u64,
    /// Queries answered from the cache.
    pub cached: u64,
    /// Queries sent to an upstream.
    pub forwarded: u64,
    /// Queries answered from a local record.
    pub local: u64,
}

impl Counts {
    /// Counts one query with `status`.
    pub fn add_status(&mut self, status: Status) {
        self.total = self.total.saturating_add(1);
        let field = match status {
            Status::Blocked => &mut self.blocked,
            Status::Cached => &mut self.cached,
            Status::Forwarded => &mut self.forwarded,
            Status::Local => &mut self.local,
            Status::Refused | Status::Error => return,
        };
        *field = field.saturating_add(1);
    }

    /// Adds `other` to `self`.
    pub fn add(&mut self, other: &Counts) {
        self.total = self.total.saturating_add(other.total);
        self.blocked = self.blocked.saturating_add(other.blocked);
        self.cached = self.cached.saturating_add(other.cached);
        self.forwarded = self.forwarded.saturating_add(other.forwarded);
        self.local = self.local.saturating_add(other.local);
    }
}

/// Counts and the first and last time of one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    /// The counts.
    pub counts: Counts,
    /// The first query, Unix seconds.
    pub first_seen: i64,
    /// The last query, Unix seconds.
    pub last_seen: i64,
}

impl Tally {
    /// A tally of one query.
    pub fn one(at: i64, status: Status) -> Self {
        let mut counts = Counts::default();
        counts.add_status(status);
        Self {
            counts,
            first_seen: at,
            last_seen: at,
        }
    }

    /// Adds `other` to `self`.
    pub fn add(&mut self, other: &Tally) {
        self.counts.add(&other.counts);
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
    }
}

/// Answers from one upstream: the count and the sum of the answer times.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamTally {
    /// Number of answers.
    pub count: u64,
    /// Sum of the answer times, in microseconds.
    pub sum_us: u64,
}

impl UpstreamTally {
    /// Adds `other` to `self`.
    pub fn add(&mut self, other: &UpstreamTally) {
        self.count = self.count.saturating_add(other.count);
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
    }
}

/// The key of one (client, full name) pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PairKey {
    /// The client address.
    pub client: IpAddr,
    /// The full query name.
    pub name: Box<str>,
}

/// The hour bucket (UTC) of a Unix time.
pub fn hour_of(at: i64) -> i64 {
    at.div_euclid(HOUR_SECONDS)
}

/// The 10-minute bucket of a Unix time.
pub fn ten_minutes_of(at: i64) -> i64 {
    at.div_euclid(TEN_MINUTES)
}

/// The name of a DNS record type, for example `A`, or `TYPE65280` for an unknown type.
pub fn qtype_name(qtype: u16) -> String {
    let name = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        _ => return format!("TYPE{qtype}"),
    };
    name.to_owned()
}
