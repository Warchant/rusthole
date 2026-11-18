//! The ring buffer of recent queries (amendment A9). It lives in RAM only and is never
//! written to disk. The data is lost at a restart.

use std::collections::{BTreeSet, VecDeque};
use std::net::IpAddr;

use super::{StatsEvent, Status};

/// The largest number of items that one query returns (docs/API.md section 6).
pub const MAX_RECENT_LIMIT: usize = 1000;

/// A bounded ring of the last events. The oldest event goes out first.
#[derive(Debug, Clone)]
pub struct RecentRing {
    capacity: usize,
    buf: VecDeque<StatsEvent>,
}

/// What [`RecentRing::query`] returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecentFilter {
    /// The largest number of items, clamped to `1..=MAX_RECENT_LIMIT`.
    pub limit: usize,
    /// Only these client addresses (all addresses of one client key).
    pub clients: Option<BTreeSet<IpAddr>>,
    /// Only this status.
    pub status: Option<Status>,
    /// Only names that contain this text (case-insensitive).
    pub q: Option<String>,
}

impl RecentRing {
    /// An empty ring for `capacity` events. A capacity of 0 keeps nothing. The ring does
    /// not reserve memory for all events at the start.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buf: VecDeque::new(),
        }
    }

    /// The number of events in the ring.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Adds an event. When the ring is full, the oldest event goes out.
    pub fn push(&mut self, ev: StatsEvent) {
        if self.capacity == 0 {
            return;
        }
        while self.buf.len() >= self.capacity {
            self.buf.pop_front();
        }
        self.buf.push_back(ev);
    }

    /// The events in the filter, newest first.
    pub fn query(&self, f: &RecentFilter) -> Vec<StatsEvent> {
        let limit = f.limit.clamp(1, MAX_RECENT_LIMIT);
        let q = f.q.as_deref().map(str::to_ascii_lowercase);
        self.buf
            .iter()
            .rev()
            .filter(|e| f.clients.as_ref().is_none_or(|c| c.contains(&e.client)))
            .filter(|e| f.status.is_none_or(|s| s == e.status))
            .filter(|e| q.as_deref().is_none_or(|q| e.name.contains(q)))
            .take(limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ev(i: u8, status: Status) -> StatsEvent {
        StatsEvent {
            at: i64::from(i),
            client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, i % 3)),
            name: format!("n{i}.example"),
            qtype: 1,
            status,
            reason: None,
            upstream: None,
            duration_us: 0,
        }
    }

    #[test]
    fn ring_keeps_the_newest() {
        let mut r = RecentRing::new(3);
        for i in 0..10 {
            r.push(ev(i, Status::Forwarded));
        }
        assert_eq!(r.len(), 3);
        let all = r.query(&RecentFilter {
            limit: 100,
            ..RecentFilter::default()
        });
        let ats: Vec<i64> = all.iter().map(|e| e.at).collect();
        assert_eq!(ats, vec![9, 8, 7]);
    }

    #[test]
    fn zero_capacity_keeps_nothing() {
        let mut r = RecentRing::new(0);
        r.push(ev(1, Status::Blocked));
        assert!(r.is_empty());
        assert_eq!(r.query(&RecentFilter::default()), Vec::new());
    }

    #[test]
    fn filters_combine() {
        let mut r = RecentRing::new(100);
        for i in 0..30 {
            let st = if i % 2 == 0 {
                Status::Blocked
            } else {
                Status::Cached
            };
            r.push(ev(i, st));
        }
        let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0));
        let got = r.query(&RecentFilter {
            limit: 1000,
            clients: Some([client].into_iter().collect()),
            status: Some(Status::Blocked),
            q: Some("N1".to_owned()),
        });
        // i % 3 == 0, even, name has "n1": 12, 18.
        let ats: Vec<i64> = got.iter().map(|e| e.at).collect();
        assert_eq!(ats, vec![18, 12]);
        let limited = r.query(&RecentFilter {
            limit: 0,
            ..RecentFilter::default()
        });
        assert_eq!(limited.len(), 1);
    }
}
