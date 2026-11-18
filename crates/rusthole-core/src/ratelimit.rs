//! Per-client query rate limit: one token bucket per client IP address.
//!
//! The config gives `queries` per `interval_seconds`. The bucket holds at most `queries`
//! tokens (the burst) and gets `queries` tokens in each interval (the rate). Each query uses
//! one token. The math uses integers only, so no rounding error can give a client more
//! queries than `burst + rate * elapsed`.
//!
//! The map of buckets is an LRU with a fixed maximum size, because a client address comes
//! from the network. When the map is full, the least recently used client loses its bucket.
//!
//! This module is pure: `now_ms` is a monotonic time in milliseconds, given by the caller.

use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;

/// Default maximum number of clients in the map.
pub const MAX_CLIENTS: usize = 65_536;

/// One client's bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    /// Tokens in units of `1 / interval_ms` of a query. One query costs `interval_ms` units.
    units: u128,
    /// The time of the last refill.
    last_ms: u64,
}

/// A rate limiter for many clients.
#[derive(Debug)]
pub struct RateLimiter {
    /// `None` when the limit is off (`queries = 0`).
    inner: Option<Inner>,
}

#[derive(Debug)]
struct Inner {
    buckets: LruCache<IpAddr, Bucket>,
    /// Queries per interval: the burst and the rate.
    queries: u128,
    /// Interval length in milliseconds. Never 0.
    interval_ms: u128,
}

impl RateLimiter {
    /// Makes a rate limiter. `queries = 0` or `interval_seconds = 0` turns the limit off.
    /// `max_clients` is the size of the map (at least 1).
    pub fn new(queries: u32, interval_seconds: u32, max_clients: usize) -> Self {
        if queries == 0 || interval_seconds == 0 {
            return Self { inner: None };
        }
        let cap = NonZeroUsize::new(max_clients).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Some(Inner {
                buckets: LruCache::new(cap),
                queries: u128::from(queries),
                interval_ms: u128::from(interval_seconds) * 1000,
            }),
        }
    }

    /// True when the limit is on.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Number of clients in the map.
    pub fn len(&self) -> usize {
        self.inner.as_ref().map_or(0, |i| i.buckets.len())
    }

    /// True when the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Takes one token for `client` at `now_ms`. Returns true when the query is allowed.
    ///
    /// A new client starts with a full bucket. A `now_ms` before the last refill (a clock that
    /// goes back) adds no tokens.
    pub fn check(&mut self, client: IpAddr, now_ms: u64) -> bool {
        let Some(inner) = &mut self.inner else {
            return true;
        };
        let full = inner.queries * inner.interval_ms;
        let cost = inner.interval_ms;
        let bucket = inner.buckets.get_or_insert_mut(client, || Bucket {
            units: full,
            last_ms: now_ms,
        });
        let elapsed = u128::from(now_ms.saturating_sub(bucket.last_ms));
        if elapsed > 0 {
            // `elapsed * queries` units: exactly `queries` tokens per `interval_ms`.
            bucket.units = bucket
                .units
                .saturating_add(elapsed.saturating_mul(inner.queries))
                .min(full);
            bucket.last_ms = now_ms;
        }
        if bucket.units >= cost {
            bucket.units -= cost;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    #[test]
    fn burst_then_refill() {
        let mut rl = RateLimiter::new(3, 1, 16);
        assert!(rl.check(ip(1), 0));
        assert!(rl.check(ip(1), 0));
        assert!(rl.check(ip(1), 0));
        assert!(!rl.check(ip(1), 0));
        // 1 s gives 3 tokens; 333 ms gives 0.999 tokens: not enough.
        assert!(!rl.check(ip(1), 333));
        assert!(rl.check(ip(1), 334));
        assert!(!rl.check(ip(1), 334));
        assert!(rl.check(ip(1), 10_000));
        assert!(rl.check(ip(1), 10_000));
        assert!(rl.check(ip(1), 10_000));
        assert!(!rl.check(ip(1), 10_000));
    }

    #[test]
    fn slow_rate_does_not_lose_fractions() {
        // 1 query per 60 s, checked each millisecond: the fractions add up.
        let mut rl = RateLimiter::new(1, 60, 16);
        assert!(rl.check(ip(1), 0));
        let mut allowed_at = None;
        for t in 1..=61_000u64 {
            if rl.check(ip(1), t) {
                allowed_at = Some(t);
                break;
            }
        }
        assert_eq!(allowed_at, Some(60_000));
    }

    #[test]
    fn clients_are_separate() {
        let mut rl = RateLimiter::new(1, 60, 16);
        assert!(rl.check(ip(1), 0));
        assert!(!rl.check(ip(1), 0));
        assert!(rl.check(ip(2), 0));
    }

    #[test]
    fn disabled_allows_all() {
        let mut rl = RateLimiter::new(0, 60, 16);
        assert!(!rl.is_enabled());
        for _ in 0..10_000 {
            assert!(rl.check(ip(1), 0));
        }
        assert!(rl.is_empty());
        assert!(!RateLimiter::new(5, 0, 16).is_enabled());
    }

    #[test]
    fn map_is_bounded() {
        let mut rl = RateLimiter::new(1, 60, 4);
        for n in 0..100u8 {
            rl.check(ip(n), 0);
            assert!(rl.len() <= 4);
        }
        // max_clients = 0 is treated as 1.
        let mut rl = RateLimiter::new(1, 60, 0);
        rl.check(ip(1), 0);
        rl.check(ip(2), 0);
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn clock_going_back_adds_nothing() {
        let mut rl = RateLimiter::new(1, 1, 4);
        assert!(rl.check(ip(1), 5_000));
        assert!(!rl.check(ip(1), 0));
        assert!(!rl.check(ip(1), 4_999));
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        let mut rl = RateLimiter::new(u32::MAX, u32::MAX, 4);
        assert!(rl.check(ip(1), 0));
        assert!(rl.check(ip(1), u64::MAX));
    }

    proptest! {
        /// In any time window that starts at the first query, a client gets at most
        /// `burst + rate * elapsed` queries.
        #[test]
        fn never_more_than_burst_plus_rate(
            queries in 1u32..50,
            interval in 1u32..10,
            steps in proptest::collection::vec(0u64..2_000, 1..300),
        ) {
            let mut rl = RateLimiter::new(queries, interval, 8);
            let start = 1_000u64;
            let mut now = start;
            let mut allowed: u128 = 0;
            for dt in steps {
                now += dt;
                if rl.check(ip(7), now) {
                    allowed += 1;
                }
                let elapsed = u128::from(now - start);
                // allowed <= queries + queries * elapsed / interval_ms, without division.
                let interval_ms = u128::from(interval) * 1000;
                prop_assert!(
                    allowed * interval_ms
                        <= u128::from(queries) * interval_ms + u128::from(queries) * elapsed,
                    "allowed {} after {} ms", allowed, elapsed
                );
            }
        }

        /// The map never holds more than `max_clients` entries.
        #[test]
        fn map_size_is_bounded(
            max in 1usize..16,
            ops in proptest::collection::vec((any::<u8>(), 0u64..100_000), 0..200),
        ) {
            let mut rl = RateLimiter::new(10, 1, max);
            for (n, t) in ops {
                rl.check(ip(n), t);
                prop_assert!(rl.len() <= max);
            }
        }
    }
}
