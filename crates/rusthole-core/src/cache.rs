//! DNS answer cache policy: keys, TTL rules and a bounded LRU map with expiry.
//!
//! The cache does not know the DNS wire format. It stores a value of any type with a TTL in
//! seconds. The DNS crate stores the unfiltered upstream answer, and lowers each record TTL
//! by [`Hit::age`] when it serves the answer (amendment A4: the filter runs on every reply).
//!
//! Rules:
//!
//! - The key is the lowercase query name, the query type, the query class and the DNSSEC OK
//!   (DO) bit.
//! - An entry expires at `stored + ttl`. [`Cache::get`] never returns an expired entry.
//! - The map holds at most `max_entries` entries. A full map drops the least recently used
//!   entry. `max_entries = 0` turns the cache off.
//!
//! This module is pure: `now_ms` is a monotonic time in milliseconds, given by the caller.

use std::num::NonZeroUsize;

use lru::LruCache;

/// The cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    name: Box<str>,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
}

impl CacheKey {
    /// Makes a key. The function changes ASCII letters in `name` to lowercase.
    ///
    /// `name` is the query name in an escaped text form (for example the presentation form
    /// of a wire name, where a dot inside a label is `\.`). Two names that differ only in the
    /// case of ASCII letters give the same key.
    pub fn new(name: &str, qtype: u16, qclass: u16, dnssec_ok: bool) -> Self {
        Self {
            name: name.to_ascii_lowercase().into_boxed_str(),
            qtype,
            qclass,
            dnssec_ok,
        }
    }

    /// The lowercase name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The query type.
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    /// The query class.
    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    /// The DNSSEC OK bit.
    pub fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }
}

/// TTL rules from the `[cache]` config section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlPolicy {
    /// Lowest TTL of a positive answer, in seconds.
    pub min_ttl: u32,
    /// Highest TTL of a positive answer, in seconds.
    pub max_ttl: u32,
    /// Highest TTL of a negative answer (NXDOMAIN or NODATA), in seconds. It is also the TTL
    /// when the answer has no SOA record.
    pub negative_ttl: u32,
}

impl TtlPolicy {
    /// The TTL of a positive record: `ttl` clamped to `[min_ttl, max_ttl]`. When
    /// `min_ttl > max_ttl` (config validation refuses this), `max_ttl` wins.
    pub fn positive(&self, ttl: u32) -> u32 {
        ttl.max(self.min_ttl).min(self.max_ttl)
    }

    /// The TTL of a negative answer (RFC 2308 section 5): the lower of the SOA record TTL and
    /// the SOA `minimum` field, capped by `negative_ttl`. Without an SOA record, the TTL is
    /// `negative_ttl`.
    ///
    /// `soa` is `(record TTL, minimum field)`.
    pub fn negative(&self, soa: Option<(u32, u32)>) -> u32 {
        soa.map_or(self.negative_ttl, |(ttl, minimum)| ttl.min(minimum))
            .min(self.negative_ttl)
    }
}

/// A value in the cache with its expiry data.
#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    stored_ms: u64,
    ttl: u32,
}

impl<V> Entry<V> {
    /// The time in milliseconds when the entry expires.
    fn expires_ms(&self) -> u64 {
        self.stored_ms
            .saturating_add(u64::from(self.ttl).saturating_mul(1000))
    }
}

/// A cache hit.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit<'a, V> {
    /// The stored value.
    pub value: &'a V,
    /// The TTL at insert time, in seconds.
    pub ttl: u32,
    /// The seconds until the entry expires, rounded up: `1..=ttl`.
    pub remaining: u32,
    /// `ttl - remaining`: lower each stored record TTL by this value.
    pub age: u32,
}

/// A bounded DNS cache.
#[derive(Debug)]
pub struct Cache<V> {
    map: Option<LruCache<CacheKey, Entry<V>>>,
}

impl<V> Cache<V> {
    /// Makes a cache with room for `max_entries` entries. 0 turns the cache off.
    pub fn new(max_entries: usize) -> Self {
        Self {
            map: NonZeroUsize::new(max_entries).map(LruCache::new),
        }
    }

    /// True when the cache is on.
    pub fn is_enabled(&self) -> bool {
        self.map.is_some()
    }

    /// Number of entries, expired entries included.
    pub fn len(&self) -> usize {
        self.map.as_ref().map_or(0, LruCache::len)
    }

    /// True when the cache has no entry.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The maximum number of entries.
    pub fn capacity(&self) -> usize {
        self.map.as_ref().map_or(0, |m| m.cap().get())
    }

    /// Stores `value` under `key` for `ttl` seconds from `now_ms`. Replaces an older entry.
    ///
    /// Returns false (and stores nothing) when the cache is off or `ttl` is 0. An older entry
    /// with the same key is removed in that case too, so a stale answer cannot stay.
    pub fn insert(&mut self, key: CacheKey, value: V, ttl: u32, now_ms: u64) -> bool {
        let Some(map) = &mut self.map else {
            return false;
        };
        if ttl == 0 {
            map.pop(&key);
            return false;
        }
        map.put(
            key,
            Entry {
                value,
                stored_ms: now_ms,
                ttl,
            },
        );
        true
    }

    /// Returns the entry for `key` if it has not expired at `now_ms`. Removes an expired
    /// entry.
    ///
    /// The entry expires when `now_ms >= stored + ttl * 1000`. A `now_ms` before the insert
    /// time (a clock that goes back) gives age 0.
    pub fn get(&mut self, key: &CacheKey, now_ms: u64) -> Option<Hit<'_, V>> {
        let map = self.map.as_mut()?;
        let expires = map.peek(key)?.expires_ms();
        if now_ms >= expires {
            map.pop(key);
            return None;
        }
        let entry = map.get(key)?;
        let remaining_ms = expires.saturating_sub(now_ms.max(entry.stored_ms));
        let remaining = u32::try_from(remaining_ms.div_ceil(1000))
            .unwrap_or(u32::MAX)
            .clamp(1, entry.ttl.max(1));
        Some(Hit {
            value: &entry.value,
            ttl: entry.ttl,
            remaining,
            age: entry.ttl.saturating_sub(remaining),
        })
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        if let Some(map) = &mut self.map {
            map.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    fn key(name: &str) -> CacheKey {
        CacheKey::new(name, 1, 1, false)
    }

    #[test]
    fn key_is_case_insensitive_and_has_do_bit() {
        assert_eq!(key("Example.COM."), key("example.com."));
        assert_ne!(
            CacheKey::new("a.", 1, 1, false),
            CacheKey::new("a.", 1, 1, true)
        );
        assert_ne!(
            CacheKey::new("a.", 1, 1, false),
            CacheKey::new("a.", 28, 1, false)
        );
        assert_ne!(
            CacheKey::new("a.", 1, 1, false),
            CacheKey::new("a.", 1, 3, false)
        );
        // An escaped dot inside a label is not a label separator.
        assert_ne!(key("a\\.b."), key("a.b."));
    }

    #[test]
    fn hit_until_expiry_then_miss() {
        let mut c = Cache::new(8);
        assert!(c.insert(key("a."), 7, 10, 1_000));
        let h = c.get(&key("a."), 1_000).unwrap();
        assert_eq!((h.ttl, h.remaining, h.age, *h.value), (10, 10, 0, 7));
        let h = c.get(&key("a."), 1_001).unwrap();
        assert_eq!((h.remaining, h.age), (10, 0));
        let h = c.get(&key("a."), 4_000).unwrap();
        assert_eq!((h.remaining, h.age), (7, 3));
        let h = c.get(&key("a."), 10_999).unwrap();
        assert_eq!((h.remaining, h.age), (1, 9));
        // Never served at age == TTL.
        assert!(c.get(&key("a."), 11_000).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn ttl_zero_is_not_stored_and_removes_old_entry() {
        let mut c = Cache::new(8);
        assert!(c.insert(key("a."), 1, 10, 0));
        assert!(!c.insert(key("a."), 2, 0, 0));
        assert!(c.get(&key("a."), 0).is_none());
    }

    #[test]
    fn disabled_cache_stores_nothing() {
        let mut c: Cache<u8> = Cache::new(0);
        assert!(!c.is_enabled());
        assert!(!c.insert(key("a."), 1, 10, 0));
        assert!(c.get(&key("a."), 0).is_none());
        assert_eq!(c.capacity(), 0);
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let mut c = Cache::new(2);
        c.insert(key("a."), 1, 100, 0);
        c.insert(key("b."), 2, 100, 0);
        assert!(c.get(&key("a."), 1).is_some());
        c.insert(key("c."), 3, 100, 2);
        assert_eq!(c.len(), 2);
        assert!(c.get(&key("b."), 3).is_none());
        assert!(c.get(&key("a."), 3).is_some());
        assert!(c.get(&key("c."), 3).is_some());
    }

    #[test]
    fn clock_going_back_gives_age_zero() {
        let mut c = Cache::new(2);
        c.insert(key("a."), 1, 5, 10_000);
        let h = c.get(&key("a."), 0).unwrap();
        assert_eq!((h.remaining, h.age), (5, 0));
    }

    #[test]
    fn huge_ttl_and_time_do_not_overflow() {
        let mut c = Cache::new(2);
        c.insert(key("a."), 1, u32::MAX, u64::MAX - 5);
        assert!(c.get(&key("a."), u64::MAX - 1).is_some());
        assert!(c.get(&key("a."), u64::MAX).is_none());
    }

    #[test]
    fn ttl_policy() {
        let p = TtlPolicy {
            min_ttl: 10,
            max_ttl: 100,
            negative_ttl: 60,
        };
        assert_eq!(p.positive(5), 10);
        assert_eq!(p.positive(50), 50);
        assert_eq!(p.positive(500), 100);
        assert_eq!(p.negative(None), 60);
        assert_eq!(p.negative(Some((30, 3600))), 30);
        assert_eq!(p.negative(Some((3600, 20))), 20);
        assert_eq!(p.negative(Some((3600, 3600))), 60);
        let odd = TtlPolicy {
            min_ttl: 100,
            max_ttl: 10,
            negative_ttl: 0,
        };
        assert_eq!(odd.positive(50), 10);
        assert_eq!(odd.negative(Some((5, 5))), 0);
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert { k: u8, ttl: u32, now: u64 },
        Get { k: u8, now: u64 },
        Clear,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..12, 0u32..20, 0u64..60_000).prop_map(|(k, ttl, now)| Op::Insert { k, ttl, now }),
            (0u8..12, 0u64..60_000).prop_map(|(k, now)| Op::Get { k, now }),
            Just(Op::Clear),
        ]
    }

    proptest! {
        /// For any op sequence with any `now` (also going back):
        /// - a hit is never expired;
        /// - the served TTL (`remaining`) is in `1..=stored ttl`, and `age + remaining == ttl`;
        /// - the hit value is the last value stored under that key;
        /// - the size never exceeds `max_entries`.
        #[test]
        fn invariants_hold(max in 0usize..6, ops in proptest::collection::vec(op(), 0..200)) {
            let mut c: Cache<u32> = Cache::new(max);
            // Model: key -> (value, stored_ms, ttl) of the last insert with ttl > 0.
            let mut model: HashMap<u8, (u32, u64, u32)> = HashMap::new();
            for (i, op) in ops.into_iter().enumerate() {
                let tag = u32::try_from(i).unwrap();
                match op {
                    Op::Insert { k, ttl, now } => {
                        let stored = c.insert(key(&format!("k{k}.")), tag, ttl, now);
                        prop_assert_eq!(stored, max > 0 && ttl > 0);
                        if stored {
                            model.insert(k, (tag, now, ttl));
                        } else {
                            model.remove(&k);
                        }
                    }
                    Op::Get { k, now } => {
                        if let Some(h) = c.get(&key(&format!("k{k}.")), now) {
                            let (value, stored_ms, ttl) = *model.get(&k).unwrap();
                            prop_assert!(now < stored_ms + u64::from(ttl) * 1000, "expired hit");
                            prop_assert_eq!(*h.value, value);
                            prop_assert_eq!(h.ttl, ttl);
                            prop_assert!(h.remaining >= 1 && h.remaining <= ttl);
                            prop_assert_eq!(h.age + h.remaining, ttl);
                        }
                    }
                    Op::Clear => {
                        c.clear();
                        model.clear();
                    }
                }
                prop_assert!(c.len() <= max);
            }
        }
    }
}
