//! DNS answer cache policy: keys, TTL rules and a bounded LRU map with expiry.
//!
//! The cache does not know the DNS wire format. It stores a value of any type with a TTL in
//! seconds and a size in bytes. The DNS crate stores the encoded, unfiltered upstream answer,
//! and lowers each record TTL by [`Hit::age`] when it serves the answer (amendment A4: the
//! filter runs on every reply).
//!
//! Rules:
//!
//! - The key is the lowercase query name, the query type, the query class and the DNSSEC OK
//!   (DO) bit.
//! - An entry expires at `stored + ttl`. [`Cache::get`] never returns an expired entry.
//! - The map holds at most `max_entries` entries. `max_entries = 0` turns the cache off.
//! - Memory bound (review item M1): the cache uses at most `max_bytes` bytes. Each entry
//!   costs [`entry_cost`]: the value size, the key name length and [`ENTRY_OVERHEAD`]. The
//!   hash table has a slot for each entry that can fit; the cache reserves [`SLOT_BYTES`]
//!   for each slot when it is made. A new entry that does not fit removes the least
//!   recently used entries until it fits. An entry that is larger than the budget is not
//!   stored.
//!
//! This module is pure: `now_ms` is a monotonic time in milliseconds, given by the caller.

use std::num::NonZeroUsize;

use lru::LruCache;

/// Heap bytes of one entry in addition to its value bytes and its key name: the LRU node
/// (key, value handle, expiry data, list links), the header of the value allocation and the
/// rounding of the allocator. An estimate of the upper bound. The counting allocator test in
/// the DNS crate checks the total heap bound for big answers and long keys, not this value.
pub const ENTRY_OVERHEAD: usize = 256;

/// Heap bytes of the hash table for one entry slot. The table has at most two times the
/// slots it needs (a power of two with a load factor of 7/8), and each slot has 16 bytes and
/// one control byte. An upper bound.
pub const SLOT_BYTES: usize = 48;

/// The cost of one entry against the byte budget: `size` (the value bytes), the key name
/// length and [`ENTRY_OVERHEAD`].
pub fn entry_cost(key: &CacheKey, size: usize) -> usize {
    size.saturating_add(key.name.len())
        .saturating_add(ENTRY_OVERHEAD)
}

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

/// A value in the cache with its expiry data and its cost.
#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    stored_ms: u64,
    ttl: u32,
    /// [`entry_cost`] at insert time.
    cost: usize,
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
    /// The byte budget for the entries: `max_bytes` minus the table reserve.
    entry_budget: usize,
    /// The sum of the costs of the entries in the map.
    used: usize,
    /// The bytes reserved for the hash table.
    reserved: usize,
}

impl<V> Cache<V> {
    /// Makes a cache with room for `max_entries` entries and `max_bytes` bytes. 0 entries
    /// turns the cache off. A byte budget that is too small for one entry also turns the
    /// cache off.
    ///
    /// The hash table gets a slot for each entry that can fit: the lower of `max_entries`
    /// and `max_bytes / (ENTRY_OVERHEAD + SLOT_BYTES)`.
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        let slots = max_entries.min(max_bytes / (ENTRY_OVERHEAD + SLOT_BYTES));
        let reserved = slots.saturating_mul(SLOT_BYTES);
        Self {
            map: NonZeroUsize::new(slots).map(LruCache::new),
            entry_budget: max_bytes.saturating_sub(reserved),
            used: 0,
            reserved,
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

    /// The bytes that the cache counts now: the table reserve and the cost of each entry.
    /// Never more than `max_bytes`.
    pub fn bytes(&self) -> usize {
        self.reserved.saturating_add(self.used)
    }

    /// Stores `value` (`size` bytes) under `key` for `ttl` seconds from `now_ms`. Replaces
    /// an older entry. Removes the least recently used entries until the new one fits.
    ///
    /// Returns false (and stores nothing) when the cache is off, `ttl` is 0, or the entry
    /// is larger than the byte budget. An older entry with the same key is removed in that
    /// case too, so a stale answer cannot stay.
    pub fn insert(&mut self, key: CacheKey, value: V, size: usize, ttl: u32, now_ms: u64) -> bool {
        let Some(map) = &mut self.map else {
            return false;
        };
        if let Some(old) = map.pop(&key) {
            self.used = self.used.saturating_sub(old.cost);
        }
        let cost = entry_cost(&key, size);
        if ttl == 0 || cost > self.entry_budget {
            return false;
        }
        // Bounded: each step removes one entry, and the map has `len` entries.
        let len = map.len();
        for _ in 0..=len {
            let fits =
                map.len() < map.cap().get() && self.used.saturating_add(cost) <= self.entry_budget;
            if fits {
                break;
            }
            match map.pop_lru() {
                Some((_, old)) => self.used = self.used.saturating_sub(old.cost),
                None => break,
            }
        }
        // The loop made room, so `push` removes nothing. If it does, the cost of the
        // removed entry still leaves the count.
        if let Some((_, old)) = map.push(
            key,
            Entry {
                value,
                stored_ms: now_ms,
                ttl,
                cost,
            },
        ) {
            self.used = self.used.saturating_sub(old.cost);
        }
        self.used = self.used.saturating_add(cost);
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
            if let Some(old) = map.pop(key) {
                self.used = self.used.saturating_sub(old.cost);
            }
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

    /// Removes the entry for `key`. Returns true when an entry was removed.
    pub fn remove(&mut self, key: &CacheKey) -> bool {
        let Some(map) = &mut self.map else {
            return false;
        };
        match map.pop(key) {
            Some(old) => {
                self.used = self.used.saturating_sub(old.cost);
                true
            }
            None => false,
        }
    }

    /// Removes all entries.
    pub fn clear(&mut self) {
        if let Some(map) = &mut self.map {
            map.clear();
        }
        self.used = 0;
    }

    /// The sum of the entry costs, computed from the entries. Tests compare it with the
    /// running count.
    #[cfg(test)]
    fn sum_of_costs(&self) -> usize {
        self.map
            .as_ref()
            .map_or(0, |m| m.iter().map(|(_, e)| e.cost).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    /// A byte budget that never limits the unit tests.
    const BIG: usize = 1 << 40;

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
        let mut c = Cache::new(8, BIG);
        assert!(c.insert(key("a."), 7, 0, 10, 1_000));
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
        let mut c = Cache::new(8, BIG);
        assert!(c.insert(key("a."), 1, 0, 10, 0));
        assert!(!c.insert(key("a."), 2, 0, 0, 0));
        assert!(c.get(&key("a."), 0).is_none());
    }

    #[test]
    fn disabled_cache_stores_nothing() {
        let mut c: Cache<u8> = Cache::new(0, BIG);
        assert!(!c.is_enabled());
        assert!(!c.insert(key("a."), 1, 0, 10, 0));
        assert!(c.get(&key("a."), 0).is_none());
        assert_eq!(c.capacity(), 0);
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let mut c = Cache::new(2, BIG);
        c.insert(key("a."), 1, 0, 100, 0);
        c.insert(key("b."), 2, 0, 100, 0);
        assert!(c.get(&key("a."), 1).is_some());
        c.insert(key("c."), 3, 0, 100, 2);
        assert_eq!(c.len(), 2);
        assert!(c.get(&key("b."), 3).is_none());
        assert!(c.get(&key("a."), 3).is_some());
        assert!(c.get(&key("c."), 3).is_some());
    }

    #[test]
    fn clock_going_back_gives_age_zero() {
        let mut c = Cache::new(2, BIG);
        c.insert(key("a."), 1, 0, 5, 10_000);
        let h = c.get(&key("a."), 0).unwrap();
        assert_eq!((h.remaining, h.age), (5, 0));
    }

    #[test]
    fn huge_ttl_and_time_do_not_overflow() {
        let mut c = Cache::new(2, BIG);
        c.insert(key("a."), 1, 0, u32::MAX, u64::MAX - 5);
        assert!(c.get(&key("a."), u64::MAX - 1).is_some());
        assert!(c.get(&key("a."), u64::MAX).is_none());
    }

    #[test]
    fn byte_budget_evicts_least_recently_used() {
        // Room for the table and about three entries of 100 bytes.
        let one = entry_cost(&key("a."), 100);
        let budget = 3 * one + 4 * SLOT_BYTES + 10;
        let mut c: Cache<u8> = Cache::new(100, budget);
        assert_eq!(c.capacity(), 4);
        for (i, k) in ["a.", "b.", "c."].iter().enumerate() {
            assert!(c.insert(key(k), u8::try_from(i).unwrap(), 100, 60, 0));
        }
        assert_eq!(c.len(), 3);
        assert!(c.get(&key("a."), 1).is_some());
        // A larger entry removes the least recently used entries until it fits.
        assert!(c.insert(key("d."), 9, 150, 60, 2));
        assert!(c.get(&key("b."), 3).is_none());
        assert!(c.get(&key("c."), 3).is_none());
        assert!(c.get(&key("a."), 3).is_some());
        assert!(c.get(&key("d."), 3).is_some());
        assert!(c.bytes() <= budget);
        assert_eq!(c.used, c.sum_of_costs());
    }

    #[test]
    fn too_large_entry_is_refused_and_removes_the_old_one() {
        let budget = 4 * (ENTRY_OVERHEAD + SLOT_BYTES);
        let mut c: Cache<u8> = Cache::new(100, budget);
        assert!(c.insert(key("a."), 1, 10, 60, 0));
        assert!(!c.insert(key("a."), 2, budget, 60, 0));
        assert!(c.get(&key("a."), 0).is_none());
        assert_eq!(c.bytes(), c.reserved);
    }

    #[test]
    fn tiny_budget_turns_the_cache_off() {
        let c: Cache<u8> = Cache::new(100, ENTRY_OVERHEAD);
        assert!(!c.is_enabled());
        assert_eq!(c.bytes(), 0);
    }

    #[test]
    fn remove_clear_and_expiry_give_the_bytes_back() {
        let mut c: Cache<u8> = Cache::new(10, BIG);
        c.insert(key("a."), 1, 50, 1, 0);
        c.insert(key("b."), 2, 50, 60, 0);
        c.insert(key("c."), 3, 50, 60, 0);
        let all = c.used;
        assert!(c.remove(&key("b.")));
        assert!(!c.remove(&key("b.")));
        assert!(c.used < all);
        // "a." expires.
        assert!(c.get(&key("a."), 1_000).is_none());
        assert_eq!(c.used, entry_cost(&key("c."), 50));
        c.clear();
        assert_eq!(c.used, 0);
        assert!(c.is_empty());
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
        Insert {
            k: u8,
            size: usize,
            ttl: u32,
            now: u64,
        },
        Remove {
            k: u8,
        },
        Get {
            k: u8,
            now: u64,
        },
        Clear,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..12, 0usize..3000, 0u32..20, 0u64..60_000)
                .prop_map(|(k, size, ttl, now)| Op::Insert { k, size, ttl, now }),
            (0u8..12).prop_map(|k| Op::Remove { k }),
            (0u8..12, 0u64..60_000).prop_map(|(k, now)| Op::Get { k, now }),
            Just(Op::Clear),
        ]
    }

    proptest! {
        /// For any op sequence with any `now` (also going back):
        /// - a hit is never expired;
        /// - the served TTL (`remaining`) is in `1..=stored ttl`, and `age + remaining == ttl`;
        /// - the hit value is the last value stored under that key;
        /// - the size never exceeds `max_entries`;
        /// - the counted bytes equal the table reserve plus the sum of the entry costs, and
        ///   never exceed `max_bytes`.
        #[test]
        fn invariants_hold(
            max in 0usize..6,
            max_bytes in 0usize..8000,
            ops in proptest::collection::vec(op(), 0..200),
        ) {
            let mut c: Cache<u32> = Cache::new(max, max_bytes);
            let on = c.is_enabled();
            // Model: key -> (value, stored_ms, ttl) of the last insert with ttl > 0.
            let mut model: HashMap<u8, (u32, u64, u32)> = HashMap::new();
            for (i, op) in ops.into_iter().enumerate() {
                let tag = u32::try_from(i).unwrap();
                match op {
                    Op::Insert { k, size, ttl, now } => {
                        let name = format!("k{k}.");
                        let fits = entry_cost(&key(&name), size) <= c.entry_budget;
                        let stored = c.insert(key(&name), tag, size, ttl, now);
                        prop_assert_eq!(stored, on && ttl > 0 && fits);
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
                    Op::Remove { k } => {
                        c.remove(&key(&format!("k{k}.")));
                        model.remove(&k);
                    }
                    Op::Clear => {
                        c.clear();
                        model.clear();
                    }
                }
                prop_assert!(c.len() <= max);
                prop_assert_eq!(c.used, c.sum_of_costs());
                prop_assert!(c.bytes() <= max_bytes);
            }
        }
    }
}
