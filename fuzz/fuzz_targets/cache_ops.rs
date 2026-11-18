#![no_main]
//! Fuzz the cache with any op sequence, any entry size, any byte budget and any `now` (also
//! going back). The invariants: a hit is never expired, the served TTL is in
//! `1..=stored TTL`, the hit value is the last value stored under the key, the size never
//! exceeds `max_entries`, and the counted bytes never exceed `max_bytes`.

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use rusthole_core::cache::{Cache, CacheKey};

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn u32(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 8) | u32::from(self.byte()?);
        }
        Some(v)
    }

    fn u64(&mut self) -> Option<u64> {
        Some((u64::from(self.u32()?) << 32) | u64::from(self.u32()?))
    }
}

fn key(k: u8) -> CacheKey {
    // Two case forms of the same name give the same key.
    let name = if k & 0x80 != 0 {
        format!("K{}.Example.", k & 0x0f)
    } else {
        format!("k{}.example.", k & 0x0f)
    };
    CacheKey::new(&name, 1, 1, k & 0x40 != 0)
}

fn model_key(k: u8) -> u8 {
    k & 0x4f
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(max) = input.byte() else {
        return;
    };
    let max = usize::from(max % 8);
    let Some(budget) = input.u32() else {
        return;
    };
    let max_bytes = usize::try_from(budget % 20_000).unwrap_or(0);
    let mut cache: Cache<u64> = Cache::new(max, max_bytes);
    let on = cache.is_enabled();
    let mut model: HashMap<u8, (u64, u64, u32)> = HashMap::new();
    let mut tag = 0u64;
    for _ in 0..1000 {
        let Some(op) = input.byte() else {
            break;
        };
        tag += 1;
        match op % 4 {
            0 => {
                let (Some(k), Some(size), Some(ttl), Some(now)) =
                    (input.byte(), input.u32(), input.u32(), input.u64())
                else {
                    break;
                };
                let size = usize::try_from(size % 5000).unwrap_or(0);
                let stored = cache.insert(key(k), tag, size, ttl, now);
                if stored {
                    assert!(on && ttl > 0, "stored in an off cache or with TTL 0");
                }
                if !on || ttl == 0 {
                    assert!(!stored);
                }
                if stored {
                    model.insert(model_key(k), (tag, now, ttl));
                } else {
                    model.remove(&model_key(k));
                }
            }
            1 => {
                let (Some(k), Some(now)) = (input.byte(), input.u64()) else {
                    break;
                };
                if let Some(hit) = cache.get(&key(k), now) {
                    let (value, stored_ms, ttl) =
                        *model.get(&model_key(k)).expect("a hit must be in the model");
                    let expires = stored_ms.saturating_add(u64::from(ttl).saturating_mul(1000));
                    assert!(now < expires, "expired hit");
                    assert_eq!(*hit.value, value);
                    assert_eq!(hit.ttl, ttl);
                    assert!(hit.remaining >= 1 && hit.remaining <= ttl);
                    assert_eq!(hit.age + hit.remaining, ttl);
                }
            }
            2 => {
                let Some(k) = input.byte() else {
                    break;
                };
                cache.remove(&key(k));
                model.remove(&model_key(k));
            }
            _ => {
                cache.clear();
                model.clear();
            }
        }
        assert!(cache.len() <= max);
        assert!(cache.bytes() <= max_bytes, "over the byte budget");
    }
});
