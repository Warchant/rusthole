#![no_main]
//! Fuzz the cache with any op sequence and any `now` (also going back). The invariants:
//! a hit is never expired, the served TTL is in `1..=stored TTL`, the hit value is the last
//! value stored under the key, and the size never exceeds `max_entries`.

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
    let mut cache: Cache<u64> = Cache::new(max);
    let mut model: HashMap<u8, (u64, u64, u32)> = HashMap::new();
    let mut tag = 0u64;
    for _ in 0..1000 {
        let Some(op) = input.byte() else {
            break;
        };
        tag += 1;
        match op % 3 {
            0 => {
                let (Some(k), Some(ttl), Some(now)) = (input.byte(), input.u32(), input.u64())
                else {
                    break;
                };
                let stored = cache.insert(key(k), tag, ttl, now);
                assert_eq!(stored, max > 0 && ttl > 0);
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
            _ => {
                cache.clear();
                model.clear();
            }
        }
        assert!(cache.len() <= max);
    }
});
