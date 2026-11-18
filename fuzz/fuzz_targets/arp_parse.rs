#![no_main]
//! Fuzz the `/proc/net/arp` parser: no panic, the snapshot stays within its size limit, and
//! it never holds the all-zero MAC address.

use libfuzzer_sys::fuzz_target;
use rusthole_dns::neighbors::{MAX_NEIGHBORS, parse_arp};

fuzz_target!(|data: &[u8]| {
    let snap = parse_arp(data);
    assert!(snap.len() <= MAX_NEIGHBORS, "the snapshot is too large");
    assert!(snap.values().all(|m| m.0 != [0; 6]), "an incomplete entry was kept");
});
