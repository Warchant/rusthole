#![no_main]
//! Fuzz the DoT frame reader (part P7): an arbitrary byte stream in arbitrary chunks.
//! Nothing may panic, each frame has a full DNS header, and the buffer stays within its
//! limit.
//!
//! Input layout: byte 0 = chunk size seed, then the stream.

use libfuzzer_sys::fuzz_target;
use rusthole_dns::dot_frame::{FrameReader, MAX_BUFFER, MAX_CHUNK};

fuzz_target!(|input: &[u8]| {
    let Some((&seed, stream)) = input.split_first() else {
        return;
    };
    let chunk = (usize::from(seed) * 97 % MAX_CHUNK).max(1);
    let mut reader = FrameReader::new();
    let mut frames_bytes = 0usize;
    for part in stream.chunks(chunk) {
        if reader.push(part).is_err() {
            return;
        }
        assert!(reader.buffered() <= MAX_BUFFER);
        // Each frame takes at least 14 bytes, so this bound is never reached.
        for _ in 0..=MAX_BUFFER {
            match reader.next_frame() {
                Ok(Some(f)) => {
                    assert!(f.len() >= 12);
                    frames_bytes += f.len() + 2;
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
    assert!(frames_bytes + reader.buffered() == stream.len());
});
