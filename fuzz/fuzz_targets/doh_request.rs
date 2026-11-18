#![no_main]
//! Fuzz the DoH request decoder (part P7): arbitrary method, path, query string, headers
//! and body. Nothing may panic. An accepted message has a full DNS header and is at most
//! 65535 bytes; the max-age helper takes any bytes.
//!
//! Input layout: byte 0 = flags (bits 0-1: method GET, POST, PUT or raw; bit 2: query
//! string present; bit 3: content type present; bit 4: content length present), then four
//! fields with a 1-byte length each (method if raw, path, query, content type), then a
//! 1-byte length and the content length, then the body.

use libfuzzer_sys::fuzz_target;
use rusthole_dns::doh_wire::{self, DohRequestParts, MAX_BODY};

/// Takes a field with a 1-byte length from the front of `data`.
fn field<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((&len, rest)) = data.split_first() else {
        return &[];
    };
    let n = usize::from(len).min(rest.len());
    let (f, rest) = rest.split_at(n);
    *data = rest;
    f
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, mut data)) = input.split_first() else {
        return;
    };
    let raw_method = String::from_utf8_lossy(field(&mut data)).into_owned();
    let path = String::from_utf8_lossy(field(&mut data)).into_owned();
    let query = String::from_utf8_lossy(field(&mut data)).into_owned();
    let content_type = field(&mut data);
    let content_length = field(&mut data);
    let body = data;
    let method = match flags & 3 {
        0 => "GET",
        1 => "POST",
        2 => "PUT",
        _ => raw_method.as_str(),
    };
    // Half of the inputs use the real path, so the deeper checks run.
    let path = if flags & 0x20 != 0 { "/dns-query" } else { path.as_str() };
    let parts = DohRequestParts {
        method,
        path,
        query: (flags & 4 != 0).then_some(query.as_str()),
        content_type: (flags & 8 != 0).then_some(content_type),
        content_length: (flags & 16 != 0).then_some(content_length),
        body,
    };
    if let Ok(msg) = doh_wire::decode_request(&parts) {
        assert!(msg.len() >= 12, "an accepted message has a DNS header");
        assert!(msg.len() <= MAX_BODY, "an accepted message is at most 65535 bytes");
    }
    if let Err(e) = doh_wire::decode_head(
        parts.method,
        parts.path,
        parts.query,
        parts.content_type,
        parts.content_length,
    ) {
        assert!(matches!(e.status(), 400 | 404 | 405 | 413 | 414 | 415));
    }
    let _ = doh_wire::reply_max_age(body);
});
