//! Small helpers: time stamps, random bytes, base64url, hashes, constant-time compare.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq;

/// Formats Unix seconds as an RFC 3339 time stamp in UTC, for example
/// `2026-11-17T08:30:00Z` (docs/API.md section 1).
pub fn rfc3339(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

/// Like [`rfc3339`], for an optional time.
pub fn rfc3339_opt(unix: Option<i64>) -> Option<String> {
    unix.map(rfc3339)
}

/// `n` random bytes from the OS random source.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b)?;
    Ok(b)
}

/// base64url without padding.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding.
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Compares two byte strings in constant time (for equal lengths). Different lengths give
/// false at once; the lengths of the CSRF token and the hashes are not secret.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn time_stamps_are_utc_with_z() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_794_903_000), "2026-11-17T08:10:00Z");
    }

    #[test]
    fn hex_and_hash() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    proptest! {
        /// The constant-time compare gives the same answer as `==`.
        #[test]
        fn ct_eq_matches_eq(a in prop::collection::vec(any::<u8>(), 0..64), b in prop::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(ct_eq(&a, &b), a == b);
            prop_assert!(ct_eq(&a, &a));
        }

        #[test]
        fn b64url_round_trip(a in prop::collection::vec(any::<u8>(), 0..64)) {
            let text = b64url(&a);
            prop_assert!(text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
            prop_assert_eq!(b64url_decode(&text), Some(a));
        }
    }
}
