//! TOTP (RFC 6238): HMAC-SHA1, 6 digits, 30 s steps, a window of one step before and after.
//! Pure: the time is an input. A code is accepted only for a step after the last accepted
//! step, so a code cannot be used two times (amendment A7).

use ring::hmac;

/// The step length in seconds.
pub const STEP_SECONDS: i64 = 30;
/// Steps before and after the current step that are accepted.
pub const WINDOW: i64 = 1;
/// The number of digits.
pub const DIGITS: u32 = 6;
/// Bytes in a new secret (160 bits, the RFC 4226 recommendation).
pub const SECRET_BYTES: usize = 20;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn alphabet(idx: u64) -> char {
    let i = usize::try_from(idx & 31).unwrap_or(0);
    char::from(ALPHABET.get(i).copied().unwrap_or(b'A'))
}

/// RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet(buf >> bits));
        }
    }
    if bits > 0 {
        out.push(alphabet(buf << (5 - bits)));
    }
    out
}

/// Decodes RFC 4648 base32. Padding, spaces and lower case are accepted. `None` for
/// another character.
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        if c == b'=' || c == b' ' {
            continue;
        }
        let v = match c.to_ascii_uppercase() {
            u @ b'A'..=b'Z' => u - b'A',
            d @ b'2'..=b'7' => d - b'2' + 26,
            _ => return None,
        };
        buf = ((buf << 5) | u64::from(v)) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap_or(0));
        }
    }
    Some(out)
}

/// The step number of a Unix time.
pub fn step_of(unix: i64) -> i64 {
    unix.div_euclid(STEP_SECONDS)
}

/// The code for a step (RFC 4226 HOTP with the step as the counter).
pub fn code_at(key: &[u8], step: i64) -> u32 {
    let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let counter = u64::try_from(step).unwrap_or(0).to_be_bytes();
    let tag = hmac::sign(&k, &counter);
    let mac = tag.as_ref();
    let offset = usize::from(mac.last().copied().unwrap_or(0) & 0x0f);
    let word = mac
        .get(offset..offset + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(0, u32::from_be_bytes);
    (word & 0x7fff_ffff) % 10u32.pow(DIGITS)
}

/// Checks `code` at `now` against the secret (base32). Returns the step that matched, when
/// it is after `last_step`. A code must have exactly six digits.
pub fn verify(secret_b32: &str, code: &str, now: i64, last_step: Option<i64>) -> Option<i64> {
    let digits = usize::try_from(DIGITS).unwrap_or(6);
    if code.len() != digits || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let key = base32_decode(secret_b32)?;
    if key.is_empty() {
        return None;
    }
    let current = step_of(now);
    let mut found = None;
    // Check all steps of the window, so the time does not depend on which one matches.
    for step in (current - WINDOW)..=(current + WINDOW) {
        let ok = crate::util::ct_eq(&code_at(&key, step).to_be_bytes(), &want.to_be_bytes());
        if ok && last_step.is_none_or(|l| step > l) && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// A new random secret in base32.
pub fn new_secret() -> Result<String, getrandom::Error> {
    Ok(base32_encode(&crate::util::random_bytes::<SECRET_BYTES>()?))
}

/// The `otpauth://` URI for an authenticator app.
pub fn otpauth_uri(secret_b32: &str) -> String {
    format!(
        "otpauth://totp/rusthole:admin?secret={secret_b32}&issuer=rusthole&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 appendix B, SHA-1 key "12345678901234567890", 8-digit codes. The last six
        // digits are the 6-digit code.
        let key = b"12345678901234567890";
        for (t, code8) in [
            (59, 94_287_082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
        ] {
            assert_eq!(code_at(key, step_of(t)), code8 % 1_000_000, "t={t}");
        }
    }

    #[test]
    fn base32_rfc4648_vectors() {
        for (raw, enc) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(raw.as_bytes()), enc);
            assert_eq!(base32_decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert!(base32_decode("MZ1").is_none());
    }

    #[test]
    fn window_and_reuse() {
        let secret = base32_encode(b"12345678901234567890");
        let now = 1_111_111_111;
        let code = |t: i64| format!("{:06}", code_at(b"12345678901234567890", step_of(t)));
        assert_eq!(verify(&secret, &code(now), now, None), Some(step_of(now)));
        // One step before and after: accepted. Two: refused.
        assert!(verify(&secret, &code(now - 30), now, None).is_some());
        assert!(verify(&secret, &code(now + 30), now, None).is_some());
        assert!(verify(&secret, &code(now - 60), now, None).is_none());
        // A code of an accepted step (or an older one) is refused.
        let used = step_of(now);
        assert!(verify(&secret, &code(now), now, Some(used)).is_none());
        assert!(verify(&secret, &code(now - 30), now, Some(used)).is_none());
        assert!(verify(&secret, &code(now + 30), now, Some(used)).is_some());
        assert!(verify(&secret, "12345", now, None).is_none());
        assert!(verify(&secret, "12a456", now, None).is_none());
    }

    #[test]
    fn uri_has_the_parameters() {
        let s = new_secret().unwrap();
        assert_eq!(s.len(), 32);
        assert!(otpauth_uri(&s).contains("&period=30"));
    }

    proptest! {
        #[test]
        fn base32_round_trip(data in prop::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(base32_decode(&base32_encode(&data)), Some(data));
        }
    }
}
