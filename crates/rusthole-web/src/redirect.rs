//! HTTP to HTTPS redirect on the admin port (docs/SECURITY.md section 2).
//!
//! A browser that opens `http://host:8443/` sends plain HTTP to the TLS port. The listener
//! looks at the first byte of a new connection: a TLS record starts with `0x16`; a plain
//! HTTP request starts with a method name in capital letters. For plain HTTP, the listener
//! reads the request head (bounded) and answers with a redirect to the same address over
//! HTTPS, then closes. It never serves the API over plain HTTP.
//!
//! ```mermaid
//! flowchart LR
//!     c[new connection] --> p{first byte}
//!     p -->|0x16| t[TLS handshake, normal path]
//!     p -->|A-Z| h[read the head, at most 8 KiB]
//!     p -->|other| x[close]
//!     h --> k{Host passes the host check?}
//!     k -->|yes| r[301 to https://Host/path]
//!     k -->|no| b[400, no Location]
//! ```
//!
//! The functions here are pure, with unit and property tests and the fuzz target
//! `http_redirect`.

use crate::host::{HostAllow, host_allowed};

/// The most bytes of a request head that the redirect reads.
pub const MAX_HEAD: usize = 8 * 1024;
/// The longest request target that the redirect keeps. A longer target becomes `/`.
pub const MAX_TARGET: usize = 2048;

/// What the first byte of a connection shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstByte {
    /// A TLS handshake record.
    Tls,
    /// Probably a plain HTTP request (a method name in capital letters).
    Http,
    /// Something else: close the connection.
    Other,
}

/// Classifies the first byte of a connection.
pub fn classify(b: u8) -> FirstByte {
    match b {
        0x16 => FirstByte::Tls,
        b'A'..=b'Z' => FirstByte::Http,
        _ => FirstByte::Other,
    }
}

/// True when `buf` holds a full request head (it ends with an empty line).
pub fn head_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n")
}

/// The request target to keep: an origin form (`/path?query`) of visible ASCII, at most
/// [`MAX_TARGET`] bytes. Any other target becomes `/`.
fn safe_target(target: &str) -> &str {
    let ok = target.starts_with('/')
        && !target.starts_with("//")
        && target.len() <= MAX_TARGET
        && target.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if ok { target } else { "/" }
}

/// The `Host` value of a request head, trimmed.
fn host_of(head: &str) -> Option<&str> {
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case("host").then(|| v.trim())
    })
}

/// The full answer (status line, headers and body) for a plain HTTP request head.
///
/// - The `Host` passes [`host_allowed`]: 301 to `https://{Host}{target}`.
/// - Else: 400 with no `Location`, so the redirect is never an open redirect.
///
/// The answer always has `Connection: close`.
pub fn answer(head: &[u8], allow: &HostAllow) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut first = text.lines().next().unwrap_or_default().split(' ');
    let _method = first.next();
    let target = safe_target(first.next().unwrap_or("/"));
    let location = host_of(&text)
        .filter(|h| host_allowed(h, allow))
        .map(|h| format!("https://{h}{target}"));
    if let Some(loc) = location {
        let body = format!("Use HTTPS: {loc}\n");
        return format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {loc}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
    }
    let body = "This port needs HTTPS.\n";
    format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests: a failure is a test failure.
mod tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use super::*;

    fn allow() -> HostAllow {
        HostAllow::new(8443, ["pi.lan"], [Ipv4Addr::new(192, 168, 50, 150)])
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8(b.to_vec()).unwrap()
    }

    #[test]
    fn classify_first_bytes() {
        assert_eq!(classify(0x16), FirstByte::Tls);
        assert_eq!(classify(b'G'), FirstByte::Http);
        assert_eq!(classify(b'P'), FirstByte::Http);
        assert_eq!(classify(b'g'), FirstByte::Other);
        assert_eq!(classify(0), FirstByte::Other);
    }

    #[test]
    fn redirects_to_the_same_host_and_path() {
        let a = text(&answer(
            b"GET /#/domains?x=1 HTTP/1.1\r\nHost: 192.168.50.150:8443\r\nUser-Agent: t\r\n\r\n",
            &allow(),
        ));
        assert!(a.starts_with("HTTP/1.1 301 "), "{a}");
        assert!(
            a.contains("\r\nLocation: https://192.168.50.150:8443/#/domains?x=1\r\n"),
            "{a}"
        );
        assert!(a.contains("\r\nConnection: close\r\n"));
        let a = text(&answer(
            b"GET /api/v1/system HTTP/1.1\r\nhOsT:pi.lan:8443\r\n\r\n",
            &allow(),
        ));
        assert!(
            a.contains("Location: https://pi.lan:8443/api/v1/system\r\n"),
            "{a}"
        );
    }

    #[test]
    fn unknown_or_missing_host_gets_400_with_no_location() {
        for head in [
            &b"GET / HTTP/1.1\r\nHost: evil.example:8443\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: 192.168.50.150:80\r\n\r\n",
            b"GET / HTTP/1.0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n",
        ] {
            let a = text(&answer(head, &allow()));
            assert!(a.starts_with("HTTP/1.1 400 "), "{a}");
            assert!(!a.contains("Location"), "{a}");
        }
    }

    #[test]
    fn odd_targets_become_slash() {
        for target in [
            "http://evil.example/",
            "//evil.example/x",
            "*",
            "/a\u{7f}b",
            &format!("/{}", "a".repeat(MAX_TARGET)),
        ] {
            let head = format!("GET {target} HTTP/1.1\r\nHost: pi.lan:8443\r\n\r\n");
            let a = text(&answer(head.as_bytes(), &allow()));
            assert!(
                a.contains("Location: https://pi.lan:8443/\r\n"),
                "{target}: {a}"
            );
        }
    }

    #[test]
    fn head_end() {
        assert!(head_complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
        assert!(head_complete(b"GET / HTTP/1.0\n\n"));
        assert!(!head_complete(b"GET / HTTP/1.1\r\nHost: a\r\n"));
    }

    proptest! {
        /// Any head gives one status line and, when there is a Location, it points to an
        /// allowed host over HTTPS on one line (no header injection).
        #[test]
        fn answer_is_safe(head in proptest::collection::vec(any::<u8>(), 0..600)) {
            let a = String::from_utf8(answer(&head, &allow())).unwrap();
            prop_assert!(a.starts_with("HTTP/1.1 301 ") || a.starts_with("HTTP/1.1 400 "));
            let (headers, _) = a.split_once("\r\n\r\n").unwrap();
            for line in headers.split("\r\n") {
                prop_assert!(!line.contains('\n') && !line.contains('\r'));
                if let Some(loc) = line.strip_prefix("Location: ") {
                    prop_assert!(loc.starts_with("https://pi.lan:8443/") || loc.starts_with("https://192.168.50.150:8443/")
                        || loc.starts_with("https://localhost:8443/") || loc.starts_with("https://127.0.0.1:8443/"), "{}", loc);
                }
            }
        }
    }
}
