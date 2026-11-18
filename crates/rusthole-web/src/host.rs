//! The `Host` header check (decision D9: a DNS rebinding defence) and the cross-site check
//! of write requests (m12). Pure.
//!
//! A request must name this server: a configured TLS name, `localhost`, `127.0.0.1` or a
//! local IPv4 address, with the admin port. Without a port the request is valid only when the
//! admin port is 443 (the HTTPS default). Other hosts get 421.
//!
//! A write request (not `GET` or `HEAD`) from a page of another site gets 403 before the
//! auth and the login ban see it ([`cross_site`]). Else such a page can send failed logins
//! with no preflight and lock the address of the admin's browser.

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// The longest `Host` value that the check reads.
pub const MAX_HOST_LEN: usize = 300;

/// The names and addresses that a request can use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAllow {
    names: HashSet<String>,
    addrs: HashSet<Ipv4Addr>,
    port: u16,
}

impl HostAllow {
    /// The list for `port`, the configured TLS names and the local addresses. `localhost`
    /// and `127.0.0.1` are always in it.
    pub fn new<'a>(
        port: u16,
        names: impl IntoIterator<Item = &'a str>,
        addrs: impl IntoIterator<Item = Ipv4Addr>,
    ) -> Self {
        let mut n: HashSet<String> = names
            .into_iter()
            .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        n.insert("localhost".to_owned());
        let mut a: HashSet<Ipv4Addr> = addrs.into_iter().collect();
        a.insert(Ipv4Addr::LOCALHOST);
        Self {
            names: n,
            addrs: a,
            port,
        }
    }

    /// The admin port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// True when `host` (the value of the `Host` header or the HTTP/2 `:authority`) names this
/// server.
pub fn host_allowed(host: &str, allow: &HostAllow) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN || host.starts_with('[') {
        // An IPv6 literal: v1 listens on IPv4 only (amendment A11).
        return false;
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            match p.parse::<u16>() {
                Ok(p) => (n, Some(p)),
                Err(_) => return false,
            }
        }
        None => (host, None),
    };
    match port {
        Some(p) if p != allow.port => return false,
        None if allow.port != 443 => return false,
        _ => {}
    }
    if name.contains(':') {
        return false;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return false;
    }
    if let Ok(ip) = name.parse::<Ipv4Addr>() {
        return allow.addrs.contains(&ip);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return false;
    }
    allow.names.contains(&name.to_ascii_lowercase())
}

/// True when `origin` (the value of an `Origin` header) is this server over HTTPS: the
/// scheme `https`, then a host that [`host_allowed`] accepts. `null` and every other value
/// are refused.
pub fn origin_allowed(origin: &str, allow: &HostAllow) -> bool {
    let origin = origin.trim();
    let Some(scheme_end) = origin.find("://") else {
        return false;
    };
    let (scheme, rest) = origin.split_at(scheme_end);
    let Some(authority) = rest.strip_prefix("://") else {
        return false;
    };
    // An origin has no path, query or user part.
    if !scheme.eq_ignore_ascii_case("https") || authority.contains(['/', '?', '#', '@']) {
        return false;
    }
    host_allowed(authority, allow)
}

/// True when a request is a cross-site write that the server must refuse (403):
///
/// - The method is not `GET` or `HEAD` (they change nothing and count no login failure
///   from a browser: the session cookie is `SameSite=Strict`, and a page cannot add an
///   `Authorization` header with no preflight).
/// - `fetch_site` (the `Sec-Fetch-Site` header) is `cross-site`, or one `Origin` value is
///   not this server ([`origin_allowed`]).
///
/// A request with no `Origin` and no `Sec-Fetch-Site` passes: tools like curl and scripts
/// with an API token send neither. A browser always sends `Origin` with a write.
pub fn cross_site<'a>(
    method: &str,
    fetch_site: Option<&str>,
    origins: impl IntoIterator<Item = Option<&'a str>>,
    allow: &HostAllow,
) -> bool {
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    if fetch_site.is_some_and(|s| s.trim().eq_ignore_ascii_case("cross-site")) {
        return true;
    }
    // A value that is not text (`None`) is refused too.
    origins
        .into_iter()
        .any(|o| o.is_none_or(|o| !origin_allowed(o, allow)))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn origins() {
        let a = allow();
        for o in [
            "https://rusthole.lan:8443",
            "HTTPS://RUSTHOLE.LAN:8443",
            "https://127.0.0.1:8443",
            "https://192.0.2.2:8443",
            " https://localhost:8443 ",
        ] {
            assert!(origin_allowed(o, &a), "{o}");
        }
        for o in [
            "",
            "null",
            "http://rusthole.lan:8443",
            "https://rusthole.lan",
            "https://rusthole.lan:8443/",
            "https://rusthole.lan:8443/x",
            "https://user@rusthole.lan:8443",
            "https://evil.example:8443",
            "https://127.0.0.1:1",
            "file://",
            "https://",
            "rusthole.lan:8443",
        ] {
            assert!(!origin_allowed(o, &a), "{o}");
        }
    }

    #[test]
    fn cross_site_writes() {
        let a = allow();
        let ok = Some("https://rusthole.lan:8443");
        let evil = Some("https://evil.example");
        assert!(!cross_site("POST", None, [], &a));
        assert!(!cross_site("POST", Some("same-origin"), [ok], &a));
        assert!(!cross_site("POST", Some("none"), [], &a));
        assert!(cross_site("POST", None, [evil], &a));
        assert!(cross_site("POST", None, [ok, evil], &a));
        assert!(cross_site("POST", None, [None], &a));
        assert!(cross_site("POST", Some("cross-site"), [], &a));
        assert!(cross_site("DELETE", Some("Cross-Site"), [ok], &a));
        assert!(cross_site("PATCH", Some("same-origin"), [Some("null")], &a));
        assert!(!cross_site("GET", Some("cross-site"), [evil], &a));
        assert!(!cross_site("HEAD", None, [evil], &a));
    }

    fn allow() -> HostAllow {
        HostAllow::new(
            8443,
            ["rusthole.lan", "Admin.Example."],
            [Ipv4Addr::new(192, 0, 2, 2)],
        )
    }

    #[test]
    fn allowed_hosts() {
        let a = allow();
        for h in [
            "localhost:8443",
            "127.0.0.1:8443",
            "192.0.2.2:8443",
            "rusthole.lan:8443",
            "RUSTHOLE.LAN:8443",
            "admin.example:8443",
            "rusthole.lan.:8443",
        ] {
            assert!(host_allowed(h, &a), "{h}");
        }
    }

    #[test]
    fn refused_hosts() {
        let a = allow();
        for h in [
            "",
            "evil.example:8443",
            "rusthole.lan",
            "rusthole.lan:443",
            "192.0.2.3:8443",
            "[::1]:8443",
            "localhost:8443:1",
            "localhost:",
            "localhost:99999",
            "local host:8443",
            "rusthole.lan.evil.example:8443",
            ":8443",
            "127.0.0.1:+8443",
        ] {
            assert!(!host_allowed(h, &a), "{h}");
        }
    }

    #[test]
    fn port_443_allows_no_port() {
        let a = HostAllow::new(443, [], []);
        assert!(host_allowed("localhost", &a));
        assert!(host_allowed("localhost:443", &a));
        assert!(!host_allowed("localhost:8443", &a));
    }

    proptest! {
        /// No input panics, and an allowed host always has the admin port (or none for 443).
        #[test]
        fn never_panics(h in ".{0,320}") {
            let a = allow();
            if host_allowed(&h, &a) {
                prop_assert!(h.ends_with(":8443"));
            }
        }

        /// No input panics. An allowed origin is `https://` and an allowed host; a write with
        /// an origin that is not allowed is always refused, and a read never.
        #[test]
        fn origin_never_panics(o in ".{0,320}", site in proptest::option::of(".{0,20}")) {
            let a = allow();
            let allowed = origin_allowed(&o, &a);
            if allowed {
                let t = o.trim();
                prop_assert!(t.get(..8).is_some_and(|p| p.eq_ignore_ascii_case("https://")));
                prop_assert!(host_allowed(t.get(8..).unwrap_or_default(), &a));
            }
            let write = cross_site("POST", site.as_deref(), [Some(o.as_str())], &a);
            if !allowed {
                prop_assert!(write);
            }
            prop_assert!(!cross_site("GET", site.as_deref(), [Some(o.as_str())], &a));
        }
    }
}
