//! The `Host` header check (decision D9: a DNS rebinding defence). Pure.
//!
//! A request must name this server: a configured TLS name, `localhost`, `127.0.0.1` or a
//! local IPv4 address, with the admin port. Without a port the request is valid only when the
//! admin port is 443 (the HTTPS default). Other hosts get 421.

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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

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
    }
}
