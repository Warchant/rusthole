//! Name lookup for list downloads.
//!
//! Downloads do not use the system resolver. A host whose `/etc/resolv.conf` points at
//! rusthole itself must still be able to fetch its lists at start. The production lookup is
//! [`rusthole_dns::HostResolver`]: it asks the upstream pool of the DNS server directly.
//!
//! [`LocalFirstLookup`] looks in the local zone of the current config first (local records
//! and local CNAMEs), then asks the upstream lookup. Thus a list URL with a local host name
//! (for example `http://nas.lan/list.txt`) works, as in Pi-hole. Conditional forwarding is
//! not used here: a name that only a conditional forwarding rule knows goes to the upstream
//! lookup (docs/LISTS.md).
//!
//! ```mermaid
//! flowchart LR
//!     h[host of the list URL] --> z{local zone}
//!     z -->|local A records| a[these addresses]
//!     z -->|local CNAME to a name that is not local| u2[upstream lookup of the target]
//!     z -->|local name with no A record| e[error]
//!     z -->|not local| u[upstream lookup]
//! ```
//!
//! [`ReqwestResolver`] adapts a [`HostLookup`] to the resolver trait of `reqwest`. A URL
//! with an IP address does not call the resolver.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rusthole_core::DomainName;
use rusthole_core::localdns::{LocalAnswer, LocalData, LocalZone, qtype};

/// Time limit for one name lookup.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

/// A boxed future of a lookup.
pub type LookupFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, LookupError>> + Send + 'a>>;

/// Why a lookup failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot resolve {host}: {reason}")]
pub struct LookupError {
    /// The host name.
    pub host: String,
    /// A short reason.
    pub reason: String,
}

/// Finds the addresses of a host name.
pub trait HostLookup: Send + Sync + fmt::Debug {
    /// The addresses of `host` (an ASCII host name from a URL).
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a>;
}

impl HostLookup for rusthole_dns::HostResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        Box::pin(async move {
            let err = |reason: String| LookupError {
                host: host.to_owned(),
                reason,
            };
            let name = DomainName::parse(host).map_err(|e| err(e.to_string()))?;
            let addrs = self
                .resolve_ipv4(&name)
                .await
                .map_err(|e| err(e.to_string()))?;
            Ok(addrs.into_iter().map(IpAddr::V4).collect())
        })
    }
}

/// The most addresses that a local lookup gives (the same bound as the upstream lookup).
pub const MAX_LOCAL_ADDRESSES: usize = 16;

/// What the local zone says about the host name of a list URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalHost {
    /// The local IPv4 addresses of the name, or of the last name of its local CNAME chain.
    /// At most [`MAX_LOCAL_ADDRESSES`].
    Addrs(Vec<IpAddr>),
    /// A local CNAME chain ends at this name, which is not local: look it up upstream.
    Alias(DomainName),
    /// The name is local, but it has no IPv4 address (for example an AAAA record only, a
    /// CNAME loop or a chain that is too long). v1 uses IPv4 transport only (A11).
    NoAddress,
    /// The local zone does not have the name: look it up upstream.
    NotLocal,
}

/// Looks up `name` in the local zone (pure). See [`LocalHost`].
pub fn local_host(zone: &LocalZone, name: &DomainName) -> LocalHost {
    let LocalAnswer::Answer(records) = zone.lookup(name, qtype::A) else {
        // Not local, a conditional forward or a private reverse name.
        return LocalHost::NotLocal;
    };
    let addrs: Vec<IpAddr> = records
        .iter()
        .filter_map(|r| match r.data {
            LocalData::A(a) => Some(IpAddr::V4(a)),
            _ => None,
        })
        .take(MAX_LOCAL_ADDRESSES)
        .collect();
    if !addrs.is_empty() {
        return LocalHost::Addrs(addrs);
    }
    // The chain stops at its last CNAME target. When that target is not local, the
    // upstreams know it. A target that is local (an AAAA record only, a loop, the chain
    // bound) has no IPv4 address.
    match records.last().map(|r| &r.data) {
        Some(LocalData::Cname(target))
            if !matches!(zone.lookup(target, qtype::A), LocalAnswer::Answer(_)) =>
        {
            LocalHost::Alias(target.clone())
        }
        _ => LocalHost::NoAddress,
    }
}

/// A [`HostLookup`] that looks in the local zone first (see the module documentation).
///
/// The zone is shared: the refresher stores a new zone at each config change, and the next
/// lookup uses it.
#[derive(Debug, Clone)]
pub struct LocalFirstLookup {
    zone: Arc<ArcSwap<LocalZone>>,
    upstream: Arc<dyn HostLookup>,
}

impl LocalFirstLookup {
    /// A lookup that reads `zone` first, then asks `upstream`.
    pub fn new(zone: Arc<ArcSwap<LocalZone>>, upstream: Arc<dyn HostLookup>) -> Self {
        Self { zone, upstream }
    }
}

impl HostLookup for LocalFirstLookup {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        let Ok(name) = DomainName::parse_idn(host) else {
            // Not a name that the local zone can hold.
            return self.upstream.lookup(host);
        };
        match local_host(&self.zone.load(), &name) {
            LocalHost::Addrs(addrs) => Box::pin(std::future::ready(Ok(addrs))),
            LocalHost::NoAddress => Box::pin(std::future::ready(Err(LookupError {
                host: host.to_owned(),
                reason: "the local DNS record of this name has no IPv4 address".to_owned(),
            }))),
            LocalHost::Alias(target) => Box::pin(async move {
                self.upstream
                    .lookup(target.as_str())
                    .await
                    .map_err(|e| LookupError {
                        host: host.to_owned(),
                        reason: format!("local CNAME to {}: {}", target.as_str(), e.reason),
                    })
            }),
            LocalHost::NotLocal => self.upstream.lookup(host),
        }
    }
}

/// A fixed table of host names, for tests and for hosts with no DNS.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    hosts: HashMap<String, Vec<IpAddr>>,
}

impl StaticResolver {
    /// An empty table: each lookup fails.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `host` with `addrs`. The match ignores ASCII case.
    #[must_use]
    pub fn with(mut self, host: &str, addrs: &[IpAddr]) -> Self {
        self.hosts.insert(host.to_ascii_lowercase(), addrs.to_vec());
        self
    }
}

impl HostLookup for StaticResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        let result = self
            .hosts
            .get(&host.to_ascii_lowercase())
            .filter(|a| !a.is_empty())
            .cloned()
            .ok_or_else(|| LookupError {
                host: host.to_owned(),
                reason: "the name is not in the table".to_owned(),
            });
        Box::pin(std::future::ready(result))
    }
}

/// Adapts a [`HostLookup`] to `reqwest`. Each lookup has the time limit
/// [`LOOKUP_TIMEOUT`].
#[derive(Debug, Clone)]
pub struct ReqwestResolver {
    lookup: Arc<dyn HostLookup>,
    timeout: Duration,
}

impl ReqwestResolver {
    /// An adapter for `lookup`.
    pub fn new(lookup: Arc<dyn HostLookup>) -> Self {
        Self {
            lookup,
            timeout: LOOKUP_TIMEOUT,
        }
    }
}

impl reqwest::dns::Resolve for ReqwestResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let lookup = Arc::clone(&self.lookup);
        let timeout = self.timeout;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = match tokio::time::timeout(timeout, lookup.lookup(&host)).await {
                Ok(Ok(a)) => a,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    return Err(LookupError {
                        host,
                        reason: "timeout".to_owned(),
                    }
                    .into());
                }
            };
            // Port 0: reqwest puts in the port of the URL or of the scheme.
            let addrs: reqwest::dns::Addrs =
                Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)] // Tests: a failure is a test failure.
mod tests {
    use std::net::Ipv4Addr;

    use rusthole_core::Config;
    use rusthole_core::config::{ConditionalForward, LocalCname, LocalRecord, RecordType};

    use super::*;

    fn record(name: &str, record_type: RecordType, value: &str) -> LocalRecord {
        LocalRecord {
            id: None,
            enabled: true,
            comment: None,
            name: name.to_owned(),
            record_type,
            value: value.to_owned(),
        }
    }

    fn cname(name: &str, target: &str) -> LocalCname {
        LocalCname {
            id: None,
            enabled: true,
            comment: None,
            name: name.to_owned(),
            target: target.to_owned(),
            ttl: None,
        }
    }

    /// A local zone: `nas.lan` (A), `v6.lan` (AAAA only), `www.lan` -> `nas.lan`,
    /// `out.lan` -> `lists.test` (not local), a loop `a.lan` <-> `b.lan`, `to-v6.lan` ->
    /// `v6.lan`, and a conditional forward for `corp`.
    fn zone() -> Arc<ArcSwap<LocalZone>> {
        let mut c = Config::default();
        c.local_dns.records = vec![
            record("nas.lan", RecordType::A, "192.0.2.10"),
            record("nas.lan", RecordType::A, "192.0.2.11"),
            record("v6.lan", RecordType::Aaaa, "2001:db8::10"),
        ];
        c.local_dns.cnames = vec![
            cname("www.lan", "nas.lan"),
            cname("out.lan", "lists.test"),
            cname("a.lan", "b.lan"),
            cname("b.lan", "a.lan"),
            cname("to-v6.lan", "v6.lan"),
        ];
        c.local_dns.conditional_forwarding = vec![ConditionalForward {
            id: None,
            comment: None,
            enabled: true,
            cidr: String::new(),
            server: "192.0.2.53".to_owned(),
            domain: Some("corp".to_owned()),
        }];
        let (z, issues) = LocalZone::from_config(&c);
        assert!(issues.is_empty(), "{issues:?}");
        Arc::new(ArcSwap::from_pointee(z))
    }

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn v4(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, a))
    }

    #[test]
    fn local_host_cases() {
        let z = zone();
        let z = z.load();
        assert_eq!(
            local_host(&z, &name("nas.lan")),
            LocalHost::Addrs(vec![v4(10), v4(11)])
        );
        assert_eq!(
            local_host(&z, &name("www.lan")),
            LocalHost::Addrs(vec![v4(10), v4(11)])
        );
        assert_eq!(
            local_host(&z, &name("out.lan")),
            LocalHost::Alias(name("lists.test"))
        );
        assert_eq!(local_host(&z, &name("v6.lan")), LocalHost::NoAddress);
        assert_eq!(local_host(&z, &name("to-v6.lan")), LocalHost::NoAddress);
        assert_eq!(local_host(&z, &name("a.lan")), LocalHost::NoAddress);
        // A conditional forward is not used for list downloads.
        assert_eq!(local_host(&z, &name("host.corp")), LocalHost::NotLocal);
        assert_eq!(local_host(&z, &name("lists.test")), LocalHost::NotLocal);
    }

    #[tokio::test]
    async fn local_first_lookup() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let upstream = Arc::new(StaticResolver::new().with("lists.test", &[ip]));
        let zone = zone();
        let l = LocalFirstLookup::new(Arc::clone(&zone), upstream);
        assert_eq!(l.lookup("NAS.lan").await.unwrap(), vec![v4(10), v4(11)]);
        assert_eq!(l.lookup("out.lan").await.unwrap(), vec![ip]);
        assert_eq!(l.lookup("lists.test").await.unwrap(), vec![ip]);
        let e = l.lookup("v6.lan").await.unwrap_err();
        assert!(e.reason.contains("no IPv4 address"), "{e}");
        assert!(l.lookup("host.corp").await.is_err());
        // A new zone applies to the next lookup.
        zone.store(Arc::new(LocalZone::default()));
        assert!(l.lookup("nas.lan").await.is_err());
        assert_eq!(l.lookup("lists.test").await.unwrap(), vec![ip]);
    }

    #[tokio::test]
    async fn static_table() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let r = StaticResolver::new().with("Lists.Test", &[ip]);
        assert_eq!(r.lookup("lists.test").await.unwrap(), vec![ip]);
        assert_eq!(r.lookup("LISTS.TEST").await.unwrap(), vec![ip]);
        assert!(r.lookup("other.test").await.is_err());
    }
}
