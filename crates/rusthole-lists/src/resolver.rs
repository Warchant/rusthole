//! Name lookup for list downloads.
//!
//! Downloads do not use the system resolver. A host whose `/etc/resolv.conf` points at
//! rusthole itself must still be able to fetch its lists at start. The production lookup is
//! [`rusthole_dns::HostResolver`]: it asks the upstream pool of the DNS server directly.
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

use rusthole_core::DomainName;

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
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[tokio::test]
    async fn static_table() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let r = StaticResolver::new().with("Lists.Test", &[ip]);
        assert_eq!(r.lookup("lists.test").await.unwrap(), vec![ip]);
        assert_eq!(r.lookup("LISTS.TEST").await.unwrap(), vec![ip]);
        assert!(r.lookup("other.test").await.is_err());
    }
}
