//! Host name lookup through the upstream pool, for rusthole's own downloads (part P3b).
//!
//! The list refresher must not use the system resolver: on a host where `/etc/resolv.conf`
//! points at rusthole itself, the system resolver needs rusthole to work first. This lookup
//! goes straight to the upstream pool. It does not pass the ACL, the filter or the cache.
//! It asks for A records only (amendment A11: IPv4 transport in v1).

use std::net::Ipv4Addr;

use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use rusthole_core::DomainName;
use rusthole_core::cache::CacheKey;
use tokio_util::sync::CancellationToken;

use crate::upstream::{Pool, Requester, UpstreamError};

/// The most addresses that one lookup gives.
pub const MAX_ADDRESSES: usize = 16;

/// Why a lookup has no address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The name cannot be a DNS query name.
    #[error("the name is not valid")]
    BadName,
    /// No upstream answer.
    #[error("upstream: {0}")]
    Upstream(UpstreamError),
    /// The upstream answer has an error code (for example 3 for NXDOMAIN).
    #[error("the upstream answer has code {0}")]
    Rcode(u16),
    /// The answer has no A record.
    #[error("the answer has no IPv4 address")]
    NoAddress,
}

/// Looks up host names through the upstream pool of a running DNS server. Cheap to clone.
/// When the server stops, each lookup fails at once.
#[derive(Debug, Clone)]
pub struct HostResolver {
    pool: Pool,
    stop: CancellationToken,
}

impl HostResolver {
    pub(crate) fn new(pool: Pool, stop: CancellationToken) -> Self {
        Self { pool, stop }
    }

    /// The IPv4 addresses of `host`, at most [`MAX_ADDRESSES`]. The time limit is the query
    /// budget of the pool.
    pub async fn resolve_ipv4(&self, host: &DomainName) -> Result<Vec<Ipv4Addr>, ResolveError> {
        let fqdn = format!("{}.", host.as_str());
        let name = Name::from_ascii(&fqdn).map_err(|_| ResolveError::BadName)?;
        let query = Query::query(name, RecordType::A);
        let key = CacheKey::new(
            &fqdn,
            u16::from(RecordType::A),
            u16::from(DNSClass::IN),
            false,
        );
        if self.stop.is_cancelled() {
            return Err(ResolveError::Upstream(UpstreamError::Stopped));
        }
        let answer = tokio::select! {
            () = self.stop.cancelled() => Err(UpstreamError::Stopped),
            r = self.pool.resolve(&key, &query, false, Requester::Local) => r,
        }
        .map_err(ResolveError::Upstream)?;
        let rcode = answer.message.metadata.response_code;
        if rcode != ResponseCode::NoError {
            return Err(ResolveError::Rcode(u16::from(rcode)));
        }
        let addrs: Vec<Ipv4Addr> = answer
            .message
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .take(MAX_ADDRESSES)
            .collect();
        if addrs.is_empty() {
            return Err(ResolveError::NoAddress);
        }
        Ok(addrs)
    }
}
