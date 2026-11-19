//! HTTPS GET for the report sections (RDAP, Tranco). The production client:
//!
//! - looks up host names through the upstream pool (never the system resolver), and keeps
//!   only public IPv4 addresses ([`crate::guard::is_public_v4`]);
//! - allows `https` only, also for each redirect; at most [`MAX_REDIRECTS`] redirects; a URL
//!   with an IP address must have a public address;
//! - reads at most the given number of body bytes, then stops.
//!
//! Tests use a fake [`HttpGet`].

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Url, redirect};
use rusthole_core::DomainName;
use rusthole_dns::HostResolver;

use crate::guard::is_public_v4;

/// The most redirects of one GET.
pub const MAX_REDIRECTS: usize = 3;
/// The time limit of a connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// The time limit of one GET (the section limit is the outer limit).
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(8);

/// The answer of a GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAnswer {
    /// The HTTP status.
    pub status: u16,
    /// The body, at most the limit of the call.
    pub body: Vec<u8>,
}

/// A boxed GET future.
pub type GetFuture<'a> = Pin<Box<dyn Future<Output = Result<HttpAnswer, String>> + Send + 'a>>;

/// An HTTPS GET with a body limit.
pub trait HttpGet: Send + Sync + fmt::Debug {
    /// GETs `url`. A body over `max_bytes` is an error.
    fn get<'a>(&'a self, url: &'a str, max_bytes: usize) -> GetFuture<'a>;
}

/// True when `url` is an `https` URL that the report can fetch: a host name, or a public
/// IPv4 address.
pub fn url_allowed(url: &Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    match url.host_str() {
        // An IPv6 literal: v1 uses IPv4 only (A11).
        None => false,
        Some(h) if h.starts_with('[') => false,
        Some(h) => h.parse::<std::net::Ipv4Addr>().map_or(true, is_public_v4),
    }
}

/// Looks up host names through the upstream pool, and gives only public IPv4 addresses.
#[derive(Debug, Clone)]
struct GuardedResolver {
    dns: HostResolver,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let dns = self.dns.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let n = DomainName::parse(&host).map_err(|e| format!("{host}: {e}"))?;
            let addrs = tokio::time::timeout(CONNECT_TIMEOUT, dns.resolve_ipv4(&n))
                .await
                .map_err(|_| format!("{host}: name lookup timed out"))?
                .map_err(|e| format!("{host}: {e}"))?;
            let public: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|a| is_public_v4(*a))
                .map(|a| SocketAddr::new(IpAddr::V4(a), 0))
                .collect();
            if public.is_empty() {
                return Err(format!("{host} has no public IPv4 address").into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(public.into_iter());
            Ok(addrs)
        })
    }
}

/// The production HTTPS client.
#[derive(Debug, Clone)]
pub struct HttpsClient {
    client: reqwest::Client,
}

impl HttpsClient {
    /// A client with `tls` (a rustls client config with the ring provider) and `dns`.
    pub fn new(tls: Arc<rustls::ClientConfig>, dns: HostResolver) -> Result<Self, String> {
        let policy = redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > MAX_REDIRECTS {
                attempt.error(format!("more than {MAX_REDIRECTS} redirects"))
            } else if !url_allowed(attempt.url()) {
                attempt.error("a redirect to a URL that is not allowed")
            } else {
                attempt.follow()
            }
        });
        let mut tls = Arc::unwrap_or_clone(tls);
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .dns_resolver(Arc::new(GuardedResolver { dns }))
            .no_proxy()
            .redirect(policy)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .http1_only()
            .user_agent(concat!("rusthole/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client })
    }
}

impl HttpGet for HttpsClient {
    fn get<'a>(&'a self, url: &'a str, max_bytes: usize) -> GetFuture<'a> {
        Box::pin(async move {
            let u = Url::parse(url).map_err(|e| format!("bad URL: {e}"))?;
            if !url_allowed(&u) {
                return Err("the URL is not allowed (https and a public address only)".to_owned());
            }
            let mut resp = self
                .client
                .get(u)
                .header("accept", "application/rdap+json, application/json")
                .send()
                .await
                .map_err(|e| short(&e))?;
            let status = resp.status().as_u16();
            let mut body = Vec::new();
            // Bounded: the body limit stops the loop.
            while let Some(chunk) = resp.chunk().await.map_err(|e| short(&e))? {
                if body.len() + chunk.len() > max_bytes {
                    return Err(format!(
                        "the answer is larger than {} KiB",
                        max_bytes / 1024
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpAnswer { status, body })
        })
    }
}

/// A short error text with its causes.
fn short(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    let mut src = std::error::Error::source(e);
    // Bounded: at most 4 causes.
    for _ in 0..4 {
        let Some(c) = src else { break };
        s.push_str(": ");
        s.push_str(&c.to_string());
        src = c.source();
    }
    crate::dns::safe_text(&s, 300)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests: a failure is a test failure.
mod tests {
    use super::*;

    #[test]
    fn only_https_and_public_addresses() {
        for ok in [
            "https://rdap.verisign.com/com/v1/domain/x.com",
            "https://1.1.1.1/x",
        ] {
            assert!(url_allowed(&Url::parse(ok).unwrap()), "{ok}");
        }
        for bad in [
            "http://rdap.verisign.com/",
            "https://192.168.50.150:8443/api/v1/system",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://[::1]/",
            "ftp://example.com/",
        ] {
            assert!(!url_allowed(&Url::parse(bad).unwrap()), "{bad}");
        }
    }
}

/// An [`HttpGet`] that always fails, for a host where the HTTPS client cannot start.
#[derive(Debug, Clone)]
pub struct NoHttp(pub String);

impl HttpGet for NoHttp {
    fn get<'a>(&'a self, _url: &'a str, _max_bytes: usize) -> GetFuture<'a> {
        let reason = self.0.clone();
        Box::pin(async move { Err(reason) })
    }
}
