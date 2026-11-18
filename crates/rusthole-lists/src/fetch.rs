//! List download with the limits of amendment A8.
//!
//! - `http` and `https` only, also for each redirect; at most [`MAX_REDIRECTS`] redirects.
//! - A connect timeout, a read timeout and a total timeout.
//! - At most [`DEFAULT_MAX_BODY`] bytes after decompression (gzip and deflate are allowed).
//!   The body is read in chunks and counted, so a gzip bomb stops at the limit.
//! - A conditional GET (`If-None-Match`, `If-Modified-Since`) when the cache has a body.
//! - Name lookup through rusthole's own upstream pool ([`crate::resolver`]), no proxy.
//! - TLS: rustls with the ring provider, from `rusthole-tls`.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{StatusCode, Url, redirect};
use rusthole_core::refresh::Validators;

use crate::resolver::{HostLookup, ReqwestResolver};

/// The default body size limit after decompression: 64 MiB.
pub const DEFAULT_MAX_BODY: u64 = 64 * 1024 * 1024;
/// Redirects that one fetch follows, at most.
pub const MAX_REDIRECTS: usize = 3;
/// Default time limit to connect (TCP and TLS).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Default time limit for one read.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Default time limit for one full fetch, with the body.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(180);

/// Limits of one fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimits {
    /// The largest body after decompression, in bytes.
    pub max_body: u64,
    /// Redirects that one fetch follows, at most.
    pub max_redirects: usize,
    /// Time limit to connect.
    pub connect_timeout: Duration,
    /// Time limit for one read.
    pub read_timeout: Duration,
    /// Time limit for the full fetch.
    pub total_timeout: Duration,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_body: DEFAULT_MAX_BODY,
            max_redirects: MAX_REDIRECTS,
            connect_timeout: CONNECT_TIMEOUT,
            read_timeout: READ_TIMEOUT,
            total_timeout: TOTAL_TIMEOUT,
        }
    }
}

/// The result of a fetch that worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// `304 Not Modified`: the cached body is current.
    NotModified(Validators),
    /// `200 OK` with the full body (after decompression).
    Body {
        /// The body.
        bytes: Vec<u8>,
        /// The `ETag` and `Last-Modified` of the response.
        validators: Validators,
    },
}

/// Why a fetch failed. The text is short, for the status of the list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The URL does not parse.
    #[error("the URL is not valid")]
    BadUrl,
    /// The URL is not `http` or `https`.
    #[error("only http and https URLs are allowed")]
    Scheme,
    /// The server answered with another status.
    #[error("HTTP {0}")]
    Status(u16),
    /// The body is larger than the limit.
    #[error("the body is larger than {limit} bytes")]
    TooLarge {
        /// The limit in bytes.
        limit: u64,
    },
    /// A time limit passed.
    #[error("timeout")]
    Timeout,
    /// A redirect went over the limit or to a URL that is not allowed.
    #[error("redirect: {0}")]
    Redirect(String),
    /// A connect, TLS, lookup or read error.
    #[error("network: {0}")]
    Network(String),
    /// The HTTP client cannot be made.
    #[error("the HTTP client cannot start: {0}")]
    Client(String),
}

/// Why a redirect was refused.
#[derive(Debug, thiserror::Error)]
enum RedirectRefused {
    #[error("more than {0} redirects")]
    TooMany(usize),
    #[error("a redirect to a URL that is not http or https")]
    Scheme,
}

fn allowed_scheme(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

/// Downloads lists. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    limits: FetchLimits,
}

impl Fetcher {
    /// A fetcher with `tls` (a rustls client config with the ring provider) and `lookup`
    /// for names.
    pub fn new(
        limits: FetchLimits,
        tls: Arc<rustls::ClientConfig>,
        lookup: Arc<dyn HostLookup>,
    ) -> Result<Self, FetchError> {
        let max_redirects = limits.max_redirects;
        let policy = redirect::Policy::custom(move |attempt| {
            // `previous` holds the first URL and each URL that redirected.
            if attempt.previous().len() > max_redirects {
                attempt.error(RedirectRefused::TooMany(max_redirects))
            } else if !allowed_scheme(attempt.url()) {
                attempt.error(RedirectRefused::Scheme)
            } else {
                attempt.follow()
            }
        });
        let mut tls = Arc::unwrap_or_clone(tls);
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .dns_resolver(Arc::new(ReqwestResolver::new(lookup)))
            .no_proxy()
            .redirect(policy)
            .connect_timeout(limits.connect_timeout)
            .read_timeout(limits.read_timeout)
            .timeout(limits.total_timeout)
            .gzip(true)
            .deflate(true)
            .http1_only()
            .user_agent(concat!("rusthole/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| FetchError::Client(e.to_string()))?;
        Ok(Self { client, limits })
    }

    /// The limits.
    pub fn limits(&self) -> FetchLimits {
        self.limits
    }

    /// Fetches `url`. With `conditional`, the request asks for the body only when it
    /// changed. The total time limit applies to the full fetch.
    pub async fn fetch(
        &self,
        url: &str,
        conditional: Option<&Validators>,
    ) -> Result<FetchOutcome, FetchError> {
        // The client has the same total limit; this outer limit also covers the lookup.
        let outer = self
            .limits
            .total_timeout
            .saturating_add(Duration::from_secs(1));
        match tokio::time::timeout(outer, self.fetch_inner(url, conditional)).await {
            Ok(r) => r,
            Err(_) => Err(FetchError::Timeout),
        }
    }

    async fn fetch_inner(
        &self,
        url: &str,
        conditional: Option<&Validators>,
    ) -> Result<FetchOutcome, FetchError> {
        let url = Url::parse(url).map_err(|_| FetchError::BadUrl)?;
        if !allowed_scheme(&url) {
            return Err(FetchError::Scheme);
        }
        let mut req = self.client.get(url);
        let conditional = conditional.filter(|v| v.etag.is_some() || v.last_modified.is_some());
        if let Some(v) = conditional {
            if let Some(etag) = &v.etag {
                req = req.header(IF_NONE_MATCH, etag);
            }
            if let Some(lm) = &v.last_modified {
                req = req.header(IF_MODIFIED_SINCE, lm);
            }
        }
        let mut resp = req.send().await.map_err(|e| map_error(&e))?;
        let status = resp.status();
        let validators = Validators {
            etag: header_text(&resp, &ETAG),
            last_modified: header_text(&resp, &LAST_MODIFIED),
        }
        .bounded();
        if status == StatusCode::NOT_MODIFIED && conditional.is_some() {
            return Ok(FetchOutcome::NotModified(validators));
        }
        if status != StatusCode::OK {
            return Err(FetchError::Status(status.as_u16()));
        }
        let limit = self.limits.max_body;
        if resp.content_length().is_some_and(|n| n > limit) {
            return Err(FetchError::TooLarge { limit });
        }
        // With a length, take the full buffer at once: growth by doubling would hold the old
        // and the new buffer for a short time (a higher peak).
        let start = resp.content_length().unwrap_or(0).min(limit);
        let mut body = Vec::with_capacity(usize::try_from(start).unwrap_or(0));
        // Bounded by the size limit (each round adds the bytes of one chunk) and by the
        // total time limit of the client.
        while let Some(chunk) = resp.chunk().await.map_err(|e| map_error(&e))? {
            if body.len() as u64 + chunk.len() as u64 > limit {
                return Err(FetchError::TooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchOutcome::Body {
            bytes: body,
            validators,
        })
    }
}

fn header_text(resp: &reqwest::Response, name: &reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// A short text for a client error, with its causes.
fn map_error(e: &reqwest::Error) -> FetchError {
    if e.is_timeout() {
        return FetchError::Timeout;
    }
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    // The cause chain of a reqwest error is short; the bound keeps the text short too.
    for _ in 0..4 {
        let Some(s) = source else { break };
        text.push_str(": ");
        text.push_str(&s.to_string());
        source = s.source();
    }
    if e.is_redirect() {
        FetchError::Redirect(text)
    } else {
        FetchError::Network(text)
    }
}
