//! The request pipeline.
//!
//! ```mermaid
//! flowchart TD
//!     raw[bytes] --> hdr{12-byte header, QR=0?}
//!     hdr -->|no| drop[drop]
//!     hdr --> acl{ACL allows client?}
//!     acl -->|no, UDP| drop
//!     acl -->|no, TCP| refused[REFUSED, close]
//!     acl --> rl{rate limit OK?}
//!     rl -->|no, UDP| drop
//!     rl -->|no, TCP| refused
//!     rl --> op{opcode QUERY?}
//!     op -->|no| ref2[REFUSED]
//!     op --> parse{parses, 1 question?}
//!     parse -->|no| formerr[FORMERR]
//!     parse --> fq{filter on_query}
//!     fq -->|block| block[block reply]
//!     fq --> cache{cache hit?}
//!     cache -->|yes| fa{filter on_answer}
//!     cache -->|no| up[upstream pool] --> store[store in cache] --> fa
//!     fa -->|block| block
//!     fa --> reply[reply, TC if too long]
//! ```
//!
//! [`Handler::front`] and [`Handler::complete`] are synchronous, so the fuzz target can
//! drive the full pipeline with a fake upstream answer. [`Handler::handle`] joins them with
//! the upstream pool.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Message, ResponseCode};
use parking_lot::Mutex;
use rusthole_core::acl::Acl;
use rusthole_core::cache::{Cache, CacheKey, TtlPolicy};
use rusthole_core::ratelimit::{self, RateLimiter};

use crate::filter::{
    AnswerSource, ClientTransport, FilterVerdict, QueryContext, QueryEvent, QueryFilter,
    QueryObserver, Verdict,
};
use crate::sync::{Clock, LOCK_TIMEOUT, SharedAcl};
use crate::upstream::{Pool, UpstreamAnswer, UpstreamError};
use crate::wire::{self, MAX_TCP_MESSAGE, RawHeader, Request, RequestError};

/// Settings of the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerSettings {
    /// TTL rules of the cache.
    pub ttl: TtlPolicy,
    /// Maximum cache entries. 0 turns the cache off.
    pub cache_entries: usize,
    /// Queries per interval for one client. 0 turns the limit off.
    pub rate_queries: u32,
    /// Rate limit interval in seconds.
    pub rate_interval_seconds: u32,
    /// Size of the rate limiter map.
    pub rate_max_clients: usize,
}

impl Default for HandlerSettings {
    fn default() -> Self {
        Self {
            ttl: TtlPolicy {
                min_ttl: 0,
                max_ttl: 86_400,
                negative_ttl: 300,
            },
            cache_entries: 10_000,
            rate_queries: 1000,
            rate_interval_seconds: 60,
            rate_max_clients: ratelimit::MAX_CLIENTS,
        }
    }
}

/// A reply for the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The DNS message.
    pub bytes: Vec<u8>,
    /// True when the TCP connection must close after this reply.
    pub close: bool,
}

/// The result of [`Handler::front`].
#[derive(Debug)]
pub enum Front {
    /// Send nothing.
    Drop,
    /// Send this reply.
    Reply(Reply),
    /// Ask the upstream, then call [`Handler::complete`].
    Resolve(Box<Pending>),
}

/// A query that waits for the upstream.
#[derive(Debug)]
pub struct Pending {
    req: Request,
    ctx: QueryContext,
    key: CacheKey,
    max_len: usize,
    started: Instant,
}

impl Pending {
    /// The parsed request.
    pub fn request(&self) -> &Request {
        &self.req
    }

    /// The cache key.
    pub fn key(&self) -> &CacheKey {
        &self.key
    }
}

/// The request pipeline: ACL, rate limit, parse, filter, cache.
#[derive(Debug)]
pub struct Handler {
    acl: SharedAcl,
    limiter: Mutex<RateLimiter>,
    cache: Mutex<Cache<Arc<Message>>>,
    ttl: TtlPolicy,
    filter: Arc<dyn QueryFilter>,
    observer: Arc<dyn QueryObserver>,
    clock: Clock,
}

impl Handler {
    /// Makes a pipeline.
    pub fn new(
        settings: &HandlerSettings,
        acl: Acl,
        filter: Arc<dyn QueryFilter>,
        observer: Arc<dyn QueryObserver>,
        clock: Clock,
    ) -> Self {
        Self {
            acl: SharedAcl::new(acl),
            limiter: Mutex::new(RateLimiter::new(
                settings.rate_queries,
                settings.rate_interval_seconds,
                settings.rate_max_clients,
            )),
            cache: Mutex::new(Cache::new(settings.cache_entries)),
            ttl: settings.ttl,
            filter,
            observer,
            clock,
        }
    }

    /// Replaces the ACL (after an interface scan).
    pub fn set_acl(&self, acl: Acl) {
        self.acl.set(acl);
    }

    /// The current ACL.
    pub fn acl(&self) -> Option<Arc<Acl>> {
        self.acl.get()
    }

    /// Number of cache entries.
    pub fn cache_len(&self) -> usize {
        self.cache.try_lock_for(LOCK_TIMEOUT).map_or(0, |c| c.len())
    }

    pub(crate) fn allowed(&self, ip: IpAddr) -> bool {
        // A lock timeout denies: the safe choice.
        self.acl.get().is_some_and(|acl| acl.allows(ip))
    }

    fn rate_ok(&self, ip: IpAddr) -> bool {
        let now_ms = self.clock.now_ms();
        self.limiter
            .try_lock_for(LOCK_TIMEOUT)
            .is_some_and(|mut l| l.check(ip, now_ms))
    }

    /// The first, synchronous part of the pipeline.
    pub fn front(&self, bytes: &[u8], client: SocketAddr, transport: ClientTransport) -> Front {
        let started = Instant::now();
        let Some(h) = RawHeader::parse(bytes) else {
            return Front::Drop;
        };
        if h.qr {
            // Never answer a response: no reflection loop.
            return Front::Drop;
        }
        let refuse_or_drop = || match transport {
            ClientTransport::Udp => Front::Drop,
            ClientTransport::Tcp => Front::Reply(Reply {
                bytes: wire::header_reply(&h, ResponseCode::Refused),
                close: true,
            }),
        };
        if !self.allowed(client.ip()) {
            // Off-net UDP: no answer, so rusthole cannot reflect traffic (amendment A8).
            return refuse_or_drop();
        }
        if !self.rate_ok(client.ip()) {
            return refuse_or_drop();
        }
        let header_only = |rcode| {
            Front::Reply(Reply {
                bytes: wire::header_reply(&h, rcode),
                close: false,
            })
        };
        if h.opcode != 0 {
            return header_only(ResponseCode::Refused);
        }
        let req = match wire::parse_request(bytes) {
            Ok((req, _)) => req,
            Err(RequestError::Malformed | RequestError::QuestionCount) => {
                return header_only(ResponseCode::FormErr);
            }
            Err(RequestError::NotImplemented) => return header_only(ResponseCode::NotImp),
        };
        let max_len = match transport {
            ClientTransport::Udp => req.max_udp_len(),
            ClientTransport::Tcp => MAX_TCP_MESSAGE,
        };
        let ctx = QueryContext {
            client: client.ip(),
            transport,
            qname: wire::qname_text(req.query.name()),
            domain: wire::domain_of(req.query.name()),
            qtype: u16::from(req.query.query_type()),
            qclass: u16::from(req.query.query_class()),
        };
        let key = req.cache_key();
        let pending = Pending {
            req,
            ctx,
            key,
            max_len,
            started,
        };
        if let FilterVerdict::Block(b) = self.filter.on_query(&pending.ctx) {
            let msg = wire::block_response(&pending.req, &b);
            return Front::Reply(self.finish(
                &pending,
                &msg,
                Verdict::BlockedQuery,
                AnswerSource::Filter,
                None,
            ));
        }
        let hit = self.cache.try_lock_for(LOCK_TIMEOUT).and_then(|mut c| {
            c.get(&pending.key, self.clock.now_ms())
                .map(|h| (Arc::clone(h.value), h.age))
        });
        if let Some((msg, age)) = hit {
            return Front::Reply(self.respond(&pending, &msg, age, AnswerSource::Cache, None));
        }
        Front::Resolve(Box::new(pending))
    }

    /// The second, synchronous part: stores the upstream answer in the cache and builds
    /// the reply. An upstream error gives SERVFAIL.
    pub fn complete(
        &self,
        pending: &Pending,
        outcome: Result<UpstreamAnswer, UpstreamError>,
    ) -> Reply {
        match outcome {
            Ok(UpstreamAnswer { message, upstream }) => {
                match wire::prepare_for_cache(message, &self.ttl) {
                    Ok(c) => {
                        let msg = Arc::new(c.message);
                        if let Some(mut cache) = self.cache.try_lock_for(LOCK_TIMEOUT) {
                            cache.insert(
                                pending.key.clone(),
                                Arc::clone(&msg),
                                c.ttl,
                                self.clock.now_ms(),
                            );
                        }
                        self.respond(pending, &msg, 0, AnswerSource::Upstream, Some(upstream))
                    }
                    Err(msg) => {
                        self.respond(pending, &msg, 0, AnswerSource::Upstream, Some(upstream))
                    }
                }
            }
            Err(e) => {
                tracing::debug!(qname = %pending.ctx.qname, error = %e, "no upstream answer");
                let msg = wire::error_response(&pending.req, ResponseCode::ServFail);
                self.finish(pending, &msg, Verdict::Allowed, AnswerSource::Local, None)
            }
        }
    }

    /// Runs the answer filter and builds the reply.
    fn respond(
        &self,
        pending: &Pending,
        answer: &Message,
        age: u32,
        source: AnswerSource,
        upstream: Option<SocketAddr>,
    ) -> Reply {
        let names = wire::answer_names(answer);
        match self.filter.on_answer(&pending.ctx, &names) {
            FilterVerdict::Allow => {
                let msg = wire::answer_response(&pending.req, answer, age);
                self.finish(pending, &msg, Verdict::Allowed, source, upstream)
            }
            FilterVerdict::Block(b) => {
                let msg = wire::block_response(&pending.req, &b);
                self.finish(pending, &msg, Verdict::BlockedAnswer, source, upstream)
            }
        }
    }

    /// Encodes the reply and sends the event to the observer.
    fn finish(
        &self,
        pending: &Pending,
        msg: &Message,
        verdict: Verdict,
        source: AnswerSource,
        upstream: Option<SocketAddr>,
    ) -> Reply {
        let bytes = wire::encode(msg, pending.max_len);
        self.observer.on_event(&QueryEvent {
            client: pending.ctx.client,
            transport: pending.ctx.transport,
            qname: pending.ctx.qname.clone(),
            qtype: pending.ctx.qtype,
            verdict,
            source,
            upstream,
            rcode: u16::from(msg.metadata.response_code),
            duration: pending.started.elapsed(),
        });
        Reply {
            bytes,
            close: false,
        }
    }

    /// The full pipeline with the upstream pool.
    pub(crate) async fn handle(
        &self,
        pool: &Pool,
        bytes: &[u8],
        client: SocketAddr,
        transport: ClientTransport,
    ) -> Option<Reply> {
        match self.front(bytes, client, transport) {
            Front::Drop => None,
            Front::Reply(r) => Some(r),
            Front::Resolve(pending) => {
                let outcome = pool
                    .resolve(&pending.key, &pending.req.query, pending.req.dnssec_ok())
                    .await;
                Some(self.complete(&pending, outcome))
            }
        }
    }
}

#[cfg(test)]
mod tests;
