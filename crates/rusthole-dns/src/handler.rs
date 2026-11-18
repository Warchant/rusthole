//! The request pipeline.
//!
//! ```mermaid
//! flowchart TD
//!     raw[bytes] --> hdr{12-byte header, QR=0?}
//!     hdr -->|no| drop[drop]
//!     hdr --> acl{ACL allows client?}
//!     acl -->|no, UDP| drop
//!     acl -->|no, TCP or DoH| refused[REFUSED, close]
//!     acl --> rl{rate limit OK?}
//!     rl -->|no, UDP| drop
//!     rl -->|no, TCP or DoH| refused
//!     rl --> op{opcode QUERY?}
//!     op -->|no| ref2[REFUSED]
//!     op --> parse{parses, 1 question?}
//!     parse -->|no| formerr[FORMERR]
//!     parse --> id[identify client]
//!     id --> local{local DNS data?}
//!     local -->|record, CNAME, PTR, NODATA| aa[authoritative reply, not blocked]
//!     local -->|private reverse, no forward| nx[NXDOMAIN]
//!     local -->|conditional forward or not local| fq{filter on_query}
//!     fq -->|block| block[block reply]
//!     fq --> cache{cache hit?}
//!     cache -->|yes| fa{filter on_answer}
//!     cache -->|no| up[upstream pool or forward server] --> store[store in cache] --> fa
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

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, ResponseCode};
use parking_lot::Mutex;
use rusthole_core::acl::Acl;
use rusthole_core::cache::{Cache, CacheKey, TtlPolicy};
use rusthole_core::localdns::{LocalAnswer, LocalZone};
use rusthole_core::ratelimit::{self, RateLimiter};

use crate::filter::{
    AnswerSource, ClientInfo, ClientTransport, FilterOutcome, FilterVerdict, PolicyInfo,
    QueryContext, QueryEvent, QueryFilter, QueryObserver, Verdict,
};
use crate::local;
use crate::sync::{Clock, LOCK_TIMEOUT, SharedAcl};
use crate::upstream::{Pool, Requester, UpstreamAnswer, UpstreamError};
use crate::wire::{self, MAX_TCP_MESSAGE, RawHeader, Request, RequestError};

/// Default of [`HandlerSettings::cache_bytes`]: the default of `cache.max_bytes`.
pub const DEFAULT_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// The highest TTL, in seconds, of an answer from a `upstreams.fallback_plain` server
/// (review item m3). The cache and the client keep such an answer for this time at most,
/// so a forged plain answer from the fallback time does not stay after the encrypted
/// upstreams are in use again.
pub const FALLBACK_MAX_TTL: u32 = 30;

/// The TTL rules for an answer from a fallback server: each limit at most
/// [`FALLBACK_MAX_TTL`]. Pure.
pub fn fallback_policy(p: &TtlPolicy) -> TtlPolicy {
    TtlPolicy {
        min_ttl: p.min_ttl.min(FALLBACK_MAX_TTL),
        max_ttl: p.max_ttl.min(FALLBACK_MAX_TTL),
        negative_ttl: p.negative_ttl.min(FALLBACK_MAX_TTL),
    }
}

/// Settings of the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerSettings {
    /// TTL rules of the cache.
    pub ttl: TtlPolicy,
    /// Maximum cache entries. 0 turns the cache off.
    pub cache_entries: usize,
    /// Most memory of the cache in bytes (`cache.max_bytes`, review item M1).
    pub cache_bytes: usize,
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
            cache_bytes: DEFAULT_CACHE_BYTES,
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

/// Where a query that is not in the cache goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The public upstream pool.
    Upstreams,
    /// A conditional forwarding server (part P3c). `rule` is the index in
    /// `local_dns.conditional_forwarding` of the config.
    Forward {
        /// The server.
        server: SocketAddr,
        /// The rule index.
        rule: usize,
    },
}

/// A query that waits for the upstream.
#[derive(Debug)]
pub struct Pending {
    req: Request,
    ctx: QueryContext,
    key: CacheKey,
    max_len: usize,
    started: Instant,
    client: ClientInfo,
    route: Route,
}

impl Pending {
    /// Where the query goes.
    pub fn route(&self) -> Route {
        self.route
    }

    /// What the filter knows about the client.
    pub fn client(&self) -> &ClientInfo {
        &self.client
    }

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
    /// The encoded answers (review item M1: bytes, not parsed messages).
    cache: Mutex<Cache<Arc<[u8]>>>,
    ttl: ArcSwap<TtlPolicy>,
    filter: Arc<dyn QueryFilter>,
    observer: Arc<dyn QueryObserver>,
    clock: Clock,
    local: ArcSwap<LocalZone>,
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
            cache: Mutex::new(Cache::new(settings.cache_entries, settings.cache_bytes)),
            ttl: ArcSwap::from_pointee(settings.ttl),
            filter,
            observer,
            clock,
            local: ArcSwap::from_pointee(LocalZone::default()),
        }
    }

    /// Uses `zone` for local DNS data and conditional forwarding (part P3c). Without it,
    /// the pipeline has no local data.
    #[must_use]
    pub fn with_local_zone(mut self, zone: Arc<LocalZone>) -> Self {
        self.local = ArcSwap::new(zone);
        self
    }

    /// Uses new local DNS data (a config change, part P5).
    pub fn set_local_zone(&self, zone: Arc<LocalZone>) {
        self.local.store(zone);
    }

    /// Uses new cache and rate limit settings (a config change, part P5). A new cache size
    /// (entries or bytes) empties the cache; new rate limit values reset the rate limiter.
    pub fn apply_settings(&self, old: &HandlerSettings, new: &HandlerSettings) {
        self.ttl.store(Arc::new(new.ttl));
        if (old.cache_entries, old.cache_bytes) != (new.cache_entries, new.cache_bytes) {
            if let Some(mut c) = self.cache.try_lock_for(LOCK_TIMEOUT) {
                *c = Cache::new(new.cache_entries, new.cache_bytes);
            } else {
                tracing::error!("the cache lock timed out; the new cache size is not used");
            }
        }
        if (
            old.rate_queries,
            old.rate_interval_seconds,
            old.rate_max_clients,
        ) != (
            new.rate_queries,
            new.rate_interval_seconds,
            new.rate_max_clients,
        ) {
            if let Some(mut l) = self.limiter.try_lock_for(LOCK_TIMEOUT) {
                *l = RateLimiter::new(
                    new.rate_queries,
                    new.rate_interval_seconds,
                    new.rate_max_clients,
                );
            } else {
                tracing::error!("the rate limiter lock timed out; the new limit is not used");
            }
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

    /// The bytes that the cache counts now (at most `cache_bytes`).
    pub fn cache_bytes(&self) -> usize {
        self.cache
            .try_lock_for(LOCK_TIMEOUT)
            .map_or(0, |c| c.bytes())
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
            ClientTransport::Tcp | ClientTransport::Https => Front::Reply(Reply {
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
            ClientTransport::Tcp | ClientTransport::Https => MAX_TCP_MESSAGE,
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
        let client_info = self.filter.identify(ctx.client);
        let mut pending = Pending {
            req,
            ctx,
            key,
            max_len,
            started,
            client: client_info,
            route: Route::Upstreams,
        };
        // Local DNS data comes before the policy, the cache and the upstreams (part P3c).
        if let Some(reply) = self.local_step(&mut pending) {
            return Front::Reply(reply);
        }
        let outcome = self.filter.decide_query(&pending.ctx, &pending.client);
        if let FilterVerdict::Block(b) = outcome.verdict {
            let msg = wire::block_response(&pending.req, &b);
            return Front::Reply(self.finish(
                &pending,
                &msg,
                Verdict::BlockedQuery,
                AnswerSource::Filter,
                None,
                Some(outcome),
            ));
        }
        if let Some((msg, age)) = self.cache_hit(&pending.key) {
            return Front::Reply(self.respond(&pending, &msg, age, AnswerSource::Cache, None));
        }
        Front::Resolve(Box::new(pending))
    }

    /// The cached answer for `key` and its age. The cache keeps the encoded answer; this
    /// function parses it outside the cache lock. An entry that does not parse is removed
    /// and gives a miss.
    fn cache_hit(&self, key: &CacheKey) -> Option<(Message, u32)> {
        let (bytes, age) = self.cache.try_lock_for(LOCK_TIMEOUT).and_then(|mut c| {
            c.get(key, self.clock.now_ms())
                .map(|h| (Arc::clone(h.value), h.age))
        })?;
        match Message::from_vec(&bytes) {
            Ok(msg) => Some((msg, age)),
            Err(e) => {
                tracing::error!(error = %e, "a cached answer does not parse; it is removed");
                if let Some(mut c) = self.cache.try_lock_for(LOCK_TIMEOUT) {
                    c.remove(key);
                }
                None
            }
        }
    }

    /// The local DNS step (part P3c): a reply from local data, or `None` to go on. A
    /// conditional forward sets the route of `pending`. A name that is not a valid domain
    /// name, or a class that is not IN, still gets the reverse-zone checks: a private
    /// reverse lookup never goes to the public upstreams.
    fn local_step(&self, pending: &mut Pending) -> Option<Reply> {
        let local = match &pending.ctx.domain {
            Some(name) if pending.ctx.qclass == local::LOCAL_CLASS => {
                self.local.load().lookup(name, pending.ctx.qtype)
            }
            _ => {
                let labels: Vec<&[u8]> = pending.req.query.name().iter().collect();
                self.local.load().lookup_reverse_zone(&labels)
            }
        };
        let msg = match local {
            LocalAnswer::Answer(records) => local::local_response(&pending.req, &records),
            LocalAnswer::PrivateReverse => local::private_reverse_response(&pending.req),
            LocalAnswer::Forward { server, rule } => {
                pending.route = Route::Forward { server, rule };
                return None;
            }
            LocalAnswer::NotLocal => return None,
        };
        Some(self.finish(
            pending,
            &msg,
            Verdict::Allowed,
            AnswerSource::LocalDns,
            None,
            None,
        ))
    }

    /// The second, synchronous part: stores the upstream answer in the cache and builds
    /// the reply. An upstream error gives SERVFAIL.
    pub fn complete(
        &self,
        pending: &Pending,
        outcome: Result<UpstreamAnswer, UpstreamError>,
    ) -> Reply {
        match outcome {
            Ok(UpstreamAnswer {
                message,
                upstream,
                fallback,
            }) => {
                let policy = **self.ttl.load();
                let policy = if fallback {
                    fallback_policy(&policy)
                } else {
                    policy
                };
                match wire::prepare_for_cache(message, &policy) {
                    Ok(c) => {
                        let size = c.bytes.len();
                        let bytes: Arc<[u8]> = c.bytes.into();
                        if let Some(mut cache) = self.cache.try_lock_for(LOCK_TIMEOUT) {
                            cache.insert(
                                pending.key.clone(),
                                bytes,
                                size,
                                c.ttl,
                                self.clock.now_ms(),
                            );
                        }
                        self.respond(
                            pending,
                            &c.message,
                            0,
                            AnswerSource::Upstream,
                            Some(upstream),
                        )
                    }
                    Err(msg) => {
                        self.respond(pending, &msg, 0, AnswerSource::Upstream, Some(upstream))
                    }
                }
            }
            Err(e) => {
                tracing::debug!(qname = %pending.ctx.qname, error = %e, "no upstream answer");
                let msg = wire::error_response(&pending.req, ResponseCode::ServFail);
                self.finish(
                    pending,
                    &msg,
                    Verdict::Allowed,
                    AnswerSource::Local,
                    None,
                    None,
                )
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
        let outcome = self
            .filter
            .decide_answer(&pending.ctx, &pending.client, &names);
        match outcome.verdict {
            FilterVerdict::Allow => {
                let msg = wire::answer_response(&pending.req, answer, age);
                self.finish(
                    pending,
                    &msg,
                    Verdict::Allowed,
                    source,
                    upstream,
                    Some(outcome),
                )
            }
            FilterVerdict::Block(b) => {
                let msg = wire::block_response(&pending.req, &b);
                self.finish(
                    pending,
                    &msg,
                    Verdict::BlockedAnswer,
                    source,
                    upstream,
                    Some(outcome),
                )
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
        outcome: Option<FilterOutcome>,
    ) -> Reply {
        let bytes = wire::encode(msg, pending.max_len);
        let (decision, cname_target) =
            outcome.map_or((None, None), |o| (o.decision, o.cname_target));
        let policy = PolicyInfo {
            client_mac: pending.client.mac,
            groups: Arc::clone(&pending.client.groups),
            matched: pending.client.matched,
            decision,
            cname_target,
            forward_rule: match pending.route {
                Route::Forward { rule, .. } => Some(rule),
                Route::Upstreams => None,
            },
        };
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
            policy,
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
                let who = Requester::Client(pending.ctx.client);
                let outcome = match pending.route {
                    Route::Upstreams => {
                        pool.resolve(
                            &pending.key,
                            &pending.req.query,
                            pending.req.dnssec_ok(),
                            who,
                        )
                        .await
                    }
                    Route::Forward { server, .. } => {
                        pool.forward(server, &pending.req.query, pending.req.dnssec_ok(), who)
                            .await
                    }
                };
                Some(self.complete(&pending, outcome))
            }
        }
    }
}

#[cfg(test)]
mod tests;
