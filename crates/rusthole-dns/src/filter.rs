//! Hooks for the policy engine and for statistics.
//!
//! The pipeline calls a [`QueryFilter`] two times for each query:
//!
//! 1. [`QueryFilter::on_query`] before the cache and the upstream.
//! 2. [`QueryFilter::on_answer`] with the names in the answer (owner names and CNAME
//!    targets), for each reply: from the cache and from the upstream (amendment A4).
//!
//! The cache holds the unfiltered upstream answer, so a policy change applies at once.
//! Part P3a gives the real policy. This part ships [`AllowAll`].
//!
//! After each query, the pipeline sends a [`QueryEvent`] to a [`QueryObserver`]. Part P4
//! counts statistics from it. This part ships [`NoopObserver`].
//!
//! Part P3c adds client identity: the pipeline calls [`QueryFilter::identify`] once for each
//! query, then [`QueryFilter::decide_query`] and [`QueryFilter::decide_answer`] with the
//! [`ClientInfo`]. These methods have default bodies that call the older methods, so a
//! filter that implements only `on_query` and `on_answer` still works.
//! [`crate::policy_filter::PolicyFilter`] is the real policy.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rusthole_core::clients::MatchedBy;
use rusthole_core::net::MacAddr;
use rusthole_core::{Decision, DomainName};

/// The transport of a client query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientTransport {
    /// DNS over UDP.
    Udp,
    /// DNS over TCP.
    Tcp,
}

/// What the filter knows about a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryContext {
    /// The client address.
    pub client: IpAddr,
    /// UDP or TCP.
    pub transport: ClientTransport,
    /// The query name in lowercase escaped text form, without the trailing dot. The root
    /// name is `"."`.
    pub qname: String,
    /// The query name as a [`DomainName`]. `None` when the name is not a valid host name
    /// (for example the root name, or a label with a space). Such a query still goes to
    /// the upstream unless the filter blocks it.
    pub domain: Option<DomainName>,
    /// The query type (for example 1 for A, 28 for AAAA).
    pub qtype: u16,
    /// The query class (1 for IN).
    pub qclass: u16,
}

/// What to answer for a blocked query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// `0.0.0.0` for A, `::` for AAAA, NODATA for other types (amendment A3).
    Null,
    /// NXDOMAIN for all types.
    Nxdomain,
    /// NODATA (NOERROR with no answer) for all types.
    Nodata,
    /// The given address for A or AAAA. A missing address, or another type, gives NODATA.
    Ip {
        /// The answer for A.
        v4: Option<Ipv4Addr>,
        /// The answer for AAAA.
        v6: Option<Ipv6Addr>,
    },
}

/// A block answer: the kind and the TTL of the records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockReply {
    /// What to answer.
    pub kind: BlockKind,
    /// TTL of the answer records, in seconds.
    pub ttl: u32,
}

/// The decision of a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    /// Answer normally.
    Allow,
    /// Answer with a block reply. A blocked ANY query gets an RFC 8482 answer.
    Block(BlockReply),
}

/// What the pipeline knows about the client of a query (part P3c).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    /// The MAC address from the neighbor table, if known.
    pub mac: Option<MacAddr>,
    /// The enabled groups of the client.
    pub groups: Arc<[String]>,
    /// Which `[[clients]]` entry kind matched. `None` when the filter does not identify
    /// clients (for example [`AllowAll`]).
    pub matched: Option<MatchedBy>,
}

/// The result of one filter step, with the policy decision for statistics (part P3c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterOutcome {
    /// What the pipeline does.
    pub verdict: FilterVerdict,
    /// The decision of the policy engine. `None` when no engine decided (for example a
    /// query name that is not a valid host name).
    pub decision: Option<Decision>,
    /// The name that decided, when it is a CNAME target and not the query name.
    pub cname_target: Option<DomainName>,
}

impl From<FilterVerdict> for FilterOutcome {
    fn from(verdict: FilterVerdict) -> Self {
        Self {
            verdict,
            decision: None,
            cname_target: None,
        }
    }
}

/// The policy hook. An implementation must be fast and must not block: the pipeline calls
/// it on each query.
pub trait QueryFilter: Send + Sync + fmt::Debug {
    /// Decides before the cache and the upstream.
    fn on_query(&self, ctx: &QueryContext) -> FilterVerdict;

    /// Decides for an answer. `answer_names` holds the owner name of each answer record and
    /// each CNAME target, without duplicates.
    fn on_answer(&self, ctx: &QueryContext, answer_names: &[DomainName]) -> FilterVerdict;

    /// Finds the client: its MAC address and groups. The pipeline calls it once for each
    /// query. It must not block. The default knows nothing.
    fn identify(&self, client: IpAddr) -> ClientInfo {
        let _ = client;
        ClientInfo::default()
    }

    /// Decides before the cache and the upstream, for the client `client`. The default calls
    /// [`QueryFilter::on_query`].
    fn decide_query(&self, ctx: &QueryContext, client: &ClientInfo) -> FilterOutcome {
        let _ = client;
        self.on_query(ctx).into()
    }

    /// Decides for an answer, for the client `client`. The default calls
    /// [`QueryFilter::on_answer`].
    fn decide_answer(
        &self,
        ctx: &QueryContext,
        client: &ClientInfo,
        answer_names: &[DomainName],
    ) -> FilterOutcome {
        let _ = client;
        self.on_answer(ctx, answer_names).into()
    }
}

/// A filter that allows everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl QueryFilter for AllowAll {
    fn on_query(&self, _ctx: &QueryContext) -> FilterVerdict {
        FilterVerdict::Allow
    }

    fn on_answer(&self, _ctx: &QueryContext, _answer_names: &[DomainName]) -> FilterVerdict {
        FilterVerdict::Allow
    }
}

/// Which filter step decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not blocked.
    Allowed,
    /// Blocked by [`QueryFilter::on_query`].
    BlockedQuery,
    /// Blocked by [`QueryFilter::on_answer`].
    BlockedAnswer,
}

/// Where the answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerSource {
    /// The cache.
    Cache,
    /// An upstream server.
    Upstream,
    /// The filter (a block reply before the cache and the upstream).
    Filter,
    /// rusthole made an error answer (for example SERVFAIL when no upstream answered).
    Local,
    /// Local DNS data (part P3c): a local record, a local CNAME, a local PTR, NODATA for a
    /// local name, or NXDOMAIN for a private reverse name.
    LocalDns,
}

/// The policy data of one finished query (part P3c), so that statistics can count and
/// explain it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyInfo {
    /// The MAC address of the client, if known.
    pub client_mac: Option<MacAddr>,
    /// The enabled groups of the client.
    pub groups: Arc<[String]>,
    /// Which `[[clients]]` entry kind matched, if a filter identified the client.
    pub matched: Option<MatchedBy>,
    /// The decision of the policy engine: the action and the reason (list ids, rule index,
    /// special domain). `None` when no engine decided.
    pub decision: Option<Decision>,
    /// The CNAME target that decided, when it is not the query name.
    pub cname_target: Option<DomainName>,
    /// The index of the conditional forwarding rule, when the query went to its server.
    pub forward_rule: Option<usize>,
}

/// One finished query, for statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEvent {
    /// The client address.
    pub client: IpAddr,
    /// UDP or TCP.
    pub transport: ClientTransport,
    /// The query name, as in [`QueryContext::qname`].
    pub qname: String,
    /// The query type.
    pub qtype: u16,
    /// The filter decision.
    pub verdict: Verdict,
    /// Where the answer came from.
    pub source: AnswerSource,
    /// The upstream that answered, when the answer came from an upstream.
    pub upstream: Option<SocketAddr>,
    /// The response code sent to the client.
    pub rcode: u16,
    /// Time from the start of the handling to the reply.
    pub duration: Duration,
    /// The client identity and the policy decision (part P3c).
    pub policy: PolicyInfo,
}

/// The statistics hook. An implementation must not block. Use a bounded channel and drop
/// events when it is full.
pub trait QueryObserver: Send + Sync + fmt::Debug {
    /// Called once for each answered query.
    fn on_event(&self, event: &QueryEvent);
}

/// An observer that does nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopObserver;

impl QueryObserver for NoopObserver {
    fn on_event(&self, _event: &QueryEvent) {}
}
