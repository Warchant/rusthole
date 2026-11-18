//! The policy filter (part P3c): [`QueryFilter`] with the policy engine of part P3a.
//!
//! - [`QueryFilter::identify`] asks the [`ClientResolver`] for the MAC address and groups.
//! - [`QueryFilter::decide_query`] checks the query name for the groups of the client.
//! - [`QueryFilter::decide_answer`] checks the query name and each name in the answer (the
//!   deep CNAME check of amendment A4) on every reply, also on a cache hit.
//!
//! The engine is in an [`ArcSwap`]: part P3b swaps a new engine in with
//! [`PolicyFilter::engine`] and the query path never waits. Each check loads the engine once
//! and makes the [`rusthole_core::GroupSet`] from that engine, because a group set is valid
//! only for the engine that made it.
//!
//! [`BlockingControl`] holds the blocking toggle (amendment A9). Part P5 drives it from the
//! API.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rusthole_core::blocking_state::{
    BlockingToggle, InvalidEvent, MonoTime, ToggleEvent, ToggleState,
};
use rusthole_core::policy::{self, Action, SpecialReply};
use rusthole_core::{Decision, DomainName, PolicyEngine};

use crate::filter::{
    BlockKind, BlockReply, ClientInfo, FilterOutcome, FilterVerdict, QueryContext, QueryFilter,
};
use crate::identity::ClientResolver;
use crate::sync::{Clock, LOCK_TIMEOUT};

/// The shared, swappable policy engine.
pub type EngineHandle = Arc<ArcSwap<PolicyEngine>>;

/// Makes an [`EngineHandle`] that holds `engine`.
pub fn engine_handle(engine: PolicyEngine) -> EngineHandle {
    Arc::new(ArcSwap::from_pointee(engine))
}

/// Why a toggle change failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ToggleError {
    /// The toggle refused the event. It logged the event at ERROR and blocking is on.
    #[error("invalid toggle event: {0}")]
    Invalid(#[from] InvalidEvent),
    /// The toggle lock timed out. Nothing changed.
    #[error("the blocking toggle lock timed out")]
    LockTimeout,
}

/// The blocking toggle, shared between the DNS path and the API. Thread-safe. The time
/// comes from a monotonic clock.
#[derive(Debug)]
pub struct BlockingControl {
    toggle: Mutex<BlockingToggle>,
    clock: Clock,
}

impl BlockingControl {
    /// A toggle that starts on (`enabled`) or off with no timer.
    pub fn new(enabled: bool) -> Self {
        Self {
            toggle: Mutex::new(BlockingToggle::new(enabled)),
            clock: Clock::new(),
        }
    }

    fn now(&self) -> MonoTime {
        MonoTime::from_duration(Duration::from_millis(self.clock.now_ms()))
    }

    /// True when blocking is on now. A lock timeout gives true (the safe choice).
    pub fn is_blocking(&self) -> bool {
        let now = self.now();
        if let Some(t) = self.toggle.try_lock_for(LOCK_TIMEOUT) {
            t.is_blocking(now)
        } else {
            tracing::error!("the blocking toggle lock timed out; blocking stays on");
            true
        }
    }

    /// Turns blocking off, for `duration` or with no timer.
    pub fn disable(&self, duration: Option<Duration>) -> Result<(), ToggleError> {
        let now = self.now();
        self.step(ToggleEvent::Disable { duration, now })
    }

    /// Turns blocking on.
    pub fn enable(&self) -> Result<(), ToggleError> {
        self.step(ToggleEvent::Enable)
    }

    /// The time until blocking comes on again, when a timer runs.
    pub fn remaining(&self) -> Option<Duration> {
        let now = self.now();
        self.toggle
            .try_lock_for(LOCK_TIMEOUT)
            .and_then(|t| t.remaining(now))
    }

    /// The state of the toggle. `None` when the lock timed out.
    pub fn state(&self) -> Option<ToggleState> {
        self.toggle.try_lock_for(LOCK_TIMEOUT).map(|t| t.state())
    }

    fn step(&self, event: ToggleEvent) -> Result<(), ToggleError> {
        let mut t = self
            .toggle
            .try_lock_for(LOCK_TIMEOUT)
            .ok_or(ToggleError::LockTimeout)?;
        t.step(event)?;
        Ok(())
    }
}

/// The policy filter. See the module documentation.
#[derive(Debug)]
pub struct PolicyFilter {
    engine: EngineHandle,
    blocking: Arc<BlockingControl>,
    clients: Arc<ClientResolver>,
}

impl PolicyFilter {
    /// Makes the filter.
    pub fn new(
        engine: EngineHandle,
        blocking: Arc<BlockingControl>,
        clients: Arc<ClientResolver>,
    ) -> Self {
        Self {
            engine,
            blocking,
            clients,
        }
    }

    /// The engine handle. Store a new engine in it to swap the policy.
    pub fn engine(&self) -> &EngineHandle {
        &self.engine
    }

    /// The blocking toggle.
    pub fn blocking(&self) -> &Arc<BlockingControl> {
        &self.blocking
    }

    /// The client resolver.
    pub fn clients(&self) -> &Arc<ClientResolver> {
        &self.clients
    }
}

/// The DNS block reply of a policy action, or `None` for an allow.
fn reply_of(action: Action, ttl: u32) -> Option<BlockReply> {
    let kind = match action {
        Action::Allow => return None,
        Action::Special(SpecialReply::Nxdomain) => BlockKind::Nxdomain,
        Action::Block(r) => match r {
            policy::BlockReply::Null => BlockKind::Null,
            policy::BlockReply::Nxdomain => BlockKind::Nxdomain,
            policy::BlockReply::Nodata => BlockKind::Nodata,
            policy::BlockReply::Ip { ipv4, ipv6 } => BlockKind::Ip { v4: ipv4, v6: ipv6 },
        },
    };
    Some(BlockReply { kind, ttl })
}

fn outcome(engine: &PolicyEngine, decision: Decision, chain: &[DomainName]) -> FilterOutcome {
    let verdict = reply_of(decision.action, engine.blocked_ttl())
        .map_or(FilterVerdict::Allow, FilterVerdict::Block);
    let cname_target = (decision.is_blocked() && decision.name_index > 0)
        .then(|| chain.get(decision.name_index).cloned())
        .flatten();
    FilterOutcome {
        verdict,
        decision: Some(decision),
        cname_target,
    }
}

impl QueryFilter for PolicyFilter {
    fn on_query(&self, ctx: &QueryContext) -> FilterVerdict {
        self.decide_query(ctx, &self.identify(ctx.client)).verdict
    }

    fn on_answer(&self, ctx: &QueryContext, answer_names: &[DomainName]) -> FilterVerdict {
        self.decide_answer(ctx, &self.identify(ctx.client), answer_names)
            .verdict
    }

    fn identify(&self, client: IpAddr) -> ClientInfo {
        self.clients.identify(client)
    }

    fn decide_query(&self, ctx: &QueryContext, client: &ClientInfo) -> FilterOutcome {
        let Some(name) = &ctx.domain else {
            // Not a host name (for example the root name): no list can hold it.
            return FilterVerdict::Allow.into();
        };
        let engine = self.engine.load();
        let groups = engine.groups_named(client.groups.iter().map(String::as_str));
        let d = engine.check(&groups, self.blocking.is_blocking(), name);
        outcome(&engine, d, std::slice::from_ref(name))
    }

    fn decide_answer(
        &self,
        ctx: &QueryContext,
        client: &ClientInfo,
        answer_names: &[DomainName],
    ) -> FilterOutcome {
        // The query name is first, so that `check_chain` checks it also when
        // `deep_cname_check` is off, and `name_index` 0 is the query name.
        let mut chain: Vec<DomainName> = Vec::with_capacity(answer_names.len() + 1);
        if let Some(q) = &ctx.domain {
            chain.push(q.clone());
        }
        for n in answer_names {
            if !chain.contains(n) {
                chain.push(n.clone());
            }
        }
        if chain.is_empty() {
            return FilterVerdict::Allow.into();
        }
        let engine = self.engine.load();
        let groups = engine.groups_named(client.groups.iter().map(String::as_str));
        let d = engine.check_chain(&groups, self.blocking.is_blocking(), &chain);
        outcome(&engine, d, &chain)
    }
}

#[cfg(test)]
mod tests;
