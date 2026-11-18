//! DNS listeners, upstream pool and request pipeline of rusthole (part P2).
//!
//! - [`server`]: settings from the config, the UDP and TCP listeners, the interface rescan
//!   and the shutdown.
//! - [`handler`]: the request pipeline (ACL, rate limit, filter, cache, upstream).
//! - [`upstream`]: the upstream pool with the hardening of amendment A5.
//! - [`wire`]: DNS wire format helpers on top of `hickory-proto`.
//! - [`filter`]: hooks for the policy engine (part P3a) and for statistics (part P4).
//! - [`interfaces`]: local interface addresses behind a trait.
//! - [`neighbors`]: the kernel neighbor table (MAC addresses of clients, part P3c).
//! - [`identity`]: client identity: MAC, host name, groups (part P3c).
//! - [`policy_filter`]: the policy filter and the blocking toggle (part P3c).
//! - [`local`]: replies from local DNS data (part P3c).
//!
//! The policy (ACL, cache rules, rate limit, upstream health) is pure code in
//! `rusthole-core`. This crate is the I/O shell around it.

pub mod filter;
pub mod handler;
pub mod identity;
pub mod interfaces;
pub mod local;
pub mod neighbors;
pub mod policy_filter;
pub mod server;
mod sync;
pub mod upstream;
pub mod wire;

pub use filter::{
    AllowAll, AnswerSource, BlockKind, BlockReply, ClientInfo, ClientTransport, FilterOutcome,
    FilterVerdict, NoopObserver, PolicyInfo, QueryContext, QueryEvent, QueryFilter, QueryObserver,
    Verdict,
};
pub use handler::{Front, Handler, HandlerSettings, Pending, Reply, Route};
pub use identity::{ClientResolver, IdentityService, IdentitySettings};
pub use interfaces::{InterfaceSource, StaticInterfaces, SystemInterfaces};
pub use neighbors::{NeighborSource, NeighborTable, StaticNeighbors, SystemNeighbors};
pub use policy_filter::{BlockingControl, EngineHandle, PolicyFilter, ToggleError, engine_handle};
pub use server::{
    BoundListener, DnsServer, DnsSettings, ListenMode, ServerDeps, SettingsError, StartError,
    TcpLimits, start,
};
pub use sync::Clock;
pub use upstream::{PoolSettings, UpstreamAnswer, UpstreamError, UpstreamProto, UpstreamServer};
