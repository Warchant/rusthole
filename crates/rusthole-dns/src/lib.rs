//! DNS listeners, upstream pool and request pipeline of rusthole (part P2).
//!
//! - [`server`]: settings from the config, the UDP and TCP listeners, the interface rescan
//!   and the shutdown.
//! - [`handler`]: the request pipeline (ACL, rate limit, filter, cache, upstream).
//! - [`upstream`]: the upstream pool with the hardening of amendment A5.
//! - [`wire`]: DNS wire format helpers on top of `hickory-proto`.
//! - [`filter`]: hooks for the policy engine (part P3a) and for statistics (part P4).
//! - [`interfaces`]: local interface addresses behind a trait.
//!
//! The policy (ACL, cache rules, rate limit, upstream health) is pure code in
//! `rusthole-core`. This crate is the I/O shell around it.

pub mod filter;
pub mod handler;
pub mod interfaces;
pub mod server;
mod sync;
pub mod upstream;
pub mod wire;

pub use filter::{
    AllowAll, AnswerSource, BlockKind, BlockReply, ClientTransport, FilterVerdict, NoopObserver,
    QueryContext, QueryEvent, QueryFilter, QueryObserver, Verdict,
};
pub use handler::{Front, Handler, HandlerSettings, Pending, Reply};
pub use interfaces::{InterfaceSource, StaticInterfaces, SystemInterfaces};
pub use server::{
    BoundListener, DnsServer, DnsSettings, ListenMode, ServerDeps, SettingsError, StartError,
    TcpLimits, start,
};
pub use sync::Clock;
pub use upstream::{PoolSettings, UpstreamAnswer, UpstreamError, UpstreamProto, UpstreamServer};
