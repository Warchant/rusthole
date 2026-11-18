//! Pure policy core of rusthole.
//!
//! This crate does no I/O. It reads no clock. A function that needs the time gets `now` as an
//! input. This makes all policy testable with property tests.

pub mod acl;
pub mod ban;
pub mod blocking_state;
pub mod cache;
pub mod clients;
pub mod config;
pub mod domain;
pub mod lists;
pub mod localdns;
pub mod net;
pub mod pattern;
pub mod policy;
pub mod ratelimit;
pub mod refresh;
pub mod session;
pub mod stats;
pub mod upstream_health;

pub use config::{Config, ConfigError, ConfigIssue};
pub use domain::{DomainError, DomainName};
pub use policy::{Decision, GroupSet, PolicyEngine};
