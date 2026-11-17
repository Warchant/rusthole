//! Pure policy core of rusthole.
//!
//! This crate does no I/O. It reads no clock. A function that needs the time gets `now` as an
//! input. This makes all policy testable with property tests.

pub mod config;
pub mod domain;
pub mod net;
pub mod pattern;

pub use config::{Config, ConfigError, ConfigIssue};
pub use domain::{DomainError, DomainName};
