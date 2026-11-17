//! Pure policy core of rusthole.
//!
//! This crate does no I/O. It reads no clock. A function that needs the time gets `now` as an
//! input. This makes all policy testable with property tests.

pub mod domain;

pub use domain::{DomainError, DomainName};
