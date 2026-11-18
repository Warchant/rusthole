//! TLS for rusthole: certificates and rustls configs for the admin listener and the DoH
//! listener, and the client config for DoT and DoH upstreams.
//!
//! Three modes give the server certificate (`tls.mode`, docs/TLS.md):
//!
//! - `file`: a certificate chain and a key from PEM files.
//! - `self-signed`: rusthole makes a self-signed certificate (admin UI only).
//! - `local-ca`: rusthole makes a local CA once and a server certificate that it signs.
//!
//! The crypto provider is `ring` (amendment A1). Each config gets it explicitly; this crate
//! never installs a process-wide default provider.
//!
//! The policy (renewal, clock check, names, the DoH rule) is in [`policy`]: pure functions
//! with `now` as an input. [`CertStore`] is the I/O shell around it.

pub mod configs;
pub mod error;
pub mod fsio;
pub mod generate;
pub mod pem;
pub mod policy;
pub mod store;

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

pub use configs::{
    ALPN_H2, ALPN_HTTP11, RootSource, admin_server_config, client_config, client_config_with_roots,
    doh_server_config, roots_from, system_roots,
};
pub use error::TlsError;
pub use pem::{CertFacts, LoadedPair, load_pem_pair};
pub use policy::{Listener, SanSet, clock_plausible, needs_renewal};
pub use store::{CertInfo, CertStore, Notice, ReloadOutcome, TlsSettings, now_unix};

#[cfg(test)]
mod tests;

/// The ring crypto provider. Each rustls config and verifier in rusthole uses it.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The lowest build time that [`build_time_unix`] gives: 2026-11-01 00:00:00 UTC.
pub const MIN_BUILD_TIME_UNIX: i64 = 1_793_491_200;

/// The build time of this binary in Unix seconds, from `build.rs`.
///
/// The value is at least [`MIN_BUILD_TIME_UNIX`]. Use it with [`clock_plausible`].
pub fn build_time_unix() -> i64 {
    env!("RUSTHOLE_BUILD_UNIX")
        .parse::<i64>()
        .unwrap_or(MIN_BUILD_TIME_UNIX)
        .max(MIN_BUILD_TIME_UNIX)
}
