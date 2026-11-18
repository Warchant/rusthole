//! DoH wiring for `rusthole run` (part P7): the TLS server config of the DoH listener.
//!
//! The DNS server starts the DoH listener and the clock check task itself (they share its
//! pipeline, its upstream pool and its shutdown). This module only makes the TLS config.
//!
//! ```mermaid
//! flowchart LR
//!     cfg[server.doh.enabled?] -->|no| none[no DoH listener]
//!     cfg -->|yes| mode{tls.mode}
//!     mode -->|self-signed| err[start error: DoH clients refuse a self-signed certificate]
//!     mode -->|file or local-ca| store[open the certificate store] --> tls[doh_server_config]
//!     store -.->|the same store| admin[admin listener and the reload task in run.rs]
//! ```

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context;
use rusthole_core::Config;
use rusthole_core::config::TlsMode;
use rusthole_dns::{InterfaceSource, SystemInterfaces};
use rusthole_tls::{CertStore, TlsError, TlsSettings};

/// The certificate store and the TLS server config for the DoH listener, or `None` when
/// DoH is off. The admin listener and the reload task use the same store (M2).
///
/// A self-signed certificate gives an error before any file is written: DoH clients refuse
/// it without a message (amendment A6, docs/TLS.md).
pub(crate) fn server_tls(
    config: &Config,
) -> anyhow::Result<Option<(Arc<CertStore>, Arc<rustls::ServerConfig>)>> {
    if !config.server.doh.enabled {
        return Ok(None);
    }
    if config.tls_mode() == TlsMode::SelfSigned {
        return Err(TlsError::SelfSignedForDoh).context("cannot start the DoH listener");
    }
    let store = open_store(config).context("cannot start the DoH listener")?;
    let tls = rusthole_tls::doh_server_config(&store).context("cannot start the DoH listener")?;
    Ok(Some((store, tls)))
}

/// Opens the certificate store of the config. The local IPv4 addresses go into a
/// certificate that rusthole makes. One store serves both listeners (one store per data
/// directory); `run.rs` gives it to the admin listener.
pub(crate) fn open_store(config: &Config) -> anyhow::Result<Arc<CertStore>> {
    let ips = local_ips(&SystemInterfaces);
    let (store, _notices) = CertStore::open(
        TlsSettings::from_config(config),
        &ips,
        rusthole_tls::now_unix(),
    )
    .context("cannot load the TLS certificate")?;
    Ok(store)
}

/// The local IPv4 addresses, or none when the interfaces cannot be read.
pub(crate) fn local_ips(interfaces: &dyn InterfaceSource) -> Vec<IpAddr> {
    match interfaces.scan() {
        Ok(nets) => rusthole_dns::interfaces::listen_addrs(&nets),
        Err(e) => {
            tracing::warn!(error = %e, "cannot read the network interfaces; the certificate gets no local address");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_off_needs_no_tls() {
        assert!(server_tls(&Config::default()).unwrap().is_none());
    }

    #[test]
    fn self_signed_is_refused_for_doh_and_writes_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.server.data_dir = dir.path().display().to_string();
        cfg.server.doh.enabled = true;
        let err = server_tls(&cfg).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("self-signed"), "{text}");
        assert!(text.contains("local-ca"), "{text}");
        assert!(!dir.path().join("tls").exists());
    }

    #[test]
    fn local_ca_gives_a_doh_config_with_h2() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.server.data_dir = dir.path().display().to_string();
        cfg.server.doh.enabled = true;
        cfg.tls.mode = Some(TlsMode::LocalCa);
        cfg.tls.names = vec!["rusthole.lan".to_owned()];
        let (_, tls) = server_tls(&cfg).unwrap().unwrap();
        assert_eq!(tls.alpn_protocols[0], b"h2");
        assert!(dir.path().join("tls").join("ca.pem").exists());
    }
}
