//! rustls server configs for the admin and DoH listeners, and the client config for DoT and
//! DoH upstreams.
//!
//! Each config gets the ring provider explicitly. This crate never installs a process-wide
//! default provider, so no other crate can change the crypto by surprise.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::CertificateDer;

use crate::error::TlsError;
use crate::policy::{Listener, check_listener_mode};
use crate::store::CertStore;

/// ALPN name of HTTP/2.
pub const ALPN_H2: &[u8] = b"h2";
/// ALPN name of HTTP/1.1.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// TLS versions: 1.3 and 1.2 only.
static VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

fn server_config(
    store: &Arc<CertStore>,
    listener: Listener,
) -> Result<Arc<ServerConfig>, TlsError> {
    check_listener_mode(listener, store.mode())?;
    // The cipher suites are the ring provider defaults: AES-GCM and ChaCha20-Poly1305 with
    // ECDHE only. No CBC, no RSA key exchange.
    let mut config = ServerConfig::builder_with_provider(crate::provider())
        .with_protocol_versions(VERSIONS)?
        .with_no_client_auth()
        .with_cert_resolver(store.resolver());
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    config.ignore_client_order = true;
    Ok(Arc::new(config))
}

/// The server config for the admin listener. ALPN: `h2`, `http/1.1`. It accepts all three
/// TLS modes.
pub fn admin_server_config(store: &Arc<CertStore>) -> Result<Arc<ServerConfig>, TlsError> {
    server_config(store, Listener::Admin)
}

/// The server config for the DoH listener. ALPN: `h2` first (RFC 8484 recommends HTTP/2),
/// then `http/1.1`.
///
/// DoH clients need a certificate that they trust (amendment A6), so a store in mode
/// `self-signed` gives [`TlsError::SelfSignedForDoh`].
pub fn doh_server_config(store: &Arc<CertStore>) -> Result<Arc<ServerConfig>, TlsError> {
    server_config(store, Listener::Doh)
}

/// Where the client trust roots came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootSource {
    /// The system certificate store.
    System {
        /// Number of roots that rustls accepted.
        count: usize,
        /// Number of load errors (a part of the store can fail).
        errors: usize,
    },
    /// The bundled Mozilla roots (`webpki-roots`), because the system store gave no root.
    Bundled {
        /// Number of system load errors.
        system_errors: usize,
    },
}

/// Builds the root store from system roots. When rustls accepts no system root, the
/// function uses the bundled Mozilla roots (amendment A8).
pub fn roots_from(
    system: Vec<CertificateDer<'static>>,
    system_errors: usize,
) -> (RootCertStore, RootSource) {
    let mut roots = RootCertStore::empty();
    let (count, _ignored) = roots.add_parsable_certificates(system);
    if count > 0 {
        return (
            roots,
            RootSource::System {
                count,
                errors: system_errors,
            },
        );
    }
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    (roots, RootSource::Bundled { system_errors })
}

/// Loads the system roots, with the bundled roots as the fallback. See [`roots_from`].
pub fn system_roots() -> (RootCertStore, RootSource) {
    let result = rustls_native_certs::load_native_certs();
    for e in &result.errors {
        tracing::warn!("cannot load a system TLS root: {e}");
    }
    let errors = result.errors.len();
    roots_from(result.certs, errors)
}

/// The client config for DoT and DoH upstreams, with `roots`.
///
/// `alpn`: `[b"h2"]` for DoH, empty for DoT. Certificate checks need a valid clock: see
/// [`clock_plausible`](crate::clock_plausible).
pub fn client_config_with_roots(
    roots: RootCertStore,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let mut config = ClientConfig::builder_with_provider(crate::provider())
        .with_protocol_versions(VERSIONS)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
}

/// The client config for DoT and DoH upstreams, with the system roots (or the bundled
/// roots). The function logs where the roots came from.
pub fn client_config(alpn: Vec<Vec<u8>>) -> Result<(Arc<ClientConfig>, RootSource), TlsError> {
    let (roots, source) = system_roots();
    match &source {
        RootSource::System { count, .. } => {
            tracing::info!(count, "TLS client roots from the system store");
        }
        RootSource::Bundled { .. } => {
            tracing::warn!("no system TLS roots; rusthole uses the bundled Mozilla roots");
        }
    }
    Ok((client_config_with_roots(roots, alpn)?, source))
}
