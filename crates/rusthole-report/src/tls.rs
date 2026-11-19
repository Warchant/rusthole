//! The TLS section (docs/PLAN.md R-D8): the certificate that the name shows on port 443.
//!
//! ```mermaid
//! flowchart LR
//!     n[name] --> a[A records through the upstream pool]
//!     a --> g{a public IPv4 address?}
//!     g -->|no| u[unavailable]
//!     g -->|yes| h[TLS handshake to the first one, SNI = name]
//!     h --> c[read the chain, send no HTTP request, close]
//!     c --> v[check the chain with the system roots]
//!     c --> p[parse the certificates]
//! ```
//!
//! A bad certificate is data, not an error: the handshake accepts any chain, keeps it, and
//! the section shows whether the system roots trust it. The certificate bytes come from the
//! network: the parser is pure, keeps a fixed set of fields with size limits, and has the
//! fuzz target `cert_chain`.

use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::{RData, RecordType};
use parking_lot::Mutex;
use rusthole_core::DomainName;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use serde_json::{Value, json};
use x509_parser::extensions::GeneralName;

use crate::dns::{DnsLookup, safe_text};
use crate::guard::is_public_v4;
use crate::model::{Outcome, Status};

/// The most certificates of a chain that the section reads.
pub const MAX_CHAIN: usize = 8;
/// The most names of a certificate that the section shows.
pub const MAX_SANS: usize = 32;
/// The most bytes of one text field.
pub const MAX_TEXT: usize = 256;
/// The time limit of the TCP connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// The time limit of the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

/// What a handshake gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The chain as the server sent it, leaf first (DER), at most [`MAX_CHAIN`].
    pub chain: Vec<Vec<u8>>,
    /// `Ok` when the system roots trust the chain for the name; else the reason.
    pub trusted: Result<(), String>,
    /// The TLS version, for example `TLSv1_3`.
    pub version: Option<String>,
}

/// A boxed probe future.
pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = Result<Probe, String>> + Send + 'a>>;

/// A TLS handshake that reads the certificate chain. Tests use a fake.
pub trait TlsProbe: Send + Sync + fmt::Debug {
    /// Connects to `addr`, sends `name` as SNI, and gives the chain.
    fn probe<'a>(&'a self, name: &'a DomainName, addr: SocketAddr) -> ProbeFuture<'a>;
}

/// The facts of one certificate as JSON.
pub fn cert_json(der: &[u8], now_unix: i64) -> Result<Value, String> {
    let (_, c) =
        x509_parser::parse_x509_certificate(der).map_err(|e| format!("certificate: {e}"))?;
    let name_of = |n: &x509_parser::x509::X509Name<'_>| -> Option<String> {
        n.iter_common_name()
            .next()
            .or_else(|| n.iter_organization().next())
            .and_then(|a| a.as_str().ok())
            .map(|s| safe_text(s, MAX_TEXT))
    };
    let org_of = |n: &x509_parser::x509::X509Name<'_>| -> Option<String> {
        n.iter_organization()
            .next()
            .and_then(|a| a.as_str().ok())
            .map(|s| safe_text(s, MAX_TEXT))
    };
    let mut sans = Vec::new();
    let mut more = false;
    if let Ok(Some(ext)) = c.subject_alternative_name() {
        for g in &ext.value.general_names {
            let v = match g {
                GeneralName::DNSName(n) => safe_text(n, MAX_TEXT),
                GeneralName::IPAddress(b) => match <[u8; 4]>::try_from(*b) {
                    Ok(a) => Ipv4Addr::from(a).to_string(),
                    Err(_) => continue,
                },
                _ => continue,
            };
            if sans.len() >= MAX_SANS {
                more = true;
                break;
            }
            sans.push(v);
        }
    }
    let v = c.validity();
    let not_after = v.not_after.timestamp();
    Ok(json!({
        "subject": name_of(c.subject()),
        "subject_org": org_of(c.subject()),
        "issuer": name_of(c.issuer()),
        "issuer_org": org_of(c.issuer()),
        "names": sans,
        "names_truncated": more,
        "not_before": v.not_before.timestamp(),
        "not_after": not_after,
        "days_left": (not_after - now_unix).div_euclid(86_400),
        "self_signed": c.subject().as_raw() == c.issuer().as_raw(),
        "key": safe_text(&c.public_key().algorithm.algorithm.to_id_string(), MAX_TEXT),
        "signature": safe_text(&c.signature_algorithm.algorithm.to_id_string(), MAX_TEXT),
    }))
}

/// The section data of a probe: the leaf and the other certificates of the chain.
pub fn probe_json(p: &Probe, now_unix: i64) -> Value {
    let certs: Vec<Value> = p
        .chain
        .iter()
        .take(MAX_CHAIN)
        .map(|der| {
            cert_json(der, now_unix).unwrap_or_else(|e| json!({ "error": safe_text(&e, MAX_TEXT) }))
        })
        .collect();
    json!({
        "trusted": p.trusted.is_ok(),
        "trust_error": p.trusted.as_ref().err().map(|e| safe_text(e, MAX_TEXT)),
        "version": p.version,
        "chain": certs,
    })
}

/// Runs the TLS section for `name`: the first public IPv4 address of the name.
pub async fn run(
    dns: &dyn DnsLookup,
    probe: &dyn TlsProbe,
    name: &DomainName,
    now_unix: i64,
) -> Outcome {
    let answer =
        match tokio::time::timeout(Duration::from_secs(3), dns.lookup(name, RecordType::A)).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => return Outcome::failed(format!("name lookup: {e}")),
            Err(_) => return Outcome::failed("name lookup: no answer in 3 s"),
        };
    let addrs: Vec<Ipv4Addr> = answer
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    let Some(ip) = addrs.iter().copied().find(|a| is_public_v4(*a)) else {
        let why = if addrs.is_empty() {
            "the name has no IPv4 address"
        } else {
            "the name has no public IPv4 address (rusthole does not connect to the LAN)"
        };
        return Outcome {
            status: Status::Unavailable,
            data: json!({ "addresses": addrs.iter().take(8).map(ToString::to_string).collect::<Vec<_>>() }),
            error: Some(why.to_owned()),
        };
    };
    let addr = SocketAddr::new(ip.into(), 443);
    match probe.probe(name, addr).await {
        Ok(p) => {
            let mut data = probe_json(&p, now_unix);
            if let Some(o) = data.as_object_mut() {
                o.insert("address".to_owned(), json!(addr.to_string()));
            }
            Outcome {
                status: Status::Ok,
                data,
                error: None,
            }
        }
        Err(e) => Outcome {
            status: Status::Failed,
            data: json!({ "address": addr.to_string() }),
            error: Some(safe_text(&e, MAX_TEXT)),
        },
    }
}

/// The chain that a server sent (DER, leaf first) and the result of the real check.
type Seen = (Vec<Vec<u8>>, Result<(), String>);

/// A verifier that accepts any chain, keeps it, and keeps the result of the real check.
#[derive(Debug)]
struct Recorder {
    /// The real check. `Err`: it cannot be built (for example no roots); the reason.
    inner: Result<Arc<WebPkiServerVerifier>, String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    seen: Mutex<Option<Seen>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let check = match &self.inner {
            Ok(v) => v
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.clone()),
        };
        let chain = std::iter::once(end_entity)
            .chain(intermediates)
            .take(MAX_CHAIN)
            .map(|c| c.as_ref().to_vec())
            .collect();
        if let Some(mut s) = self.seen.try_lock_for(Duration::from_secs(1)) {
            *s = Some((chain, check));
        }
        // Accept: the section reads the chain and sends no data.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A [`TlsProbe`] that always fails (tests, tools).
#[derive(Debug, Clone)]
pub struct NoTls(pub String);

impl TlsProbe for NoTls {
    fn probe<'a>(&'a self, _name: &'a DomainName, _addr: SocketAddr) -> ProbeFuture<'a> {
        let reason = self.0.clone();
        Box::pin(async move { Err(reason) })
    }
}

/// The production probe: TCP to the address, a TLS handshake with SNI, then close.
#[derive(Debug, Clone)]
pub struct TlsClient {
    roots: Arc<RootCertStore>,
}

impl TlsClient {
    /// A probe that checks chains with `roots`.
    pub fn new(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
        }
    }
}

impl TlsProbe for TlsClient {
    fn probe<'a>(&'a self, name: &'a DomainName, addr: SocketAddr) -> ProbeFuture<'a> {
        Box::pin(async move {
            let provider = rusthole_tls::provider();
            let inner = WebPkiServerVerifier::builder_with_provider(
                Arc::clone(&self.roots),
                Arc::clone(&provider),
            )
            .build()
            .map_err(|e| format!("no trust check: {e}"));
            let recorder = Arc::new(Recorder {
                inner,
                provider: Arc::clone(&provider),
                seen: Mutex::new(None),
            });
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("TLS setup: {e}"))?
                .dangerous()
                .with_custom_certificate_verifier(
                    Arc::clone(&recorder) as Arc<dyn ServerCertVerifier>
                )
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let sni =
                ServerName::try_from(name.as_str().to_owned()).map_err(|e| format!("SNI: {e}"))?;
            let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
                .await
                .map_err(|_| {
                    format!(
                        "no TCP connection to {addr} in {} s",
                        CONNECT_TIMEOUT.as_secs()
                    )
                })?
                .map_err(|e| format!("TCP connection to {addr}: {e}"))?;
            let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(sni, tcp)).await;
            let version = match &tls {
                Ok(Ok(s)) => s.get_ref().1.protocol_version().map(|v| format!("{v:?}")),
                _ => None,
            };
            // The chain is known after the verifier ran, also when the handshake failed later.
            let seen = recorder
                .seen
                .try_lock_for(Duration::from_secs(1))
                .and_then(|mut s| s.take());
            match (seen, tls) {
                (Some((chain, trusted)), _) => Ok(Probe {
                    chain,
                    trusted,
                    version,
                }),
                (None, Ok(Err(e))) => Err(format!("TLS handshake: {e}")),
                (None, Err(_)) => Err(format!(
                    "no TLS handshake in {} s",
                    HANDSHAKE_TIMEOUT.as_secs()
                )),
                (None, Ok(Ok(_))) => Err("the server sent no certificate".to_owned()),
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)] // Tests: a failure is a test failure.
mod tests {
    use std::net::IpAddr;

    use hickory_proto::rr::rdata::A;
    use proptest::prelude::*;
    use rusthole_tls::SanSet;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::PemObject;

    use super::*;
    use crate::dns::tests::{FakeDns, answer, rec};

    const NOW: i64 = 1_795_000_000;

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn pair(host: &str) -> rusthole_tls::generate::GeneratedPair {
        let mut sans = SanSet::default();
        sans.names.insert(host.to_owned());
        rusthole_tls::generate::self_signed(&sans, NOW).unwrap()
    }

    fn der(p: &rusthole_tls::generate::GeneratedPair) -> Vec<u8> {
        CertificateDer::from_pem_slice(p.cert_pem.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    #[test]
    fn cert_facts_of_a_self_signed_certificate() {
        let v = cert_json(&der(&pair("probe.test")), NOW).unwrap();
        assert_eq!(v["subject"], "rusthole self-signed");
        assert_eq!(v["names"][0], "probe.test");
        assert_eq!(v["self_signed"], true);
        assert!(v["days_left"].as_i64().unwrap() > 300);
        assert!(cert_json(b"not a certificate", NOW).is_err());
    }

    /// A fake probe: a fixed chain, or an error.
    #[derive(Debug)]
    struct FakeProbe(Result<Probe, String>);

    impl TlsProbe for FakeProbe {
        fn probe<'a>(&'a self, _name: &'a DomainName, addr: SocketAddr) -> ProbeFuture<'a> {
            assert!(
                matches!(addr.ip(), IpAddr::V4(v) if is_public_v4(v)),
                "probe to {addr}"
            );
            let r = self.0.clone();
            Box::pin(async move { r })
        }
    }

    fn dns_with(n: &str, ips: &[[u8; 4]]) -> FakeDns {
        let mut d = FakeDns::default();
        let recs = ips
            .iter()
            .map(|i| rec(n, RData::A(A(Ipv4Addr::from(*i)))))
            .collect();
        d.table
            .insert((n.to_owned(), RecordType::A), Ok(answer(0, recs)));
        d
    }

    #[tokio::test]
    async fn run_uses_the_first_public_address_only() {
        let chain = vec![der(&pair("site.test"))];
        let ok = FakeProbe(Ok(Probe {
            chain,
            trusted: Err("unknown issuer".to_owned()),
            version: Some("TLSv1_3".to_owned()),
        }));
        let dns = dns_with("site.test", &[[192, 168, 1, 5], [20, 42, 65, 92]]);
        let o = run(&dns, &ok, &name("site.test"), NOW).await;
        assert_eq!(o.status, Status::Ok, "{o:?}");
        assert_eq!(o.data["address"], "20.42.65.92:443");
        assert_eq!(o.data["trusted"], false);
        assert_eq!(o.data["trust_error"], "unknown issuer");
        assert_eq!(o.data["chain"][0]["names"][0], "site.test");

        let lan = dns_with("nas.test", &[[192, 168, 1, 5]]);
        let o = run(&lan, &ok, &name("nas.test"), NOW).await;
        assert_eq!(o.status, Status::Unavailable);
        assert_eq!(o.data["addresses"][0], "192.168.1.5");

        let none = FakeDns::default();
        assert_eq!(
            run(&none, &ok, &name("x.test"), NOW).await.status,
            Status::Unavailable
        );

        let bad = FakeProbe(Err("refused".to_owned()));
        let o = run(
            &dns_with("site.test", &[[20, 42, 65, 92]]),
            &bad,
            &name("site.test"),
            NOW,
        )
        .await;
        assert_eq!(o.status, Status::Failed);
    }

    #[tokio::test]
    async fn real_handshake_reads_an_untrusted_chain() {
        let p = pair("probe.test");
        let cert = CertificateDer::from_pem_slice(p.cert_pem.as_bytes()).unwrap();
        let key = PrivateKeyDer::from_pem_slice(p.key_pem.as_bytes()).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(rusthole_tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await;
        });
        let probe = TlsClient::new(RootCertStore::empty());
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            probe.probe(&name("probe.test"), addr),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r.chain.len(), 1);
        assert!(r.trusted.is_err());
        assert!(r.version.is_some());
        let v = probe_json(&r, NOW);
        assert_eq!(v["chain"][0]["names"][0], "probe.test");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn real_handshake_with_a_known_ca_is_trusted() {
        let now = rusthole_tls::now_unix();
        let ca = rusthole_tls::generate::local_ca(&rusthole_tls::policy::CaScope::default(), now)
            .unwrap();
        let ca_der = CertificateDer::from_pem_slice(ca.cert_pem.as_bytes()).unwrap();
        let mut sans = SanSet::default();
        sans.names.insert("probe.test".to_owned());
        let leaf = rusthole_tls::generate::issue_leaf(&ca_der, &ca.key_pem, &sans, now).unwrap();
        let leaf_der = CertificateDer::from_pem_slice(leaf.cert_pem.as_bytes()).unwrap();
        let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(rusthole_tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der, ca_der.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await;
        });
        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let probe = TlsClient::new(roots);
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            probe.probe(&name("probe.test"), addr),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(r.trusted, Ok(()));
        assert_eq!(r.chain.len(), 2);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_closed_port_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let probe = TlsClient::new(RootCertStore::empty());
        assert!(probe.probe(&name("probe.test"), addr).await.is_err());
    }

    proptest! {
        /// Any bytes: the parser never panics.
        #[test]
        fn cert_parser_is_total(body in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = cert_json(&body, NOW);
        }
    }
}
