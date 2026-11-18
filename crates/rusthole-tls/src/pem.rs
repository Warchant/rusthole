//! PEM parsing and certificate facts. No I/O: the functions read bytes.
//!
//! The input can come from a file that a user gives, so it is untrusted. Each function
//! returns an error for bad input and never panics. The fuzz target `pem_load` covers
//! [`load_pem_pair`].

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::X509Certificate;

use crate::error::TlsError;
use crate::policy::{CaScope, CertDates, Net4, SanSet};

/// Largest PEM input that rusthole reads (1 MiB).
pub const MAX_PEM_BYTES: usize = 1024 * 1024;
/// Largest number of certificates in a chain.
pub const MAX_CHAIN_LEN: usize = 16;

/// Parses a certificate chain from PEM text. `what` names the input in an error.
///
/// Sections that are not certificates are skipped. The first certificate is the server
/// certificate.
pub fn parse_cert_chain(
    pem_bytes: &[u8],
    what: &str,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    if pem_bytes.len() > MAX_PEM_BYTES {
        return Err(TlsError::TooLarge {
            what: what.to_owned(),
            limit: MAX_PEM_BYTES,
        });
    }
    let mut chain = Vec::new();
    // Bounded: at most MAX_CHAIN_LEN + 1 items are read.
    for item in CertificateDer::pem_slice_iter(pem_bytes).take(MAX_CHAIN_LEN + 1) {
        let cert = item.map_err(|e| TlsError::BadCertPem {
            what: what.to_owned(),
            detail: cert_pem_error_text(&e),
        })?;
        chain.push(cert);
    }
    if chain.len() > MAX_CHAIN_LEN {
        return Err(TlsError::TooManyCerts {
            what: what.to_owned(),
            limit: MAX_CHAIN_LEN,
        });
    }
    if chain.is_empty() {
        return Err(TlsError::NoCertificate {
            what: what.to_owned(),
        });
    }
    Ok(chain)
}

/// Describes a certificate PEM error. A certificate is public, but the text stays short.
fn cert_pem_error_text(e: &pem::Error) -> String {
    match e {
        pem::Error::MissingSectionEnd { .. } => "a section has no END line".to_owned(),
        pem::Error::IllegalSectionStart { .. } => "a BEGIN line is not valid".to_owned(),
        pem::Error::Base64Decode(_) => "the base64 text is not valid".to_owned(),
        pem::Error::SectionTooLarge => "a section is too large".to_owned(),
        other => other.to_string(),
    }
}

/// Parses the first private key (PKCS#8, PKCS#1 or SEC1) from PEM text.
///
/// The error never holds bytes of the input, because the input is a secret.
pub fn parse_private_key(pem_bytes: &[u8], what: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    if pem_bytes.len() > MAX_PEM_BYTES {
        return Err(TlsError::TooLarge {
            what: what.to_owned(),
            limit: MAX_PEM_BYTES,
        });
    }
    PrivateKeyDer::from_pem_slice(pem_bytes).map_err(|e| {
        let kind = match e {
            pem::Error::NoItemsFound => {
                return TlsError::NoKey {
                    what: what.to_owned(),
                };
            }
            pem::Error::MissingSectionEnd { .. } => "a section has no END line",
            pem::Error::IllegalSectionStart { .. } => "a BEGIN line is not valid",
            pem::Error::Base64Decode(_) => "the base64 text is not valid",
            pem::Error::SectionTooLarge => "a section is too large",
            _ => "unknown PEM error",
        };
        TlsError::BadKeyPem {
            what: what.to_owned(),
            kind,
        }
    })
}

/// A certificate chain and key that belong together, with the facts of the server
/// certificate.
#[derive(Debug, Clone)]
pub struct LoadedPair {
    /// The chain and the signing key, ready for rustls.
    pub certified: Arc<CertifiedKey>,
    /// Facts about the server certificate.
    pub facts: CertFacts,
}

/// Parses a PEM certificate chain and a PEM private key, and checks that they belong
/// together. `cert_what` and `key_what` name the inputs in an error.
pub fn load_pem_pair_named(
    cert_pem: &[u8],
    key_pem: &[u8],
    cert_what: &str,
    key_what: &str,
    provider: &CryptoProvider,
) -> Result<LoadedPair, TlsError> {
    let chain = parse_cert_chain(cert_pem, cert_what)?;
    let key = parse_private_key(key_pem, key_what)?;
    let facts = match chain.first() {
        Some(leaf) => cert_facts(leaf, cert_what)?,
        None => {
            return Err(TlsError::NoCertificate {
                what: cert_what.to_owned(),
            });
        }
    };
    let signing_key =
        provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| TlsError::BadKey {
                what: key_what.to_owned(),
                detail: e.to_string(),
            })?;
    let certified = CertifiedKey::new(chain, signing_key);
    match certified.keys_match() {
        Ok(()) => {}
        Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) => {
            return Err(TlsError::KeyMismatch {
                cert: cert_what.to_owned(),
                key: key_what.to_owned(),
            });
        }
        // The key cannot give its public key, so rustls cannot compare. The ring provider
        // gives the public key for each key type, so this path is not expected. rustls also
        // accepts this case in `CertifiedKey::from_der`.
        Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
            tracing::warn!(
                key = key_what,
                "cannot check that the key matches the certificate"
            );
        }
        Err(e) => {
            return Err(TlsError::BadCert {
                what: cert_what.to_owned(),
                detail: e.to_string(),
            });
        }
    }
    Ok(LoadedPair {
        certified: Arc::new(certified),
        facts,
    })
}

/// Like [`load_pem_pair_named`], with the names "certificate" and "key".
pub fn load_pem_pair(
    cert_pem: &[u8],
    key_pem: &[u8],
    provider: &CryptoProvider,
) -> Result<LoadedPair, TlsError> {
    load_pem_pair_named(cert_pem, key_pem, "certificate", "key", provider)
}

/// Facts about one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFacts {
    /// Validity, Unix seconds.
    pub dates: CertDates,
    /// The DNS names and IP addresses in the subject alternative name extension.
    pub sans: SanSet,
    /// SHA-256 of the DER bytes.
    pub sha256: [u8; 32],
    /// The raw subject name (DER).
    pub subject: Vec<u8>,
    /// The raw issuer name (DER).
    pub issuer: Vec<u8>,
    /// The subject key identifier, if the certificate has one.
    pub subject_key_id: Option<Vec<u8>>,
    /// The key identifier in the authority key identifier extension, if any.
    pub authority_key_id: Option<Vec<u8>>,
    /// The name constraints of a CA certificate.
    pub scope: CaScope,
}

impl CertFacts {
    /// The SHA-256 fingerprint as upper-case hex pairs with colons (`AB:CD:...`). Browsers
    /// show the fingerprint in this form.
    pub fn fingerprint(&self) -> String {
        fingerprint_text(&self.sha256)
    }

    /// Tells if `self` (a server certificate) names `ca` as its issuer: the issuer name is
    /// the subject name of the CA, and the authority key identifier is the subject key
    /// identifier of the CA.
    pub fn issued_by(&self, ca: &CertFacts) -> bool {
        self.issuer == ca.subject
            && self.authority_key_id.is_some()
            && self.authority_key_id == ca.subject_key_id
    }
}

/// Formats a SHA-256 digest as upper-case hex pairs with colons.
pub fn fingerprint_text(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(32 * 3);
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        // Writing to a String cannot fail.
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Computes the SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Reads the facts of one DER certificate. `what` names the input in an error.
pub fn cert_facts(der: &CertificateDer<'_>, what: &str) -> Result<CertFacts, TlsError> {
    let bad = |detail: String| TlsError::BadCert {
        what: what.to_owned(),
        detail,
    };
    let (_rest, x509) =
        x509_parser::parse_x509_certificate(der.as_ref()).map_err(|e| bad(e.to_string()))?;
    let validity = x509.validity();
    let dates = CertDates {
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
    };
    let sans = san_set(&x509).map_err(bad)?;
    let scope = ca_scope(&x509).map_err(bad)?;
    let mut subject_key_id = None;
    let mut authority_key_id = None;
    for ext in x509.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => subject_key_id = Some(id.0.to_vec()),
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                authority_key_id = aki.key_identifier.as_ref().map(|id| id.0.to_vec());
            }
            _ => {}
        }
    }
    Ok(CertFacts {
        dates,
        sans,
        sha256: sha256(der.as_ref()),
        subject: x509.subject().as_raw().to_vec(),
        issuer: x509.issuer().as_raw().to_vec(),
        subject_key_id,
        authority_key_id,
        scope,
    })
}

/// Reads an IP address in the encoded form of a SAN (4 or 16 bytes).
fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok(b) = <[u8; 4]>::try_from(bytes) {
        return Some(IpAddr::from(b));
    }
    <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from)
}

fn san_set(x509: &X509Certificate<'_>) -> Result<SanSet, String> {
    let mut set = SanSet::default();
    let Some(ext) = x509.subject_alternative_name().map_err(|e| e.to_string())? else {
        return Ok(set);
    };
    for name in &ext.value.general_names {
        match name {
            GeneralName::DNSName(n) => {
                set.names.insert(n.to_ascii_lowercase());
            }
            GeneralName::IPAddress(bytes) => {
                if let Some(ip) = ip_from_bytes(bytes) {
                    set.ips.insert(ip);
                }
            }
            _ => {}
        }
    }
    Ok(set)
}

fn ca_scope(x509: &X509Certificate<'_>) -> Result<CaScope, String> {
    let Some(ext) = x509.name_constraints().map_err(|e| e.to_string())? else {
        return Ok(CaScope::default());
    };
    let mut dns = BTreeSet::new();
    let mut ipv4 = BTreeSet::new();
    let permitted = ext.value.permitted_subtrees.as_deref().unwrap_or_default();
    for subtree in permitted {
        match &subtree.base {
            GeneralName::DNSName(n) => {
                dns.insert(n.to_ascii_lowercase());
            }
            GeneralName::IPAddress(bytes) => {
                // An IPv4 subtree is the address and the mask: 8 bytes.
                if let Ok([a, b, c, d, m0, m1, m2, m3]) = <[u8; 8]>::try_from(*bytes) {
                    let mask = u32::from_be_bytes([m0, m1, m2, m3]);
                    let prefix = u8::try_from(mask.leading_ones()).unwrap_or(32);
                    ipv4.insert(Net4 {
                        addr: std::net::Ipv4Addr::new(a, b, c, d),
                        prefix,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(CaScope {
        dns: (!dns.is_empty()).then_some(dns),
        ipv4: (!ipv4.is_empty()).then_some(ipv4),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_junk_input() {
        let p = crate::provider();
        assert!(matches!(
            parse_cert_chain(b"", "c"),
            Err(TlsError::NoCertificate { .. })
        ));
        assert!(matches!(
            parse_private_key(b"", "k"),
            Err(TlsError::NoKey { .. })
        ));
        assert!(matches!(
            parse_cert_chain(
                b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
                "c"
            ),
            Err(TlsError::BadCertPem { .. })
        ));
        assert!(matches!(
            parse_cert_chain(b"-----BEGIN CERTIFICATE-----\nAAAA\n", "c"),
            Err(TlsError::BadCertPem { .. })
        ));
        // Valid base64, but not a certificate.
        let fake = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            load_pem_pair(fake, b"", &p),
            Err(TlsError::NoKey { .. })
        ));
        let key = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(matches!(
            load_pem_pair(fake, key, &p),
            Err(TlsError::BadCert { .. })
        ));
        let big = vec![b'a'; MAX_PEM_BYTES + 1];
        assert!(matches!(
            parse_cert_chain(&big, "c"),
            Err(TlsError::TooLarge { .. })
        ));
        assert!(matches!(
            parse_private_key(&big, "k"),
            Err(TlsError::TooLarge { .. })
        ));
    }

    #[test]
    fn key_errors_hold_no_key_bytes() {
        let key = b"-----BEGIN PRIVATE KEY-----\nSECRETSECRET%%%\n-----END PRIVATE KEY-----\n";
        let e = parse_private_key(key, "k").unwrap_err();
        assert!(!e.to_string().contains("SECRET"), "{e}");
        let key = b"-----BEGIN PRIVATE KEY-----\nSECRETSECRET\n";
        let e = parse_private_key(key, "k").unwrap_err();
        assert!(!e.to_string().contains("SECRET"), "{e}");
    }

    #[test]
    fn too_many_certs() {
        let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let text = one.repeat(MAX_CHAIN_LEN + 1);
        assert!(matches!(
            parse_cert_chain(text.as_bytes(), "c"),
            Err(TlsError::TooManyCerts { .. })
        ));
        let text = one.repeat(MAX_CHAIN_LEN);
        assert_eq!(
            parse_cert_chain(text.as_bytes(), "c").unwrap().len(),
            MAX_CHAIN_LEN
        );
    }

    #[test]
    fn fingerprint_format() {
        let mut d = [0u8; 32];
        d[0] = 0xab;
        d[31] = 0x01;
        let t = fingerprint_text(&d);
        assert!(t.starts_with("AB:00:"));
        assert!(t.ends_with(":01"));
        assert_eq!(t.len(), 32 * 3 - 1);
    }

    #[test]
    fn ip_bytes() {
        assert_eq!(
            ip_from_bytes(&[192, 0, 2, 1]),
            Some(IpAddr::from([192, 0, 2, 1]))
        );
        assert!(ip_from_bytes(&[0; 16]).is_some());
        assert_eq!(ip_from_bytes(&[1, 2, 3]), None);
    }
}
