//! Key and certificate generation with rcgen (ring). The keys are ECDSA P-256.
//!
//! These functions get `now` as an input and do no file I/O. They use the system random
//! number generator for keys and serial numbers.

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256, SanType, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::CertificateDer;
use time::OffsetDateTime;

use crate::error::TlsError;
use crate::policy::{
    CA_VALIDITY, CaScope, CertDates, LEAF_VALIDITY, SELF_SIGNED_VALIDITY, SanSet, new_validity,
};

/// A new certificate and its private key, as PEM text.
pub struct GeneratedPair {
    /// The certificate (PEM).
    pub cert_pem: String,
    /// The private key (PKCS#8 PEM). It is a secret.
    pub key_pem: String,
}

// Debug must never show the private key.
impl std::fmt::Debug for GeneratedPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedPair")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

fn to_time(unix: i64) -> Result<OffsetDateTime, TlsError> {
    OffsetDateTime::from_unix_timestamp(unix).map_err(|_| TlsError::TimeRange { unix })
}

/// A random positive serial number of 16 bytes. Firefox refuses two certificates with the
/// same issuer and serial number, so each new certificate needs a new serial.
fn random_serial() -> Result<SerialNumber, TlsError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| TlsError::Generate("the random number generator failed".to_owned()))?;
    // Clear the top bit (a positive number) and set the next one (no leading zero byte).
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

fn new_key() -> Result<KeyPair, TlsError> {
    Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
}

fn san_list(sans: &SanSet) -> Result<Vec<SanType>, TlsError> {
    let mut out = Vec::with_capacity(sans.names.len() + sans.ips.len());
    for n in &sans.names {
        out.push(SanType::DnsName(n.as_str().try_into()?));
    }
    out.extend(sans.ips.iter().map(|ip| SanType::IpAddress(*ip)));
    Ok(out)
}

fn base_params(dates: &CertDates, common_name: &str) -> Result<CertificateParams, TlsError> {
    let mut params = CertificateParams::default();
    params.not_before = to_time(dates.not_before)?;
    params.not_after = to_time(dates.not_after)?;
    params.serial_number = Some(random_serial()?);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "rusthole");
    params.distinguished_name = dn;
    Ok(params)
}

/// Settings of a server certificate: the names, the server-auth purpose, and the key usage.
/// Apple devices need the SAN extension and the server-auth purpose.
fn leaf_params(sans: &SanSet, dates: &CertDates, cn: &str) -> Result<CertificateParams, TlsError> {
    let mut params = base_params(dates, cn)?;
    params.subject_alt_names = san_list(sans)?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

/// Makes a self-signed server certificate for `sans`, valid from `now` for one year.
pub fn self_signed(sans: &SanSet, now: i64) -> Result<GeneratedPair, TlsError> {
    let key = new_key()?;
    let dates = new_validity(now, SELF_SIGNED_VALIDITY);
    let mut params = leaf_params(sans, &dates, "rusthole self-signed")?;
    // A self-signed certificate has no other issuer, so it needs no authority key ID.
    params.use_authority_key_identifier_extension = false;
    let cert = params.self_signed(&key)?;
    Ok(GeneratedPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Makes a local CA certificate with the name constraints of `scope`, valid for ten years.
///
/// The CA can sign server certificates only (path length 0).
pub fn local_ca(scope: &CaScope, now: i64) -> Result<GeneratedPair, TlsError> {
    let key = new_key()?;
    let dates = new_validity(now, CA_VALIDITY);
    let mut params = base_params(&dates, "rusthole local CA")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut permitted = Vec::new();
    if let Some(dns) = &scope.dns {
        permitted.extend(dns.iter().map(|d| GeneralSubtree::DnsName(d.clone())));
    }
    if let Some(nets) = &scope.ipv4 {
        permitted.extend(nets.iter().map(|n| {
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix(n.addr.octets(), n.prefix))
        }));
    }
    if !permitted.is_empty() {
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: Vec::new(),
        });
    }
    let cert = params.self_signed(&key)?;
    Ok(GeneratedPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Makes a server certificate for `sans`, signed by the CA (`ca_cert` and `ca_key_pem`),
/// valid from `now` for one year.
pub fn issue_leaf(
    ca_cert: &CertificateDer<'_>,
    ca_key_pem: &str,
    sans: &SanSet,
    now: i64,
) -> Result<GeneratedPair, TlsError> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let issuer = Issuer::from_ca_cert_der(ca_cert, ca_key)?;
    let key = new_key()?;
    let dates = new_validity(now, LEAF_VALIDITY);
    let params = leaf_params(sans, &dates, "rusthole")?;
    let cert = params.signed_by(&key, &issuer)?;
    Ok(GeneratedPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}
