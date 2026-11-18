//! The error type of this crate.

use std::path::PathBuf;

/// Why a TLS operation failed. Each variant tells which file or input has the problem.
///
/// No variant holds bytes of a private key: a key PEM error gives only the kind of problem.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A file cannot be read.
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A file or a directory cannot be written.
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A file is larger than the limit.
    #[error("{what} is larger than {limit} bytes")]
    TooLarge { what: String, limit: usize },
    /// The PEM text has no certificate.
    #[error("{what} has no certificate (no \"BEGIN CERTIFICATE\" section)")]
    NoCertificate { what: String },
    /// The certificate PEM text is not valid.
    #[error("{what} is not a valid certificate PEM file: {detail}")]
    BadCertPem { what: String, detail: String },
    /// The chain has too many certificates.
    #[error("{what} has more than {limit} certificates")]
    TooManyCerts { what: String, limit: usize },
    /// The PEM text has no private key.
    #[error("{what} has no private key (no \"BEGIN PRIVATE KEY\" section)")]
    NoKey { what: String },
    /// The private key PEM text is not valid. The message holds no key bytes.
    #[error("{what} is not a valid private key PEM file ({kind})")]
    BadKeyPem { what: String, kind: &'static str },
    /// The private key has a type or form that the ring provider cannot use.
    #[error("{what}: the private key cannot be used: {detail}")]
    BadKey { what: String, detail: String },
    /// A certificate cannot be parsed.
    #[error("{what}: the certificate cannot be parsed: {detail}")]
    BadCert { what: String, detail: String },
    /// The private key does not belong to the certificate.
    #[error("the private key in {key} does not match the certificate in {cert}")]
    KeyMismatch { cert: String, key: String },
    /// A time value is out of the range that a certificate can hold.
    #[error("the time {unix} (Unix seconds) is out of range for a certificate")]
    TimeRange { unix: i64 },
    /// rcgen cannot make a key or a certificate.
    #[error("cannot make a certificate: {0}")]
    Generate(String),
    /// The local CA files exist but rusthole cannot use them. rusthole does not replace a CA
    /// by itself, because each device that trusts it must then install a new one.
    #[error(
        "the local CA in {dir} cannot be used: {detail}. Repair the files, or remove ca.pem \
         and ca.key to make a new CA (then install the new CA on each device)"
    )]
    CaUnusable { dir: PathBuf, detail: String },
    /// A name in `tls.names` cannot be a host name in a certificate. rusthole does not make
    /// a certificate or a CA with it, because TLS clients would refuse it.
    #[error("tls.names: {name:?} cannot be a certificate host name: {problem}")]
    BadName { name: String, problem: String },
    /// Mode `file` has no certificate path or no key path.
    #[error("TLS mode \"file\" needs tls.cert_path and tls.key_path")]
    NoFiles,
    /// The DoH listener got a self-signed certificate (amendment A6).
    #[error(
        "the DoH listener needs a certificate that clients trust: use tls.mode \"file\" or \
         \"local-ca\"; a self-signed certificate is only for the admin UI"
    )]
    SelfSignedForDoh,
    /// rustls refused a setting.
    #[error("TLS setup failed: {0}")]
    Rustls(String),
}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> Self {
        Self::Rustls(e.to_string())
    }
}

impl From<rcgen::Error> for TlsError {
    fn from(e: rcgen::Error) -> Self {
        Self::Generate(e.to_string())
    }
}
