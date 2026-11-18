//! The certificate store: it loads or makes the certificate, and it reloads it without a
//! restart.
//!
//! ```mermaid
//! flowchart TD
//!     open[CertStore::open] --> mode{tls mode}
//!     mode -->|file| file[read cert + key PEM<br/>check key matches cert<br/>WARN if expired]
//!     mode -->|self-signed| ss[load self-signed.pem/.key<br/>plan_cert: reuse or make new]
//!     mode -->|local-ca| ca[load or make ca.pem/.key once<br/>load server.pem/.key<br/>plan_cert: reuse or issue new]
//!     file --> cur[current cert in ArcSwap]
//!     ss --> cur
//!     ca --> cur
//!     reload[CertStore::reload] -->|file: mtime or size changed<br/>generated: renewal due or names changed| mode
//!     cur --> res[StoreResolver: rustls asks for the cert per handshake]
//! ```
//!
//! A failed reload keeps the current certificate. The resolver never waits: it reads the
//! current certificate from an `ArcSwap`. A reload that starts while another reload runs
//! returns [`ReloadOutcome::Busy`] at once (no lock wait).

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};

use arc_swap::ArcSwap;
use rusthole_core::Config;
use rusthole_core::config::{TlsMode, tls_name_problem};
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::error::TlsError;
use crate::fsio::{self, CERT_MODE, FileStamp, KEY_MODE};
use crate::generate;
use crate::pem::{LoadedPair, MAX_PEM_BYTES, load_pem_pair_named};
use crate::policy::{self, Plan, Reason, SanSet};

/// File name of the self-signed certificate in `<data_dir>/tls/`.
pub const SELF_SIGNED_CERT: &str = "self-signed.pem";
/// File name of the self-signed key.
pub const SELF_SIGNED_KEY: &str = "self-signed.key";
/// File name of the local CA certificate. Users install this file on their devices.
pub const CA_CERT: &str = "ca.pem";
/// File name of the local CA key.
pub const CA_KEY: &str = "ca.key";
/// File name of the server certificate that the local CA signs.
pub const SERVER_CERT: &str = "server.pem";
/// File name of the server key.
pub const SERVER_KEY: &str = "server.key";

/// The TLS settings that the store needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    /// Where the certificate comes from.
    pub mode: TlsMode,
    /// Certificate chain for mode `file`.
    pub cert_path: Option<PathBuf>,
    /// Private key for mode `file`.
    pub key_path: Option<PathBuf>,
    /// Host names for a certificate that rusthole makes.
    pub names: Vec<String>,
    /// The data directory. The generated files go to `<data_dir>/tls/`.
    pub data_dir: PathBuf,
}

impl TlsSettings {
    /// Takes the settings from a config (see [`Config::tls_mode`] and
    /// [`Config::tls_files`]).
    pub fn from_config(config: &Config) -> Self {
        let files = config.tls_files();
        Self {
            mode: config.tls_mode(),
            cert_path: files.map(|(c, _)| PathBuf::from(c)),
            key_path: files.map(|(_, k)| PathBuf::from(k)),
            names: config.tls.names.clone(),
            data_dir: PathBuf::from(&config.server.data_dir),
        }
    }

    /// The directory for generated TLS files: `<data_dir>/tls`.
    pub fn tls_dir(&self) -> PathBuf {
        self.data_dir.join("tls")
    }
}

/// Something that the store found or did. The store logs each notice; the caller can also
/// show it (for example in the UI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// The certificate from a file expired.
    Expired {
        /// The certificate file.
        path: PathBuf,
        /// End of validity, Unix seconds.
        not_after: i64,
    },
    /// The certificate from a file is not valid yet.
    NotYetValid {
        /// The certificate file.
        path: PathBuf,
        /// Start of validity, Unix seconds.
        not_before: i64,
    },
    /// The group or others can read or write a private key file (amendment A7).
    KeyReadableByOthers {
        /// The key file.
        path: PathBuf,
        /// Its Unix mode.
        mode: u32,
    },
    /// The store made a new certificate.
    Generated {
        /// The new certificate file.
        path: PathBuf,
        /// Why.
        reason: Reason,
    },
    /// The store made a new local CA. Users must install it on their devices.
    NewCa {
        /// The CA certificate file.
        path: PathBuf,
    },
    /// The local CA expires in less than 30 days. rusthole does not replace it by itself.
    CaExpiresSoon {
        /// End of validity, Unix seconds.
        not_after: i64,
    },
    /// The name constraints of the local CA do not cover these names, so the server
    /// certificate does not contain them.
    NamesNotInCa {
        /// The names and addresses (text).
        names: Vec<String>,
    },
    /// The wall clock is before the build time of rusthole, so it is probably wrong. The
    /// store keeps a usable certificate and does not renew it.
    ClockNotPlausible {
        /// The wall clock, Unix seconds.
        now: i64,
    },
}

impl Notice {
    /// Tells if the notice is a warning (else it is information).
    pub fn is_warning(&self) -> bool {
        !matches!(self, Self::Generated { .. })
    }

    /// Logs the notice: WARN for a warning, INFO for information.
    pub fn log(&self) {
        if self.is_warning() {
            tracing::warn!("{self}");
        } else {
            tracing::info!("{self}");
        }
    }
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { path, not_after } => write!(
                f,
                "the TLS certificate {} expired on {}",
                path.display(),
                format_unix(*not_after)
            ),
            Self::NotYetValid { path, not_before } => write!(
                f,
                "the TLS certificate {} is not valid before {}",
                path.display(),
                format_unix(*not_before)
            ),
            Self::KeyReadableByOthers { path, mode } => write!(
                f,
                "the private key {} has mode {mode:o}; other users can read it. Use mode 600",
                path.display()
            ),
            Self::Generated { path, reason } => {
                write!(
                    f,
                    "made a new TLS certificate {} ({reason:?})",
                    path.display()
                )
            }
            Self::NewCa { path } => write!(
                f,
                "made a new local CA {}; install it on each device that uses DoH or the admin UI",
                path.display()
            ),
            Self::CaExpiresSoon { not_after } => write!(
                f,
                "the local CA expires on {}; remove ca.pem and ca.key to make a new one, then \
                 install it on each device",
                format_unix(*not_after)
            ),
            Self::NamesNotInCa { names } => write!(
                f,
                "the local CA does not cover {}; the server certificate leaves them out. Remove \
                 ca.pem and ca.key to make a new CA that covers them",
                names.join(", ")
            ),
            Self::ClockNotPlausible { now } => write!(
                f,
                "the clock ({}) is before the build time of rusthole; certificates are not \
                 renewed until the clock is set",
                format_unix(*now)
            ),
        }
    }
}

/// Formats Unix seconds as an RFC 3339 UTC date for a person to read.
pub fn format_unix(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| format!("{unix} (Unix seconds)"))
}

/// Facts about the current certificate, for the log and the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// The mode that made or loaded the certificate.
    pub mode: TlsMode,
    /// SHA-256 fingerprint of the server certificate (`AB:CD:...`).
    pub fingerprint_sha256: String,
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// Names and addresses in the certificate.
    pub sans: SanSet,
    /// The certificate file.
    pub cert_path: PathBuf,
    /// The local CA certificate (mode `local-ca` only). P5 serves it for download.
    pub ca_cert_path: Option<PathBuf>,
    /// SHA-256 fingerprint of the local CA certificate (mode `local-ca` only).
    pub ca_fingerprint_sha256: Option<String>,
}

/// The current certificate and what the store knows about it.
struct Current {
    certified: Arc<CertifiedKey>,
    info: CertInfo,
    /// Stamps of the certificate file and the key file (mode `file` only).
    stamps: Option<(FileStamp, FileStamp)>,
}

/// The result of [`CertStore::reload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// Nothing changed. The current certificate stays.
    Unchanged,
    /// A new certificate is in use.
    Reloaded(Vec<Notice>),
    /// Another reload runs now. Try again later.
    Busy,
}

/// Holds the current certificate. See the module documentation.
pub struct CertStore {
    settings: TlsSettings,
    provider: Arc<CryptoProvider>,
    build_time: i64,
    current: ArcSwap<Current>,
    reload_lock: Mutex<()>,
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore")
            .field("settings", &self.settings)
            .field("info", &self.current.load().info)
            .finish_non_exhaustive()
    }
}

impl CertStore {
    /// Loads or makes the certificate.
    ///
    /// - `local_ips`: the local IPv4 addresses. They go into a certificate that rusthole
    ///   makes.
    /// - `now`: the wall clock in Unix seconds (see [`now_unix`]).
    ///
    /// The function logs each notice and also returns them.
    pub fn open(
        settings: TlsSettings,
        local_ips: &[IpAddr],
        now: i64,
    ) -> Result<(Arc<Self>, Vec<Notice>), TlsError> {
        Self::open_with_build_time(settings, local_ips, now, crate::build_time_unix())
    }

    /// Like [`CertStore::open`], with a given build time for the clock check.
    pub fn open_with_build_time(
        settings: TlsSettings,
        local_ips: &[IpAddr],
        now: i64,
        build_time: i64,
    ) -> Result<(Arc<Self>, Vec<Notice>), TlsError> {
        let provider = crate::provider();
        let (current, notices) = load(&settings, &provider, local_ips, now, build_time)?;
        for n in &notices {
            n.log();
        }
        log_ready(&current.info);
        let store = Arc::new(Self {
            settings,
            provider,
            build_time,
            current: ArcSwap::from_pointee(current),
            reload_lock: Mutex::new(()),
        });
        Ok((store, notices))
    }

    /// Checks the certificate again and uses a new one when necessary.
    ///
    /// - Mode `file`: the store reads the files again when the size or the modification time
    ///   of the certificate file or the key file changed.
    /// - Modes `self-signed` and `local-ca`: the store makes a new certificate when renewal
    ///   is due or when the names changed (for example a new local address).
    ///
    /// On an error, the current certificate stays in use.
    pub fn reload(&self, local_ips: &[IpAddr], now: i64) -> Result<ReloadOutcome, TlsError> {
        let _guard = match self.reload_lock.try_lock() {
            Ok(g) => g,
            // The lock guards no data, so a panic in an earlier reload left nothing broken.
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return Ok(ReloadOutcome::Busy),
        };
        let old = self.current.load_full();
        if self.settings.mode == TlsMode::File {
            let (cert, key) = file_paths(&self.settings)?;
            let stamps = (fsio::file_stamp(cert)?, fsio::file_stamp(key)?);
            if old.stamps == Some(stamps) {
                return Ok(ReloadOutcome::Unchanged);
            }
        }
        let (new, notices) = load(
            &self.settings,
            &self.provider,
            local_ips,
            now,
            self.build_time,
        )?;
        let same = new.info == old.info && new.stamps == old.stamps;
        if same {
            return Ok(ReloadOutcome::Unchanged);
        }
        for n in &notices {
            n.log();
        }
        log_ready(&new.info);
        self.current.store(Arc::new(new));
        Ok(ReloadOutcome::Reloaded(notices))
    }

    /// The mode of this store.
    pub fn mode(&self) -> TlsMode {
        self.settings.mode
    }

    /// Facts about the current certificate.
    pub fn info(&self) -> CertInfo {
        self.current.load().info.clone()
    }

    /// The current certificate and key.
    pub fn current_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.current.load().certified)
    }

    /// A rustls certificate resolver that always gives the current certificate.
    pub fn resolver(self: &Arc<Self>) -> Arc<dyn ResolvesServerCert> {
        Arc::new(StoreResolver(Arc::clone(self)))
    }
}

/// Logs the certificate in use: the mode, the SHA-256 fingerprint, the end of validity, and
/// the path of the local CA certificate that users install on their devices.
fn log_ready(info: &CertInfo) {
    if let Some(ca) = &info.ca_cert_path {
        tracing::info!(
            mode = ?info.mode,
            fingerprint = %info.fingerprint_sha256,
            not_after = %format_unix(info.not_after),
            ca_fingerprint = info.ca_fingerprint_sha256.as_deref().unwrap_or_default(),
            "TLS certificate in use; install the local CA {} on your devices",
            ca.display()
        );
    } else {
        tracing::info!(
            mode = ?info.mode,
            fingerprint = %info.fingerprint_sha256,
            not_after = %format_unix(info.not_after),
            "TLS certificate in use"
        );
    }
}

/// Gives rustls the current certificate of a [`CertStore`] for each handshake.
#[derive(Debug)]
struct StoreResolver(Arc<CertStore>);

impl ResolvesServerCert for StoreResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.current_key())
    }
}

/// Reads the wall clock in Unix seconds. A clock before 1970 gives a negative value.
///
/// This is the I/O shell: the policy functions get the result as `now`.
pub fn now_unix() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

fn file_paths(settings: &TlsSettings) -> Result<(&Path, &Path), TlsError> {
    match (&settings.cert_path, &settings.key_path) {
        (Some(c), Some(k)) => Ok((c.as_path(), k.as_path())),
        _ => Err(TlsError::NoFiles),
    }
}

/// The wall clock for one load.
#[derive(Debug, Clone, Copy)]
struct Clock {
    /// The wall clock, Unix seconds.
    now: i64,
    /// The result of [`policy::clock_plausible`] for `now`.
    plausible: bool,
    /// The start time for a new certificate: `now`, or the build time when the clock is
    /// not plausible.
    gen_now: i64,
}

fn load(
    settings: &TlsSettings,
    provider: &CryptoProvider,
    local_ips: &[IpAddr],
    now: i64,
    build_time: i64,
) -> Result<(Current, Vec<Notice>), TlsError> {
    if settings.mode != TlsMode::File {
        check_names(&settings.names)?;
    }
    let mut notices = Vec::new();
    let clock_ok = policy::clock_plausible(now, build_time);
    if !clock_ok && settings.mode != TlsMode::File {
        notices.push(Notice::ClockNotPlausible { now });
    }
    let wanted = SanSet::wanted(&settings.names, local_ips);
    let clock = Clock {
        now,
        plausible: clock_ok,
        // A certificate that rusthole makes with a wrong clock starts at the build time.
        // Dates from 1970 would make a CA that is dead when NTP sets the clock.
        gen_now: if clock_ok { now } else { build_time },
    };
    let current = match settings.mode {
        TlsMode::File => load_file(settings, provider, now, &mut notices)?,
        TlsMode::SelfSigned => load_self_signed(settings, provider, &wanted, clock, &mut notices)?,
        TlsMode::LocalCa => load_local_ca(settings, provider, &wanted, clock, &mut notices)?,
    };
    Ok((current, notices))
}

/// Refuses a name that cannot be in a certificate, before rusthole writes a file. A local
/// CA with such a name in its name constraints is refused for every name, and rusthole never
/// replaces a CA by itself. [`TlsSettings`] can come from a config that did not go through
/// `Config::validate`, so the store checks again.
fn check_names(names: &[String]) -> Result<(), TlsError> {
    for name in names {
        if let Some(problem) = tls_name_problem(name) {
            return Err(TlsError::BadName {
                name: name.clone(),
                problem,
            });
        }
    }
    Ok(())
}

fn check_key_mode(path: &Path, notices: &mut Vec<Notice>) {
    if let Some(mode) = fsio::key_mode_too_open(path) {
        notices.push(Notice::KeyReadableByOthers {
            path: path.to_owned(),
            mode,
        });
    }
}

fn info_from(mode: TlsMode, pair: &LoadedPair, cert_path: &Path) -> CertInfo {
    CertInfo {
        mode,
        fingerprint_sha256: pair.facts.fingerprint(),
        not_before: pair.facts.dates.not_before,
        not_after: pair.facts.dates.not_after,
        sans: pair.facts.sans.clone(),
        cert_path: cert_path.to_owned(),
        ca_cert_path: None,
        ca_fingerprint_sha256: None,
    }
}

fn load_file(
    settings: &TlsSettings,
    provider: &CryptoProvider,
    now: i64,
    notices: &mut Vec<Notice>,
) -> Result<Current, TlsError> {
    let (cert, key) = file_paths(settings)?;
    // Stamps first: a change after this point gives a new stamp at the next reload.
    let stamps = (fsio::file_stamp(cert)?, fsio::file_stamp(key)?);
    let cert_pem = fsio::read_required(cert, MAX_PEM_BYTES)?;
    let key_pem = fsio::read_required(key, MAX_PEM_BYTES)?;
    check_key_mode(key, notices);
    let pair = load_pem_pair_named(
        &cert_pem,
        &key_pem,
        &cert.display().to_string(),
        &key.display().to_string(),
        provider,
    )?;
    let dates = &pair.facts.dates;
    if policy::is_expired(dates.not_after, now) {
        notices.push(Notice::Expired {
            path: cert.to_owned(),
            not_after: dates.not_after,
        });
    } else if now < dates.not_before {
        notices.push(Notice::NotYetValid {
            path: cert.to_owned(),
            not_before: dates.not_before,
        });
    }
    Ok(Current {
        certified: Arc::clone(&pair.certified),
        info: info_from(TlsMode::File, &pair, cert),
        stamps: Some(stamps),
    })
}

/// Reads a generated pair from `dir`. `Err(Reason)` tells why it cannot be used.
fn read_generated(
    cert: &Path,
    key: &Path,
    provider: &CryptoProvider,
    notices: &mut Vec<Notice>,
) -> Result<LoadedPair, Reason> {
    let cert_pem = fsio::read_limited(cert, MAX_PEM_BYTES);
    let key_pem = fsio::read_limited(key, MAX_PEM_BYTES);
    match (cert_pem, key_pem) {
        (Ok(None), Ok(None)) => Err(Reason::Missing),
        (Ok(Some(c)), Ok(Some(k))) => {
            check_key_mode(key, notices);
            load_pem_pair_named(
                &c,
                &k,
                &cert.display().to_string(),
                &key.display().to_string(),
                provider,
            )
            .map_err(|e| {
                tracing::warn!("{e}; rusthole makes a new certificate");
                Reason::Unusable
            })
        }
        (c, k) => {
            if let Err(e) = c.and(k) {
                tracing::warn!("{e}; rusthole makes a new certificate");
            }
            Err(Reason::Unusable)
        }
    }
}

/// Writes a new key and certificate. The key goes first: after a crash between the two
/// writes, the pair does not match, and the next start makes a new pair.
fn write_pair(cert: &Path, key: &Path, pair: &generate::GeneratedPair) -> Result<(), TlsError> {
    fsio::write_atomic(key, pair.key_pem.as_bytes(), KEY_MODE)?;
    fsio::write_atomic(cert, pair.cert_pem.as_bytes(), CERT_MODE)?;
    Ok(())
}

fn load_self_signed(
    settings: &TlsSettings,
    provider: &CryptoProvider,
    wanted: &SanSet,
    clock: Clock,
    notices: &mut Vec<Notice>,
) -> Result<Current, TlsError> {
    let dir = settings.tls_dir();
    fsio::ensure_private_dir(&dir)?;
    let cert = dir.join(SELF_SIGNED_CERT);
    let key = dir.join(SELF_SIGNED_KEY);
    let existing = read_generated(&cert, &key, provider, notices);
    let plan = policy::plan_cert(
        existing
            .as_ref()
            .map(|p| (&p.facts.dates, &p.facts.sans))
            .map_err(|r| *r),
        wanted,
        clock.now,
        clock.plausible,
    );
    let pair = match (plan, existing) {
        (Plan::Reuse, Ok(pair)) => pair,
        (Plan::Generate(reason), _) => {
            let generated = generate::self_signed(wanted, clock.gen_now)?;
            write_pair(&cert, &key, &generated)?;
            notices.push(Notice::Generated {
                path: cert.clone(),
                reason,
            });
            load_pem_pair_named(
                generated.cert_pem.as_bytes(),
                generated.key_pem.as_bytes(),
                &cert.display().to_string(),
                &key.display().to_string(),
                provider,
            )?
        }
        // plan_cert gives Reuse only for an existing pair.
        (Plan::Reuse, Err(reason)) => {
            tracing::error!(?reason, "plan Reuse without a certificate; this is a bug");
            return Err(TlsError::Generate(
                "internal error: no certificate to reuse".to_owned(),
            ));
        }
    };
    Ok(Current {
        certified: Arc::clone(&pair.certified),
        info: info_from(TlsMode::SelfSigned, &pair, &cert),
        stamps: None,
    })
}

/// Loads the local CA, or makes it when `ca.pem` does not exist. Any other problem is an
/// error: rusthole never replaces a CA by itself, because each device must then install it
/// again. A `ca.key` without `ca.pem` is the result of a crash during the first write (the
/// key goes first), so rusthole makes a new CA and writes over that key.
fn load_or_make_ca(
    dir: &Path,
    provider: &CryptoProvider,
    wanted: &SanSet,
    now: i64,
    notices: &mut Vec<Notice>,
) -> Result<(LoadedPair, String), TlsError> {
    let cert = dir.join(CA_CERT);
    let key = dir.join(CA_KEY);
    let unusable = |detail: String| TlsError::CaUnusable {
        dir: dir.to_owned(),
        detail,
    };
    let mut make_ca = || -> Result<(Vec<u8>, Vec<u8>), TlsError> {
        let generated = generate::local_ca(&policy::CaScope::for_new_ca(wanted), now)?;
        write_pair(&cert, &key, &generated)?;
        notices.push(Notice::NewCa { path: cert.clone() });
        Ok((
            generated.cert_pem.into_bytes(),
            generated.key_pem.into_bytes(),
        ))
    };
    let cert_pem = fsio::read_limited(&cert, MAX_PEM_BYTES)?;
    let key_pem = fsio::read_limited(&key, MAX_PEM_BYTES)?;
    let (cert_pem, key_pem) = match (cert_pem, key_pem) {
        (None, None) => make_ca()?,
        (Some(c), Some(k)) => {
            check_key_mode(&key, notices);
            (c, k)
        }
        (Some(_), None) => return Err(unusable(format!("{CA_KEY} is missing"))),
        // write_pair writes ca.key first. A crash before ca.pem was written leaves this
        // state. No device can trust a CA certificate that was never written, so a new CA
        // is safe here.
        (None, Some(_)) => {
            tracing::warn!(
                "{} exists but {} is missing; rusthole makes a new local CA",
                key.display(),
                cert.display()
            );
            make_ca()?
        }
    };
    let pair = load_pem_pair_named(
        &cert_pem,
        &key_pem,
        &cert.display().to_string(),
        &key.display().to_string(),
        provider,
    )
    .map_err(|e| unusable(e.to_string()))?;
    let key_text =
        String::from_utf8(key_pem).map_err(|_| unusable(format!("{CA_KEY} is not text")))?;
    Ok((pair, key_text))
}

fn load_local_ca(
    settings: &TlsSettings,
    provider: &CryptoProvider,
    wanted: &SanSet,
    clock: Clock,
    notices: &mut Vec<Notice>,
) -> Result<Current, TlsError> {
    let dir = settings.tls_dir();
    fsio::ensure_private_dir(&dir)?;
    let (ca, ca_key_pem) = load_or_make_ca(&dir, provider, wanted, clock.gen_now, notices)?;
    if clock.plausible && policy::ca_expires_soon(ca.facts.dates.not_after, clock.now) {
        notices.push(Notice::CaExpiresSoon {
            not_after: ca.facts.dates.not_after,
        });
    }
    let (covered, uncovered) = wanted.split_by(&ca.facts.scope);
    if !uncovered.is_empty() {
        notices.push(Notice::NamesNotInCa { names: uncovered });
    }
    let cert = dir.join(SERVER_CERT);
    let key = dir.join(SERVER_KEY);
    let existing = read_generated(&cert, &key, provider, notices).and_then(|p| {
        if p.facts.issued_by(&ca.facts) {
            Ok(p)
        } else {
            tracing::warn!(
                "{} is not signed by the local CA; rusthole issues a new one",
                cert.display()
            );
            Err(Reason::Unusable)
        }
    });
    let plan = policy::plan_cert(
        existing
            .as_ref()
            .map(|p| (&p.facts.dates, &p.facts.sans))
            .map_err(|r| *r),
        &covered,
        clock.now,
        clock.plausible,
    );
    let ca_der = ca
        .certified
        .end_entity_cert()
        .map_err(|e| TlsError::CaUnusable {
            dir: dir.clone(),
            detail: e.to_string(),
        })?;
    let pair = match (plan, existing) {
        (Plan::Reuse, Ok(pair)) => pair,
        (Plan::Generate(reason), _) => {
            let generated = generate::issue_leaf(ca_der, &ca_key_pem, &covered, clock.gen_now)?;
            write_pair(&cert, &key, &generated)?;
            notices.push(Notice::Generated {
                path: cert.clone(),
                reason,
            });
            load_pem_pair_named(
                generated.cert_pem.as_bytes(),
                generated.key_pem.as_bytes(),
                &cert.display().to_string(),
                &key.display().to_string(),
                provider,
            )?
        }
        // plan_cert gives Reuse only for an existing pair.
        (Plan::Reuse, Err(reason)) => {
            tracing::error!(?reason, "plan Reuse without a certificate; this is a bug");
            return Err(TlsError::Generate(
                "internal error: no certificate to reuse".to_owned(),
            ));
        }
    };
    let mut info = info_from(TlsMode::LocalCa, &pair, &cert);
    info.ca_cert_path = Some(dir.join(CA_CERT));
    info.ca_fingerprint_sha256 = Some(ca.facts.fingerprint());
    Ok(Current {
        certified: Arc::clone(&pair.certified),
        info,
        stamps: None,
    })
}
