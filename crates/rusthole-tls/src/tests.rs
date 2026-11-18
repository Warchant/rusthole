//! Tests of the store, the configs and TLS handshakes.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rusthole_core::config::TlsMode;
use rustls::client::danger::ServerCertVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::fsio::tests::{entries, scratch};
use crate::policy::{DAY, Reason, SanSet};
use crate::store::{CA_CERT, CA_KEY, SELF_SIGNED_CERT, SELF_SIGNED_KEY, SERVER_CERT, SERVER_KEY};
use crate::*;

/// A wall clock for tests: 2027-01-15. It is after [`MIN_BUILD_TIME_UNIX`].
const NOW: i64 = 1_800_000_000;
const BUILD: i64 = MIN_BUILD_TIME_UNIX;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn settings(data_dir: &Path, mode: TlsMode, names: &[&str]) -> TlsSettings {
    TlsSettings {
        mode,
        cert_path: None,
        key_path: None,
        names: names.iter().map(|s| (*s).to_owned()).collect(),
        data_dir: data_dir.to_owned(),
    }
}

fn file_settings(data_dir: &Path, cert: &Path, key: &Path) -> TlsSettings {
    TlsSettings {
        mode: TlsMode::File,
        cert_path: Some(cert.to_owned()),
        key_path: Some(key.to_owned()),
        names: Vec::new(),
        data_dir: data_dir.to_owned(),
    }
}

fn open(
    s: TlsSettings,
    ips: &[IpAddr],
    now: i64,
) -> Result<(Arc<CertStore>, Vec<Notice>), TlsError> {
    CertStore::open_with_build_time(s, ips, now, BUILD)
}

/// Writes a self-signed pair to `dir` as `<stem>.pem` and `<stem>.key`.
fn write_pair(dir: &Path, stem: &str, now: i64) -> (PathBuf, PathBuf) {
    let pair = generate::self_signed(&SanSet::wanted(&["files.lan".into()], &[]), now).unwrap();
    let cert = dir.join(format!("{stem}.pem"));
    let key = dir.join(format!("{stem}.key"));
    std::fs::write(&cert, &pair.cert_pem).unwrap();
    std::fs::write(&key, &pair.key_pem).unwrap();
    (cert, key)
}

/// Moves the modification time of `path` forward, so that a reload sees a change even when
/// the file system has a coarse time.
fn touch_forward(path: &Path, secs: u64) {
    let f = std::fs::File::options().write(true).open(path).unwrap();
    let t = std::time::SystemTime::now() + Duration::from_secs(secs);
    f.set_modified(t).unwrap();
}

fn generated_reasons(notices: &[Notice]) -> Vec<Reason> {
    notices
        .iter()
        .filter_map(|n| match n {
            Notice::Generated { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect()
}

fn read_cert(path: &Path) -> CertificateDer<'static> {
    let pem = std::fs::read(path).unwrap();
    pem::parse_cert_chain(&pem, "test").unwrap().remove(0)
}

// ---------------------------------------------------------------------------------------
// Mode `file`.

#[test]
fn file_mode_loads_a_good_pair() {
    let dir = scratch();
    let (cert, key) = write_pair(dir.path(), "good", NOW);
    let (store, notices) = open(file_settings(dir.path(), &cert, &key), &[], NOW).unwrap();
    assert!(
        notices
            .iter()
            .all(|n| matches!(n, Notice::KeyReadableByOthers { .. })),
        "{notices:?}"
    );
    let info = store.info();
    assert_eq!(info.mode, TlsMode::File);
    assert_eq!(info.cert_path, cert);
    assert!(info.sans.names.contains("files.lan"));
    assert_eq!(info.fingerprint_sha256.len(), 95);
    assert_eq!(store.reload(&[], NOW).unwrap(), ReloadOutcome::Unchanged);
}

#[test]
fn file_mode_missing_files() {
    let dir = scratch();
    let (cert, key) = write_pair(dir.path(), "a", NOW);
    let none = dir.path().join("none.pem");
    let e = open(file_settings(dir.path(), &none, &key), &[], NOW).unwrap_err();
    assert!(matches!(e, TlsError::Read { .. }), "{e}");
    assert!(e.to_string().contains("none.pem"), "{e}");
    let e = open(file_settings(dir.path(), &cert, &none), &[], NOW).unwrap_err();
    assert!(matches!(e, TlsError::Read { .. }), "{e}");
    let mut s = file_settings(dir.path(), &cert, &key);
    s.key_path = None;
    assert!(matches!(open(s, &[], NOW), Err(TlsError::NoFiles)));
}

#[test]
fn file_mode_no_cert_and_no_key() {
    let dir = scratch();
    let (cert, key) = write_pair(dir.path(), "a", NOW);
    let junk = dir.path().join("junk.pem");
    std::fs::write(&junk, b"just text\n").unwrap();
    assert!(matches!(
        open(file_settings(dir.path(), &junk, &key), &[], NOW),
        Err(TlsError::NoCertificate { .. })
    ));
    assert!(matches!(
        open(file_settings(dir.path(), &cert, &junk), &[], NOW),
        Err(TlsError::NoKey { .. })
    ));
    // A key in place of a certificate, and a certificate in place of a key.
    assert!(matches!(
        open(file_settings(dir.path(), &key, &key), &[], NOW),
        Err(TlsError::NoCertificate { .. })
    ));
    assert!(matches!(
        open(file_settings(dir.path(), &cert, &cert), &[], NOW),
        Err(TlsError::NoKey { .. })
    ));
}

#[test]
fn file_mode_refuses_a_key_that_does_not_match() {
    let dir = scratch();
    let (cert, _) = write_pair(dir.path(), "a", NOW);
    let (_, other_key) = write_pair(dir.path(), "b", NOW);
    let e = open(file_settings(dir.path(), &cert, &other_key), &[], NOW).unwrap_err();
    assert!(matches!(e, TlsError::KeyMismatch { .. }), "{e}");
    assert!(e.to_string().contains("b.key"), "{e}");
}

#[test]
fn file_mode_warns_for_an_expired_cert() {
    let dir = scratch();
    // Made two years ago with one year of validity.
    let (cert, key) = write_pair(dir.path(), "old", NOW - 730 * DAY);
    let (store, notices) = open(file_settings(dir.path(), &cert, &key), &[], NOW).unwrap();
    let expired: Vec<_> = notices
        .iter()
        .filter_map(|n| match n {
            Notice::Expired { not_after, .. } => Some(*not_after),
            _ => None,
        })
        .collect();
    assert_eq!(expired, [store.info().not_after]);
    let text = notices
        .iter()
        .find(|n| matches!(n, Notice::Expired { .. }))
        .unwrap()
        .to_string();
    // NOW - 730 days + 365 days is in January 2026.
    assert!(text.contains("2026-01-"), "{text}");
    assert!(text.contains("old.pem"), "{text}");
    // A certificate that is not valid yet also gives a notice.
    let (cert, key) = write_pair(dir.path(), "future", NOW + 10 * DAY);
    let (_, notices) = open(file_settings(dir.path(), &cert, &key), &[], NOW).unwrap();
    assert!(
        notices
            .iter()
            .any(|n| matches!(n, Notice::NotYetValid { .. }))
    );
}

#[test]
fn file_mode_reload_on_change_and_keep_on_error() {
    let dir = scratch();
    let (cert, key) = write_pair(dir.path(), "live", NOW);
    let (store, _) = open(file_settings(dir.path(), &cert, &key), &[], NOW).unwrap();
    let first = store.info().fingerprint_sha256;
    // A new pair at the same paths.
    let (c2, k2) = write_pair(dir.path(), "next", NOW);
    std::fs::copy(&c2, &cert).unwrap();
    std::fs::copy(&k2, &key).unwrap();
    touch_forward(&cert, 10);
    let out = store.reload(&[], NOW).unwrap();
    assert!(matches!(out, ReloadOutcome::Reloaded(_)), "{out:?}");
    let second = store.info().fingerprint_sha256;
    assert_ne!(first, second);
    assert_eq!(store.reload(&[], NOW).unwrap(), ReloadOutcome::Unchanged);
    // Half of an update: a new certificate with the old key. The reload fails, and the
    // current certificate stays in use.
    let (c3, _) = write_pair(dir.path(), "third", NOW);
    std::fs::copy(&c3, &cert).unwrap();
    touch_forward(&cert, 20);
    assert!(matches!(
        store.reload(&[], NOW),
        Err(TlsError::KeyMismatch { .. })
    ));
    assert_eq!(store.info().fingerprint_sha256, second);
    // A bad PEM file also keeps the current certificate.
    std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\n!!\n").unwrap();
    touch_forward(&cert, 30);
    assert!(store.reload(&[], NOW).is_err());
    assert_eq!(store.info().fingerprint_sha256, second);
    // A removed file also keeps it.
    std::fs::remove_file(&cert).unwrap();
    assert!(matches!(store.reload(&[], NOW), Err(TlsError::Read { .. })));
    assert_eq!(store.info().fingerprint_sha256, second);
}

// ---------------------------------------------------------------------------------------
// Mode `self-signed`.

#[test]
fn self_signed_generate_then_reuse() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::SelfSigned, &["rusthole.lan"]);
    let ips = [ip("192.0.2.7")];
    let (store, notices) = open(s.clone(), &ips, NOW).unwrap();
    assert_eq!(generated_reasons(&notices), [Reason::Missing]);
    let info = store.info();
    assert_eq!(info.sans, SanSet::wanted(&["rusthole.lan".into()], &ips));
    assert_eq!(info.not_before, NOW - policy::BACKDATE);
    assert_eq!(info.not_after, NOW + policy::SELF_SIGNED_VALIDITY);
    assert_eq!(info.ca_cert_path, None);
    // Only the two files are in the directory: no temp file is left.
    assert_eq!(entries(&s.tls_dir()), [SELF_SIGNED_KEY, SELF_SIGNED_CERT]);
    // A restart (a new store) reuses the files.
    let (again, notices) = open(s, &ips, NOW + DAY).unwrap();
    assert_eq!(generated_reasons(&notices), []);
    assert_eq!(again.info().fingerprint_sha256, info.fingerprint_sha256);
}

#[test]
fn self_signed_renews_when_expiring() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::SelfSigned, &[]);
    let (store, _) = open(s, &[], NOW).unwrap();
    let first = store.info();
    let edge = first.not_after - policy::RENEW_BEFORE;
    assert_eq!(
        store.reload(&[], edge - 1).unwrap(),
        ReloadOutcome::Unchanged
    );
    let ReloadOutcome::Reloaded(notices) = store.reload(&[], edge).unwrap() else {
        panic!("expected a new certificate at the renewal edge");
    };
    assert_eq!(generated_reasons(&notices), [Reason::Expiring]);
    let second = store.info();
    assert_ne!(second.fingerprint_sha256, first.fingerprint_sha256);
    assert_eq!(second.not_after, edge + policy::SELF_SIGNED_VALIDITY);
    assert_eq!(store.reload(&[], edge).unwrap(), ReloadOutcome::Unchanged);
}

#[test]
fn self_signed_regenerates_when_names_change() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::SelfSigned, &["a.lan"]);
    let (store, _) = open(s.clone(), &[ip("192.0.2.7")], NOW).unwrap();
    let first = store.info().fingerprint_sha256;
    assert_eq!(
        store.reload(&[ip("192.0.2.7")], NOW).unwrap(),
        ReloadOutcome::Unchanged
    );
    let ReloadOutcome::Reloaded(notices) = store.reload(&[ip("192.0.2.8")], NOW).unwrap() else {
        panic!("a new address must give a new certificate");
    };
    assert_eq!(generated_reasons(&notices), [Reason::NamesChanged]);
    assert!(store.info().sans.ips.contains(&ip("192.0.2.8")));
    assert_ne!(store.info().fingerprint_sha256, first);
    // A new configured name at a restart.
    let mut s2 = s;
    s2.names.push("b.lan".into());
    let (_, notices) = open(s2, &[ip("192.0.2.8")], NOW).unwrap();
    assert_eq!(generated_reasons(&notices), [Reason::NamesChanged]);
}

#[test]
fn self_signed_replaces_bad_files() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::SelfSigned, &[]);
    let (store, _) = open(s.clone(), &[], NOW).unwrap();
    let first = store.info().fingerprint_sha256;
    std::fs::write(s.tls_dir().join(SELF_SIGNED_CERT), b"junk").unwrap();
    let (store, notices) = open(s.clone(), &[], NOW).unwrap();
    assert_eq!(generated_reasons(&notices), [Reason::Unusable]);
    assert_ne!(store.info().fingerprint_sha256, first);
    std::fs::remove_file(s.tls_dir().join(SELF_SIGNED_KEY)).unwrap();
    let (_, notices) = open(s, &[], NOW).unwrap();
    assert_eq!(generated_reasons(&notices), [Reason::Unusable]);
}

#[test]
fn wrong_clock_keeps_the_certificate() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::SelfSigned, &[]);
    let (store, _) = open(s.clone(), &[], NOW).unwrap();
    let first = store.info().fingerprint_sha256;
    // A Pi with no RTC starts in 1970.
    let (again, notices) = open(s, &[], 0).unwrap();
    assert!(notices.contains(&Notice::ClockNotPlausible { now: 0 }));
    assert_eq!(generated_reasons(&notices), []);
    assert_eq!(again.info().fingerprint_sha256, first);
    assert_eq!(store.reload(&[], 0).unwrap(), ReloadOutcome::Unchanged);
}

#[test]
fn first_start_with_a_wrong_clock_uses_the_build_time() {
    // A Pi with no RTC starts in 1970 at the first start.
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["rusthole.lan"]);
    let (store, notices) = open(s.clone(), &[], 0).unwrap();
    assert!(notices.contains(&Notice::ClockNotPlausible { now: 0 }));
    let info = store.info();
    assert_eq!(info.not_before, BUILD - policy::BACKDATE);
    // After NTP sets the clock, the CA and the server certificate are valid.
    let ca = read_cert(&s.tls_dir().join(CA_CERT));
    verify_leaf(
        &ca,
        store.current_key().end_entity_cert().unwrap(),
        "rusthole.lan",
        NOW,
    )
    .unwrap();
    // While the clock stays wrong, a reload makes nothing new.
    assert_eq!(store.reload(&[], 0).unwrap(), ReloadOutcome::Unchanged);
    assert_eq!(store.reload(&[], 0).unwrap(), ReloadOutcome::Unchanged);
    // Self-signed mode also uses the build time.
    let dir2 = scratch();
    let (ss, _) = open(settings(dir2.path(), TlsMode::SelfSigned, &[]), &[], 0).unwrap();
    assert_eq!(ss.info().not_before, BUILD - policy::BACKDATE);
    assert_eq!(ss.reload(&[], 0).unwrap(), ReloadOutcome::Unchanged);
    // A new address with a wrong clock gives a certificate from the build time too.
    let ReloadOutcome::Reloaded(_) = ss.reload(&[ip("192.0.2.9")], 0).unwrap() else {
        panic!("a new address must give a new certificate");
    };
    assert_eq!(ss.info().not_before, BUILD - policy::BACKDATE);
}

#[cfg(unix)]
#[test]
fn generated_key_has_mode_0600_and_open_key_gives_a_warning() {
    use std::os::unix::fs::PermissionsExt;
    let Some(dir) = crate::fsio::tests::scratch_keeping_modes(
        "generated_key_has_mode_0600_and_open_key_gives_a_warning",
    ) else {
        return;
    };
    let s = settings(dir.path(), TlsMode::SelfSigned, &[]);
    open(s.clone(), &[], NOW).unwrap();
    let key = s.tls_dir().join(SELF_SIGNED_KEY);
    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(s.tls_dir()).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_, notices) = open(s, &[], NOW).unwrap();
    assert!(notices.contains(&Notice::KeyReadableByOthers {
        path: key,
        mode: 0o644
    }));
}

// ---------------------------------------------------------------------------------------
// Mode `local-ca`.

fn verify_leaf(
    ca: &CertificateDer<'static>,
    leaf: &CertificateDer<'_>,
    name: &str,
    now: i64,
) -> Result<(), rustls::Error> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .unwrap();
    let name = ServerName::try_from(name.to_owned()).unwrap();
    let t = UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(now).unwrap()));
    verifier
        .verify_server_cert(leaf, &[], &name, &[], t)
        .map(|_| ())
}

#[test]
fn local_ca_issues_a_cert_that_verifies() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["rusthole.lan"]);
    let ips = [ip("192.168.1.2"), ip("192.0.2.7")];
    let (store, notices) = open(s.clone(), &ips, NOW).unwrap();
    assert!(notices.contains(&Notice::NewCa {
        path: s.tls_dir().join(CA_CERT)
    }));
    assert_eq!(generated_reasons(&notices), [Reason::Missing]);
    let info = store.info();
    assert_eq!(info.ca_cert_path, Some(s.tls_dir().join(CA_CERT)));
    assert!(info.ca_fingerprint_sha256.is_some());
    assert_eq!(info.not_after, NOW + policy::LEAF_VALIDITY);
    let ca = read_cert(&s.tls_dir().join(CA_CERT));
    let key = store.current_key();
    let leaf = key.end_entity_cert().unwrap();
    for name in [
        "rusthole.lan",
        "localhost",
        "127.0.0.1",
        "192.168.1.2",
        "192.0.2.7",
    ] {
        verify_leaf(&ca, leaf, name, NOW).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    // A name that is not in the certificate fails.
    assert!(verify_leaf(&ca, leaf, "other.lan", NOW).is_err());
    assert_eq!(
        entries(&s.tls_dir()),
        [CA_KEY, CA_CERT, SERVER_KEY, SERVER_CERT]
    );
    // A restart reuses the CA and the server certificate.
    let (again, notices) = open(s, &ips, NOW + DAY).unwrap();
    assert_eq!(generated_reasons(&notices), []);
    assert!(!notices.iter().any(|n| matches!(n, Notice::NewCa { .. })));
    assert_eq!(again.info(), info);
}

#[test]
fn local_ca_name_constraints_stop_other_names() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["rusthole.lan"]);
    let (_, _) = open(s.clone(), &[ip("192.0.2.7")], NOW).unwrap();
    let ca_pem = std::fs::read_to_string(s.tls_dir().join(CA_CERT)).unwrap();
    let ca_key = std::fs::read_to_string(s.tls_dir().join(CA_KEY)).unwrap();
    let ca = read_cert(&s.tls_dir().join(CA_CERT));
    // Sign a certificate for a public name with the CA key directly: a client refuses it.
    let sans = SanSet::wanted(&["example.com".into()], &[ip("198.51.100.1")]);
    let bad = generate::issue_leaf(&ca, &ca_key, &sans, NOW).unwrap();
    let bad = pem::parse_cert_chain(bad.cert_pem.as_bytes(), "bad")
        .unwrap()
        .remove(0);
    assert!(verify_leaf(&ca, &bad, "example.com", NOW).is_err());
    assert!(verify_leaf(&ca, &bad, "198.51.100.1", NOW).is_err());
    assert!(ca_pem.contains("BEGIN CERTIFICATE"));
}

#[test]
fn local_ca_leaves_out_names_that_the_ca_does_not_cover() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["a.lan"]);
    let (first, _) = open(s.clone(), &[], NOW).unwrap();
    let ca_fp = first.info().ca_fingerprint_sha256;
    let mut s2 = s;
    s2.names.push("b.example".into());
    let (store, notices) = open(s2.clone(), &[], NOW).unwrap();
    assert!(notices.contains(&Notice::NamesNotInCa {
        names: vec!["b.example".into()]
    }));
    // The CA stays, and the server certificate is the same (its names did not change).
    assert_eq!(store.info().ca_fingerprint_sha256, ca_fp);
    assert_eq!(generated_reasons(&notices), []);
    assert!(!store.info().sans.names.contains("b.example"));
    // The result is stable: a reload makes no new certificate.
    assert_eq!(store.reload(&[], NOW).unwrap(), ReloadOutcome::Unchanged);
}

#[test]
fn local_ca_is_never_replaced_by_itself() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &[]);
    open(s.clone(), &[], NOW).unwrap();
    let ca_path = s.tls_dir().join(CA_CERT);
    let key_path = s.tls_dir().join(CA_KEY);
    let ca_before = std::fs::read(&ca_path).unwrap();
    let key_before = std::fs::read(&key_path).unwrap();
    // A missing key.
    std::fs::rename(&key_path, dir.path().join("saved.key")).unwrap();
    let e = open(s.clone(), &[], NOW).unwrap_err();
    assert!(matches!(e, TlsError::CaUnusable { .. }), "{e}");
    assert_eq!(std::fs::read(&ca_path).unwrap(), ca_before);
    assert!(!key_path.exists());
    std::fs::rename(dir.path().join("saved.key"), &key_path).unwrap();
    // A bad CA certificate.
    std::fs::write(&ca_path, b"junk").unwrap();
    let e = open(s.clone(), &[], NOW).unwrap_err();
    assert!(matches!(e, TlsError::CaUnusable { .. }), "{e}");
    assert_eq!(std::fs::read(&key_path).unwrap(), key_before);
    // A CA key of another CA.
    std::fs::write(&ca_path, &ca_before).unwrap();
    let other = generate::local_ca(&policy::CaScope::default(), NOW).unwrap();
    std::fs::write(&key_path, other.key_pem).unwrap();
    let e = open(s.clone(), &[], NOW).unwrap_err();
    assert!(matches!(e, TlsError::CaUnusable { .. }), "{e}");
    // A CA that expires soon gives a warning, not a new CA.
    std::fs::write(&key_path, &key_before).unwrap();
    let late = NOW + policy::CA_VALIDITY - 10 * DAY;
    let (store, notices) = open(s, &[], late).unwrap();
    assert!(
        notices
            .iter()
            .any(|n| matches!(n, Notice::CaExpiresSoon { .. }))
    );
    assert!(!notices.iter().any(|n| matches!(n, Notice::NewCa { .. })));
    assert_eq!(std::fs::read(&ca_path).unwrap(), ca_before);
    assert_eq!(generated_reasons(&notices), [Reason::Expiring]);
    drop(store);
}

/// A crash during the first CA write leaves `ca.key` without `ca.pem` (the key goes first).
/// No device can trust that CA, so rusthole makes a new one.
#[test]
fn local_ca_key_without_cert_gives_a_new_ca() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["rusthole.lan"]);
    open(s.clone(), &[], NOW).unwrap();
    let ca_path = s.tls_dir().join(CA_CERT);
    let key_path = s.tls_dir().join(CA_KEY);
    let key_before = std::fs::read(&key_path).unwrap();
    std::fs::remove_file(&ca_path).unwrap();
    let (store, notices) = open(s.clone(), &[], NOW).unwrap();
    assert!(notices.contains(&Notice::NewCa {
        path: ca_path.clone()
    }));
    assert_ne!(std::fs::read(&key_path).unwrap(), key_before);
    // The old server certificate is from the old CA, so rusthole issues a new one.
    assert_eq!(generated_reasons(&notices), [Reason::Unusable]);
    let ca = read_cert(&ca_path);
    let key = store.current_key();
    let leaf = key.end_entity_cert().unwrap();
    for name in ["rusthole.lan", "localhost", "127.0.0.1"] {
        verify_leaf(&ca, leaf, name, NOW).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// webpki refuses these names. A local CA with one of them in its name constraints would be
/// refused for every name, and rusthole never replaces a CA by itself. Thus the store refuses
/// them before it writes a file, also for settings that did not go through
/// `Config::validate`.
#[test]
fn generated_modes_refuse_bad_names() {
    for bad in [
        "-pi.lan",
        "pi-.lan",
        "10.0.0",
        "123",
        "a_b.lan",
        "192.0.2.1",
    ] {
        for mode in [TlsMode::LocalCa, TlsMode::SelfSigned] {
            let dir = scratch();
            let s = settings(dir.path(), mode, &["rusthole.lan", bad]);
            let e = open(s.clone(), &[], NOW).unwrap_err();
            assert!(
                matches!(&e, TlsError::BadName { name, .. } if name == bad),
                "{bad} {mode:?}: {e}"
            );
            assert!(!s.tls_dir().exists(), "{bad} {mode:?}: a file was written");
        }
    }
    // Good names give a CA whose leaf verifies for each name, `localhost` too.
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["pi-1.lan", "rusthole.lan."]);
    let (store, _) = open(s.clone(), &[], NOW).unwrap();
    let ca = read_cert(&s.tls_dir().join(CA_CERT));
    let key = store.current_key();
    let leaf = key.end_entity_cert().unwrap();
    for name in ["pi-1.lan", "rusthole.lan", "localhost", "127.0.0.1"] {
        verify_leaf(&ca, leaf, name, NOW).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    // Mode `file` does not use the names.
    let (cert, key) = write_pair(dir.path(), "f", NOW);
    let mut f = file_settings(dir.path(), &cert, &key);
    f.names = vec!["-pi.lan".into()];
    assert!(open(f, &[], NOW).is_ok());
}

#[test]
fn local_ca_renews_the_server_cert_and_keeps_the_ca() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["rusthole.lan"]);
    let (store, _) = open(s.clone(), &[], NOW).unwrap();
    let first = store.info();
    let edge = first.not_after - policy::RENEW_BEFORE;
    let ReloadOutcome::Reloaded(notices) = store.reload(&[], edge).unwrap() else {
        panic!("expected a new server certificate");
    };
    assert_eq!(generated_reasons(&notices), [Reason::Expiring]);
    let second = store.info();
    assert_eq!(second.ca_fingerprint_sha256, first.ca_fingerprint_sha256);
    assert_ne!(second.fingerprint_sha256, first.fingerprint_sha256);
    let ca = read_cert(&s.tls_dir().join(CA_CERT));
    verify_leaf(
        &ca,
        store.current_key().end_entity_cert().unwrap(),
        "rusthole.lan",
        edge,
    )
    .unwrap();
}

#[test]
fn local_ca_replaces_a_server_cert_from_another_issuer() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &[]);
    open(s.clone(), &[], NOW).unwrap();
    // Put a self-signed pair with the same names in place of the server pair.
    let pair = generate::self_signed(&SanSet::wanted(&[], &[]), NOW).unwrap();
    std::fs::write(s.tls_dir().join(SERVER_CERT), pair.cert_pem).unwrap();
    std::fs::write(s.tls_dir().join(SERVER_KEY), pair.key_pem).unwrap();
    let (_, notices) = open(s, &[], NOW).unwrap();
    assert_eq!(generated_reasons(&notices), [Reason::Unusable]);
}

// ---------------------------------------------------------------------------------------
// Server and client configs.

#[test]
fn doh_builder_refuses_self_signed() {
    let dir = scratch();
    let (ss, _) = open(settings(dir.path(), TlsMode::SelfSigned, &[]), &[], NOW).unwrap();
    assert!(matches!(
        doh_server_config(&ss),
        Err(TlsError::SelfSignedForDoh)
    ));
    let admin = admin_server_config(&ss).unwrap();
    assert_eq!(admin.alpn_protocols, [b"h2".to_vec(), b"http/1.1".to_vec()]);
    let dir2 = scratch();
    let (ca, _) = open(settings(dir2.path(), TlsMode::LocalCa, &[]), &[], NOW).unwrap();
    let doh = doh_server_config(&ca).unwrap();
    assert_eq!(doh.alpn_protocols.first().map(Vec::as_slice), Some(ALPN_H2));
    admin_server_config(&ca).unwrap();
    let (cert, key) = write_pair(dir2.path(), "f", NOW);
    let (file, _) = open(file_settings(dir2.path(), &cert, &key), &[], NOW).unwrap();
    doh_server_config(&file).unwrap();
}

#[test]
fn roots_fall_back_to_the_bundled_set() {
    let (roots, source) = roots_from(Vec::new(), 2);
    assert_eq!(source, RootSource::Bundled { system_errors: 2 });
    assert!(roots.len() > 50);
    let (_, source) = roots_from(vec![CertificateDer::from(vec![1, 2, 3])], 0);
    assert_eq!(source, RootSource::Bundled { system_errors: 0 });
    let dir = scratch();
    let (cert, _) = write_pair(dir.path(), "root", NOW);
    let (roots, source) = roots_from(vec![read_cert(&cert)], 0);
    assert_eq!(
        source,
        RootSource::System {
            count: 1,
            errors: 0
        }
    );
    assert_eq!(roots.len(), 1);
    let c = client_config_with_roots(roots, vec![ALPN_H2.to_vec()]).unwrap();
    assert_eq!(c.alpn_protocols, [ALPN_H2.to_vec()]);
}

#[test]
fn system_roots_load_or_fall_back() {
    // The test host may have no system store; both results are valid. It must not panic.
    let (roots, _source) = system_roots();
    assert!(!roots.is_empty());
    let (config, _) = client_config(Vec::new()).unwrap();
    assert_eq!(config.alpn_protocols, Vec::<Vec<u8>>::new());
}

#[test]
fn build_time_is_plausible_now() {
    assert!(build_time_unix() >= MIN_BUILD_TIME_UNIX);
    assert!(clock_plausible(now_unix(), build_time_unix()));
    assert!(!clock_plausible(0, build_time_unix()));
}

#[test]
fn settings_from_config() {
    let mut c = rusthole_core::Config::default();
    c.server.data_dir = "/data".into();
    c.tls.names = vec!["pi.lan".into()];
    let s = TlsSettings::from_config(&c);
    assert_eq!(s.mode, TlsMode::SelfSigned);
    assert_eq!(s.tls_dir(), Path::new("/data").join("tls"));
    assert_eq!(s.names, ["pi.lan"]);
    c.admin.tls_cert_path = Some("/c.pem".into());
    c.admin.tls_key_path = Some("/k.pem".into());
    let s = TlsSettings::from_config(&c);
    assert_eq!(s.mode, TlsMode::File);
    assert_eq!(s.cert_path.as_deref(), Some(Path::new("/c.pem")));
    assert_eq!(s.key_path.as_deref(), Some(Path::new("/k.pem")));
}

// ---------------------------------------------------------------------------------------
// Handshakes over an in-memory pipe.

/// The result of a handshake as the client sees it: the ALPN protocol and the server
/// certificate.
type Seen = (Option<Vec<u8>>, Vec<u8>);

async fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    name: &str,
) -> Result<Seen, String> {
    let name = ServerName::try_from(name.to_owned()).map_err(|e| e.to_string())?;
    let (c, s) = tokio::io::duplex(64 * 1024);
    let acceptor = tokio_rustls::TlsAcceptor::from(server);
    let connector = tokio_rustls::TlsConnector::from(client);
    let server_side = async move {
        let mut tls = acceptor.accept(s).await?;
        let mut b = [0u8; 4];
        tls.read_exact(&mut b).await?;
        tls.write_all(&b).await?;
        tls.shutdown().await?;
        Ok::<_, std::io::Error>(())
    };
    let client_side = async move {
        let mut tls = connector.connect(name, c).await?;
        tls.write_all(b"ping").await?;
        let mut b = [0u8; 4];
        tls.read_exact(&mut b).await?;
        assert_eq!(&b, b"ping");
        let conn = tls.get_ref().1;
        let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
        let leaf = conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map_or_else(Vec::new, |c| c.to_vec());
        Ok::<_, std::io::Error>((alpn, leaf))
    };
    let joined = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server_side, client_side)
    })
    .await
    .map_err(|_| "the handshake timed out".to_owned())?;
    let (server_result, client_result) = joined;
    let seen = client_result.map_err(|e| format!("client: {e}"))?;
    server_result.map_err(|e| format!("server: {e}"))?;
    Ok(seen)
}

fn client_trusting(cert: CertificateDer<'static>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    client_config_with_roots(roots, alpn.iter().map(|p| p.to_vec()).collect()).unwrap()
}

#[tokio::test]
async fn handshake_with_the_self_signed_cert() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::SelfSigned, &["rusthole.lan"]);
    let (store, _) = CertStore::open(s.clone(), &[ip("192.0.2.7")], now_unix()).unwrap();
    let cert = read_cert(&s.tls_dir().join(SELF_SIGNED_CERT));
    let server = admin_server_config(&store).unwrap();
    let client = client_trusting(cert.clone(), &[ALPN_H2, ALPN_HTTP11]);
    for name in ["rusthole.lan", "localhost", "192.0.2.7"] {
        let (alpn, leaf) = handshake(Arc::clone(&server), Arc::clone(&client), name)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(alpn.as_deref(), Some(ALPN_H2));
        assert_eq!(leaf, cert.to_vec());
    }
    // A client that asks only for HTTP/1.1 gets HTTP/1.1.
    let http1 = client_trusting(cert, &[ALPN_HTTP11]);
    let (alpn, _) = handshake(Arc::clone(&server), http1, "localhost")
        .await
        .unwrap();
    assert_eq!(alpn.as_deref(), Some(ALPN_HTTP11));
    // A name that is not in the certificate fails.
    assert!(handshake(server, client, "other.lan").await.is_err());
}

#[tokio::test]
async fn handshake_with_the_local_ca() {
    let dir = scratch();
    let s = settings(dir.path(), TlsMode::LocalCa, &["rusthole.lan"]);
    let (store, _) = CertStore::open(s.clone(), &[], now_unix()).unwrap();
    let ca = read_cert(&s.tls_dir().join(CA_CERT));
    let server = doh_server_config(&store).unwrap();
    let client = client_trusting(ca, &[ALPN_H2]);
    let (alpn, _) = handshake(Arc::clone(&server), client, "rusthole.lan")
        .await
        .unwrap();
    assert_eq!(alpn.as_deref(), Some(ALPN_H2));
    // A client without the CA fails.
    let dir2 = scratch();
    let (_, _) = CertStore::open(
        settings(dir2.path(), TlsMode::LocalCa, &["rusthole.lan"]),
        &[],
        now_unix(),
    )
    .unwrap();
    let other_ca = read_cert(&dir2.path().join("tls").join(CA_CERT));
    let stranger = client_trusting(other_ca, &[ALPN_H2]);
    let e = handshake(Arc::clone(&server), stranger, "rusthole.lan")
        .await
        .unwrap_err();
    assert!(e.contains("client"), "{e}");
    // A client with only the bundled public roots also fails.
    let (roots, _) = roots_from(Vec::new(), 0);
    let public = client_config_with_roots(roots, vec![ALPN_H2.to_vec()]).unwrap();
    assert!(handshake(server, public, "rusthole.lan").await.is_err());
}

#[tokio::test]
async fn handshake_uses_the_reloaded_cert() {
    let dir = scratch();
    let (cert, key) = write_pair(dir.path(), "live", now_unix());
    let (store, _) =
        CertStore::open(file_settings(dir.path(), &cert, &key), &[], now_unix()).unwrap();
    let server = admin_server_config(&store).unwrap();
    let first = read_cert(&cert);
    let (_, leaf) = handshake(
        Arc::clone(&server),
        client_trusting(first.clone(), &[]),
        "files.lan",
    )
    .await
    .unwrap();
    assert_eq!(leaf, first.to_vec());
    let (c2, k2) = write_pair(dir.path(), "next", now_unix());
    std::fs::copy(&c2, &cert).unwrap();
    std::fs::copy(&k2, &key).unwrap();
    touch_forward(&cert, 10);
    assert!(matches!(
        store.reload(&[], now_unix()).unwrap(),
        ReloadOutcome::Reloaded(_)
    ));
    // The same server config now gives the new certificate: no restart.
    let second = read_cert(&cert);
    let (alpn, leaf) = handshake(server, client_trusting(second.clone(), &[]), "files.lan")
        .await
        .unwrap();
    assert_eq!(leaf, second.to_vec());
    assert_eq!(alpn, None);
}
