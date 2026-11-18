//! End-to-end tests of the `rusthole` binary: import, then check-config.
// Test helpers: a failed setup step is a test failure, so unwrap is the right result.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A new empty directory under the cargo target directory (not the system temp directory).
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn rusthole(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rusthole"))
        .args(args)
        .env("RUSTHOLE_LOG", "error")
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn import_then_check_config() {
    let dir = scratch("import_then_check_config");
    let zip = dir.join("teleporter.zip");
    std::fs::write(&zip, rusthole_import::testkit::home_zip()).unwrap();
    let out = dir.join("rusthole.toml");
    let (zip_s, out_s) = (zip.to_str().unwrap(), out.to_str().unwrap());

    let o = rusthole(&["import", zip_s, "-o", out_s]);
    assert!(o.status.success(), "{o:?}");
    let text = stdout(&o);
    assert!(text.contains("Translated (66):"), "{text}");
    assert!(text.contains("rusthole passwd"));
    assert!(!text.contains("BALLOON"));
    // The command prints the full report, then the output path.
    let report = rusthole_import::import_teleporter(
        &rusthole_import::testkit::home_zip(),
        &rusthole_import::Limits::default(),
    )
    .unwrap()
    .report
    .to_string();
    assert!(text.starts_with(&report), "{text}");

    let o = rusthole(&["check-config", "-c", out_s]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert!(stdout(&o).contains("config is valid"));

    // A second import does not replace the file without --force.
    let before = std::fs::read(&out).unwrap();
    let o = rusthole(&["import", zip_s, "-o", out_s]);
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), before);
    let o = rusthole(&["import", zip_s, "-o", out_s, "--force"]);
    assert!(o.status.success());

    // No temp file stays in the directory.
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["rusthole.toml", "teleporter.zip"]);
}

#[test]
fn check_config_reports_issues_with_exit_code_1() {
    let dir = scratch("check_config_reports_issues");
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "config_version = 1\n[[rules]]\nkind = \"regex\"\naction = \"deny\"\nvalue = \"(\"\n",
    )
    .unwrap();
    let o = rusthole(&["check-config", "-c", path.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("rules[0].value"), "{}", stdout(&o));

    std::fs::write(&path, "config_version = 9\n").unwrap();
    let o = rusthole(&["check-config", "-c", path.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("not supported"));

    let o = rusthole(&[
        "check-config",
        "-c",
        dir.join("missing.toml").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn check_config_never_prints_a_secret() {
    let dir = scratch("check_config_never_prints_a_secret");
    let path = dir.join("secret.toml");
    let cases = [
        "config_version = 1\n[admin]\ntotp_secret = \"JBSWY3DPEHPK3PXPSECRET\n",
        "config_version = 1\n[admin]\ntotp_secret = JBSWY3DPEHPK3PXPSECRET\n",
        "config_version = 1\n[admin]\npassword_hash = 5\napi_tokens = \"SECRETHASH\"\n",
        "config_version = 1\n[admin]\ntotp_secrt = \"JBSWY3DPEHPK3PXPSECRET\"\n",
    ];
    for text in cases {
        std::fs::write(&path, text).unwrap();
        let o = rusthole(&["check-config", "-c", path.to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(1));
        let all = format!("{}{}", stdout(&o), String::from_utf8_lossy(&o.stderr));
        assert!(!all.contains("SECRET"), "{text:?} gives {all}");
        assert!(all.contains("line "), "{text:?} gives {all}");
    }
}

#[test]
fn import_of_garbage_fails_cleanly() {
    let dir = scratch("import_of_garbage");
    let zip = dir.join("bad.zip");
    std::fs::write(&zip, b"not a zip").unwrap();
    let out = dir.join("out.toml");
    let o = rusthole(&["import", zip.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(!out.exists());
}

#[test]
fn run_refuses_a_bad_config_with_exit_code_1() {
    let dir = scratch("run_refuses_a_bad_config");
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "config_version = 1\n[server]\ndns_listen = [\"2001:db8::1\"]\n",
    )
    .unwrap();
    let o = rusthole(&["run", "-c", path.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("server.dns_listen"), "{}", stdout(&o));

    // The DoH listener with the default TLS mode (self-signed): DoH clients refuse such a
    // certificate, so `run` stops before it binds a socket or writes a TLS file (part P7).
    // Before part P7, this case was a config with only a DoH upstream; such a config is
    // valid now, so `run` would start.
    let data = dir.join("data");
    std::fs::write(
        &path,
        format!(
            "config_version = 1\n[server]\ndata_dir = '{}'\ndns_listen = [\"127.0.0.1\"]\n\
             [server.doh]\nenabled = true\nlisten = [\"127.0.0.1\"]\n",
            data.display()
        ),
    )
    .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_rusthole"))
        .args(["run", "-c", path.to_str().unwrap()])
        .env("RUSTHOLE_LOG", "error")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("self-signed"), "{err}");
    assert!(!data.join("tls").exists());
}

#[test]
fn version_shows_the_version_and_the_commit() {
    let o = rusthole(&["--version"]);
    assert!(o.status.success(), "{o:?}");
    let text = stdout(&o);
    let line = text.trim_end();
    let rest = line
        .strip_prefix(concat!("rusthole ", env!("CARGO_PKG_VERSION"), " (commit "))
        .unwrap_or_else(|| panic!("unexpected version text: {line}"));
    let commit = rest.strip_suffix(')').unwrap();
    let is_id = (7..=12).contains(&commit.len())
        && commit
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    assert!(is_id || commit == "unknown", "{line}");
}

#[test]
fn passwd_reads_the_password_from_a_pipe() {
    use std::io::Write as _;
    use std::process::Stdio;

    let dir = scratch("passwd_reads_the_password_from_a_pipe");
    let path = dir.join("rusthole.toml");
    let text = "# keep me\nconfig_version = 1\n";
    std::fs::write(&path, text).unwrap();
    let pipe = |input: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rusthole"))
            .args(["passwd", "-c", path.to_str().unwrap()])
            .env("RUSTHOLE_LOG", "error")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    // Two different lines: nothing changes.
    let o = pipe("correct horse battery\ncorrect horse batterz\n");
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    // No input at all: nothing changes.
    let o = pipe("");
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    // A line that is longer than the password limit (1024 bytes): nothing changes.
    let long = "a".repeat(4096);
    let o = pipe(&format!("{long}\n{long}\n"));
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

    let o = pipe("correct horse battery\ncorrect horse battery\n");
    assert!(o.status.success(), "{o:?}");
    let new = std::fs::read_to_string(&path).unwrap();
    assert!(new.starts_with("# keep me\n"), "{new}");
    assert!(new.contains("password_hash = \"$argon2id$"), "{new}");
    // The output never shows the password.
    let all = format!("{}{}", stdout(&o), String::from_utf8_lossy(&o.stderr));
    assert!(!all.contains("correct horse"), "{all}");
}

/// The default config of `packaging/install.sh` is valid, and it holds the values that the
/// install script, the systemd unit and docs/INSTALL.md expect.
#[test]
fn packaged_default_config_is_valid() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/rusthole.toml");
    let o = rusthole(&["check-config", "-c", path.to_str().unwrap()]);
    assert!(o.status.success(), "{}", stdout(&o));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("data_dir = \"/var/lib/rusthole\""), "{text}");
    assert!(text.contains("port = 8443"), "{text}");
    // No secret in the template: the password is set with `rusthole passwd`.
    assert!(!text.contains("password_hash ="), "{text}");
}

/// The unit runs the binary with the config path that install.sh writes.
#[test]
fn systemd_unit_matches_the_install_script() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging");
    let unit = std::fs::read_to_string(root.join("rusthole.service")).unwrap();
    let install = std::fs::read_to_string(root.join("install.sh")).unwrap();
    assert!(
        unit.contains("ExecStart=/usr/local/bin/rusthole run -c /etc/rusthole/rusthole.toml"),
        "{unit}"
    );
    assert!(unit.contains("Type=notify"));
    assert!(unit.contains("User=rusthole"));
    assert!(unit.contains("ReadWritePaths=/var/lib/rusthole /etc/rusthole"));
    assert!(install.contains("BIN=\"$DESTDIR/usr/local/bin/rusthole\""));
    assert!(install.contains("CONF=\"$CONF_DIR/rusthole.toml\""));
    assert!(install.contains("CONF_DIR=\"$DESTDIR/etc/rusthole\""));
    assert!(install.contains("DATA_DIR=\"$DESTDIR/var/lib/rusthole\""));
}
