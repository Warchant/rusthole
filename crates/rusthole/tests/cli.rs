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
