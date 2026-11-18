//! The `passwd` command: set the admin password, or set up or turn off TOTP (decision D10,
//! amendment A7). The API has no endpoint to set the password.
//!
//! The command changes `admin.password_hash` (or `admin.totp_secret`) with `toml_edit`, so
//! comments and order stay, and writes the file atomically with mode 0600. A running
//! rusthole reads the changed file at the next login.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use rusthole_web::config_edit::{EditError, edit_file};
use rusthole_web::password::{MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, hash_password};
use rusthole_web::totp;

/// Reads one secret line (no echo on a terminal).
pub(crate) type ReadSecret<'a> = dyn FnMut(&str) -> io::Result<String> + 'a;

/// Runs the command with the terminal.
pub(crate) fn run(
    path: &Path,
    totp_setup: bool,
    disable_totp: bool,
    out: &mut impl Write,
) -> anyhow::Result<ExitCode> {
    if disable_totp {
        return disable(path, out);
    }
    if totp_setup {
        let stdin = io::stdin();
        let mut read_line = |prompt: &str| -> io::Result<String> {
            eprint_prompt(prompt)?;
            let mut s = String::new();
            stdin.lock().read_line(&mut s)?;
            Ok(s)
        };
        return setup_totp(path, &mut read_line, rusthole_store::wall_now(), out);
    }
    // Without a terminal (a pipe, a file, a CI job) rpassword cannot open `/dev/tty`, so
    // the password comes from stdin. It never comes from the command line or the
    // environment, where other users can see it.
    if io::stdin().is_terminal() {
        set_password(path, &mut |p: &str| rpassword::prompt_password(p), out)
    } else {
        set_password(path, &mut read_stdin_line, out)
    }
}

/// The longest line that the stdin path reads: a password of the largest size, and the line
/// end.
const MAX_STDIN_LINE: u64 = MAX_PASSWORD_LEN as u64 + 2;

/// Reads one line from stdin, with at most [`MAX_STDIN_LINE`] bytes. The prompt goes to
/// stderr. A longer line gives a text that is too long, and `set_password` refuses it.
fn read_stdin_line(prompt: &str) -> io::Result<String> {
    eprint_prompt(prompt)?;
    let mut line = String::new();
    io::stdin()
        .lock()
        .take(MAX_STDIN_LINE)
        .read_line(&mut line)?;
    Ok(line)
}

/// Writes a prompt to stderr (the output of the command stays on stdout).
fn eprint_prompt(prompt: &str) -> io::Result<()> {
    let mut e = io::stderr().lock();
    e.write_all(prompt.as_bytes())?;
    e.flush()
}

fn write_error(path: &Path, e: EditError) -> anyhow::Error {
    match e {
        EditError::Invalid(issues) => {
            let text: Vec<String> = issues.iter().map(ToString::to_string).collect();
            anyhow::anyhow!(
                "{}: the config has problems: {}",
                path.display(),
                text.join("; ")
            )
        }
        other => anyhow::Error::new(other).context(format!("cannot change {}", path.display())),
    }
}

/// Asks for the new password two times, hashes it with Argon2id and writes it.
pub(crate) fn set_password(
    path: &Path,
    read: &mut ReadSecret<'_>,
    out: &mut impl Write,
) -> anyhow::Result<ExitCode> {
    let first = read("New admin password: ").context("cannot read the password")?;
    let first = first.trim_end_matches(['\r', '\n']).to_owned();
    if first.len() < MIN_PASSWORD_LEN || first.len() > MAX_PASSWORD_LEN {
        writeln!(
            out,
            "The password must have {MIN_PASSWORD_LEN} to {MAX_PASSWORD_LEN} bytes. Nothing changed."
        )?;
        return Ok(ExitCode::FAILURE);
    }
    let second = read("Type the password again: ").context("cannot read the password")?;
    if second.trim_end_matches(['\r', '\n']) != first {
        writeln!(out, "The two passwords are not the same. Nothing changed.")?;
        return Ok(ExitCode::FAILURE);
    }
    let hash = hash_password(&first).context("cannot hash the password")?;
    edit_file(path, |c| c.admin.password_hash = hash).map_err(|e| write_error(path, e))?;
    writeln!(
        out,
        "The admin password is set in {}. A running rusthole uses it at the next login.",
        path.display()
    )?;
    writeln!(
        out,
        "The hash is Argon2id (m=19456 KiB, t=2, p=1). The file has mode 0600."
    )?;
    Ok(ExitCode::SUCCESS)
}

/// Makes a TOTP secret, shows the `otpauth://` URI one time, checks one code from the app,
/// and writes the secret. A wrong code writes nothing.
pub(crate) fn setup_totp(
    path: &Path,
    read: &mut ReadSecret<'_>,
    now: i64,
    out: &mut impl Write,
) -> anyhow::Result<ExitCode> {
    let secret = totp::new_secret().context("the OS random source failed")?;
    writeln!(
        out,
        "Add this URI to your authenticator app (it is shown one time):"
    )?;
    writeln!(out, "{}", totp::otpauth_uri(&secret))?;
    let code = read("Code from the app: ").context("cannot read the code")?;
    if totp::verify(&secret, code.trim(), now, None).is_none() {
        writeln!(out, "The code is not correct. Nothing changed.")?;
        return Ok(ExitCode::FAILURE);
    }
    edit_file(path, |c| c.admin.totp_secret = secret).map_err(|e| write_error(path, e))?;
    writeln!(
        out,
        "TOTP is on. A login now needs the password and a code."
    )?;
    Ok(ExitCode::SUCCESS)
}

/// Turns TOTP off.
fn disable(path: &Path, out: &mut impl Write) -> anyhow::Result<ExitCode> {
    edit_file(path, |c| c.admin.totp_secret.clear()).map_err(|e| write_error(path, e))?;
    writeln!(out, "TOTP is off.")?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use rusthole_core::Config;

    use super::*;

    const TEXT: &str =
        "# keep me\nconfig_version = 1\n\n[admin]\nsession_ttl_seconds = 3600 # one hour\n";

    fn file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let p = dir.path().join("rusthole.toml");
        std::fs::write(&p, TEXT).unwrap();
        p
    }

    #[test]
    fn sets_the_password_and_keeps_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir);
        let mut answers = vec!["correct horse battery\n", "correct horse battery\n"].into_iter();
        let mut read = |_: &str| Ok(answers.next().unwrap().to_owned());
        let mut out = Vec::new();
        let code = set_password(&path, &mut read, &mut out).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# keep me\n"));
        assert!(text.contains("session_ttl_seconds = 3600 # one hour"));
        let cfg = Config::from_toml_str(&text).unwrap();
        assert!(rusthole_web::password::verify_password(
            "correct horse battery",
            &cfg.admin.password_hash
        ));
        // The output never shows the password or the hash.
        let shown = String::from_utf8(out).unwrap();
        assert!(!shown.contains("correct horse"));
        assert!(!shown.contains(&cfg.admin.password_hash));
    }

    #[test]
    fn refuses_short_and_different_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir);
        let mut out = Vec::new();
        let mut short = |_: &str| Ok("short".to_owned());
        assert_eq!(
            set_password(&path, &mut short, &mut out).unwrap(),
            ExitCode::FAILURE
        );
        let mut answers = vec!["correct horse battery", "correct horse batterz"].into_iter();
        let mut differ = |_: &str| Ok(answers.next().unwrap().to_owned());
        assert_eq!(
            set_password(&path, &mut differ, &mut out).unwrap(),
            ExitCode::FAILURE
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), TEXT);
    }

    /// A writer that keeps the text, so the test can read the printed URI.
    struct Shared(Rc<RefCell<String>>);

    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().push_str(&String::from_utf8_lossy(b));
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The codes of the window at `now` for the secret in the printed URI.
    fn window_codes(printed: &str, now: i64) -> Vec<String> {
        let secret = printed
            .split("secret=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let key = totp::base32_decode(secret).unwrap();
        let step = totp::step_of(now);
        (step - 1..=step + 1)
            .map(|s| format!("{:06}", totp::code_at(&key, s)))
            .collect()
    }

    #[test]
    fn totp_setup_checks_a_code_and_disable_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir);
        let now = 1_794_903_000;

        // A wrong code writes nothing.
        let printed = Rc::new(RefCell::new(String::new()));
        let p = Rc::clone(&printed);
        let mut wrong = move |_: &str| -> io::Result<String> {
            let codes = window_codes(&p.borrow(), now);
            Ok((0..1_000_000)
                .map(|n| format!("{n:06}"))
                .find(|c| !codes.contains(c))
                .unwrap())
        };
        let mut w = Shared(Rc::clone(&printed));
        assert_eq!(
            setup_totp(&path, &mut wrong, now, &mut w).unwrap(),
            ExitCode::FAILURE
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), TEXT);

        // The right code writes the secret.
        let printed = Rc::new(RefCell::new(String::new()));
        let p = Rc::clone(&printed);
        let mut right =
            move |_: &str| -> io::Result<String> { Ok(window_codes(&p.borrow(), now)[1].clone()) };
        let mut w = Shared(Rc::clone(&printed));
        assert_eq!(
            setup_totp(&path, &mut right, now, &mut w).unwrap(),
            ExitCode::SUCCESS
        );
        let cfg = Config::from_toml_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.admin.totp_secret.len(), 32);
        assert!(printed.borrow().contains(&cfg.admin.totp_secret));

        let mut out = Vec::new();
        assert_eq!(disable(&path, &mut out).unwrap(), ExitCode::SUCCESS);
        let cfg = Config::from_toml_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.admin.totp_secret, "");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .starts_with("# keep me\n")
        );
    }

    use std::cell::RefCell;
    use std::rc::Rc;
}
