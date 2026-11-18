//! systemd service notification (the `sd_notify` protocol), in pure Rust with std only.
//!
//! The unit `packaging/rusthole.service` has `Type=notify`. systemd gives the path of its
//! notification socket in `NOTIFY_SOCKET`. rusthole sends `READY=1` when all listeners are
//! bound, and `STOPPING=1` when it gets the stop signal. Without `NOTIFY_SOCKET` (a manual
//! start, a test, another OS), each call does nothing.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant S as systemd
//!     participant R as rusthole
//!     S->>R: start (NOTIFY_SOCKET=/run/systemd/notify)
//!     R->>R: bind DNS, DoH and admin listeners
//!     R->>S: READY=1, STATUS=...
//!     S->>R: SIGTERM
//!     R->>S: STOPPING=1
//!     R->>R: stop all parts, exit 0
//! ```
//!
//! The message builder and the address parser are pure functions with unit tests. The send
//! is a thin shell: one datagram with a time limit.

use std::path::PathBuf;
use std::time::Duration;

/// Time limit for one send to the notification socket.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// The longest status text that a message holds, in bytes.
pub(crate) const MAX_STATUS_LEN: usize = 200;

/// One item of a notification message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum State {
    /// `READY=1`: the service is ready (all listeners are bound).
    Ready,
    /// `STOPPING=1`: the service stops.
    Stopping,
    /// `STATUS=...`: a short text that `systemctl status` shows.
    Status(String),
}

/// Makes the message text: one `KEY=VALUE` line for each state, each line ends with `\n`.
///
/// A status text has no line break (each one becomes a space) and has at most
/// [`MAX_STATUS_LEN`] bytes, so it cannot add another key to the message.
pub(crate) fn message(states: &[State]) -> String {
    let mut text = String::new();
    for s in states {
        match s {
            State::Ready => text.push_str("READY=1\n"),
            State::Stopping => text.push_str("STOPPING=1\n"),
            State::Status(text_in) => {
                text.push_str("STATUS=");
                let mut len = 0;
                for ch in text_in.chars() {
                    let ch = if ch.is_control() { ' ' } else { ch };
                    len += ch.len_utf8();
                    if len > MAX_STATUS_LEN {
                        break;
                    }
                    text.push(ch);
                }
                text.push('\n');
            }
        }
    }
    text
}

/// Where the notification socket is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A socket file, for example `/run/systemd/notify`.
    Path(PathBuf),
    /// A Linux abstract socket name (the value starts with `@`; the name has no `@`).
    Abstract(Vec<u8>),
}

/// Reads the value of `NOTIFY_SOCKET`. An empty value or another form (for example
/// `vsock:`) gives `None`: rusthole does not send then.
pub(crate) fn parse_target(value: &str) -> Option<Target> {
    if value.starts_with('/') {
        return Some(Target::Path(PathBuf::from(value)));
    }
    let name = value.strip_prefix('@')?;
    if name.is_empty() {
        return None;
    }
    Some(Target::Abstract(name.as_bytes().to_vec()))
}

/// Sends `states` to the socket in `NOTIFY_SOCKET`. Does nothing when the variable is not
/// set. A send error is logged at WARN: it must not stop DNS service.
pub(crate) fn notify(states: &[State]) {
    let Some(value) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Some(target) = value.to_str().and_then(parse_target) else {
        tracing::warn!("NOTIFY_SOCKET has a form that rusthole does not support; no notification");
        return;
    };
    if let Err(e) = send(&target, &message(states)) {
        tracing::warn!(error = %e, "cannot send the systemd notification");
    }
}

/// Sends one datagram to `target`, with the time limit [`SEND_TIMEOUT`].
#[cfg(target_os = "linux")]
pub(crate) fn send(target: &Target, text: &str) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let sock = UnixDatagram::unbound()?;
    sock.set_write_timeout(Some(SEND_TIMEOUT))?;
    let sent = match target {
        Target::Path(p) => sock.send_to(text.as_bytes(), p)?,
        Target::Abstract(name) => {
            let addr = SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(text.as_bytes(), &addr)?
        }
    };
    if sent != text.len() {
        return Err(std::io::Error::other(
            "the notification was sent in part only",
        ));
    }
    Ok(())
}

/// systemd runs on Linux only. On another OS the send does nothing.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)] // The same signature as the Linux function.
pub(crate) fn send(_target: &Target, _text: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_has_one_line_for_each_state() {
        assert_eq!(message(&[State::Ready]), "READY=1\n");
        assert_eq!(message(&[State::Stopping]), "STOPPING=1\n");
        assert_eq!(
            message(&[State::Ready, State::Status("DNS on 2 addresses".into())]),
            "READY=1\nSTATUS=DNS on 2 addresses\n"
        );
        assert_eq!(message(&[]), "");
    }

    #[test]
    fn status_cannot_add_a_key() {
        let m = message(&[State::Status("ok\nREADY=1\r\tx".into())]);
        assert_eq!(m, "STATUS=ok READY=1  x\n");
        assert_eq!(m.lines().count(), 1);
    }

    #[test]
    fn status_has_at_most_the_limit() {
        let exact = "a".repeat(MAX_STATUS_LEN);
        assert_eq!(
            message(&[State::Status(exact.clone())]),
            format!("STATUS={exact}\n")
        );
        let m = message(&[State::Status("a".repeat(MAX_STATUS_LEN + 1))]);
        assert_eq!(m, format!("STATUS={exact}\n"));
    }

    #[test]
    fn status_is_cut_on_a_char_boundary() {
        let long = "é".repeat(MAX_STATUS_LEN);
        let m = message(&[State::Status(long)]);
        let value = m
            .strip_prefix("STATUS=")
            .unwrap()
            .strip_suffix('\n')
            .unwrap();
        assert!(value.len() <= MAX_STATUS_LEN);
        assert_eq!(value.len(), MAX_STATUS_LEN);
        assert!(value.chars().all(|c| c == 'é'));
    }

    #[test]
    fn parses_the_socket_address() {
        assert_eq!(
            parse_target("/run/systemd/notify"),
            Some(Target::Path(PathBuf::from("/run/systemd/notify")))
        );
        assert_eq!(
            parse_target("@/org/freedesktop/systemd1/notify/1"),
            Some(Target::Abstract(
                b"/org/freedesktop/systemd1/notify/1".to_vec()
            ))
        );
        assert_eq!(parse_target(""), None);
        assert_eq!(parse_target("@"), None);
        assert_eq!(parse_target("vsock:2:1234"), None);
        assert_eq!(parse_target("relative/path"), None);
    }

    /// The send reaches a socket file. No systemd is necessary.
    #[cfg(target_os = "linux")]
    #[test]
    fn send_reaches_a_socket_file() {
        use std::os::unix::net::UnixDatagram;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let rx = UnixDatagram::bind(&path).unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let text = message(&[State::Ready, State::Status("test".into())]);
        send(&Target::Path(path), &text).unwrap();
        let mut buf = [0u8; 256];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], text.as_bytes());
    }

    /// The send reaches an abstract socket (systemd can give such an address).
    #[cfg(target_os = "linux")]
    #[test]
    fn send_reaches_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        let name = format!("rusthole-test-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let rx = UnixDatagram::bind_addr(&addr).unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let target = parse_target(&format!("@{name}")).unwrap();
        send(&target, "STOPPING=1\n").unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1\n");
    }

    /// A socket that does not exist gives an error, not a hang.
    #[cfg(target_os = "linux")]
    #[test]
    fn send_to_a_missing_socket_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let target = Target::Path(dir.path().join("missing"));
        assert!(send(&target, "READY=1\n").is_err());
    }
}
