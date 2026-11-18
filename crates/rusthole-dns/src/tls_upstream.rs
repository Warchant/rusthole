//! Parts that the DoT and DoH upstreams share: the target (name and bootstrap addresses),
//! the rustls client configs, the TLS connect, and the hyper executor.
//!
//! rusthole never resolves the name of a DoT or DoH upstream through the system resolver
//! (amendment A6). It connects to the bootstrap IPv4 addresses from the config. The name is
//! the TLS SNI and the name that the certificate check verifies.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::{CertificateError, ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::sync::Spawner;
use crate::upstream::UpstreamError;

/// Bootstrap addresses of one upstream, at most. More are ignored.
pub const MAX_BOOTSTRAP: usize = 8;

/// The shortest time between two WARN logs of a failed handshake (review item m1). The
/// other failures in that time go to DEBUG, and the next WARN gives their count.
pub const HANDSHAKE_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// True when a WARN is due: no WARN before (`last_ms` is `None`), or the last WARN is at
/// least `every_ms` before `now_ms`. `now_ms` is a monotonic time. Pure.
pub(crate) fn warn_due(last_ms: Option<u64>, now_ms: u64, every_ms: u64) -> bool {
    last_ms.is_none_or(|last| now_ms >= last && now_ms - last >= every_ms)
}

/// The rate limit of the handshake WARN, for all upstreams.
#[derive(Debug)]
struct WarnLimit {
    /// The time of the last WARN in ms from the first call of [`mono_ms`], or `u64::MAX`
    /// for none.
    last_ms: AtomicU64,
    /// Failures logged at DEBUG since the last WARN.
    suppressed: AtomicU64,
}

static HANDSHAKE_WARN: WarnLimit = WarnLimit::new();

/// Monotonic milliseconds since the first call.
fn mono_ms() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX - 1)
}

impl WarnLimit {
    const fn new() -> Self {
        Self {
            last_ms: AtomicU64::new(u64::MAX),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Takes the WARN slot when it is due. Gives the count of the failures that were
    /// logged at DEBUG since the last WARN, or `None` when no WARN is due.
    fn take(&self, now_ms: u64, every_ms: u64) -> Option<u64> {
        let last = self.last_ms.load(Ordering::Acquire);
        let last_opt = (last != u64::MAX).then_some(last);
        if warn_due(last_opt, now_ms, every_ms)
            && self
                .last_ms
                .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::AcqRel));
        }
        self.suppressed.fetch_add(1, Ordering::AcqRel);
        None
    }
}

/// Logs a failed handshake: a WARN at most once in [`HANDSHAKE_WARN_INTERVAL`], else DEBUG.
fn log_handshake_failure(addr: SocketAddr, name: &str, e: &io::Error) {
    let every = u64::try_from(HANDSHAKE_WARN_INTERVAL.as_millis()).unwrap_or(u64::MAX);
    if let Some(suppressed) = HANDSHAKE_WARN.take(mono_ms(), every) {
        tracing::warn!(
            upstream = %addr,
            name,
            error = %e,
            suppressed,
            "TLS handshake failed (the next failures in one minute go to DEBUG; suppressed \
             is their count since the last WARN)"
        );
    } else {
        tracing::debug!(upstream = %addr, name, error = %e, "TLS handshake failed");
    }
}

/// Where a DoT or DoH upstream is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsTarget {
    /// The TLS name: a host name, or an IP address in text form. It is the SNI (for a host
    /// name) and the name that the certificate must have.
    pub name: String,
    /// The addresses to connect to (bootstrap addresses, or the IP address of the URL), in
    /// order. Not empty.
    pub addrs: Vec<SocketAddr>,
    /// The port (also in each address).
    pub port: u16,
    /// The HTTP path for DoH (for example `/dns-query`). Empty for DoT.
    pub path: String,
}

impl TlsTarget {
    /// The HTTP authority for DoH: the name, and the port when it is not 443.
    pub fn authority(&self) -> String {
        let host = if self.name.contains(':') {
            // An IPv6 address needs brackets. v1 refuses IPv6 upstreams (amendment A11),
            // but the type stays ready for v2.
            format!("[{}]", self.name)
        } else {
            self.name.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The first address, for logs and statistics.
    pub fn first_addr(&self) -> Option<SocketAddr> {
        self.addrs.first().copied()
    }
}

/// The rustls client configs for DoT (no ALPN) and DoH (ALPN `h2`).
#[derive(Debug, Clone)]
pub struct UpstreamTls {
    /// The config for DoT upstreams.
    pub dot: Arc<ClientConfig>,
    /// The config for DoH upstreams.
    pub doh: Arc<ClientConfig>,
}

impl UpstreamTls {
    /// Configs that trust `roots` only. Tests use a test CA here.
    pub fn with_roots(roots: RootCertStore) -> Result<Self, rusthole_tls::TlsError> {
        Ok(Self {
            dot: rusthole_tls::client_config_with_roots(roots.clone(), Vec::new())?,
            doh: rusthole_tls::client_config_with_roots(
                roots,
                vec![rusthole_tls::ALPN_H2.to_vec()],
            )?,
        })
    }

    /// Configs that trust the system roots, or the bundled Mozilla roots when the system
    /// store gives none (amendment A8).
    pub fn system() -> Result<Self, rusthole_tls::TlsError> {
        let (roots, source) = rusthole_tls::system_roots();
        match &source {
            rusthole_tls::RootSource::System { count, .. } => {
                tracing::info!(
                    count,
                    "TLS client roots for DoT and DoH from the system store"
                );
            }
            rusthole_tls::RootSource::Bundled { .. } => {
                tracing::warn!(
                    "no system TLS roots; DoT and DoH upstreams use the bundled Mozilla roots"
                );
            }
        }
        Self::with_roots(roots)
    }
}

/// Connects to `target` over TCP and makes the TLS handshake, all before `deadline`.
///
/// The function tries the addresses in order, from `start` (it wraps), at most
/// [`MAX_BOOTSTRAP`]. It gives the stream and the index of the address that worked.
pub(crate) async fn connect(
    target: &TlsTarget,
    config: &Arc<ClientConfig>,
    start: usize,
    deadline: Instant,
) -> Result<(TlsStream<TcpStream>, usize), UpstreamError> {
    let name = ServerName::try_from(target.name.clone()).map_err(|_| UpstreamError::Tls)?;
    let connector = TlsConnector::from(Arc::clone(config));
    let n = target.addrs.len().min(MAX_BOOTSTRAP);
    let mut last = UpstreamError::NoUpstream;
    for k in 0..n {
        let idx = (start + k) % n;
        let Some(addr) = target.addrs.get(idx).copied() else {
            continue;
        };
        let tcp = match timeout_at(deadline, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(upstream = %addr, error = %e, "TCP connect failed");
                last = UpstreamError::Io(e.kind());
                continue;
            }
            Err(_) => return Err(UpstreamError::Timeout),
        };
        // DNS messages are small; send each one at once.
        let _ = tcp.set_nodelay(true);
        match timeout_at(deadline, connector.connect(name.clone(), tcp)).await {
            Ok(Ok(tls)) => return Ok((tls, idx)),
            Ok(Err(e)) => {
                log_handshake_failure(addr, &target.name, &e);
                last = tls_error(&e);
            }
            Err(_) => return Err(UpstreamError::Timeout),
        }
    }
    Err(last)
}

/// A handshake error: a certificate that is not yet valid or expired is
/// [`UpstreamError::CertDate`] (review item m1), another TLS problem is
/// [`UpstreamError::Tls`], other errors keep their I/O kind.
fn tls_error(e: &io::Error) -> UpstreamError {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(c)) if is_date_error(c) => UpstreamError::CertDate,
        Some(_) => UpstreamError::Tls,
        None => UpstreamError::Io(e.kind()),
    }
}

/// True for a certificate error that a wrong clock can cause.
fn is_date_error(c: &CertificateError) -> bool {
    matches!(
        c,
        CertificateError::Expired
            | CertificateError::ExpiredContext { .. }
            | CertificateError::NotValidYet
            | CertificateError::NotValidYetContext { .. }
    )
}

/// True when a DoT or DoH connection stays in the pool after the failed query `e`.
/// `seen_before` and `seen_now` count the replies (or reads) on the connection before the
/// query was sent and now.
///
/// - A connection error: the connection is dead.
/// - A timeout: the connection is dead only when nothing came on it after the query was
///   sent. Else the upstream is slow for this name only.
/// - Other errors (a full connection, an HTTP status, a wrong reply, an encode error) are
///   not about the connection.
pub(crate) fn keeps_conn(e: UpstreamError, seen_before: u64, seen_now: u64) -> bool {
    match e {
        UpstreamError::Io(_)
        | UpstreamError::Tls
        | UpstreamError::CertDate
        | UpstreamError::Stopped => false,
        UpstreamError::Timeout => seen_now != seen_before,
        UpstreamError::Overloaded
        | UpstreamError::Http(_)
        | UpstreamError::BadReply
        | UpstreamError::Encode
        | UpstreamError::NoRandom
        | UpstreamError::NoUpstream => true,
    }
}

/// A hyper executor that runs each task through the [`Spawner`], so shutdown stops it.
#[derive(Debug, Clone)]
pub(crate) struct HyperExec(pub(crate) Spawner);

impl<F> hyper::rt::Executor<F> for HyperExec
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        self.0.spawn(fut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_has_the_port_when_not_443() {
        let mut t = TlsTarget {
            name: "doh.example".to_owned(),
            addrs: vec!["192.0.2.81:443".parse().unwrap()],
            port: 443,
            path: "/dns-query".to_owned(),
        };
        assert_eq!(t.authority(), "doh.example");
        t.port = 8443;
        assert_eq!(t.authority(), "doh.example:8443");
        t.name = "2001:db8::1".to_owned();
        assert_eq!(t.authority(), "[2001:db8::1]:8443");
    }

    #[test]
    fn keeps_conn_rules() {
        use std::io::ErrorKind;
        // A timeout with no reply after the query: the connection is dead.
        assert!(!keeps_conn(UpstreamError::Timeout, 5, 5));
        // A timeout with a reply after the query: the connection lives.
        assert!(keeps_conn(UpstreamError::Timeout, 5, 6));
        assert!(!keeps_conn(
            UpstreamError::Io(ErrorKind::ConnectionAborted),
            5,
            6
        ));
        assert!(keeps_conn(UpstreamError::Overloaded, 0, 0));
        assert!(keeps_conn(UpstreamError::Http(503), 0, 0));
        assert!(keeps_conn(UpstreamError::BadReply, 0, 0));
        assert!(!keeps_conn(UpstreamError::CertDate, 0, 1));
    }

    fn io_tls(e: rustls::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }

    /// m1: the date errors are told apart from the other TLS errors.
    #[test]
    fn date_errors_are_classified() {
        for c in [CertificateError::Expired, CertificateError::NotValidYet] {
            assert_eq!(
                tls_error(&io_tls(rustls::Error::InvalidCertificate(c))),
                UpstreamError::CertDate
            );
        }
        for c in [
            CertificateError::NotValidForName,
            CertificateError::UnknownIssuer,
        ] {
            assert_eq!(
                tls_error(&io_tls(rustls::Error::InvalidCertificate(c))),
                UpstreamError::Tls
            );
        }
        assert_eq!(
            tls_error(&io::Error::from(io::ErrorKind::ConnectionReset)),
            UpstreamError::Io(io::ErrorKind::ConnectionReset)
        );
    }

    #[test]
    fn warn_rule() {
        assert!(warn_due(None, 0, 60_000));
        assert!(!warn_due(Some(1_000), 60_999, 60_000));
        assert!(warn_due(Some(1_000), 61_000, 60_000));
        // A time before the last WARN (not possible with a monotonic clock) gives no WARN.
        assert!(!warn_due(Some(5_000), 1_000, 60_000));
    }

    /// m1: many failures in one interval give one WARN; the next WARN counts the others.
    #[test]
    fn warn_limit_counts_the_suppressed_failures() {
        let w = WarnLimit::new();
        assert_eq!(w.take(10, 60_000), Some(0));
        for t in 11..20 {
            assert_eq!(w.take(t, 60_000), None);
        }
        assert_eq!(w.take(60_009, 60_000), None);
        assert_eq!(w.take(60_010, 60_000), Some(10));
        assert_eq!(w.take(60_011, 60_000), None);
    }

    proptest::proptest! {
        /// Two WARNs are at least `every` ms apart, and the first failure gives a WARN.
        #[test]
        fn at_most_one_warn_per_interval(
            steps in proptest::collection::vec(0u64..5_000, 1..200),
            every in 1u64..20_000,
        ) {
            let w = WarnLimit::new();
            let mut now = 0u64;
            let mut warns: Vec<u64> = Vec::new();
            for d in steps {
                now += d;
                if w.take(now, every).is_some() {
                    warns.push(now);
                }
            }
            proptest::prop_assert!(!warns.is_empty());
            for pair in warns.windows(2) {
                proptest::prop_assert!(pair[1] - pair[0] >= every);
            }
        }
    }
}
