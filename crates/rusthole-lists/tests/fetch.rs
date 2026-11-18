//! Fetch limits (amendment A8) against a local HTTP server on 127.0.0.1.

// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right result.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Resp, TEST_HOST, no_roots_tls, serve, serve_tls, test_limits, test_lookup};
use rusthole_core::refresh::Validators;
use rusthole_lists::{FetchError, FetchLimits, FetchOutcome, Fetcher, StaticResolver};

fn fetcher(limits: FetchLimits) -> Fetcher {
    Fetcher::new(limits, no_roots_tls(), test_lookup()).unwrap()
}

fn body(outcome: FetchOutcome) -> Vec<u8> {
    match outcome {
        FetchOutcome::Body { bytes, .. } => bytes,
        FetchOutcome::NotModified(_) => panic!("a body expected"),
    }
}

#[tokio::test]
async fn conditional_get_sends_validators() {
    let server = serve(|req| {
        if req.header("if-none-match") == Some("\"v1\"") {
            Resp::status(304).header("ETag", "\"v1\"")
        } else {
            Resp::ok("a.example\n")
                .header("ETag", "\"v1\"")
                .header("Last-Modified", "Tue, 17 Nov 2026 03:00:00 GMT")
        }
    })
    .await;
    let f = fetcher(test_limits());
    let FetchOutcome::Body { bytes, validators } = f.fetch(&server.url("/l"), None).await.unwrap()
    else {
        panic!("a body expected");
    };
    assert_eq!(bytes, b"a.example\n");
    assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
    let out = f.fetch(&server.url("/l"), Some(&validators)).await.unwrap();
    assert!(matches!(out, FetchOutcome::NotModified(_)));
    let req = server.last_request();
    assert_eq!(req.header("if-none-match"), Some("\"v1\""));
    assert_eq!(
        req.header("if-modified-since"),
        Some("Tue, 17 Nov 2026 03:00:00 GMT")
    );
    // Without validators, no conditional headers.
    let empty = Validators::default();
    let out = f.fetch(&server.url("/l"), Some(&empty)).await.unwrap();
    assert!(matches!(out, FetchOutcome::Body { .. }));
    assert_eq!(server.last_request().header("if-none-match"), None);
}

#[tokio::test]
async fn a_304_without_a_conditional_request_is_an_error() {
    let server = serve(|_| Resp::status(304)).await;
    let err = fetcher(test_limits())
        .fetch(&server.url("/l"), None)
        .await
        .unwrap_err();
    assert_eq!(err, FetchError::Status(304));
}

#[tokio::test]
async fn http_errors_and_bad_urls() {
    let server = serve(|_| Resp::status(404)).await;
    let f = fetcher(test_limits());
    assert_eq!(
        f.fetch(&server.url("/x"), None).await.unwrap_err(),
        FetchError::Status(404)
    );
    assert_eq!(
        f.fetch("ftp://127.0.0.1/x", None).await.unwrap_err(),
        FetchError::Scheme
    );
    assert_eq!(
        f.fetch("file:///etc/passwd", None).await.unwrap_err(),
        FetchError::Scheme
    );
    assert_eq!(
        f.fetch("not a url", None).await.unwrap_err(),
        FetchError::BadUrl
    );
}

/// `/r/N` redirects to `/r/N-1`; `/r/0` gives the body.
fn redirector() -> impl Fn(&common::Req) -> Resp + Send + Sync + 'static {
    |req| {
        let n: u32 = req
            .path
            .strip_prefix("/r/")
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        if req.path == "/ftp" {
            return Resp::status(302).header("Location", "ftp://127.0.0.1/list");
        }
        if n == 0 {
            Resp::ok("a.example\n")
        } else {
            Resp::status(302).header("Location", &format!("/r/{}", n - 1))
        }
    }
}

#[tokio::test]
async fn redirect_limit_is_exact() {
    let server = serve(redirector()).await;
    let f = fetcher(test_limits());
    // Three redirects are allowed.
    let out = f.fetch(&server.url("/r/3"), None).await.unwrap();
    assert_eq!(body(out), b"a.example\n");
    // Four are not.
    let err = f.fetch(&server.url("/r/4"), None).await.unwrap_err();
    assert!(matches!(err, FetchError::Redirect(_)), "{err:?}");
    // A redirect to another scheme is refused.
    let err = f.fetch(&server.url("/ftp"), None).await.unwrap_err();
    assert!(matches!(err, FetchError::Redirect(_)), "{err:?}");
}

fn limits(max_body: u64) -> FetchLimits {
    FetchLimits {
        max_body,
        ..test_limits()
    }
}

#[tokio::test]
async fn body_limit_is_exact_with_content_length() {
    let server = serve(|req| {
        let n = if req.path == "/big" { 101 } else { 100 };
        Resp::ok(vec![b'a'; n])
    })
    .await;
    let f = fetcher(limits(100));
    assert_eq!(
        body(f.fetch(&server.url("/ok"), None).await.unwrap()).len(),
        100
    );
    assert_eq!(
        f.fetch(&server.url("/big"), None).await.unwrap_err(),
        FetchError::TooLarge { limit: 100 }
    );
}

#[tokio::test]
async fn body_limit_is_exact_without_content_length() {
    // No Content-Length: the limit applies while the body is read.
    let server = serve(|req| {
        let n = if req.path == "/big" { 101 } else { 100 };
        Resp {
            no_length: true,
            ..Resp::ok(vec![b'a'; n])
        }
    })
    .await;
    let f = fetcher(limits(100));
    assert_eq!(
        body(f.fetch(&server.url("/ok"), None).await.unwrap()).len(),
        100
    );
    assert_eq!(
        f.fetch(&server.url("/big"), None).await.unwrap_err(),
        FetchError::TooLarge { limit: 100 }
    );
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[tokio::test]
async fn gzip_is_decoded_and_a_gzip_bomb_is_rejected() {
    // 16 MiB of zeros compress to a few KiB.
    let bomb = Arc::new(gzip(&vec![0u8; 16 * 1024 * 1024]));
    let small = Arc::new(gzip(b"a.example\nb.example\n"));
    assert!(bomb.len() < 64 * 1024);
    let server = serve(move |req| {
        let data = if req.path == "/bomb" { &bomb } else { &small };
        Resp::ok(data.as_ref().clone()).header("Content-Encoding", "gzip")
    })
    .await;
    let f = fetcher(limits(1024 * 1024));
    let out = f.fetch(&server.url("/small"), None).await.unwrap();
    assert_eq!(body(out), b"a.example\nb.example\n");
    assert!(
        server
            .last_request()
            .header("accept-encoding")
            .is_some_and(|v| v.contains("gzip"))
    );
    let err = f.fetch(&server.url("/bomb"), None).await.unwrap_err();
    assert_eq!(err, FetchError::TooLarge { limit: 1024 * 1024 });
}

#[tokio::test]
async fn a_silent_server_times_out() {
    let server = serve(|_| Resp::hang()).await;
    let lim = FetchLimits {
        total_timeout: Duration::from_millis(500),
        read_timeout: Duration::from_millis(400),
        ..test_limits()
    };
    let start = Instant::now();
    let err = fetcher(lim)
        .fetch(&server.url("/l"), None)
        .await
        .unwrap_err();
    assert_eq!(err, FetchError::Timeout);
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn names_go_through_the_given_lookup() {
    let server = serve(|_| Resp::ok("a.example\n")).await;
    // The test host resolves through the static table.
    let out = fetcher(test_limits())
        .fetch(&server.host_url("http", "/l"), None)
        .await
        .unwrap();
    assert_eq!(body(out), b"a.example\n");
    // A lookup that fails makes the fetch fail; no system resolver is used.
    let none = Fetcher::new(
        test_limits(),
        no_roots_tls(),
        Arc::new(StaticResolver::new()),
    )
    .unwrap();
    let err = none
        .fetch(&server.host_url("http", "/l"), None)
        .await
        .unwrap_err();
    let FetchError::Network(text) = err else {
        panic!("a network error expected: {err:?}");
    };
    assert!(text.contains(TEST_HOST), "{text}");
}

#[tokio::test]
async fn https_with_a_self_signed_certificate() {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let sans = rusthole_tls::SanSet {
        names: [TEST_HOST.to_owned()].into_iter().collect(),
        ips: std::collections::BTreeSet::new(),
    };
    let pair = rusthole_tls::generate::self_signed(&sans, rusthole_tls::now_unix()).unwrap();
    let cert = CertificateDer::from_pem_slice(pair.cert_pem.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(pair.key_pem.as_bytes()).unwrap();
    let server_cfg = rustls::ServerConfig::builder_with_provider(rusthole_tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let server = serve_tls(|_| Resp::ok("tls.example\n"), acceptor).await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let tls = rusthole_tls::client_config_with_roots(roots, Vec::new()).unwrap();
    let f = Fetcher::new(test_limits(), tls, test_lookup()).unwrap();
    let out = f
        .fetch(&server.host_url("https", "/l"), None)
        .await
        .unwrap();
    assert_eq!(body(out), b"tls.example\n");

    // A client that does not trust the certificate refuses it.
    let err = fetcher(test_limits())
        .fetch(&server.host_url("https", "/l"), None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Network(_)), "{err:?}");
}
