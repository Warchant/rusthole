//! Integration tests of the plain HTTP redirect on the admin port (docs/SECURITY.md
//! section 2): plain HTTP gets a 301 to HTTPS, a foreign Host gets 400, and TLS still works.

// Test helpers: a failed setup step is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Creds, Options, harness};
use reqwest::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Sends `data` over plain TCP and reads the answer until the server closes (10 s limit).
async fn plain(addr: SocketAddr, data: &[u8]) -> String {
    let io = async {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(data).await.unwrap();
        let mut out = Vec::new();
        let _ = tcp.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    };
    tokio::time::timeout(Duration::from_secs(10), io)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_gets_a_redirect_and_tls_still_works() {
    let h = harness(Options::default()).await;
    let host = format!("127.0.0.1:{}", h.addr.port());

    let a = plain(
        h.addr,
        format!("GET /#/domains?name=a.test HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(a.starts_with("HTTP/1.1 301 "), "{a}");
    assert!(
        a.contains(&format!(
            "\r\nLocation: https://{host}/#/domains?name=a.test\r\n"
        )),
        "{a}"
    );

    // The head can come in parts.
    let io = async {
        let mut tcp = TcpStream::connect(h.addr).await.unwrap();
        tcp.write_all(b"GET /api/v1/system HT").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        tcp.write_all(format!("TP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tcp.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    };
    let a = tokio::time::timeout(Duration::from_secs(10), io)
        .await
        .unwrap();
    assert!(
        a.contains(&format!("Location: https://{host}/api/v1/system\r\n")),
        "{a}"
    );

    // A foreign Host: no open redirect.
    let a = plain(h.addr, b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n").await;
    assert!(a.starts_with("HTTP/1.1 400 "), "{a}");
    assert!(!a.contains("Location"), "{a}");

    // Bytes that are not TLS or HTTP: closed with no answer.
    let a = plain(h.addr, b"\x00\x01\x02").await;
    assert!(a.is_empty(), "{a}");

    // HTTPS still works.
    let r = h.get("/api/v1/auth/session", &Creds::default()).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    h.stop().await;
}
