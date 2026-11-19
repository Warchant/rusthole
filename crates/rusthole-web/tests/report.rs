//! Integration tests of `GET /report/domain/{name}/{section}` (docs/API.md section 17)
//! and of the setting `report.external`. The DNS source is a fake: no network.

// Test helpers: a failed setup step is a test failure, so unwrap and panic are the right
// result.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Creds, Options, harness};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use reqwest::{Method, StatusCode};
use rusthole_core::DomainName;
use rusthole_dns::LookupAnswer;
use rusthole_report::dns::{DnsLookup, LookupFuture};
use rusthole_report::http::{GetFuture, HttpAnswer, HttpGet};
use rusthole_report::{Reporter, Sources};
use serde_json::json;

/// A fake DNS: one A record for each name, and a count of lookups.
#[derive(Debug, Default)]
struct FakeDns {
    calls: AtomicUsize,
}

impl DnsLookup for FakeDns {
    fn lookup<'a>(&'a self, name: &'a DomainName, rtype: RecordType) -> LookupFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let answers = if rtype == RecordType::A {
                let owner = Name::from_str(&format!("{}.", name.as_str())).unwrap();
                vec![Record::from_rdata(
                    owner,
                    60,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
                )]
            } else {
                Vec::new()
            };
            Ok(LookupAnswer {
                rcode: 0,
                answers,
                authorities: Vec::new(),
            })
        })
    }
}

/// A fake HTTPS: the IANA bootstrap file and one RDAP answer.
#[derive(Debug)]
struct FakeHttp;

impl HttpGet for FakeHttp {
    fn get<'a>(&'a self, url: &'a str, _max_bytes: usize) -> GetFuture<'a> {
        Box::pin(async move {
            let body = match url {
                rusthole_report::rdap::BOOTSTRAP_URL => {
                    r#"{"services":[[["test"],["https://rdap.nic.test/"]]]}"#
                }
                "https://rdap.nic.test/domain/example.test" => {
                    r#"{"ldhName":"example.test","events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}"#
                }
                _ => return Err(format!("no answer for {url}")),
            };
            Ok(HttpAnswer {
                status: 200,
                body: body.as_bytes().to_vec(),
            })
        })
    }
}

#[tokio::test]
async fn rdap_section_follows_the_setting() {
    let h = harness(Options {
        report: Some(Reporter::new(Sources {
            dns: Arc::new(FakeDns::default()),
            http: Arc::new(FakeHttp),
            tls: Arc::new(rusthole_report::tls::NoTls(
                "no TLS in this test".to_owned(),
            )),
        })),
        ..Options::default()
    })
    .await;
    let s = h.login().await;
    let r = h
        .get("/api/v1/report/domain/www.example.test/rdap", &s)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.body["status"], "ok");
    assert_eq!(r.body["data"]["domain"], "example.test");
    assert_eq!(r.body["data"]["created"], "2020-01-01T00:00:00Z");
    // The fake DNS gives a documentation address: the TLS section does not connect.
    let r = h
        .get("/api/v1/report/domain/www.example.test/tls", &s)
        .await;
    assert_eq!(r.body["status"], "unavailable", "{}", r.text);
    assert_eq!(r.body["data"]["addresses"][0], "192.0.2.7");
    let r = h
        .req(
            Method::PATCH,
            "/api/v1/settings",
            Some(json!({ "report": { "external": false } })),
            &s,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let r = h.get("/api/v1/report/domain/other.test/rdap", &s).await;
    assert_eq!(r.body["status"], "off");
    assert_eq!(r.body["data"], serde_json::Value::Null);
    h.stop().await;
}

#[tokio::test]
async fn dns_section_answers_then_comes_from_the_cache() {
    let dns = Arc::new(FakeDns::default());
    let h = harness(Options {
        report: Some(Reporter::new(Sources {
            dns: Arc::clone(&dns) as Arc<dyn DnsLookup>,
            http: Arc::new(FakeHttp),
            tls: Arc::new(rusthole_report::tls::NoTls(
                "no TLS in this test".to_owned(),
            )),
        })),
        ..Options::default()
    })
    .await;
    let s = h.login().await;

    // No session: 401.
    let r = h
        .get(
            "/api/v1/report/domain/www.example.test/dns",
            &Creds::default(),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let r = h
        .get("/api/v1/report/domain/WWW.Example.test/dns", &s)
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert_eq!(r.body["section"], "dns");
    assert_eq!(r.body["name"], "www.example.test");
    assert_eq!(r.body["status"], "ok");
    assert_eq!(r.body["cached"], false);
    assert!(r.body["fetched_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(r.body["error"], serde_json::Value::Null);
    let types = r.body["data"]["types"].as_array().unwrap();
    let a = types.iter().find(|t| t["type"] == "A").unwrap();
    assert_eq!(a["records"][0]["value"], "192.0.2.7");
    let first = dns.calls.load(Ordering::SeqCst);

    let r = h
        .get("/api/v1/report/domain/www.example.test/dns", &s)
        .await;
    assert_eq!(r.body["cached"], true);
    assert_eq!(dns.calls.load(Ordering::SeqCst), first);

    let r = h
        .get(
            "/api/v1/report/domain/www.example.test/dns?refresh=true",
            &s,
        )
        .await;
    assert_eq!(r.body["cached"], false);
    assert_eq!(dns.calls.load(Ordering::SeqCst), 2 * first);

    // An IDN name is changed to punycode.
    let r = h
        .get("/api/v1/report/domain/b%C3%BCcher.example/dns", &s)
        .await;
    assert_eq!(r.body["name"], "xn--bcher-kva.example");
    h.stop().await;
}

#[tokio::test]
async fn bad_input_gives_400_and_no_reporter_gives_503() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    for (path, why) in [
        (
            "/api/v1/report/domain/www.example.test/whois",
            "unknown section",
        ),
        ("/api/v1/report/domain/bad_name!/dns", "bad name"),
        (
            "/api/v1/report/domain/www.example.test/dns?refresh=maybe",
            "bad refresh",
        ),
    ] {
        let r = h.get(path, &s).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}: {}", r.text);
    }
    let r = h
        .get("/api/v1/report/domain/www.example.test/dns", &s)
        .await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    h.stop().await;
}

#[tokio::test]
async fn report_external_setting_round_trips() {
    let h = harness(Options::default()).await;
    let s = h.login().await;
    let r = h.get("/api/v1/settings", &s).await;
    assert_eq!(r.body["report"], json!({ "external": true }));
    let r = h
        .req(
            Method::PATCH,
            "/api/v1/settings",
            Some(json!({ "report": { "external": false } })),
            &s,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    assert!(!h.config().report.external);
    assert!(h.config_text().contains("external = false"));
    let r = h.get("/api/v1/settings", &s).await;
    assert_eq!(r.body["report"]["external"], false);
    h.stop().await;
}
