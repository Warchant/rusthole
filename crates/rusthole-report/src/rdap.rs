//! The RDAP section (docs/PLAN.md R-D7): who registered the domain, and when.
//!
//! ```mermaid
//! flowchart LR
//!     n[name] --> b[registrable domain]
//!     i[IANA bootstrap file, RAM cache 24 h] --> s{RDAP server for the TLD?}
//!     b --> s
//!     s -->|no| u[unavailable]
//!     s -->|yes| q[GET server/domain/base, HTTPS only]
//!     q -->|404| u
//!     q -->|200| p[parse a fixed set of fields]
//! ```
//!
//! The JSON comes from the network: the parsers are pure, keep a fixed set of fields with
//! size limits, and have property tests and the fuzz target `rdap_json`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusthole_core::DomainName;
use rusthole_core::blocking_state::MonoTime;
use rusthole_core::stats::base::registrable;
use serde_json::{Value, json};

use crate::dns::safe_text;
use crate::http::HttpGet;
use crate::model::{Outcome, Status};

/// The IANA bootstrap file for domain names (RFC 9224).
pub const BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";
/// The most bytes of the bootstrap file.
pub const MAX_BOOTSTRAP_BYTES: usize = 512 * 1024;
/// The most bytes of one RDAP answer.
pub const MAX_ANSWER_BYTES: usize = 256 * 1024;
/// How long the bootstrap file stays in RAM.
pub const BOOTSTRAP_TTL: Duration = Duration::from_hours(24);
/// The most TLD entries kept from the bootstrap file.
pub const MAX_TLDS: usize = 4096;
/// The most items of a list field (status, name servers).
pub const MAX_ITEMS: usize = 16;
/// The most bytes of one text field.
pub const MAX_TEXT: usize = 256;

/// The RDAP servers for each TLD, from the bootstrap file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bootstrap {
    servers: HashMap<String, String>,
}

impl Bootstrap {
    /// The number of TLD entries.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// True when the file had no usable entry.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// The base URL of the RDAP server for `domain` (the longest suffix that the file has).
    pub fn server_for(&self, domain: &str) -> Option<&str> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = domain.as_str();
        // Bounded: each pass removes one label.
        for _ in 0..=domain.len() {
            if let Some(s) = self.servers.get(rest) {
                return Some(s);
            }
            let (_, tail) = rest.split_once('.')?;
            rest = tail;
        }
        None
    }
}

/// Parses the bootstrap file. Keeps the first `https` URL of each service, and at most
/// [`MAX_TLDS`] entries.
pub fn parse_bootstrap(body: &[u8]) -> Result<Bootstrap, String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| format!("bootstrap file: {e}"))?;
    let services = v
        .get("services")
        .and_then(Value::as_array)
        .ok_or("bootstrap file: no services")?;
    let mut servers = HashMap::new();
    for svc in services {
        let (Some(tlds), Some(urls)) = (
            svc.get(0).and_then(Value::as_array),
            svc.get(1).and_then(Value::as_array),
        ) else {
            continue;
        };
        let Some(url) = urls
            .iter()
            .filter_map(Value::as_str)
            .find(|u| u.starts_with("https://") && u.len() <= 512)
        else {
            continue;
        };
        let url = if url.ends_with('/') {
            url.to_owned()
        } else {
            format!("{url}/")
        };
        for tld in tlds.iter().filter_map(Value::as_str) {
            if servers.len() >= MAX_TLDS {
                break;
            }
            let t = tld.trim_end_matches('.').to_ascii_lowercase();
            if !t.is_empty() && t.len() <= 253 {
                servers.entry(t).or_insert_with(|| url.clone());
            }
        }
    }
    if servers.is_empty() {
        return Err("bootstrap file: no usable entry".to_owned());
    }
    Ok(Bootstrap { servers })
}

/// The text of `v` as a bounded safe string.
fn text(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| safe_text(s, MAX_TEXT))
}

/// A value of a jCard (`vcardArray`): the first property `prop`.
fn vcard(entity: &Value, prop: &str) -> Option<String> {
    let props = entity.get("vcardArray")?.get(1)?.as_array()?;
    props
        .iter()
        .find(|p| p.get(0).and_then(Value::as_str) == Some(prop))
        .and_then(|p| text(p.get(3)))
}

/// True when an entity has `role`.
fn has_role(entity: &Value, role: &str) -> bool {
    entity
        .get("roles")
        .and_then(Value::as_array)
        .is_some_and(|r| r.iter().any(|x| x.as_str() == Some(role)))
}

/// A name that the registry hides is not data.
fn shown(s: Option<String>) -> Option<String> {
    s.filter(|v| {
        let l = v.to_ascii_lowercase();
        !(l.contains("redacted")
            || l.contains("privacy")
            || l.contains("not disclosed")
            || l.contains("withheld"))
    })
}

/// The entities of `v`, and one level of nested entities (the abuse contact of a registrar).
fn entities(v: &Value) -> Vec<&Value> {
    let top: Vec<&Value> = v
        .get("entities")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |a| a.iter().take(64).collect());
    let mut all = top.clone();
    for e in top {
        if let Some(inner) = e.get("entities").and_then(Value::as_array) {
            all.extend(inner.iter().take(16));
        }
    }
    all
}

/// Parses an RDAP domain answer into the fixed fields of the section.
pub fn parse_domain(body: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| format!("RDAP answer: {e}"))?;
    if !v.is_object() {
        return Err("RDAP answer: not an object".to_owned());
    }
    let event = |action: &str| {
        v.get("events").and_then(Value::as_array).and_then(|evs| {
            evs.iter()
                .take(64)
                .find(|e| e.get("eventAction").and_then(Value::as_str) == Some(action))
                .and_then(|e| text(e.get("eventDate")))
        })
    };
    let list = |key: &str, field: Option<&str>| -> Vec<String> {
        v.get(key)
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |a| {
                a.iter()
                    .filter_map(|x| match field {
                        Some(f) => text(x.get(f)),
                        None => text(Some(x)),
                    })
                    .take(MAX_ITEMS)
                    .collect()
            })
    };
    let ents = entities(&v);
    let registrar = ents.iter().find(|e| has_role(e, "registrar"));
    let registrar_name = registrar.and_then(|e| vcard(e, "fn"));
    let registrar_id = registrar
        .and_then(|e| e.get("publicIds"))
        .and_then(Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(|id| text(id.get("identifier")));
    let registrant = ents
        .iter()
        .find(|e| has_role(e, "registrant"))
        .and_then(|e| shown(vcard(e, "org")).or_else(|| shown(vcard(e, "fn"))));
    let abuse = ents
        .iter()
        .find(|e| has_role(e, "abuse"))
        .and_then(|e| vcard(e, "email"));
    let signed = v
        .get("secureDNS")
        .and_then(|s| s.get("delegationSigned"))
        .and_then(Value::as_bool);
    Ok(json!({
        "domain": text(v.get("ldhName")).map(|s| s.to_ascii_lowercase()),
        "registrar": registrar_name,
        "registrar_iana_id": registrar_id,
        "registrant": registrant,
        "abuse_email": abuse,
        "created": event("registration"),
        "updated": event("last changed"),
        "expires": event("expiration"),
        "status": list("status", None),
        "nameservers": list("nameservers", Some("ldhName")).into_iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>(),
        "dnssec": signed,
    }))
}

/// The RDAP source: the HTTP client and the cached bootstrap file.
#[derive(Debug)]
pub struct Rdap {
    http: Arc<dyn HttpGet>,
    bootstrap: Mutex<Option<(MonoTime, Arc<Bootstrap>)>>,
}

impl Rdap {
    /// A source that fetches with `http`.
    pub fn new(http: Arc<dyn HttpGet>) -> Self {
        Self {
            http,
            bootstrap: Mutex::new(None),
        }
    }

    /// The bootstrap file: from RAM when it is younger than [`BOOTSTRAP_TTL`], else fetched.
    async fn bootstrap(&self, now: MonoTime) -> Result<Arc<Bootstrap>, String> {
        if let Some(guard) = self.bootstrap.try_lock_for(crate::service::LOCK_TIMEOUT)
            && let Some((at, b)) = guard.as_ref()
            && now.saturating_since(*at) < BOOTSTRAP_TTL
        {
            return Ok(Arc::clone(b));
        }
        let r = self.http.get(BOOTSTRAP_URL, MAX_BOOTSTRAP_BYTES).await?;
        if r.status != 200 {
            return Err(format!("bootstrap file: HTTP {}", r.status));
        }
        let b = Arc::new(parse_bootstrap(&r.body)?);
        if let Some(mut guard) = self.bootstrap.try_lock_for(crate::service::LOCK_TIMEOUT) {
            *guard = Some((now, Arc::clone(&b)));
        }
        Ok(b)
    }

    /// Runs the RDAP section for `name`.
    pub async fn run(&self, name: &DomainName, now: MonoTime) -> Outcome {
        let base = registrable(name.as_str()).to_owned();
        let boot = match self.bootstrap(now).await {
            Ok(b) => b,
            Err(e) => return Outcome::failed(e),
        };
        let Some(server) = boot.server_for(&base) else {
            return Outcome {
                status: Status::Unavailable,
                data: json!({ "domain": base }),
                error: Some(format!("IANA lists no RDAP server for {base}")),
            };
        };
        let url = format!("{server}domain/{base}");
        let r = match self.http.get(&url, MAX_ANSWER_BYTES).await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(e),
        };
        match r.status {
            200 => match parse_domain(&r.body) {
                Ok(mut data) => {
                    if let Some(obj) = data.as_object_mut() {
                        obj.insert("server".to_owned(), json!(safe_text(server, MAX_TEXT)));
                    }
                    Outcome {
                        status: Status::Ok,
                        data,
                        error: None,
                    }
                }
                Err(e) => Outcome::failed(e),
            },
            404 => Outcome {
                status: Status::Unavailable,
                data: json!({ "domain": base }),
                error: Some(format!("the registry has no record of {base}")),
            },
            s => Outcome::failed(format!("RDAP server: HTTP {s}")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests: a failure is a test failure.
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use proptest::prelude::*;

    use super::*;
    use crate::http::{GetFuture, HttpAnswer};

    pub(crate) const BOOT: &str = r#"{"version":"1.0","services":[
        [["com","net"],["http://rdap.verisign.test/com/v1/","https://rdap.verisign.test/com/v1/"]],
        [["test"],["https://rdap.nic.test"]],
        [["co.example"],["https://rdap.co.example/"]],
        [["bad"],["http://only.http.test/"]],
        "junk", [[1,2],[3]]
    ]}"#;

    pub(crate) const DOMAIN: &str = r#"{
        "objectClassName":"domain","ldhName":"MICROSOFT.COM",
        "status":["client delete prohibited","server transfer prohibited"],
        "events":[{"eventAction":"registration","eventDate":"1991-05-02T04:00:00Z"},
                  {"eventAction":"expiration","eventDate":"2027-05-03T04:00:00Z"},
                  {"eventAction":"last changed","eventDate":"2025-01-01T00:00:00Z"}],
        "nameservers":[{"ldhName":"NS1-39.AZURE-DNS.COM"},{"ldhName":"NS2-39.AZURE-DNS.NET"}],
        "secureDNS":{"delegationSigned":false},
        "entities":[
          {"roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"292"}],
           "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]],
           "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abusecomplaints@markmonitor.com"]]]}]},
          {"roles":["registrant"],"vcardArray":["vcard",[["org",{},"text","Microsoft Corporation"],["fn",{},"text","REDACTED FOR PRIVACY"]]]}
        ]}"#;

    /// A fake HTTP: fixed answers by URL, and a count of calls.
    #[derive(Debug, Default)]
    pub(crate) struct FakeHttp {
        pub(crate) answers: HashMap<String, Result<HttpAnswer, String>>,
        pub(crate) calls: AtomicUsize,
    }

    impl FakeHttp {
        pub(crate) fn with(mut self, url: &str, status: u16, body: &str) -> Self {
            self.answers.insert(
                url.to_owned(),
                Ok(HttpAnswer {
                    status,
                    body: body.as_bytes().to_vec(),
                }),
            );
            self
        }
    }

    impl HttpGet for FakeHttp {
        fn get<'a>(&'a self, url: &'a str, max_bytes: usize) -> GetFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let a = self
                    .answers
                    .get(url)
                    .cloned()
                    .unwrap_or_else(|| Err(format!("no answer for {url}")))?;
                if a.body.len() > max_bytes {
                    return Err("too large".to_owned());
                }
                Ok(a)
            })
        }
    }

    fn name(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[test]
    fn bootstrap_keeps_https_and_longest_suffix() {
        let b = parse_bootstrap(BOOT.as_bytes()).unwrap();
        assert_eq!(
            b.server_for("microsoft.com"),
            Some("https://rdap.verisign.test/com/v1/")
        );
        assert_eq!(b.server_for("x.y.test"), Some("https://rdap.nic.test/"));
        assert_eq!(
            b.server_for("a.co.example"),
            Some("https://rdap.co.example/")
        );
        assert_eq!(b.server_for("a.example"), None);
        assert_eq!(b.server_for("a.bad"), None);
        assert!(parse_bootstrap(b"{}").is_err());
        assert!(parse_bootstrap(b"not json").is_err());
    }

    #[test]
    fn domain_fields() {
        let d = parse_domain(DOMAIN.as_bytes()).unwrap();
        assert_eq!(d["domain"], "microsoft.com");
        assert_eq!(d["registrar"], "MarkMonitor Inc.");
        assert_eq!(d["registrar_iana_id"], "292");
        assert_eq!(d["registrant"], "Microsoft Corporation");
        assert_eq!(d["abuse_email"], "abusecomplaints@markmonitor.com");
        assert_eq!(d["created"], "1991-05-02T04:00:00Z");
        assert_eq!(d["expires"], "2027-05-03T04:00:00Z");
        assert_eq!(d["updated"], "2025-01-01T00:00:00Z");
        assert_eq!(d["nameservers"][1], "ns2-39.azure-dns.net");
        assert_eq!(d["status"].as_array().unwrap().len(), 2);
        assert_eq!(d["dnssec"], false);
    }

    #[test]
    fn a_hidden_registrant_is_not_shown() {
        let body = r#"{"ldhName":"x.com","entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","REDACTED FOR PRIVACY"]]]}]}"#;
        assert_eq!(
            parse_domain(body.as_bytes()).unwrap()["registrant"],
            Value::Null
        );
        assert!(parse_domain(b"[1,2]").is_err());
    }

    fn rdap(http: FakeHttp) -> (Rdap, Arc<FakeHttp>) {
        let http = Arc::new(http);
        (Rdap::new(Arc::clone(&http) as Arc<dyn HttpGet>), http)
    }

    #[tokio::test]
    async fn run_asks_the_registrable_domain_and_keeps_the_bootstrap() {
        let (r, http) = rdap(FakeHttp::default().with(BOOTSTRAP_URL, 200, BOOT).with(
            "https://rdap.verisign.test/com/v1/domain/microsoft.com",
            200,
            DOMAIN,
        ));
        let now = MonoTime::ZERO;
        let o = r.run(&name("mobile.events.data.microsoft.com"), now).await;
        assert_eq!(o.status, Status::Ok, "{o:?}");
        assert_eq!(o.data["registrar"], "MarkMonitor Inc.");
        assert_eq!(o.data["server"], "https://rdap.verisign.test/com/v1/");
        let _ = r.run(&name("www.microsoft.com"), now).await;
        // One bootstrap fetch and two domain fetches.
        assert_eq!(http.calls.load(Ordering::SeqCst), 3);
        // After 24 h the bootstrap file is fetched again.
        let later = now.checked_add(BOOTSTRAP_TTL).unwrap();
        let _ = r.run(&name("microsoft.com"), later).await;
        assert_eq!(http.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn no_server_404_and_errors() {
        let (r, _) = rdap(
            FakeHttp::default()
                .with(BOOTSTRAP_URL, 200, BOOT)
                .with("https://rdap.nic.test/domain/gone.test", 404, "{}")
                .with("https://rdap.nic.test/domain/err.test", 500, "")
                .with("https://rdap.nic.test/domain/junk.test", 200, "<html>"),
        );
        let now = MonoTime::ZERO;
        assert_eq!(
            r.run(&name("nas.lan"), now).await.status,
            Status::Unavailable
        );
        assert_eq!(
            r.run(&name("gone.test"), now).await.status,
            Status::Unavailable
        );
        assert_eq!(r.run(&name("err.test"), now).await.status, Status::Failed);
        assert_eq!(r.run(&name("junk.test"), now).await.status, Status::Failed);
        let (r, _) = rdap(FakeHttp::default());
        let o = r.run(&name("x.com"), now).await;
        assert_eq!(o.status, Status::Failed);
    }

    proptest! {
        /// Any bytes: the parsers never panic, and the text fields keep their bounds.
        #[test]
        fn parsers_are_total(body in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = parse_bootstrap(&body);
            let _ = parse_domain(&body);
        }

        /// Long or odd strings in the fields stay bounded and have no control characters.
        #[test]
        fn fields_are_bounded(s in any::<String>()) {
            let many = vec![s.clone(); 40];
            let body = json!({ "ldhName": s, "status": many, "events": [{ "eventAction": "registration", "eventDate": s }] });
            let d = parse_domain(body.to_string().as_bytes()).unwrap();
            for f in ["domain", "created"] {
                if let Some(t) = d[f].as_str() {
                    prop_assert!(t.len() <= MAX_TEXT + 3);
                    prop_assert!(!t.chars().any(char::is_control));
                }
            }
            prop_assert!(d["status"].as_array().unwrap().len() <= MAX_ITEMS);
        }
    }
}
