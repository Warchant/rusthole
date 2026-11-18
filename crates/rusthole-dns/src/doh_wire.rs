//! DoH request decoder and reply helpers (RFC 8484). All functions here are pure.
//!
//! ```mermaid
//! flowchart TD
//!     req[HTTP request] --> path{path is /dns-query?}
//!     path -->|no| e404[404]
//!     path --> method{method}
//!     method -->|other| e405[405]
//!     method -->|GET| qs{query string length}
//!     qs -->|too long| e414[414]
//!     qs --> dns{one dns= parameter, base64url}
//!     dns -->|no, or bad| e400[400]
//!     dns --> msg[DNS message]
//!     method -->|POST| ct{content type application/dns-message?}
//!     ct -->|no| e415[415]
//!     ct --> len{Content-Length and body at most 65535 bytes?}
//!     len -->|no| e413[413]
//!     len --> msg
//!     msg --> hdr{at least 12 bytes?}
//!     hdr -->|no| e400
//!     hdr --> ok[to the DNS pipeline]
//! ```
//!
//! The decoder does not parse the DNS message. The pipeline does that, so DoH clients get
//! the same checks as plain DNS clients.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT;
use hickory_proto::op::Message;

use crate::wire::HEADER_LEN;

/// The DoH path.
pub const DOH_PATH: &str = "/dns-query";
/// The media type of a DNS message in DoH.
pub const DNS_MESSAGE: &str = "application/dns-message";
/// The largest POST body in bytes (the largest DNS message). A larger body gets 413.
pub const MAX_BODY: usize = 65_535;
/// The longest `dns=` value of a GET request, in characters. It holds a DNS message of
/// about 3 KiB. A real query is much smaller. A longer value gets 414.
pub const MAX_GET_PARAM: usize = 4096;
/// The longest query string of a GET request, in characters. A longer one gets 414.
pub const MAX_QUERY_STRING: usize = 8192;
/// Parameters in a query string, at most. More give 400.
pub const MAX_QUERY_PARAMS: usize = 32;

/// Why a DoH request gets no DNS answer. Each value maps to one HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DohError {
    /// The path is not [`DOH_PATH`]. 404.
    #[error("not found")]
    NotFound,
    /// The method is not GET or POST. 405.
    #[error("method not allowed")]
    MethodNotAllowed,
    /// A POST request without the content type [`DNS_MESSAGE`]. 415.
    #[error("unsupported media type")]
    UnsupportedMediaType,
    /// The request is not valid: no `dns=` parameter, bad base64url, a message shorter
    /// than a DNS header, a bad Content-Length. 400.
    #[error("bad request")]
    BadRequest,
    /// The body is longer than [`MAX_BODY`]. 413.
    #[error("payload too large")]
    PayloadTooLarge,
    /// The query string or the `dns=` value is too long. 414.
    #[error("URI too long")]
    UriTooLong,
}

impl DohError {
    /// The HTTP status code.
    pub fn status(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::UnsupportedMediaType => 415,
            Self::BadRequest => 400,
            Self::PayloadTooLarge => 413,
            Self::UriTooLong => 414,
        }
    }
}

/// The result of [`decode_head`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohHead {
    /// A GET request with this DNS message.
    Get(Vec<u8>),
    /// A POST request. Read the body (at most [`MAX_BODY`] bytes), then call
    /// [`decode_body`].
    Post,
}

/// The parts of an HTTP request that the decoder reads. The fuzz target fills them with
/// arbitrary data.
#[derive(Debug, Clone, Copy)]
pub struct DohRequestParts<'a> {
    /// The method, for example `GET`.
    pub method: &'a str,
    /// The path, without the query string.
    pub path: &'a str,
    /// The query string, without the `?`.
    pub query: Option<&'a str>,
    /// The value of the Content-Type header.
    pub content_type: Option<&'a [u8]>,
    /// The value of the Content-Length header.
    pub content_length: Option<&'a [u8]>,
    /// The body.
    pub body: &'a [u8],
}

/// Decodes the request head: the path, the method, the GET parameter and the POST headers.
///
/// The server calls this before it reads the body, so a wrong request costs no body read.
pub fn decode_head(
    method: &str,
    path: &str,
    query: Option<&str>,
    content_type: Option<&[u8]>,
    content_length: Option<&[u8]>,
) -> Result<DohHead, DohError> {
    if path != DOH_PATH {
        return Err(DohError::NotFound);
    }
    match method {
        "GET" => decode_get(query.unwrap_or_default()).map(DohHead::Get),
        "POST" => {
            if !content_type.is_some_and(is_dns_message) {
                return Err(DohError::UnsupportedMediaType);
            }
            if let Some(len) = content_length {
                let len = parse_content_length(len).ok_or(DohError::BadRequest)?;
                if len > MAX_BODY {
                    return Err(DohError::PayloadTooLarge);
                }
            }
            Ok(DohHead::Post)
        }
        _ => Err(DohError::MethodNotAllowed),
    }
}

/// Checks a POST body: at most [`MAX_BODY`] bytes and at least one DNS header.
pub fn decode_body(body: &[u8]) -> Result<Vec<u8>, DohError> {
    if body.len() > MAX_BODY {
        return Err(DohError::PayloadTooLarge);
    }
    if body.len() < HEADER_LEN {
        return Err(DohError::BadRequest);
    }
    Ok(body.to_vec())
}

/// Decodes a full request: the head, then the body for POST. Gives the DNS message.
pub fn decode_request(req: &DohRequestParts<'_>) -> Result<Vec<u8>, DohError> {
    match decode_head(
        req.method,
        req.path,
        req.query,
        req.content_type,
        req.content_length,
    )? {
        DohHead::Get(msg) => Ok(msg),
        DohHead::Post => decode_body(req.body),
    }
}

/// True when `value` is the media type [`DNS_MESSAGE`]. ASCII case does not matter, and
/// parameters after `;` are ignored.
fn is_dns_message(value: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let media = text.split(';').next().unwrap_or_default().trim();
    media.eq_ignore_ascii_case(DNS_MESSAGE)
}

/// Parses a Content-Length value: ASCII digits only, at most 10 digits.
fn parse_content_length(value: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(value).ok()?.trim();
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Finds the one `dns=` parameter and decodes it.
fn decode_get(query: &str) -> Result<Vec<u8>, DohError> {
    if query.len() > MAX_QUERY_STRING {
        return Err(DohError::UriTooLong);
    }
    let mut found: Option<&str> = None;
    for (i, pair) in query.split('&').enumerate() {
        if i >= MAX_QUERY_PARAMS {
            return Err(DohError::BadRequest);
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "dns" {
            if found.is_some() {
                // Two `dns=` values: the request is ambiguous.
                return Err(DohError::BadRequest);
            }
            found = Some(value);
        }
    }
    let value = found.ok_or(DohError::BadRequest)?;
    if value.len() > MAX_GET_PARAM {
        return Err(DohError::UriTooLong);
    }
    // Base64url (RFC 4648 section 5). RFC 8484 sends no padding; a padded value is also
    // accepted. A percent-encoded value is not valid base64url, so it gets 400.
    let msg = URL_SAFE_NO_PAD_INDIFFERENT
        .decode(value)
        .map_err(|_| DohError::BadRequest)?;
    if msg.len() < HEADER_LEN {
        return Err(DohError::BadRequest);
    }
    Ok(msg)
}

/// Encodes a DNS message for the `dns=` parameter of a GET request (base64url, no padding).
pub fn encode_get_param(msg: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(msg)
}

/// The `max-age` of a DoH reply (RFC 8484 section 5.1): the lowest TTL of the records in
/// the reply. A reply with no record, or a reply that does not parse, gives 0.
///
/// The reply bytes are the final reply, so a cached answer already has its aged TTLs.
pub fn reply_max_age(reply: &[u8]) -> u32 {
    let Ok(msg) = Message::from_vec(reply) else {
        return 0;
    };
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use proptest::prelude::*;

    fn query_bytes() -> Vec<u8> {
        let mut m = Message::new(0, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        m.to_vec().unwrap()
    }

    fn get(query: &str) -> Result<DohHead, DohError> {
        decode_head("GET", DOH_PATH, Some(query), None, None)
    }

    fn post(ct: Option<&str>, len: Option<&str>) -> Result<DohHead, DohError> {
        decode_head(
            "POST",
            DOH_PATH,
            None,
            ct.map(str::as_bytes),
            len.map(str::as_bytes),
        )
    }

    #[test]
    fn get_decodes_base64url_without_padding() {
        let q = query_bytes();
        let p = encode_get_param(&q);
        assert!(!p.contains('='));
        assert_eq!(get(&format!("dns={p}")).unwrap(), DohHead::Get(q.clone()));
        // Other parameters do not matter.
        assert_eq!(
            get(&format!("ct=x&dns={p}&z")).unwrap(),
            DohHead::Get(q.clone())
        );
        // Padding is accepted too.
        let padded = base64::engine::general_purpose::URL_SAFE.encode(&q);
        assert_eq!(get(&format!("dns={padded}")).unwrap(), DohHead::Get(q));
    }

    #[test]
    fn get_errors() {
        assert_eq!(get(""), Err(DohError::BadRequest));
        assert_eq!(get("other=1"), Err(DohError::BadRequest));
        assert_eq!(get("dns="), Err(DohError::BadRequest));
        assert_eq!(get("dns=!!!!"), Err(DohError::BadRequest));
        // Standard base64 (`+`, `/`) is not base64url.
        assert_eq!(get("dns=AAAA+AAAA/AAAAAAAAAAAA"), Err(DohError::BadRequest));
        // Shorter than a DNS header.
        assert_eq!(
            get(&format!("dns={}", encode_get_param(&[0; 11]))),
            Err(DohError::BadRequest)
        );
        let p = encode_get_param(&query_bytes());
        assert_eq!(get(&format!("dns={p}&dns={p}")), Err(DohError::BadRequest));
        let long = "A".repeat(MAX_GET_PARAM + 4);
        assert_eq!(get(&format!("dns={long}")), Err(DohError::UriTooLong));
        let longer = "x".repeat(MAX_QUERY_STRING + 1);
        assert_eq!(get(&longer), Err(DohError::UriTooLong));
        let many = "a=1&".repeat(MAX_QUERY_PARAMS + 1);
        assert_eq!(get(&format!("{many}dns={p}")), Err(DohError::BadRequest));
    }

    #[test]
    fn path_and_method() {
        assert_eq!(
            decode_head("GET", "/", None, None, None),
            Err(DohError::NotFound)
        );
        assert_eq!(
            decode_head("GET", "/dns-query/", None, None, None),
            Err(DohError::NotFound)
        );
        // The path comes first: a wrong path with a wrong method is 404.
        assert_eq!(
            decode_head("PUT", "/x", None, None, None),
            Err(DohError::NotFound)
        );
        for m in ["PUT", "DELETE", "HEAD", "OPTIONS", "get", "PATCH"] {
            assert_eq!(
                decode_head(m, DOH_PATH, None, None, None),
                Err(DohError::MethodNotAllowed),
                "{m}"
            );
        }
    }

    #[test]
    fn post_content_type() {
        assert_eq!(post(Some(DNS_MESSAGE), None), Ok(DohHead::Post));
        assert_eq!(
            post(Some("Application/DNS-Message; charset=x"), None),
            Ok(DohHead::Post)
        );
        assert_eq!(post(None, None), Err(DohError::UnsupportedMediaType));
        assert_eq!(
            post(Some("application/json"), None),
            Err(DohError::UnsupportedMediaType)
        );
        assert_eq!(
            post(Some("application/dns-message-x"), None),
            Err(DohError::UnsupportedMediaType)
        );
        assert_eq!(
            decode_head("POST", DOH_PATH, None, Some(&[0xff, 0xfe]), None),
            Err(DohError::UnsupportedMediaType)
        );
    }

    #[test]
    fn post_length_limits() {
        assert_eq!(post(Some(DNS_MESSAGE), Some("65535")), Ok(DohHead::Post));
        assert_eq!(
            post(Some(DNS_MESSAGE), Some("65536")),
            Err(DohError::PayloadTooLarge)
        );
        assert_eq!(
            post(Some(DNS_MESSAGE), Some("99999999999")),
            Err(DohError::BadRequest)
        );
        assert_eq!(
            post(Some(DNS_MESSAGE), Some("-1")),
            Err(DohError::BadRequest)
        );
        assert_eq!(post(Some(DNS_MESSAGE), Some("")), Err(DohError::BadRequest));
        assert_eq!(
            decode_body(&vec![0; MAX_BODY]).map(|v| v.len()),
            Ok(MAX_BODY)
        );
        assert_eq!(
            decode_body(&vec![0; MAX_BODY + 1]),
            Err(DohError::PayloadTooLarge)
        );
        assert_eq!(decode_body(&[0; 11]), Err(DohError::BadRequest));
    }

    #[test]
    fn statuses() {
        assert_eq!(DohError::NotFound.status(), 404);
        assert_eq!(DohError::MethodNotAllowed.status(), 405);
        assert_eq!(DohError::UnsupportedMediaType.status(), 415);
        assert_eq!(DohError::BadRequest.status(), 400);
        assert_eq!(DohError::PayloadTooLarge.status(), 413);
        assert_eq!(DohError::UriTooLong.status(), 414);
    }

    #[test]
    fn max_age_is_the_lowest_ttl() {
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("example.com.").unwrap();
        m.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        m.answers
            .push(Record::from_rdata(name, 42, RData::A(A::new(192, 0, 2, 2))));
        assert_eq!(reply_max_age(&m.to_vec().unwrap()), 42);
        m.answers.clear();
        assert_eq!(reply_max_age(&m.to_vec().unwrap()), 0);
        assert_eq!(reply_max_age(&[1, 2, 3]), 0);
    }

    proptest! {
        /// Any message of 12 to 3000 bytes goes through GET and POST unchanged.
        #[test]
        fn round_trip(msg in proptest::collection::vec(any::<u8>(), 12..3000)) {
            let p = encode_get_param(&msg);
            prop_assert_eq!(get(&format!("dns={p}")), Ok(DohHead::Get(msg.clone())));
            let len = msg.len().to_string();
            let parts = DohRequestParts {
                method: "POST",
                path: DOH_PATH,
                query: None,
                content_type: Some(DNS_MESSAGE.as_bytes()),
                content_length: Some(len.as_bytes()),
                body: &msg,
            };
            prop_assert_eq!(decode_request(&parts), Ok(msg.clone()));
        }

        /// Arbitrary input never panics, and an accepted message is a bounded size with a
        /// full DNS header.
        #[test]
        fn arbitrary_input_is_bounded(
            method in "[A-Z]{0,8}",
            path in ".{0,20}",
            query in proptest::option::of(".{0,200}"),
            ct in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..40)),
            len in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..12)),
            body in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            let parts = DohRequestParts {
                method: &method,
                path: &path,
                query: query.as_deref(),
                content_type: ct.as_deref(),
                content_length: len.as_deref(),
                body: &body,
            };
            if let Ok(msg) = decode_request(&parts) {
                prop_assert!(msg.len() >= HEADER_LEN);
                prop_assert!(msg.len() <= MAX_BODY);
            }
        }
    }
}
