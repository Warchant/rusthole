//! The API handlers. Each module serves one part of docs/API.md.

pub(crate) mod auth;
pub(crate) mod items;
pub(crate) mod misc;
pub(crate) mod report;
pub(crate) mod stats;

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use http::header;
use http::request::Parts;
use rusthole_store::NewAudit;
use serde::de::DeserializeOwned;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::router::MAX_BODY;
use crate::state::AppState;

/// A JSON request body: 415 with no `Content-Type: application/json` (m12: a page of another
/// site can send other types with no preflight), 400 for bad JSON, 422 for an unknown,
/// read-only or wrong field, 413 for a body over 64 KiB.
pub(crate) struct ApiJson<T>(pub(crate) T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let ct_ok = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(is_json_type);
        let bytes = Bytes::from_request(req, state).await.map_err(|e| {
            if e.status() == http::StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::for_status(http::StatusCode::PAYLOAD_TOO_LARGE)
            } else {
                ApiError::bad_request("The request body cannot be read.")
            }
        })?;
        if bytes.len() > MAX_BODY {
            return Err(ApiError::for_status(http::StatusCode::PAYLOAD_TOO_LARGE));
        }
        if !ct_ok {
            return Err(ApiError::for_status(
                http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ));
        }
        parse_json(&bytes).map(ApiJson)
    }
}

/// True for the media type `application/json`, with or without parameters (any case).
pub(crate) fn is_json_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

/// Parses a JSON body like [`ApiJson`].
pub(crate) fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|e| {
        use serde_json::error::Category;
        match e.classify() {
            Category::Data => {
                let msg: String = e.to_string().chars().take(200).collect();
                ApiError::invalid("body", msg)
            }
            Category::Syntax | Category::Eof | Category::Io => {
                ApiError::bad_request("The body is not valid JSON.")
            }
        }
    })
}

/// The query parameters. 400 for a bad query string.
pub(crate) struct Params(pub(crate) HashMap<String, String>);

impl<S: Send + Sync> FromRequestParts<S> for Params {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let q = parts.uri.query().unwrap_or_default();
        let result = if q.len() > 4096 {
            Err(ApiError::bad_request("The query string is too long."))
        } else {
            Ok(Params(form_pairs(q).into_iter().collect()))
        };
        std::future::ready(result)
    }
}

/// Splits `a=1&b=x%20y` into decoded pairs.
fn form_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok());
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Params {
    pub(crate) fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }

    /// An integer parameter in `lo..=hi`, or the default. 400 when it is bad.
    pub(crate) fn int(&self, k: &str, default: i64, lo: i64, hi: i64) -> Result<i64, ApiError> {
        match self.get(k) {
            None => Ok(default),
            Some(v) => v
                .parse::<i64>()
                .ok()
                .filter(|n| (lo..=hi).contains(n))
                .ok_or_else(|| {
                    ApiError::bad_request(format!("`{k}` must be an integer from {lo} to {hi}."))
                }),
        }
    }

    /// A boolean parameter (`true` or `false`).
    pub(crate) fn flag(&self, k: &str) -> Result<bool, ApiError> {
        match self.get(k) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            Some(_) => Err(ApiError::bad_request(format!(
                "`{k}` must be true or false."
            ))),
        }
    }
}

/// The request facts that handlers need: who sent it, and from where.
pub(crate) struct Caller {
    pub(crate) principal: Option<Principal>,
    pub(crate) ip: IpAddr,
}

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self {
            principal: parts.extensions.get::<Principal>().cloned(),
            ip: crate::auth::client_ip(&parts.extensions),
        }))
    }
}

impl Caller {
    pub(crate) fn actor(&self) -> String {
        self.principal
            .as_ref()
            .map_or_else(|| "anonymous".to_owned(), Principal::actor)
    }
}

/// A path id: 404 when it is not a number.
pub(crate) fn path_id(text: &str) -> Result<u32, ApiError> {
    text.parse::<u32>().map_err(|_| ApiError::not_found())
}

/// Writes an audit line for a request.
pub(crate) async fn audit(
    state: &AppState,
    caller: &Caller,
    action: &str,
    target: Option<String>,
    ok: bool,
    detail: Option<String>,
) {
    state
        .audit(NewAudit {
            at: state.clock().wall(),
            action: action.to_owned(),
            target,
            actor: caller.actor(),
            client_ip: Some(caller.ip),
            ok,
            detail,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_decoding() {
        let p = form_pairs("a=1&b=x%20y&c=a+b&d&e=%zz&k=02%3A00");
        assert_eq!(
            p,
            [
                ("a".into(), "1".into()),
                ("b".into(), "x y".into()),
                ("c".into(), "a b".into()),
                ("d".into(), String::new()),
                ("e".into(), "%zz".into()),
                ("k".into(), "02:00".into()),
            ]
        );
    }

    #[test]
    fn json_media_type() {
        for v in [
            "application/json",
            "Application/JSON",
            "application/json; charset=utf-8",
            " application/json ;x=y",
        ] {
            assert!(is_json_type(v), "{v}");
        }
        for v in [
            "",
            "text/plain",
            "application/jsonx",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/json-seq",
        ] {
            assert!(!is_json_type(v), "{v}");
        }
    }

    #[test]
    fn json_errors() {
        #[derive(serde::Deserialize, Debug)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct T {
            a: u32,
        }
        assert_eq!(parse_json::<T>(b"{").unwrap_err().code, "bad_request");
        assert_eq!(
            parse_json::<T>(b"{\"a\":1,\"b\":2}").unwrap_err().code,
            "validation_failed"
        );
        assert_eq!(
            parse_json::<T>(b"{\"a\":\"x\"}").unwrap_err().code,
            "validation_failed"
        );
        assert!(parse_json::<T>(b"{\"a\":1}").is_ok());
    }
}
