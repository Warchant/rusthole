//! API errors (docs/API.md section 2). Every error response has a JSON body with `code`,
//! `message`, `details` and `retry_after_seconds`.

use std::time::Duration;

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;

/// One field error of a 422 response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    /// The field, for example `url` or `cache.max_ttl`.
    pub field: String,
    /// What is wrong.
    pub message: String,
}

/// An API error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status.
    pub status: StatusCode,
    /// The stable code.
    pub code: &'static str,
    /// A sentence for people. It never holds a secret.
    pub message: String,
    /// Field errors (422).
    pub details: Vec<FieldError>,
    /// The wait time (429).
    pub retry_after: Option<Duration>,
}

#[derive(Serialize)]
struct Body<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "<[FieldError]>::is_empty")]
    details: &'a [FieldError],
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    /// An error with a status, a code and a message.
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: Vec::new(),
            retry_after: None,
        }
    }

    /// 400 `bad_request`.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// 401 `unauthorized`.
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Log in first, or send a valid API token.",
        )
    }

    /// 401 `invalid_credentials`.
    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "The password or the code is not correct.",
        )
    }

    /// 403 `forbidden`.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// 403 `csrf_failed`.
    pub fn csrf_failed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "csrf_failed",
            "The X-CSRF-Token header is missing or not valid.",
        )
    }

    /// 404 `not_found`.
    pub fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "The path or the item does not exist.",
        )
    }

    /// 409 `conflict`.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// 409 `config_conflict`.
    pub fn config_conflict() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "config_conflict",
            "The config file changed on disk. rusthole read it again; load the data again and retry.",
        )
    }

    /// 422 `validation_failed` with one field error.
    pub fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::invalid_many(vec![FieldError {
            field: field.into(),
            message: message.into(),
        }])
    }

    /// 422 `validation_failed` with field errors.
    pub fn invalid_many(details: Vec<FieldError>) -> Self {
        Self {
            details,
            ..Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
                "The request has invalid fields.",
            )
        }
    }

    /// 429 `rate_limited`.
    pub fn rate_limited(retry_after: Duration) -> Self {
        Self {
            retry_after: Some(retry_after.max(Duration::from_secs(1))),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many failed attempts. Wait, then try again.",
            )
        }
    }

    /// 500 `internal`. The message never shows internal data; the caller logs the cause.
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "The server has a fault. See the server log.",
        )
    }

    /// 503 `unavailable`.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }

    /// The error for a status with no specific cause (for example a 404 from the router).
    pub fn for_status(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_REQUEST => Self::bad_request("The request is not valid."),
            StatusCode::UNAUTHORIZED => Self::unauthorized(),
            StatusCode::FORBIDDEN => Self::forbidden("The request is not allowed."),
            StatusCode::NOT_FOUND => Self::not_found(),
            StatusCode::METHOD_NOT_ALLOWED => Self::new(
                status,
                "method_not_allowed",
                "The path does not allow this method.",
            ),
            StatusCode::PAYLOAD_TOO_LARGE => Self::new(
                status,
                "payload_too_large",
                "The request body is larger than 64 KiB.",
            ),
            StatusCode::REQUEST_TIMEOUT => {
                Self::new(status, "timeout", "The request took too long.")
            }
            StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                Self::new(status, "bad_request", "Send the body as application/json.")
            }
            StatusCode::MISDIRECTED_REQUEST => misdirected(),
            s if s.is_server_error() => Self::internal(),
            s => Self::new(s, "bad_request", "The request is not valid."),
        }
    }
}

/// 421 `misdirected_request`: the `Host` header is not a name or an address of this server
/// (a DNS rebinding defence).
pub fn misdirected() -> ApiError {
    ApiError::new(
        StatusCode::MISDIRECTED_REQUEST,
        "misdirected_request",
        "The Host header does not name this server.",
    )
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let secs = self.retry_after.map(|d| d.as_secs().max(1));
        let body = Body {
            code: self.code,
            message: &self.message,
            details: &self.details,
            retry_after_seconds: secs,
        };
        let mut resp = (self.status, Json(body)).into_response();
        if let Some(s) = secs
            && let Ok(v) = HeaderValue::from_str(&s.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}

/// The result of a handler.
pub type ApiResult<T> = Result<T, ApiError>;
