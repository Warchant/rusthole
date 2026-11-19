//! `GET /report/domain/{name}/{section}`: one section of the domain report (docs/API.md
//! section 17, docs/PLAN.md section 9).

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use rusthole_core::DomainName;
use rusthole_report::{ReportError, Request, Section};
use serde_json::{Value, json};

use super::Params;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::util::rfc3339;

/// The `Retry-After` of a 429 `busy`.
pub(crate) const BUSY_RETRY: Duration = Duration::from_secs(2);

/// `GET /report/domain/{name}/{section}`. Optional query: `refresh=true` skips the cache.
pub(crate) async fn domain(
    State(state): State<AppState>,
    Path((name, section)): Path<(String, String)>,
    p: Params,
) -> ApiResult<Json<Value>> {
    let name = DomainName::parse_idn(name.trim())
        .map_err(|e| ApiError::bad_request(format!("The name is not a valid domain name: {e}.")))?;
    let section = Section::parse(&section).ok_or_else(|| {
        let all: Vec<&str> = Section::ALL.iter().map(|s| s.as_str()).collect();
        ApiError::bad_request(format!("Unknown section. Use one of: {}.", all.join(", ")))
    })?;
    let refresh = match p.get("refresh") {
        None | Some("false" | "0") => false,
        Some("true" | "1") => true,
        Some(_) => return Err(ApiError::bad_request("`refresh` is true or false.")),
    };
    let Some(reporter) = state.deps().report.clone() else {
        return Err(ApiError::unavailable("The domain report is not available."));
    };
    let req = Request {
        refresh,
        external: state.config().report.external,
        now: state.clock().mono(),
        wall: state.clock().wall(),
    };
    let r = reporter
        .report(&name, section, req)
        .await
        .map_err(|e| match e {
            ReportError::Busy => ApiError {
                retry_after: Some(BUSY_RETRY),
                ..ApiError::new(
                    http::StatusCode::TOO_MANY_REQUESTS,
                    "busy",
                    "Too many reports run now. Try again in a few seconds.",
                )
            },
            ReportError::Internal => ApiError::internal(),
        })?;
    Ok(Json(json!({
        "section": r.section.as_str(),
        "name": r.name,
        "status": r.outcome.status.as_str(),
        "cached": r.cached,
        "fetched_at": rfc3339(r.fetched_at),
        "data": r.outcome.data,
        "error": r.outcome.error,
    })))
}
