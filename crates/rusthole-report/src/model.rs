//! The data of a report: sections, states and one section result.

use std::time::Duration;

use serde_json::Value;

/// One part of the report. Each section has its own time limit and its own result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    /// DNS records through the upstream pool.
    Dns,
    /// Registration data from the RDAP server of the registry.
    Rdap,
    /// The TLS certificate of the name on port 443.
    Tls,
}

impl Section {
    /// All sections, in the order of the UI.
    pub const ALL: [Self; 3] = [Self::Dns, Self::Rdap, Self::Tls];

    /// The section with the API name `s`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// The API name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Rdap => "rdap",
            Self::Tls => "tls",
        }
    }

    /// The time limit of the section (docs/PLAN.md R-D4).
    pub const fn limit(self) -> Duration {
        match self {
            Self::Dns => Duration::from_secs(5),
            Self::Rdap => Duration::from_secs(10),
            Self::Tls => Duration::from_secs(8),
        }
    }

    /// True when the section sends the name to a third party. The setting
    /// `report.external = false` turns such a section off.
    pub const fn external(self) -> bool {
        match self {
            Self::Dns => false,
            Self::Rdap | Self::Tls => true,
        }
    }
}

/// The state of a section result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The section has data.
    Ok,
    /// The sources did not answer, or the answer was not usable. `error` tells why.
    Failed,
    /// The setting `report.external` is off. Nothing was sent.
    Off,
    /// The section does not apply to this name (for example a private address).
    Unavailable,
}

impl Status {
    /// The API name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Off => "off",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What a section run gives: the state, the data and the reason of a failure.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The state.
    pub status: Status,
    /// The data of the section (a JSON object), or `null`.
    pub data: Value,
    /// A short reason for `failed` and `unavailable`.
    pub error: Option<String>,
}

impl Outcome {
    /// A failure with a reason and no data.
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            status: Status::Failed,
            data: Value::Null,
            error: Some(reason.into()),
        }
    }
}

/// The result of one section for one name.
#[derive(Debug, Clone, PartialEq)]
pub struct SectionReport {
    /// The section.
    pub section: Section,
    /// The name (lower case, IDN as punycode).
    pub name: String,
    /// The result.
    pub outcome: Outcome,
    /// True when the result came from the cache.
    pub cached: bool,
    /// The wall clock time of the lookup, Unix seconds.
    pub fetched_at: i64,
}
