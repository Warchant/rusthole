//! The domain report of rusthole (docs/PLAN.md section 9, docs/API.md section 17).
//!
//! The admin UI asks for each section of the report with its own request. Each section has
//! its own time limit and its own state (`ok`, `failed`, `off`, `unavailable`), so one slow
//! or failed source does not block the others. All lookups run on the server. Host names go
//! through the upstream pool of rusthole, never the system resolver.
//!
//! Pure parts: [`cache`] (time to live and bound), [`guard`] (public addresses only), the
//! value parsers of [`dns`]. The I/O shell: [`service::Reporter`] and the section runs.

pub mod cache;
pub mod dns;
pub mod fuzzing;
pub mod guard;
pub mod http;
pub mod model;
pub mod rdap;
pub mod service;
pub mod tls;

pub use model::{Outcome, Section, SectionReport, Status};
pub use service::{ReportError, Reporter, Request, Sources};
