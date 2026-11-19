//! Admin REST API, auth and embedded UI of rusthole (part P5). See docs/API.md and
//! docs/SECURITY.md.
//!
//! - [`server`]: the HTTPS listener (TLS, limits, ACL, shutdown).
//! - [`router`]: the route table and the middleware (Host check, security headers, auth).
//! - [`auth`]: sessions, API tokens, CSRF and the login ban.
//! - [`config_edit`]: safe writes of `rusthole.toml`.
//! - [`model`] and [`settings`]: the JSON model and its mapping to the config.
//! - [`assets`]: the embedded UI.

pub mod assets;
pub mod auth;
pub mod clock;
pub mod config_edit;
pub mod error;
pub mod fuzzing;
pub mod host;
pub mod model;
pub mod password;
pub mod redirect;
pub mod router;
pub(crate) mod routes;
pub mod server;
pub mod settings;
pub mod state;
pub mod totp;
pub mod util;

pub use server::{AdminServer, AdminSettings, listen_addrs, start};
pub use state::{AdminDeps, AppState, LiveApply, NoLiveApply, SystemStatic};
