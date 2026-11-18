//! The embedded web UI (decision D14).
//!
//! `build.rs` picks the folder: `web/dist` when `web/dist/index.html` exists, else the
//! placeholder page in `crates/rusthole-web/placeholder`. `cargo build` never runs bun.
//!
//! Cache rules: files under `/assets/` have a content hash in the name (Vite), so they get
//! `Cache-Control: public, max-age=31536000, immutable`. `index.html` and other files get
//! `no-cache`. A path that is not a file and has no file extension gets `index.html` (the
//! UI routes in the browser); a missing file with an extension gets 404.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, Method, StatusCode, header};
use rust_embed::RustEmbed;

use crate::state::AppState;

/// The UI files that the build chose.
#[derive(RustEmbed)]
#[folder = "$RUSTHOLE_WEB_DIST"]
struct Dist;

/// The placeholder page (always embedded, for tests and for the fallback).
#[derive(RustEmbed)]
#[folder = "$RUSTHOLE_WEB_PLACEHOLDER"]
struct Placeholder;

/// True when this binary embeds the built UI (not the placeholder).
pub const HAS_BUILT_UI: bool = matches!(env!("RUSTHOLE_WEB_FROM_DIST").as_bytes(), b"1");

/// One file.
#[derive(Debug, Clone)]
pub struct Asset {
    /// The bytes.
    pub data: Cow<'static, [u8]>,
    /// The MIME type.
    pub mime: String,
}

/// A source of UI files.
pub trait AssetSource: Send + Sync + fmt::Debug {
    /// The file at `path` (no leading `/`), if any.
    fn get(&self, path: &str) -> Option<Asset>;
}

fn mime_of(path: &str) -> String {
    let m = mime_guess::from_path(path).first_or_octet_stream();
    let text = m.essence_str().to_owned();
    if text.starts_with("text/") || text == "application/javascript" || text == "image/svg+xml" {
        format!("{text}; charset=utf-8")
    } else {
        text
    }
}

/// The files that the build embedded.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmbeddedAssets;

impl AssetSource for EmbeddedAssets {
    fn get(&self, path: &str) -> Option<Asset> {
        Dist::get(path).map(|f| Asset {
            data: f.data,
            mime: mime_of(path),
        })
    }
}

/// The placeholder page only.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlaceholderAssets;

impl AssetSource for PlaceholderAssets {
    fn get(&self, path: &str) -> Option<Asset> {
        Placeholder::get(path).map(|f| Asset {
            data: f.data,
            mime: mime_of(path),
        })
    }
}

/// Files in memory (tests).
#[derive(Debug, Clone, Default)]
pub struct MemoryAssets(pub HashMap<String, Vec<u8>>);

impl AssetSource for MemoryAssets {
    fn get(&self, path: &str) -> Option<Asset> {
        self.0.get(path).map(|d| Asset {
            data: Cow::Owned(d.clone()),
            mime: mime_of(path),
        })
    }
}

fn respond(asset: Asset, cache: &'static str, head: bool) -> Response {
    let mut resp = if head {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(asset.data))
    };
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&asset.mime) {
        h.insert(header::CONTENT_TYPE, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    resp
}

/// The handler for all paths outside `/api/`.
pub(crate) async fn serve(State(state): State<AppState>, req: Request) -> Response {
    let head = req.method() == Method::HEAD;
    if !head && req.method() != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = req.uri().path().trim_start_matches('/');
    let src = &state.deps().assets;
    if path.contains("..") || path.contains('\\') {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !path.is_empty()
        && path != "index.html"
        && let Some(a) = src.get(path)
    {
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return respond(a, cache, head);
    }
    let last = path.rsplit('/').next().unwrap_or_default();
    if !path.is_empty() && path != "index.html" && last.contains('.') {
        return StatusCode::NOT_FOUND.into_response();
    }
    match src.get("index.html") {
        Some(a) => respond(a, "no-cache", head),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_embedded() {
        let p = PlaceholderAssets.get("index.html").unwrap();
        let text = String::from_utf8_lossy(&p.data);
        assert!(text.contains("bun run build"), "{text}");
        assert!(!text.contains("<script"), "no inline script");
        assert_eq!(p.mime, "text/html; charset=utf-8");
        // The build embeds the placeholder when web/dist is missing.
        let main = EmbeddedAssets.get("index.html").unwrap();
        if !HAS_BUILT_UI {
            assert_eq!(main.data, p.data);
        }
    }

    #[test]
    fn mime_types() {
        assert_eq!(mime_of("a.js"), "text/javascript; charset=utf-8");
        assert_eq!(mime_of("a.css"), "text/css; charset=utf-8");
        assert_eq!(mime_of("a.svg"), "image/svg+xml; charset=utf-8");
        assert_eq!(mime_of("a.woff2"), "font/woff2");
    }
}
