//! Embedded frontend static assets + SPA fallback.
//!
//! The React console is built to `web/dist` and compiled directly into the
//! binary via `rust-embed`, so the whole admin panel ships as one executable.
//!
//! Build the frontend first (`cd web && npm install && npm run build`) so
//! `web/dist` contains the real bundle; a placeholder `index.html` is committed
//! so the crate always compiles even before the first frontend build.

use axum::{
    http::{header, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../../web/dist"]
struct Assets;

/// Catch-all handler for any path not claimed by the API.
///
/// Serves the matching embedded file when one exists, otherwise falls back to
/// `index.html` so client-side (React Router) deep links resolve. Only GET/HEAD
/// are served — other methods on unmatched paths get a 404 rather than the SPA,
/// so the API surface doesn't masquerade HTML as a success for, say, POST.
pub async fn static_handler(method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match serve(path) {
        Some(resp) => resp,
        // SPA fallback: unknown non-asset path -> index.html
        None => match serve("index.html") {
            Some(resp) => resp,
            None => (
                StatusCode::NOT_FOUND,
                "FluxGate console assets not found. Run `cd web && npm run build`.",
            )
                .into_response(),
        },
    }
}

fn serve(path: &str) -> Option<Response> {
    let file = Assets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();

    // Hashed asset bundles can be cached aggressively; HTML should not be.
    let cache_control = if path == "index.html" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };

    Some(
        (
            [
                (header::CONTENT_TYPE, mime.as_ref()),
                (header::CACHE_CONTROL, cache_control),
            ],
            file.data.into_owned(),
        )
            .into_response(),
    )
}
