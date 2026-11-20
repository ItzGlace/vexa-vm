//! Authenticated onboarding for the local MCP bridge; this is not a remote MCP listener.
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;

use super::auth::AuthContext;
use crate::{error::AppResult, state::AppState};

fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn setup(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("settings:read")?;
    // An origin cannot expose URL credentials, paths, queries, or fragments from configuration.
    let origin = url::Url::parse(&state.config.public_url)
        .ok()
        .map(|url| url.origin().ascii_serialization());
    Ok(private(
        Json(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "transport": "stdio",
            "api_origin": origin,
            "client_download": "/api/v1/mcp/client",
            "documentation": "/api/v1/mcp/documentation",
            "can_create_key": auth.allows("api_keys:write"),
        }))
        .into_response(),
    ))
}

pub async fn client(Extension(auth): Extension<AuthContext>) -> AppResult<Response> {
    auth.require("settings:read")?;
    Ok(private(
        (
            [
                (header::CONTENT_TYPE, "text/x-python; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"vexa_mcp.py\"",
                ),
            ],
            include_str!("../../docs/mcp/vexa_mcp.py"),
        )
            .into_response(),
    ))
}

pub async fn documentation(Extension(auth): Extension<AuthContext>) -> AppResult<Response> {
    auth.require("settings:read")?;
    Ok(private(
        (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            include_str!("../../docs/MCP.md"),
        )
            .into_response(),
    ))
}
