use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::{Html, IntoResponse, Redirect, Response},
};
use tera::Context;

use crate::{error::AppResult, state::AppState};

pub async fn root() -> Redirect {
    Redirect::temporary("/overall")
}

pub async fn login_page(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "login.html", Context::new(), true)
}

pub async fn overall(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "overall.html", Context::new(), false)
}

pub async fn vms(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "vms.html", Context::new(), false)
}

pub async fn vm_create(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "vm_create.html", Context::new(), false)
}

pub async fn vm_detail(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "vm_detail.html", Context::new(), false)
}

pub async fn network(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "network.html", Context::new(), false)
}

pub async fn isos(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "isos.html", Context::new(), false)
}

pub async fn settings(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "settings.html", Context::new(), false)
}

pub async fn logs(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "logs.html", Context::new(), false)
}

pub async fn docs(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    render(&state, "docs.html", Context::new(), false)
}

pub fn render(state: &AppState, template: &str, mut context: Context, no_store: bool) -> AppResult<Response> {
    context.insert("asset_version", env!("CARGO_PKG_VERSION"));
    let html = state.templates.render(template, &context)?;
    let mut response = Html(html).into_response();
    if no_store {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        );
    }
    Ok(response)
}
