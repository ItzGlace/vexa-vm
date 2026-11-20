//! Explicitly scoped, audited support operations used by the panel and MCP bridge.
use super::auth::AuthContext;
use crate::{
    error::{AppError, AppResult},
    hypervisor::RecoveryRequest,
    models::{NewAuditEvent, Vm},
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

fn vm(state: &AppState, id: &str) -> AppResult<Vm> {
    state
        .db
        .get_vm(id)?
        .ok_or_else(|| AppError::NotFound("VM".into()))
}
fn record(
    state: &AppState,
    auth: &AuthContext,
    vm: &Vm,
    action: &str,
    success: bool,
    details: serde_json::Value,
) -> AppResult<()> {
    state.db.append_audit(&NewAuditEvent {
        actor_type: auth.actor_type.into(),
        actor_id: Some(auth.actor_id.clone()),
        action: action.into(),
        resource_type: "vm".into(),
        resource_id: Some(vm.id.clone()),
        request_id: auth.request_id.clone(),
        source_ip: auth.source_ip.clone(),
        user_agent: auth.user_agent.clone(),
        success,
        details,
    })?;
    Ok(())
}
fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}
pub async fn recover_password(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<RecoveryRequest>,
) -> AppResult<Response> {
    auth.require("vms:recovery")?;
    let vm = vm(&state, &id)?;
    recover(state, auth, vm, input).await
}
pub(crate) async fn recover(
    state: Arc<AppState>,
    auth: AuthContext,
    vm: Vm,
    input: RecoveryRequest,
) -> AppResult<Response> {
    // Detach the owned operation from HTTP cancellation. The lifecycle lock and child
    // processes stay owned until completion, even if a client closes its connection.
    tokio::spawn(async move { recover_inner(&state, &auth, &vm, input).await })
        .await
        .map_err(|_| {
            AppError::Internal("recovery task failed; inspect audit and backup before retrying".into())
        })?
}
async fn recover_inner(
    state: &AppState,
    auth: &AuthContext,
    vm: &Vm,
    input: RecoveryRequest,
) -> AppResult<Response> {
    if input.confirmation != vm.name || !input.backup_confirmed {
        return Err(AppError::Validation(
            "type the VM name and acknowledge a tested disk backup".into(),
        ));
    }
    crate::hypervisor::libvirt::validate_recovery(&input)?;
    state
        .rate_limiter
        .check("offline-recovery", &vm.id, 2, 300, chrono::Utc::now().timestamp())?;
    // An accepted request is durable before any disk mutation. Never include passwords/hashes.
    record(
        state,
        auth,
        vm,
        "vm.recovery.request",
        true,
        json!({"method":input.method,"username":input.username}),
    )?;
    let result = state.hypervisor.recover_password(&vm.name, &input).await;
    record(
        state,
        auth,
        vm,
        "vm.recovery.complete",
        result.is_ok(),
        json!({"method":input.method,"username":input.username}),
    )?;
    result?;
    if input.username == vm.root_username {
        if let Some(password) = &input.password {
            state.db.set_vm_password(&vm.id, password, &state.security)?;
        } else {
            state.db.clear_vm_password(&vm.id)?;
        }
    }
    Ok(no_store(Json(json!({"applied":true,"method":input.method,"username":input.username,
        "restart_required":true,"password_cleared":input.method == "windows-sam",
        "message": "Disk changed. Boot and verify through the console. Windows: set a new local password immediately."})).into_response()))
}
pub async fn screenshot(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:console:read")?;
    let vm = vm(&state, &id)?;
    state.rate_limiter.check(
        "console-screenshot",
        &auth.actor_id,
        30,
        60,
        chrono::Utc::now().timestamp(),
    )?;
    record(&state, &auth, &vm, "vm.console.screenshot", true, json!({}))?;
    let bytes = state.hypervisor.console_screenshot(&vm.name).await?;
    let mime = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(b"P6") {
        "image/x-portable-pixmap"
    } else {
        return Err(AppError::Hypervisor("unsupported screenshot format".into()));
    };
    Ok(no_store(([(header::CONTENT_TYPE, mime)], bytes).into_response()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBody {
    pub keys: Vec<String>,
    pub confirmation: String,
}
pub async fn keys(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<KeysBody>,
) -> AppResult<Response> {
    auth.require("vms:console:write")?;
    let vm = vm(&state, &id)?;
    if input.confirmation != vm.name {
        return Err(AppError::Validation("confirmation must match VM name".into()));
    }
    state.rate_limiter.check(
        "console-input",
        &auth.actor_id,
        60,
        60,
        chrono::Utc::now().timestamp(),
    )?;
    record(
        &state,
        &auth,
        &vm,
        "vm.console.keys.request",
        true,
        json!({"key_count":input.keys.len()}),
    )?;
    let result = state.hypervisor.console_keys(&vm.name, &input.keys).await;
    record(
        &state,
        &auth,
        &vm,
        "vm.console.keys.complete",
        result.is_ok(),
        json!({"key_count":input.keys.len()}),
    )?;
    result?;
    Ok(no_store(Json(json!({"sent":true})).into_response()))
}
