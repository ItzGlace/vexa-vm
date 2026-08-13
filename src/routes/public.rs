use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tera::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use vexa_guest_protocol::Command as GuestCommand;

use crate::{
    error::{AppError, AppResult},
    hypervisor::{PowerAction, ReinstallVmRequest},
    models::{
        CustomerTokenRecord, FirewallAction, FirewallDirection, FirewallProtocol, NewAuditEvent,
        NewJob, NewVmFirewallRule, Vm, VmFirewallRule, VmFirewallRulePatch,
        VmNetworkSecurityPatch, VmState,
    },
    security::{hash_token, verify_token, vm_password_context},
    state::AppState,
};

use super::{
    api::{
        cleanup_uncommitted_guest_tools_stage, idempotency_key, iso_is_ready,
        normalize_ssh_keys, reinstall_request_fingerprint, stage_reinstall_guest_tools,
        validate_guest_password, vm_image_from_iso, DnsBody, SecretBody,
    },
    auth::{append_cookie, client_ip, cookie, cookie_value},
    pages,
};

const STATUS_COOKIE: &str = "vexa_status";
const STATUS_CSRF_COOKIE: &str = "vexa_status_csrf";
const VNC_COOKIE: &str = "vexa_vnc";
const PUBLIC_SESSION_SECONDS: i64 = 600;

#[derive(Deserialize)]
pub struct PublicActionBody {
    #[serde(default)]
    pub image_id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct ExchangeBody {
    pub token: String,
}

#[derive(Deserialize)]
pub struct PublicSshKeysBody {
    #[serde(default)]
    pub ssh_keys: Vec<String>,
}

pub async fn exchange_session_api(
    State(state): State<Arc<AppState>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(input): Json<ExchangeBody>,
) -> AppResult<Response> {
    let now = Utc::now().timestamp();
    let source_ip = client_ip(&headers, connect.as_ref());
    state.rate_limiter.check(
        "public-token-exchange",
        source_ip.as_deref().unwrap_or("unknown"),
        30,
        60,
        now,
    )?;
    if input.token.starts_with("vxc_") {
        let session = state.security.issue_customer_session_token();
        let csrf = state.security.issue_csrf_token();
        let record = state
            .db
            .exchange_customer_link(
                &hash_token(&input.token),
                session.hash(),
                source_ip.as_deref(),
                now,
                PUBLIC_SESSION_SECONDS as u64,
            )?
            .ok_or_else(|| AppError::NotFound("status link".into()))?;
        public_exchange_audit(
            &state,
            "customer_token",
            Some(&record.id),
            "status_link.exchange",
            &record.vm_id,
            &headers,
            source_ip.as_deref(),
        );
        let max_age = record
            .session_expires_at
            .unwrap_or(now)
            .saturating_sub(now)
            .clamp(0, PUBLIC_SESSION_SECONDS);
        let mut response = Json(json!({
            "kind": "status",
            "redirect": "/status/session",
            "expires_at": record.session_expires_at,
        }))
        .into_response();
        append_cookie(
            response.headers_mut(),
            &cookie_value(
                STATUS_COOKIE,
                session.expose(),
                max_age,
                true,
                state.config.secure_cookies,
            ),
        )?;
        append_cookie(
            response.headers_mut(),
            &cookie_value(
                STATUS_CSRF_COOKIE,
                csrf.expose(),
                max_age,
                false,
                state.config.secure_cookies,
            ),
        )?;
        no_store(response.headers_mut());
        return Ok(response);
    }
    if input.token.starts_with("vxv_") {
        ensure_vnc_enabled(&state)?;
        let session = state.security.issue_vnc_session_token();
        let record = state
            .db
            .exchange_vnc_link(
                &hash_token(&input.token),
                session.hash(),
                source_ip.as_deref(),
                now,
            )?
            .ok_or_else(|| AppError::NotFound("VNC link".into()))?;
        public_exchange_audit(
            &state,
            "vnc_token",
            Some(&record.id),
            "vnc_link.exchange",
            &record.vm_id,
            &headers,
            source_ip.as_deref(),
        );
        let vm = required_vm(&state, &record.vm_id)?;
        let max_age = record
            .expires_at
            .saturating_sub(now)
            .clamp(0, PUBLIC_SESSION_SECONDS);
        let mut response = Json(json!({
            "kind": "vnc",
            "vm_name": vm.name,
            "websocket_url": "/ws/vnc",
            "expires_at": record.session_expires_at,
        }))
        .into_response();
        append_cookie(
            response.headers_mut(),
            &cookie_value(
                VNC_COOKIE,
                session.expose(),
                max_age,
                true,
                state.config.secure_cookies,
            ),
        )?;
        no_store(response.headers_mut());
        return Ok(response);
    }
    Err(AppError::NotFound("public link".into()))
}

pub async fn logout_session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> AppResult<Response> {
    let now = Utc::now().timestamp();
    if let Some(token) = cookie(&headers, STATUS_COOKIE) {
        let _ = state.db.revoke_customer_session(&hash_token(token), now)?;
    }
    if let Some(token) = cookie(&headers, VNC_COOKIE) {
        let _ = state.db.revoke_vnc_session(&hash_token(token), now)?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    for (name, http_only) in [
        (STATUS_COOKIE, true),
        (STATUS_CSRF_COOKIE, false),
        (VNC_COOKIE, true),
    ] {
        append_cookie(
            response.headers_mut(),
            &cookie_value(name, "", 0, http_only, state.config.secure_cookies),
        )?;
    }
    no_store(response.headers_mut());
    Ok(response)
}

pub async fn exchange_status_link(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let session = state.security.issue_customer_session_token();
    let csrf = state.security.issue_csrf_token();
    let now = Utc::now().timestamp();
    let source_ip = client_ip(&headers, connect.as_ref());
    state.rate_limiter.check(
        "public-status-exchange",
        source_ip.as_deref().unwrap_or("unknown"),
        30,
        60,
        now,
    )?;
    let record = state
        .db
        .exchange_customer_link(
            &hash_token(&token),
            session.hash(),
            source_ip.as_deref(),
            now,
            PUBLIC_SESSION_SECONDS as u64,
        )?
        .ok_or_else(|| AppError::NotFound("status link".into()))?;
    public_exchange_audit(
        &state,
        "customer_token",
        Some(&record.id),
        "status_link.exchange",
        &record.vm_id,
        &headers,
        source_ip.as_deref(),
    );
    let max_age = record
        .session_expires_at
        .unwrap_or(now)
        .saturating_sub(now)
        .clamp(0, PUBLIC_SESSION_SECONDS);
    let mut response = Redirect::to("/status/session").into_response();
    append_cookie(
        response.headers_mut(),
        &cookie_value(
            STATUS_COOKIE,
            session.expose(),
            max_age,
            true,
            state.config.secure_cookies,
        ),
    )?;
    append_cookie(
        response.headers_mut(),
        &cookie_value(
            STATUS_CSRF_COOKIE,
            csrf.expose(),
            max_age,
            false,
            state.config.secure_cookies,
        ),
    )?;
    no_store(response.headers_mut());
    Ok(response)
}

pub async fn status_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let _ = customer_session(&state, &headers, connect.as_ref())?;
    pages::render(&state, "status.html", Context::new(), true)
}

pub async fn public_vm(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "vm:read")?;
    let vm = required_vm(&state, &token.vm_id)?;
    let addresses = state.db.vm_ip_addresses(&vm.id)?;
    let dns = state.db.dns_servers(None, Some(&vm.id))?;
    let mut metrics = state
        .db
        .vm_metrics(&vm.id, Utc::now().timestamp() - 24 * 60 * 60, 1)?;
    metrics.reverse();
    let operations = state
        .db
        .list_jobs(None, Some(&vm.id), 20)?
        .iter()
        .map(public_job_value)
        .collect::<Vec<_>>();
    let traffic_quota = crate::services::traffic::quota_status(&state, &vm)?;
    Ok(Json(json!({
        "vm": {
            "id": vm.id,
            "name": vm.name,
            "hostname": vm.hostname,
            "state": vm.state,
            "os_family": vm.os_family,
            "vcpus": vm.vcpus,
            "ram_mb": vm.memory_mib,
            "disk_gb": vm.disk_gib,
            "network_limit_mbps": vm.network_limit_mbps,
            "traffic_limit_bytes": vm.traffic_limit_bytes,
            "traffic_used_bytes": vm.traffic_used_bytes,
            "traffic_quota": traffic_quota,
            "root_username": vm.root_username,
            "guest_agent": vm.guest_agent,
            "guest_tools": crate::services::guest_tools::public_status_for_vm(
                &vm,
                state.db.vm_guest_tools(&vm.id)?,
            ),
            "maintenance": vm.metadata.get("maintenance").cloned().unwrap_or_else(|| json!({ "enabled": false })),
            "addresses": addresses,
            "dns_servers": dns,
            "metrics": metrics.last(),
            "metric_samples": metrics,
            "operations": operations,
            "allowed_actions": token.scopes,
            "session_expires_at": token.session_expires_at,
        }
    }))
    .into_response())
}

pub async fn public_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "metrics:read")?;
    let mut items = state
        .db
        .vm_metrics(&token.vm_id, Utc::now().timestamp() - 24 * 60 * 60, 360)?;
    items.reverse();
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn public_dns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "vm:read")?;
    Ok(Json(json!({
        "items": state.db.dns_servers(None, Some(&token.vm_id))?
    }))
    .into_response())
}

pub async fn public_isos(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "reinstall:write")?;
    let items = state
        .db
        .list_isos(false)?
        .iter()
        .map(|image| public_iso_value(&state.config, image))
        .collect::<Vec<_>>();
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn public_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = customer_session(&state, &headers, connect.as_ref())?;
    let job = state
        .db
        .get_job(&id)?
        .filter(|job| job.vm_id.as_deref() == Some(token.vm_id.as_str()))
        .ok_or_else(|| AppError::NotFound("job".into()))?;
    Ok(Json(json!({ "operation": public_job_value(&job) })).into_response())
}

pub async fn public_power_action(
    State(state): State<Arc<AppState>>,
    Path(action): Path<String>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "power:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    let action = parse_public_power(&action)?;
    let job = state.db.enqueue_job(&NewJob {
        kind: "vm.power".into(),
        vm_id: Some(vm.id.clone()),
        payload: json!({ "action": action }),
        idempotency_key: None,
        run_after: None,
        max_attempts: 1,
        actor_type: Some("customer_token".into()),
        actor_id: Some(token.id.clone()),
    })?;
    public_audit(&state, &token, "vm.power", &vm, json!({ "job_id": job.id }));
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "operation": public_job_value(&job) })),
    )
        .into_response())
}

pub async fn public_update_dns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<DnsBody>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "dns:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    let items = state
        .db
        .replace_dns_servers(None, Some(&token.vm_id), &input.dns_servers)?;
    let servers = items
        .iter()
        .map(|item| item.address.parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal("stored VM DNS address is invalid".into()))?;
    let applied = if servers.is_empty() {
        crate::services::guest_tools::GuestApplyResult {
            applied: false,
            pending: true,
            mechanism: "provisioning",
            status: "pending".into(),
            message: "An empty DNS list will apply on the next reinstall".into(),
        }
    } else {
        crate::services::guest_tools::try_apply(
            &state,
            &vm,
            GuestCommand::SetDns {
                interface: None,
                servers,
            },
        )
        .await
    };
    public_audit(
        &state,
        &token,
        "vm.dns.update",
        &vm,
        json!({ "count": items.len(), "guest_tools": &applied }),
    );
    Ok(Json(json!({
        "items": items,
        "guest_agent_applied": applied.applied,
        "guest_tools": applied,
    }))
    .into_response())
}

pub async fn public_reveal_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "password:read")?;
    let vm = required_vm(&state, &token.vm_id)?;
    let password = state
        .db
        .decrypt_vm_password(&vm.id, &state.security)?
        .ok_or_else(|| AppError::NotFound("VM password".into()))?;
    public_audit(&state, &token, "vm.password.reveal", &vm, json!({}));
    let mut response = Json(json!({ "password": password, "hide_after_seconds": 30 })).into_response();
    no_store(response.headers_mut());
    Ok(response)
}

pub async fn public_update_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<SecretBody>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "password:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    validate_guest_password(&vm.root_username, &input.password)?;
    let routeros = crate::services::guest_tools::is_routeros_vm(&vm);
    if !routeros {
        state
            .db
            .set_vm_password(&vm.id, &input.password, &state.security)?;
    }
    let applied = crate::services::guest_tools::try_apply(
        &state,
        &vm,
        GuestCommand::SetPassword {
            username: vm.root_username.clone(),
            password: input.password.clone(),
        },
    )
    .await;
    if routeros && applied.applied {
        state
            .db
            .set_vm_password(&vm.id, &input.password, &state.security)?;
    }
    let updated = !routeros || applied.applied;
    public_audit(
        &state,
        &token,
        "vm.password.update",
        &vm,
        json!({ "guest_tools": &applied }),
    );
    Ok(Json(json!({
        "updated": updated,
        "guest_agent_applied": applied.applied,
        "guest_tools": applied,
    }))
    .into_response())
}

pub async fn public_update_ssh_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<PublicSshKeysBody>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "ssh:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    let keys = normalize_ssh_keys(input.ssh_keys)?;
    let mut metadata = vm.metadata.clone();
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("VM metadata is not an object".into()))?;
    object.insert("ssh_keys".into(), json!(keys));
    state.db.patch_vm(
        &vm.id,
        &crate::models::VmPatch {
            metadata: Some(metadata),
            ..crate::models::VmPatch::default()
        },
    )?;
    let applied = crate::services::guest_tools::try_apply(
        &state,
        &vm,
        GuestCommand::SetSshKeys {
            username: vm.root_username.clone(),
            authorized_keys: keys.clone(),
        },
    )
    .await;
    public_audit(
        &state,
        &token,
        "vm.ssh_keys.update",
        &vm,
        json!({ "count": keys.len(), "guest_tools": &applied }),
    );
    Ok(Json(json!({
        "updated": true,
        "count": keys.len(),
        "guest_agent_applied": applied.applied,
        "applies_on_reinstall": applied.pending,
        "guest_tools": applied,
    }))
    .into_response())
}

pub async fn public_reinstall(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<PublicActionBody>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "reinstall:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    let image_id = input
        .image_id
        .as_deref()
        .ok_or_else(|| AppError::Validation("image_id is required".into()))?;
    let idempotency_key = idempotency_key(&headers)?;
    let request_fingerprint = reinstall_request_fingerprint(
        &vm.id,
        image_id,
        true,
        false,
        vm.disk_gib,
        input.password.as_deref().is_some_and(|value| !value.trim().is_empty()),
    )?;
    if let Some(existing) = idempotency_key
        .as_deref()
        .map(|key| state.db.job_by_idempotency_key(key))
        .transpose()?
        .flatten()
    {
        let matches_original = existing.kind == "vm.reinstall"
            && existing.vm_id.as_deref() == Some(vm.id.as_str())
            && existing
                .payload
                .get("request_fingerprint")
                .and_then(Value::as_str)
                == Some(request_fingerprint.as_str());
        if !matches_original {
            return Err(AppError::Conflict(
                "idempotency key was already used for a different request".into(),
            ));
        }
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({
                "operation": public_job_value(&existing),
                "replayed": true,
            })),
        )
            .into_response());
    }
    let image = state
        .db
        .get_iso(image_id)?
        .ok_or_else(|| AppError::NotFound("ISO image".into()))?;
    let vm_image = vm_image_from_iso(image.clone())?;
    let manual_install = vm_image.is_manual_installer();
    if manual_install && input.password.is_some() {
        return Err(AppError::Validation(
            "manual installer ISOs cannot provision a guest password; set it inside the installer"
                .into(),
        ));
    }
    let password_envelope = if let Some(password) = input.password.as_deref() {
        validate_guest_password(&vm.root_username, password)?;
        Some(
            state
                .security
                .encrypt_secret(password, &vm_password_context(&vm.id))?,
        )
    } else {
        None
    };
    if !manual_install
        && password_envelope.is_none()
        && state.db.vm_password_envelope(&vm.id)?.is_none()
    {
        return Err(AppError::Validation(
            "an automated reinstall requires a guest password because this VM has no stored credential"
                .into(),
        ));
    }
    let current_guest_tools = state.db.vm_guest_tools(&vm.id)?;
    let compatibility = crate::services::guest_tools::compatibility(&state.config, &image);
    let builtin_guest_integration =
        crate::services::guest_tools::is_builtin_routeros_image(&image);
    let wants_guest_tools = current_guest_tools
        .as_ref()
        .is_some_and(|record| record.enabled)
        && !builtin_guest_integration
        && compatibility.supported
        && compatibility.artifact_available;
    let disable_guest_tools_after_success = current_guest_tools
        .as_ref()
        .is_some_and(|record| record.enabled)
        && !wants_guest_tools;
    let guest_tools_stage = stage_reinstall_guest_tools(
        &state,
        &vm,
        &image,
        wants_guest_tools,
        &request_fingerprint,
    )?;
    let guest_tools_socket = guest_tools_stage
        .as_ref()
        .map(|stage| stage.socket_path.clone());
    let payload = json!({
        "request": ReinstallVmRequest {
            image: vm_image,
            disk_gib: vm.disk_gib,
            cloud_init_iso: None,
            guest_tools_socket,
            start: true,
        },
        "clear_password_after_success": manual_install,
        "request_fingerprint": request_fingerprint,
        "_guest_tools_rotation_generation": guest_tools_stage.as_ref().map(|stage| &stage.generation),
        "guest_tools_new_configuration": guest_tools_stage.as_ref().is_some_and(|stage| stage.new_configuration),
        "disable_guest_tools_after_success": disable_guest_tools_after_success,
        "replacement_iso_id": image.id.clone(),
        "replacement_os_family": image.os_family.clone(),
        "replacement_root_username": super::api::guest_administrator_default(&image.os_family),
    });
    let job = match state.db.enqueue_reinstall_job(
        &NewJob {
            kind: "vm.reinstall".into(),
            vm_id: Some(vm.id.clone()),
            payload,
            idempotency_key,
            run_after: None,
            max_attempts: 1,
            actor_type: Some("customer_token".into()),
            actor_id: Some(token.id.clone()),
        },
        password_envelope.as_deref(),
        VmState::Running,
    ) {
        Ok(job) => job,
        Err(error) => {
            if let Some(stage) = guest_tools_stage.as_ref() {
                cleanup_uncommitted_guest_tools_stage(&state, &vm.id, stage);
            }
            return Err(error);
        }
    };
    public_audit(
        &state,
        &token,
        "vm.reinstall.request",
        &vm,
        json!({ "job_id": job.id }),
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "operation": public_job_value(&job) })),
    )
        .into_response())
}

pub async fn public_network_security(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "firewall:read")?;
    let vm = required_vm(&state, &token.vm_id)?;
    let profile = state
        .db
        .vm_network_security(&vm.id)?
        .ok_or_else(|| AppError::NotFound("VM network security profile".into()))?;
    // Customer sessions never receive administrator/system rules. They can
    // manage only the narrow port-block rules created through status access.
    let rules = state
        .db
        .list_vm_firewall_rules(&vm.id)?
        .into_iter()
        .filter(|rule| {
            rule.owner_type == "customer_token"
                && rule.owner_id.as_deref() == Some(token.id.as_str())
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "profile": profile, "rules": rules })).into_response())
}

pub async fn public_update_network_security(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<VmNetworkSecurityPatch>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "firewall:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    validate_customer_network_security_patch(&input)?;
    state.db.patch_vm_network_security(&vm.id, &input)?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    let profile = state
        .db
        .vm_network_security(&vm.id)?
        .ok_or_else(|| AppError::NotFound("VM network security profile".into()))?;
    public_audit(
        &state,
        &token,
        "vm.network_security.update",
        &vm,
        json!({
            "revision": profile.revision,
            "firewall_enabled": profile.firewall_enabled,
            "ddos_enabled": profile.ddos_enabled,
        }),
    );
    Ok(Json(json!({ "profile": profile, "enforcement": enforcement })).into_response())
}

pub async fn public_create_firewall_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<NewVmFirewallRule>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "firewall:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    validate_customer_firewall_rule(&input)?;
    let rule = state.db.create_vm_firewall_rule_owned(
        &vm.id,
        &input,
        "customer_token",
        Some(&token.id),
    )?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    public_audit(
        &state,
        &token,
        "vm.firewall_rule.create",
        &vm,
        json!({ "rule_id": rule.id, "enabled": rule.enabled }),
    );
    Ok((StatusCode::CREATED, Json(json!({ "rule": rule, "enforcement": enforcement }))).into_response())
}

pub async fn public_patch_firewall_rule(
    State(state): State<Arc<AppState>>,
    Path(rule_id): Path<String>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<VmFirewallRulePatch>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "firewall:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    let current = customer_owned_firewall_rule(&state, &vm.id, &rule_id, &token.id)?;
    let merged = NewVmFirewallRule {
        priority: input.priority.unwrap_or(current.priority),
        direction: input.direction.unwrap_or(current.direction),
        action: input.action.unwrap_or(current.action),
        protocol: input.protocol.unwrap_or(current.protocol),
        source_cidr: input
            .source_cidr
            .clone()
            .unwrap_or_else(|| current.source_cidr.clone()),
        destination_cidr: input
            .destination_cidr
            .clone()
            .unwrap_or_else(|| current.destination_cidr.clone()),
        source_ports: input
            .source_ports
            .clone()
            .unwrap_or_else(|| current.source_ports.clone()),
        destination_ports: input
            .destination_ports
            .clone()
            .unwrap_or_else(|| current.destination_ports.clone()),
        log: input.log.unwrap_or(current.log),
        enabled: input.enabled.unwrap_or(current.enabled),
        description: input
            .description
            .clone()
            .unwrap_or_else(|| current.description.clone()),
    };
    validate_customer_firewall_rule(&merged)?;
    let rule = state.db.patch_vm_firewall_rule(&vm.id, &rule_id, &input)?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    public_audit(
        &state,
        &token,
        "vm.firewall_rule.update",
        &vm,
        json!({ "rule_id": rule.id, "enabled": rule.enabled }),
    );
    Ok(Json(json!({ "rule": rule, "enforcement": enforcement })).into_response())
}

pub async fn public_delete_firewall_rule(
    State(state): State<Arc<AppState>>,
    Path(rule_id): Path<String>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    let token = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&token, "firewall:write")?;
    let vm = required_vm(&state, &token.vm_id)?;
    require_customer_mutation_available(&vm)?;
    customer_owned_firewall_rule(&state, &vm.id, &rule_id, &token.id)?;
    state.db.delete_vm_firewall_rule(&vm.id, &rule_id)?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    public_audit(
        &state,
        &token,
        "vm.firewall_rule.delete",
        &vm,
        json!({ "rule_id": rule_id }),
    );
    Ok(Json(json!({ "deleted": true, "enforcement": enforcement })).into_response())
}

pub async fn public_create_vnc_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    require_public_csrf(&headers)?;
    ensure_vnc_enabled(&state)?;
    let customer = customer_session(&state, &headers, connect.as_ref())?;
    require_scope(&customer, "console:write")?;
    let vm = required_vm(&state, &customer.vm_id)?;
    state.hypervisor.vnc_target(&vm.name).await?;
    let link = state.security.issue_vnc_link_token();
    let source_ip = customer.bound_ip.as_deref();
    let record = state
        .db
        .create_vnc_link(&vm.id, link.hash(), source_ip, Utc::now().timestamp())?;
    public_audit(
        &state,
        &customer,
        "vnc_token.create",
        &vm,
        json!({ "token_id": record.id }),
    );
    let mut response = Json(json!({
        "url": format!("{}/vnc/{}", state.config.public_url, link.expose()),
        "expires_at": record.expires_at,
    }))
    .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

pub async fn exchange_vnc_link(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> AppResult<Response> {
    ensure_vnc_enabled(&state)?;
    let session = state.security.issue_vnc_session_token();
    let now = Utc::now().timestamp();
    let source_ip = client_ip(&headers, connect.as_ref());
    state.rate_limiter.check(
        "public-vnc-exchange",
        source_ip.as_deref().unwrap_or("unknown"),
        30,
        60,
        now,
    )?;
    let record = state
        .db
        .exchange_vnc_link(&hash_token(&token), session.hash(), source_ip.as_deref(), now)?
        .ok_or_else(|| AppError::NotFound("VNC link".into()))?;
    public_exchange_audit(
        &state,
        "vnc_token",
        Some(&record.id),
        "vnc_link.exchange",
        &record.vm_id,
        &headers,
        source_ip.as_deref(),
    );
    let max_age = record
        .expires_at
        .saturating_sub(now)
        .clamp(0, PUBLIC_SESSION_SECONDS);
    let mut response = Redirect::to("/vnc/session").into_response();
    append_cookie(
        response.headers_mut(),
        &cookie_value(
            VNC_COOKIE,
            session.expose(),
            max_age,
            true,
            state.config.secure_cookies,
        ),
    )?;
    no_store(response.headers_mut());
    Ok(response)
}

pub async fn vnc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let _ = vnc_session(&state, &headers, connect.as_ref())?;
    pages::render(&state, "vnc.html", Context::new(), true)
}

pub async fn vnc_session_info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let token = vnc_session(&state, &headers, connect.as_ref())?;
    let vm = required_vm(&state, &token.vm_id)?;
    let mut response = Json(json!({
        "vm": { "id": vm.id, "name": vm.name, "state": vm.state },
        "vm_name": vm.name,
        "websocket_url": "/ws/vnc",
        "expires_at": token.session_expires_at,
    }))
    .into_response();
    no_store(response.headers_mut());
    Ok(response)
}

pub async fn vnc_websocket(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    validate_origin(&state, &headers)?;
    let token = vnc_session(&state, &headers, connect.as_ref())?;
    let vm = required_vm(&state, &token.vm_id)?;
    let target = state.hypervisor.vnc_target(&vm.name).await?;
    if !target.host.is_loopback() {
        return Err(AppError::Hypervisor(
            "refusing to relay a non-loopback VNC target".into(),
        ));
    }
    let expires_at = token.session_expires_at.ok_or_else(|| AppError::Unauthorized)?;
    let relay_state = state.clone();
    Ok(ws
        .on_upgrade(move |socket| {
            relay_vnc(
                socket,
                target.host.to_string(),
                target.port,
                expires_at,
                relay_state,
            )
        })
        .into_response())
}

async fn relay_vnc(socket: WebSocket, host: String, port: u16, expires_at: i64, state: Arc<AppState>) {
    let remaining = expires_at.saturating_sub(Utc::now().timestamp()).max(0) as u64;
    if remaining == 0 {
        return;
    }
    let Ok(Ok(stream)) =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host.as_str(), port))).await
    else {
        return;
    };
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (mut tcp_reader, mut tcp_writer) = stream.into_split();

    let websocket_to_tcp = async {
        while let Some(message) = ws_receiver.next().await {
            match message {
                Ok(Message::Binary(bytes)) => tcp_writer.write_all(&bytes).await?,
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        Ok::<(), std::io::Error>(())
    };
    let tcp_to_websocket = async {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = tcp_reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            if ws_sender
                .send(Message::Binary(buffer[..read].to_vec()))
                .await
                .is_err()
            {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    };
    let policy_guard = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if ensure_vnc_enabled(&state).is_err() {
                break;
            }
        }
    };
    let relay = async {
        tokio::select! {
            _ = websocket_to_tcp => {},
            _ = tcp_to_websocket => {},
            _ = policy_guard => {},
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(remaining), relay).await;
}

fn customer_session(
    state: &AppState,
    headers: &HeaderMap,
    connect: Option<&ConnectInfo<SocketAddr>>,
) -> AppResult<CustomerTokenRecord> {
    let token = cookie(headers, STATUS_COOKIE).ok_or(AppError::Unauthorized)?;
    let source_ip = client_ip(headers, connect);
    state
        .db
        .authenticate_customer_session(&hash_token(token), source_ip.as_deref(), Utc::now().timestamp())?
        .ok_or(AppError::Unauthorized)
}

fn vnc_session(
    state: &AppState,
    headers: &HeaderMap,
    connect: Option<&ConnectInfo<SocketAddr>>,
) -> AppResult<crate::models::VncTokenRecord> {
    ensure_vnc_enabled(state)?;
    let token = cookie(headers, VNC_COOKIE).ok_or(AppError::Unauthorized)?;
    let source_ip = client_ip(headers, connect);
    state
        .db
        .authenticate_vnc_session(&hash_token(token), source_ip.as_deref(), Utc::now().timestamp())?
        .ok_or(AppError::Unauthorized)
}

fn require_scope(token: &CustomerTokenRecord, scope: &str) -> AppResult<()> {
    let aliases: &[&str] = match scope {
        "power:write" => &["power", "vm:power"],
        "dns:write" => &["dns", "vm:dns"],
        "password:read" => &["password", "vm:password:read"],
        "password:write" => &["password", "vm:password:write"],
        "reinstall:write" => &["reinstall", "vm:reinstall"],
        "console:write" => &["console", "vnc", "vm:vnc"],
        "firewall:read" => &["firewall:write", "firewall", "vm:firewall"],
        "firewall:write" => &["firewall", "vm:firewall"],
        "metrics:read" | "vm:read" => &["read", "vm:read"],
        _ => &[],
    };
    if token
        .scopes
        .iter()
        .any(|item| item == scope || item == "*" || aliases.contains(&item.as_str()))
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn ensure_vnc_enabled(state: &AppState) -> AppResult<()> {
    if state.setting_bool("console", "vnc_enabled")?.unwrap_or(true) {
        Ok(())
    } else {
        Err(AppError::Conflict("VNC console access is disabled".into()))
    }
}

fn require_public_csrf(headers: &HeaderMap) -> AppResult<()> {
    let cookie_value = cookie(headers, STATUS_CSRF_COOKIE).ok_or(AppError::Forbidden)?;
    let header_value = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    if verify_token(header_value, &hash_token(cookie_value)) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn validate_origin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let expected = url::Url::parse(&state.config.public_url)
        .map_err(|_| AppError::Configuration("public URL is invalid".into()))?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    let presented = url::Url::parse(origin).map_err(|_| AppError::Forbidden)?;
    if presented.scheme() == expected.scheme()
        && presented.host_str() == expected.host_str()
        && presented.port_or_known_default() == expected.port_or_known_default()
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn parse_public_power(action: &str) -> AppResult<PowerAction> {
    match action {
        "start" => Ok(PowerAction::Start),
        "shutdown" => Ok(PowerAction::Shutdown),
        "stop" | "force-off" => Ok(PowerAction::ForceOff),
        "reboot" => Ok(PowerAction::Reboot),
        "reset" | "hard-reboot" => Ok(PowerAction::Reset),
        _ => Err(AppError::Validation("unsupported customer power action".into())),
    }
}

fn required_vm(state: &AppState, id: &str) -> AppResult<Vm> {
    state
        .db
        .get_vm(id)?
        .ok_or_else(|| AppError::NotFound("VM".into()))
}

fn validate_customer_network_security_patch(input: &VmNetworkSecurityPatch) -> AppResult<()> {
    if input.default_ingress_action.is_some()
        || input.default_egress_action.is_some()
        || input.syn_rate_limit_pps.is_some()
        || input.udp_rate_limit_pps.is_some()
        || input.icmp_rate_limit_pps.is_some()
        || input.new_connection_limit_pps.is_some()
        || input.concurrent_connection_limit.is_some()
        || input.port_scan_protection.is_some()
        || input.drop_invalid_packets.is_some()
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Customer firewall access is intentionally limited to inbound TCP/UDP port
/// blocks. Administrator rules, allowlists, egress policy, CIDR matching and
/// packet logging remain admin-only even when `firewall:write` was granted.
fn validate_customer_firewall_rule(input: &NewVmFirewallRule) -> AppResult<()> {
    if input.direction != FirewallDirection::Ingress
        || input.action != FirewallAction::Drop
        || !matches!(input.protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp)
        || input.source_cidr.is_some()
        || input.destination_cidr.is_some()
        || !input.source_ports.is_empty()
        || input.destination_ports.is_empty()
        || input.destination_ports.len() > 32
        || input.log
    {
        return Err(AppError::Validation(
            "customer firewall rules may only block up to 32 inbound TCP or UDP destination-port ranges"
                .into(),
        ));
    }
    Ok(())
}

fn customer_owned_firewall_rule(
    state: &AppState,
    vm_id: &str,
    rule_id: &str,
    token_id: &str,
) -> AppResult<VmFirewallRule> {
    let rule = state
        .db
        .get_vm_firewall_rule(vm_id, rule_id)?
        .ok_or_else(|| AppError::NotFound("VM firewall rule".into()))?;
    require_customer_rule_owner(rule, token_id)
}

fn require_customer_rule_owner(rule: VmFirewallRule, token_id: &str) -> AppResult<VmFirewallRule> {
    if rule.owner_type != "customer_token" || rule.owner_id.as_deref() != Some(token_id) {
        return Err(AppError::Forbidden);
    }
    Ok(rule)
}

fn require_customer_mutation_available(vm: &Vm) -> AppResult<()> {
    if vm
        .metadata
        .pointer("/maintenance/enabled")
        .and_then(Value::as_bool)
        == Some(true)
    {
        let reason = vm
            .metadata
            .pointer("/maintenance/reason")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());
        return Err(AppError::Conflict(match reason {
            Some(reason) => format!("the VM is in maintenance: {reason}"),
            None => "the VM is in maintenance; customer changes are temporarily unavailable".into(),
        }));
    }
    Ok(())
}

fn public_audit(state: &AppState, token: &CustomerTokenRecord, action: &str, vm: &Vm, details: Value) {
    if let Err(error) = state.db.append_audit(&NewAuditEvent {
        actor_type: "customer_token".into(),
        actor_id: Some(token.id.clone()),
        action: action.into(),
        resource_type: "vm".into(),
        resource_id: Some(vm.id.clone()),
        request_id: None,
        source_ip: token.bound_ip.clone(),
        user_agent: None,
        success: true,
        details,
    }) {
        tracing::warn!(error = %error, "could not persist customer action audit event");
    }
}

fn public_exchange_audit(
    state: &AppState,
    actor_type: &str,
    actor_id: Option<&str>,
    action: &str,
    vm_id: &str,
    headers: &HeaderMap,
    source_ip: Option<&str>,
) {
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect());
    if let Err(error) = state.db.append_audit(&NewAuditEvent {
        actor_type: actor_type.into(),
        actor_id: actor_id.map(str::to_owned),
        action: action.into(),
        resource_type: "vm".into(),
        resource_id: Some(vm_id.into()),
        request_id,
        source_ip: source_ip.map(str::to_owned),
        user_agent,
        success: true,
        details: json!({}),
    }) {
        tracing::warn!(error = %error, "could not persist public-link exchange audit event");
    }
}

fn public_job_value(job: &crate::models::Job) -> Value {
    json!({
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "progress": job.progress_percent,
        "progress_percent": job.progress_percent,
        "error": job.error,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "finished_at": job.finished_at,
    })
}

fn public_iso_value(config: &crate::config::Config, image: &crate::models::IsoImage) -> Value {
    let available = iso_is_ready(image);
    let guest_tools = crate::services::guest_tools::compatibility(config, image);
    json!({
        "id": image.id,
        "slug": image.slug,
        "name": image.name,
        "version": image.version,
        "os_family": image.os_family,
        "architecture": image.architecture,
        "install_mode": image.install_mode,
        "supports_guest_agent": image.supports_guest_agent,
        "supports_cloud_init": image.supports_cloud_init,
        "uefi": image.uefi,
        "size_bytes": image.size_bytes,
        "available": available,
        "status": if available { "ready" } else { "missing" },
        "guest_tools": guest_tools,
    })
}

fn no_store(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PortRange;

    fn customer_port_block() -> NewVmFirewallRule {
        NewVmFirewallRule {
            priority: 1000,
            direction: FirewallDirection::Ingress,
            action: FirewallAction::Drop,
            protocol: FirewallProtocol::Tcp,
            source_cidr: None,
            destination_cidr: None,
            source_ports: Vec::new(),
            destination_ports: vec![PortRange::single(22)],
            log: false,
            enabled: false,
            description: "Block SSH".into(),
        }
    }

    fn stored_rule(owner_type: &str) -> VmFirewallRule {
        let rule = customer_port_block();
        VmFirewallRule {
            id: "rule-1".into(),
            vm_id: "vm-1".into(),
            priority: rule.priority,
            direction: rule.direction,
            action: rule.action,
            protocol: rule.protocol,
            source_cidr: rule.source_cidr,
            destination_cidr: rule.destination_cidr,
            source_ports: rule.source_ports,
            destination_ports: rule.destination_ports,
            log: rule.log,
            enabled: rule.enabled,
            description: rule.description,
            owner_type: owner_type.into(),
            owner_id: Some("actor-1".into()),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn customer_token(scopes: &[&str]) -> CustomerTokenRecord {
        CustomerTokenRecord {
            id: "token-1".into(),
            vm_id: "vm-1".into(),
            scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
            bound_ip: None,
            created_at: 0,
            expires_at: 100,
            consumed_at: Some(1),
            session_expires_at: Some(100),
            last_used_at: Some(1),
            revoked_at: None,
        }
    }

    #[test]
    fn firewall_write_scope_includes_read_for_existing_customer_tokens() {
        assert!(require_scope(&customer_token(&["firewall:write"]), "firewall:read").is_ok());
        assert!(require_scope(&customer_token(&["vm:firewall"]), "firewall:write").is_ok());
        assert!(matches!(
            require_scope(&customer_token(&["firewall:read"]), "firewall:write"),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn customer_can_only_toggle_vm_firewall_and_ddos_profile() {
        let allowed = VmNetworkSecurityPatch {
            firewall_enabled: Some(true),
            ddos_enabled: Some(true),
            ..VmNetworkSecurityPatch::default()
        };
        assert!(validate_customer_network_security_patch(&allowed).is_ok());

        let forbidden = [
            VmNetworkSecurityPatch {
                default_ingress_action: Some(FirewallAction::Drop),
                ..VmNetworkSecurityPatch::default()
            },
            VmNetworkSecurityPatch {
                syn_rate_limit_pps: Some(Some(1)),
                ..VmNetworkSecurityPatch::default()
            },
            VmNetworkSecurityPatch {
                udp_rate_limit_pps: Some(None),
                ..VmNetworkSecurityPatch::default()
            },
            VmNetworkSecurityPatch {
                icmp_rate_limit_pps: Some(Some(1)),
                ..VmNetworkSecurityPatch::default()
            },
            VmNetworkSecurityPatch {
                new_connection_limit_pps: Some(Some(1)),
                ..VmNetworkSecurityPatch::default()
            },
            VmNetworkSecurityPatch {
                concurrent_connection_limit: Some(Some(1)),
                ..VmNetworkSecurityPatch::default()
            },
            VmNetworkSecurityPatch {
                port_scan_protection: Some(true),
                ..VmNetworkSecurityPatch::default()
            },
            VmNetworkSecurityPatch {
                drop_invalid_packets: Some(false),
                ..VmNetworkSecurityPatch::default()
            },
        ];
        for patch in forbidden {
            assert!(matches!(
                validate_customer_network_security_patch(&patch),
                Err(AppError::Forbidden)
            ));
        }
    }

    #[test]
    fn customer_rule_boundary_allows_only_inbound_port_blocks() {
        let valid = customer_port_block();
        assert!(validate_customer_firewall_rule(&valid).is_ok());

        let mut egress = valid.clone();
        egress.direction = FirewallDirection::Egress;
        assert!(validate_customer_firewall_rule(&egress).is_err());

        let mut allow = valid.clone();
        allow.action = FirewallAction::Accept;
        assert!(validate_customer_firewall_rule(&allow).is_err());

        let mut source_match = valid.clone();
        source_match.source_cidr = Some("192.0.2.0/24".into());
        assert!(validate_customer_firewall_rule(&source_match).is_err());

        let mut source_port = valid.clone();
        source_port.source_ports = vec![PortRange::single(1024)];
        assert!(validate_customer_firewall_rule(&source_port).is_err());

        let mut logged = valid.clone();
        logged.log = true;
        assert!(validate_customer_firewall_rule(&logged).is_err());

        let mut no_ports = valid.clone();
        no_ports.destination_ports.clear();
        assert!(validate_customer_firewall_rule(&no_ports).is_err());

        let mut too_many_ports = valid;
        too_many_ports.destination_ports = (1..=33).map(PortRange::single).collect();
        assert!(validate_customer_firewall_rule(&too_many_ports).is_err());
    }

    #[test]
    fn customer_cannot_mutate_admin_or_system_owned_rules() {
        assert!(require_customer_rule_owner(stored_rule("customer_token"), "actor-1").is_ok());
        assert!(matches!(
            require_customer_rule_owner(stored_rule("customer_token"), "another-token"),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            require_customer_rule_owner(stored_rule("admin"), "actor-1"),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            require_customer_rule_owner(stored_rule("system"), "actor-1"),
            Err(AppError::Forbidden)
        ));
    }
}
