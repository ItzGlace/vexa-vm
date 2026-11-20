pub mod api;
pub mod auth;
pub mod pages;
pub mod mcp;
pub mod public;
pub mod support;

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use serde_json::json;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    services::ServeDir,
    trace::TraceLayer,
};

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    let admin_pages = Router::new()
        .route("/overall", get(pages::overall))
        .route("/vms", get(pages::vms))
        .route("/vms/create", get(pages::vm_create))
        .route("/vms/:id", get(pages::vm_detail))
        .route("/network", get(pages::network))
        .route("/isos", get(pages::isos))
        .route("/settings", get(pages::settings))
        .route("/logs", get(pages::logs))
        .route("/docs", get(pages::docs))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::admin_page_guard,
        ));

    let protected_api = Router::new()
        .route("/mcp/setup", get(mcp::setup))
        .route("/mcp/client", get(mcp::client))
        .route("/mcp/documentation", get(mcp::documentation))
        .route("/vms/:id/recovery", post(support::recover_password))
        .route("/vms/:id/console/screenshot", get(support::screenshot))
        .route("/vms/:id/console/keys", post(support::keys))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(api::auth_me))
        .route("/host", get(api::host))
        .route("/host/metrics", get(api::host_metrics))
        .route("/vms", get(api::list_vms).post(api::create_vm))
        .route(
            "/vms/:id",
            get(api::get_vm).patch(api::patch_vm).delete(api::delete_vm),
        )
        .route("/vms/:id/actions/:action", post(api::vm_action))
        .route("/vms/:id/maintenance", put(api::set_vm_maintenance))
        .route("/vms/:id/disk-protection", put(api::set_vm_disk_protection))
        .route("/vms/:id/reinstall", post(api::reinstall_vm))
        .route("/vms/:id/metrics", get(api::vm_metrics))
        .route("/vms/:id/traffic/reset", post(api::reset_vm_traffic))
        .route(
            "/vms/:id/network-security",
            get(api::get_vm_network_security).patch(api::patch_vm_network_security),
        )
        .route(
            "/vms/:id/firewall/rules",
            get(api::list_vm_firewall_rules).post(api::create_vm_firewall_rule),
        )
        .route(
            "/vms/:id/firewall/rules/:rule_id",
            patch(api::patch_vm_firewall_rule).delete(api::delete_vm_firewall_rule),
        )
        .route(
            "/vms/:id/password",
            get(api::reveal_vm_password).put(api::update_vm_password),
        )
        .route("/vms/:id/dns", get(api::get_vm_dns).put(api::update_vm_dns))
        .route(
            "/vms/:id/ssh-keys",
            get(api::get_vm_ssh_keys).put(api::update_vm_ssh_keys),
        )
        .route("/vms/:id/guest-tools", get(api::get_vm_guest_tools))
        .route(
            "/vms/:id/guest-tools/probe",
            post(api::probe_vm_guest_tools),
        )
        .route("/vms/:id/status-tokens", post(api::create_status_token))
        .route(
            "/vms/:id/status-tokens/:token_id",
            delete(api::revoke_status_token),
        )
        .route("/vms/:id/vnc-tokens", post(api::create_vnc_token))
        .route(
            "/vms/:id/snapshots",
            get(api::list_snapshots).post(api::create_snapshot),
        )
        .route("/vms/:id/snapshots/:snapshot_id", delete(api::delete_snapshot))
        .route(
            "/vms/:id/snapshots/:snapshot_id/revert",
            post(api::revert_snapshot),
        )
        .route(
            "/network/pools",
            get(api::list_ip_pools).post(api::create_ip_pool),
        )
        .route(
            "/network/pools/:id",
            get(api::get_ip_pool)
                .patch(api::patch_ip_pool)
                .delete(api::delete_ip_pool),
        )
        .route(
            "/network/addresses",
            get(api::list_ip_addresses).post(api::create_ip_address),
        )
        .route(
            "/network/addresses/:address",
            get(api::get_ip_address)
                .patch(api::patch_ip_address)
                .delete(api::delete_ip_address),
        )
        .route("/network/addresses/:address/assign", post(api::assign_ip_address))
        .route(
            "/network/addresses/:address/release",
            post(api::release_ip_address),
        )
        .route(
            "/network/security",
            get(api::get_hypervisor_network_security).patch(api::patch_hypervisor_network_security),
        )
        .route(
            "/network/blacklist",
            get(api::list_ip_blacklist).post(api::create_ip_blacklist),
        )
        .route(
            "/network/blacklist/:id",
            patch(api::patch_ip_blacklist).delete(api::delete_ip_blacklist),
        )
        .route(
            "/network/abuse-records",
            get(api::list_ip_abuse_records).post(api::create_ip_abuse_record),
        )
        .route(
            "/network/abuse-records/:id/resolve",
            post(api::resolve_ip_abuse_record),
        )
        .route("/ip-ranges", get(api::list_ip_pools).post(api::create_ip_pool))
        .route(
            "/ip-ranges/:id",
            get(api::get_ip_pool)
                .patch(api::patch_ip_pool)
                .delete(api::delete_ip_pool),
        )
        .route(
            "/ip-addresses",
            get(api::list_ip_addresses).post(api::create_ip_address),
        )
        .route(
            "/ip-addresses/:address",
            get(api::get_ip_address)
                .patch(api::patch_ip_address)
                .delete(api::delete_ip_address),
        )
        .route("/ip-addresses/:address/assign", post(api::assign_ip_address))
        .route("/ip-addresses/:address/release", post(api::release_ip_address))
        .route(
            "/dns/defaults",
            get(api::default_dns).put(api::update_default_dns),
        )
        .route("/isos", get(api::list_isos).post(api::create_iso))
        .route(
            "/isos/upload",
            post(api::upload_iso).layer(DefaultBodyLimit::max(16 * 1024 * 1024 * 1024usize)),
        )
        .route(
            "/isos/:id",
            get(api::get_iso).patch(api::patch_iso).delete(api::delete_iso),
        )
        .route("/isos/:id/verify", post(api::verify_iso))
        .route("/settings", get(api::list_settings).patch(api::update_settings))
        .route("/admin/credentials", put(api::update_credentials))
        .route("/admins", get(api::list_admins).post(api::create_admin))
        .route(
            "/admins/:id",
            get(api::get_admin)
                .patch(api::patch_admin)
                .delete(api::delete_admin),
        )
        .route("/admins/:id/credentials", put(api::update_admin_credentials))
        .route("/api-keys", get(api::list_api_keys).post(api::create_api_key))
        .route("/api-keys/:id", delete(api::revoke_api_key))
        .route("/jobs", get(api::list_jobs))
        .route("/jobs/:id", get(api::get_job))
        .route("/jobs/:id/cancel", post(api::cancel_job))
        .route("/operations", get(api::list_jobs))
        .route("/operations/:id", get(api::get_job))
        .route("/audit", get(api::list_audit))
        .route("/updates", get(api::update_status))
        .route("/updates/check", post(api::check_updates))
        .route("/updates/stage", post(api::stage_update))
        .route("/updates/approve", post(api::approve_update))
        .route("/updates/rollback", post(api::approve_rollback))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::api_guard));

    let public_api = Router::new()
        .route("/session/exchange", post(public::exchange_session_api))
        .route("/session/logout", post(public::logout_session))
        .route("/vm", get(public::public_vm))
        .route("/vm/metrics", get(public::public_metrics))
        .route("/vm/dns", get(public::public_dns).put(public::public_update_dns))
        .route(
            "/vm/password",
            get(public::public_reveal_password).put(public::public_update_password),
        )
        .route("/vm/recovery", post(public::public_recover_password))
        .route("/vm/ssh-keys", put(public::public_update_ssh_keys))
        .route(
            "/vm/firewall",
            get(public::public_network_security).put(public::public_update_network_security),
        )
        .route(
            "/vm/firewall/rules",
            get(public::public_network_security).post(public::public_create_firewall_rule),
        )
        .route(
            "/vm/firewall/rules/:rule_id",
            patch(public::public_patch_firewall_rule).delete(public::public_delete_firewall_rule),
        )
        .route("/vm/actions/:action", post(public::public_power_action))
        .route("/vm/reinstall", post(public::public_reinstall))
        .route("/vm/vnc-token", post(public::public_create_vnc_token))
        .route("/actions/:action", post(public::public_power_action))
        .route("/dns", get(public::public_dns).put(public::public_update_dns))
        .route(
            "/password",
            get(public::public_reveal_password).put(public::public_update_password),
        )
        .route("/ssh-keys", put(public::public_update_ssh_keys))
        .route("/vnc-token", post(public::public_create_vnc_token))
        .route("/vnc-session", get(public::vnc_session_info))
        .route("/vnc", post(public::vnc_session_info))
        .route("/reinstall", post(public::public_reinstall))
        .route("/isos", get(public::public_isos))
        .route("/jobs/:id", get(public::public_job))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::public_api_rate_limit,
        ));

    // Stable compatibility aliases for the unversioned URLs documented by the
    // original panel. They intentionally share the versioned API guard and
    // handlers so they cannot bypass authentication, CSRF, scopes, jobs, or
    // audit logging.
    let compatibility_api = Router::new()
        .route("/create", post(api::create_vm))
        .route("/set-ip", post(api::compatibility_set_ip))
        .route("/set-ip/", post(api::compatibility_set_ip))
        .route("/set-ip/:address", patch(api::patch_ip_address))
        .route("/vms/reboot", post(api::compatibility_power_action))
        .route("/vms/:id/reboot", post(api::compatibility_reboot_path))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::api_guard));

    let request_id_header = HeaderName::from_static("x-request-id");
    let layers = ServiceBuilder::new()
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .layer(SetRequestIdLayer::new(request_id_header.clone(), MakeRequestUuid))
        .layer(PropagateRequestIdLayer::new(request_id_header))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new());

    Router::new()
        .route("/", get(pages::root))
        .route("/login", get(pages::login_page))
        .route("/healthz", get(api::healthz))
        .route("/readyz", get(api::readyz))
        .route("/api/openapi.json", get(openapi))
        .route("/api/v1/health", get(api::healthz))
        .route("/api/v1/auth/login", post(auth::login))
        .nest("/api/v1", protected_api)
        .nest("/api/public", public_api)
        .nest("/api", compatibility_api)
        .route("/status/:token", get(public::exchange_status_link))
        .route("/status/session", get(public::status_page))
        .route("/vnc/:token", get(public::exchange_vnc_link))
        .route("/vnc/session", get(public::vnc_page))
        .route("/ws/vnc", get(public::vnc_websocket))
        .merge(admin_pages)
        .nest_service(
            "/static",
            ServeDir::new(state.config.static_dir.clone()).precompressed_gzip(),
        )
        .fallback(fallback)
        .layer(layers)
        .layer(middleware::from_fn(request_timeout))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers))
        .with_state(state)
}

async fn request_timeout(request: axum::extract::Request, next: Next) -> Response {
    let path = request.uri().path();
    let timeout = if path.ends_with("/recovery") {
        Duration::from_secs(600)
    } else if path == "/api/v1/isos/upload"
        || path == "/api/v1/updates/stage"
        || (path.starts_with("/api/v1/isos/") && path.ends_with("/verify"))
    {
        Duration::from_secs(6 * 60 * 60)
    } else {
        Duration::from_secs(180)
    };
    match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            Json(json!({
                "success": false,
                "error": {
                    "code": "request_timeout",
                    "message": "The request exceeded its processing time limit"
                }
            })),
        )
            .into_response(),
    }
}

async fn openapi() -> Response {
    let document = include_str!("../../docs/openapi.json");
    (
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        document,
    )
        .into_response()
}

async fn fallback(State(state): State<Arc<AppState>>, uri: axum::http::Uri) -> Response {
    if uri.path().starts_with("/api/") {
        return crate::error::AppError::NotFound("API route".into()).into_response();
    }
    pages::render(&state, "error.html", tera::Context::new(), true)
        .map(|mut response| {
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        })
        .unwrap_or_else(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": { "code": "not_found", "message": "Page not found" } })),
            )
                .into_response()
        })
}

async fn security_headers(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let request_path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let status_frame_ancestors = status_frame_ancestors();
    let allow_status_frame = request_path.starts_with("/status/")
        && status_frame_ancestors.as_deref().is_some_and(|value| !value.is_empty());
    if !allow_status_frame {
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    let secure_public_url = state.config.public_url.starts_with("https://");
    let frame_ancestors = if allow_status_frame {
        status_frame_ancestors.as_deref().unwrap_or("'none'")
    } else {
        "'none'"
    };
    let content_security_policy = if secure_public_url {
        format!("default-src 'self'; base-uri 'none'; frame-ancestors {frame_ancestors}; form-action 'self'; object-src 'none'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'; connect-src 'self' ws: wss:; upgrade-insecure-requests")
    } else {
        format!("default-src 'self'; base-uri 'none'; frame-ancestors {frame_ancestors}; form-action 'self'; object-src 'none'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'; connect-src 'self' ws: wss:")
    };
    if let Ok(value) = HeaderValue::from_str(&content_security_policy) {
        headers.insert(HeaderName::from_static("content-security-policy"), value);
    }
    if secure_public_url {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

fn status_frame_ancestors() -> Option<String> {
    let raw = std::env::var("VEXA_STATUS_FRAME_ANCESTORS").ok()?;
    let ancestors = raw
        .split_whitespace()
        .filter(|value| {
            *value == "'self'"
                || value
                    .strip_prefix("https://")
                    .or_else(|| value.strip_prefix("http://"))
                    .is_some_and(|host| {
                        !host.is_empty()
                            && host.len() <= 253
                            && !host.contains('/')
                            && host
                                .chars()
                                .all(|character| character.is_ascii_alphanumeric() || ".:-".contains(character))
                    })
        })
        .collect::<Vec<_>>();
    (!ancestors.is_empty()).then(|| ancestors.join(" "))
}
