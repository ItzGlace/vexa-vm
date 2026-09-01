use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, Method},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    error::{AppError, AppResult},
    models::{Admin, AdminRole, NewAuditEvent},
    security::{hash_token, verify_password},
    state::AppState,
};

pub const SESSION_COOKIE: &str = "vexa_session";
pub const CSRF_COOKIE: &str = "vexa_csrf";
const DEFAULT_SESSION_SECONDS: i64 = 12 * 60 * 60;

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub actor_type: &'static str,
    pub actor_id: String,
    pub admin: Option<Admin>,
    pub permissions: Vec<String>,
    pub session_hash: Option<[u8; 32]>,
    /// Request attribution populated by the API guard. Page guards leave
    /// these empty because pages never write action-specific audit events.
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

impl AuthContext {
    pub fn allows(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|item| {
                item == "*"
                    || item == permission
                    // Preserve the established API-key contract: legacy
                    // vms:write keys retain all VM mutation capabilities.
                    || (item == "vms:write" && permission.starts_with("vms:"))
            })
    }

    pub fn require(&self, permission: &str) -> AppResult<()> {
        if self.allows(permission) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    admin: Admin,
    expires_at: i64,
    redirect: &'static str,
}

pub async fn admin_page_guard(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    match session_context(&state, request.headers()) {
        Ok(Some(context)) => {
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Ok(None) | Err(_) => Redirect::to("/login").into_response(),
    }
}

pub async fn api_guard(State(state): State<Arc<AppState>>, mut request: Request, next: Next) -> Response {
    let source_ip = client_ip(
        request.headers(),
        request.extensions().get::<ConnectInfo<SocketAddr>>(),
    );
    let mut context = match authenticate_api_request(&state, request.headers(), source_ip.as_deref()) {
        Ok(Some(context)) => context,
        Ok(None) => return AppError::Unauthorized.into_response(),
        Err(error) => return error.into_response(),
    };
    let now = Utc::now().timestamp();
    let api_limit = state
        .setting_u64("security", "api_rate_limit")
        .unwrap_or(None)
        .unwrap_or(600)
        .clamp(10, 100_000) as u32;
    let rate_key = format!(
        "{}:{}:{}",
        context.actor_type,
        context.actor_id,
        source_ip.as_deref().unwrap_or("unknown")
    );
    if let Err(error) = state
        .rate_limiter
        .check("authenticated-api", &rate_key, api_limit, 60, now)
    {
        return error.into_response();
    }

    if let (true, Some(session_hash)) = (is_mutating(request.method()), context.session_hash.as_ref()) {
        let Some(csrf) = request
            .headers()
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
        else {
            return AppError::Forbidden.into_response();
        };
        let valid = state
            .db
            .verify_admin_session_csrf(session_hash, &hash_token(csrf), Utc::now().timestamp())
            .unwrap_or(false);
        if !valid {
            return AppError::Forbidden.into_response();
        }
    }

    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    context.source_ip = source_ip.clone();
    context.user_agent = user_agent.clone();
    context.request_id = request_id.clone();
    let audit_context = context.clone();
    request.extensions_mut().insert(context);
    let response = next.run(request).await;
    if is_mutating(&method) {
        let success = response.status().is_success();
        let _ = state.db.append_audit(&NewAuditEvent {
            actor_type: audit_context.actor_type.into(),
            actor_id: Some(audit_context.actor_id),
            action: format!(
                "api.{}.{}",
                method.as_str().to_ascii_lowercase(),
                if success { "succeeded" } else { "failed" }
            ),
            resource_type: "api_request".into(),
            resource_id: Some(path),
            request_id,
            source_ip,
            user_agent,
            success,
            details: json!({ "status": response.status().as_u16() }),
        });
    }
    response
}

/// Bound status-link and VNC-session API traffic by the real peer address.
/// Public sessions are already scoped and CSRF protected, but without this
/// outer guard a valid or guessed endpoint could still be used to exhaust
/// application workers before token validation runs.
pub async fn public_api_rate_limit(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let source_ip = client_ip(
        request.headers(),
        request.extensions().get::<ConnectInfo<SocketAddr>>(),
    )
    .unwrap_or_else(|| "unknown".into());
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let limit = state
        .setting_u64("security", "api_rate_limit")
        .unwrap_or(None)
        .unwrap_or(600)
        .clamp(30, 10_000) as u32;
    if let Err(error) = state.rate_limiter.check(
        "public-api-ip",
        &source_ip,
        limit,
        60,
        Utc::now().timestamp(),
    ) {
        let _ = state.db.append_audit(&NewAuditEvent {
            actor_type: "public_client".into(),
            actor_id: None,
            action: "public_api.rate_limited".into(),
            resource_type: "api_request".into(),
            resource_id: Some(path),
            request_id,
            source_ip: (source_ip != "unknown").then_some(source_ip),
            user_agent,
            success: false,
            details: json!({ "status": 429 }),
        });
        return error.into_response();
    }
    let response = next.run(request).await;
    if is_mutating(&method) {
        let success = response.status().is_success();
        let _ = state.db.append_audit(&NewAuditEvent {
            actor_type: "public_client".into(),
            actor_id: None,
            action: format!(
                "public_api.{}.{}",
                method.as_str().to_ascii_lowercase(),
                if success { "succeeded" } else { "failed" }
            ),
            resource_type: "api_request".into(),
            resource_id: Some(path),
            request_id,
            source_ip: (source_ip != "unknown").then_some(source_ip),
            user_agent,
            success,
            details: json!({ "status": response.status().as_u16() }),
        });
    }
    response
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(input): Json<LoginRequest>,
) -> AppResult<Response> {
    let now = Utc::now().timestamp();
    let source_ip = client_ip(&headers, connect.as_ref());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let ip_key = source_ip.as_deref().unwrap_or("unknown");
    let account_key = format!("{}:{}", ip_key, input.username.trim().to_ascii_lowercase());
    let login_limit = state
        .setting_u64("security", "login_rate_limit")?
        .unwrap_or(8)
        .clamp(1, 1000) as u32;
    state.rate_limiter.check(
        "admin-login-ip",
        ip_key,
        login_limit.saturating_mul(4),
        15 * 60,
        now,
    )?;
    state
        .rate_limiter
        .check("admin-login-account", &account_key, login_limit, 15 * 60, now)?;
    let Some(auth) = state.db.admin_auth_by_username(input.username.trim())? else {
        record_failed_login(&state, &input.username, source_ip.as_deref(), user_agent, "unknown_account");
        return Err(AppError::Unauthorized);
    };
    if !auth.admin.enabled || !verify_password(&input.password, &auth.password_hash)? {
        record_failed_login(&state, &input.username, source_ip.as_deref(), user_agent, "invalid_credentials");
        return Err(AppError::Unauthorized);
    }

    let session = state.security.issue_session_token();
    let csrf = state.security.issue_csrf_token();
    let session_seconds = state
        .setting_u64("security", "session_lifetime_minutes")?
        .and_then(|minutes| i64::try_from(minutes).ok())
        .map(|minutes| minutes.saturating_mul(60))
        .unwrap_or(DEFAULT_SESSION_SECONDS)
        .clamp(5 * 60, 24 * 60 * 60);
    let expires_at = now + session_seconds;
    state.rate_limiter.reset("admin-login-account", &account_key)?;
    state.db.create_admin_session(
        &auth.admin.id,
        session.hash(),
        csrf.hash(),
        expires_at,
        source_ip.as_deref(),
        user_agent,
    )?;
    state.db.record_admin_login(&auth.admin.id, now)?;
    let _ = state.db.append_audit(&NewAuditEvent {
        actor_type: "admin".into(),
        actor_id: Some(auth.admin.id.clone()),
        action: "auth.login".into(),
        resource_type: "admin_session".into(),
        resource_id: None,
        request_id: None,
        source_ip,
        user_agent: user_agent.map(ToOwned::to_owned),
        success: true,
        details: json!({}),
    });

    let mut response = Json(LoginResponse {
        success: true,
        admin: auth.admin,
        expires_at,
        redirect: "/overall",
    })
    .into_response();
    append_cookie(
        response.headers_mut(),
        &cookie_value(
            SESSION_COOKIE,
            session.expose(),
            session_seconds,
            true,
            state.config.secure_cookies,
        ),
    )?;
    append_cookie(
        response.headers_mut(),
        &cookie_value(
            CSRF_COOKIE,
            csrf.expose(),
            session_seconds,
            false,
            state.config.secure_cookies,
        ),
    )?;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    Ok(response)
}

fn record_failed_login(
    state: &AppState,
    username: &str,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
    reason: &str,
) {
    let username = username.trim().chars().take(128).collect::<String>();
    let _ = state.db.append_audit(&NewAuditEvent {
        actor_type: "login_attempt".into(),
        actor_id: None,
        action: "auth.login.failed".into(),
        resource_type: "admin_session".into(),
        resource_id: None,
        request_id: None,
        source_ip: source_ip.map(str::to_owned),
        user_agent: user_agent.map(|value| value.chars().take(512).collect()),
        success: false,
        details: json!({ "username": username, "reason": reason }),
    });
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    if let Some(hash) = auth.session_hash {
        let _ = state.db.revoke_admin_session(&hash)?;
    }
    let mut response = Json(json!({ "success": true })).into_response();
    append_cookie(
        response.headers_mut(),
        &cookie_value(SESSION_COOKIE, "", 0, true, state.config.secure_cookies),
    )?;
    append_cookie(
        response.headers_mut(),
        &cookie_value(CSRF_COOKIE, "", 0, false, state.config.secure_cookies),
    )?;
    Ok(response)
}

pub fn session_context(state: &AppState, headers: &HeaderMap) -> AppResult<Option<AuthContext>> {
    let Some(token) = cookie(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let hash = hash_token(token);
    let Some(session) = state
        .db
        .authenticate_admin_session(&hash, Utc::now().timestamp())?
    else {
        return Ok(None);
    };
    let permissions = state
        .db
        .admin_permission_override(&session.admin.id)?
        .unwrap_or_else(|| permissions_for_role(session.admin.role));
    Ok(Some(AuthContext {
        actor_type: "admin",
        actor_id: session.admin.id.clone(),
        admin: Some(session.admin),
        permissions,
        session_hash: Some(hash),
        source_ip: None,
        user_agent: None,
        request_id: None,
    }))
}

pub(crate) fn permissions_for_role(role: AdminRole) -> Vec<String> {
    let permissions: &[&str] = match role {
        AdminRole::SuperAdmin => &["*"],
        AdminRole::Admin => &[
            "host:read",
            "vms:read",
            "vms:create",
            "vms:edit",
            "vms:power",
            "vms:reinstall",
            "vms:resources:write",
            "vms:traffic:write",
            "vms:network:write",
            "vms:delete",
            "vms:snapshots:write",
            "vms:password:read",
            "vms:password:write",
            "vms:vnc",
            "network:read",
            "network:write",
            "isos:read",
            "isos:write",
            "settings:read",
            "settings:write",
            "admins:read",
            "api_keys:read",
            "api_keys:write",
            "audit:read",
            "updates:read",
            "updates:write",
            "jobs:read",
            "jobs:write",
        ],
        AdminRole::ReadOnly => &[
            "host:read",
            "vms:read",
            "network:read",
            "isos:read",
            "settings:read",
            "admins:read",
            "api_keys:read",
            "audit:read",
            "updates:read",
            "jobs:read",
        ],
    };
    permissions
        .iter()
        .map(|permission| (*permission).into())
        .collect()
}

fn authenticate_api_request(
    state: &AppState,
    headers: &HeaderMap,
    source_ip: Option<&str>,
) -> AppResult<Option<AuthContext>> {
    if let Some(token) = bearer_token(headers) {
        let Some(key) = state
            .db
            .authenticate_api_key(&hash_token(token), Utc::now().timestamp())?
        else {
            return Ok(None);
        };
        if !key.ip_allowlist.is_empty() {
            let Some(address) = source_ip.and_then(|value| value.parse::<std::net::IpAddr>().ok()) else {
                return Ok(None);
            };
            let allowed = key.ip_allowlist.iter().any(|cidr| {
                cidr.parse::<ipnet::IpNet>()
                    .is_ok_and(|network| network.contains(&address))
            });
            if !allowed {
                return Ok(None);
            }
        }
        return Ok(Some(AuthContext {
            actor_type: "api_key",
            actor_id: key.id,
            admin: None,
            permissions: key.permissions,
            session_hash: None,
            source_ip: None,
            user_agent: None,
            request_id: None,
        }));
    }
    session_context(state, headers)
}

/// Trust forwarded client addresses only when the immediate peer is loopback,
/// which is the supported deployment shape for the bundled reverse proxy.
pub fn client_ip(headers: &HeaderMap, connect: Option<&ConnectInfo<SocketAddr>>) -> Option<String> {
    let peer = connect.map(|ConnectInfo(address)| address.ip());
    if peer.is_some_and(|address| address.is_loopback()) {
        let forwarded = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .or_else(|| {
                headers
                    .get("x-forwarded-for")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(',').next())
            })
            .map(str::trim)
            .and_then(|value| value.parse::<std::net::IpAddr>().ok());
        if let Some(address) = forwarded {
            return Some(address.to_string());
        }
    }
    peer.map(|address| address.to_string())
}

pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|item| item.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

pub fn cookie_value(name: &str, value: &str, max_age: i64, http_only: bool, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; Path=/; Max-Age={max_age}; SameSite=Strict");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn append_cookie(headers: &mut HeaderMap, value: &str) -> AppResult<()> {
    let value = HeaderValue::try_from(value)
        .map_err(|_| AppError::Internal("could not encode response cookie".into()))?;
    headers.append(header::SET_COOKIE, value);
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn is_mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(permissions: &[&str]) -> AuthContext {
        AuthContext {
            actor_type: "test",
            actor_id: "test".into(),
            admin: None,
            permissions: permissions.iter().map(|value| (*value).into()).collect(),
            session_hash: None,
            source_ip: None,
            user_agent: None,
            request_id: None,
        }
    }

    #[test]
    fn fine_grained_vm_permissions_do_not_imply_resource_or_traffic_access() {
        let rebuild_only = context(&["vms:read", "vms:reinstall", "vms:power"]);
        assert!(rebuild_only.allows("vms:reinstall"));
        assert!(!rebuild_only.allows("vms:create"));
        assert!(!rebuild_only.allows("vms:resources:write"));
        assert!(!rebuild_only.allows("vms:traffic:write"));

        let legacy = context(&["vms:write"]);
        assert!(legacy.allows("vms:create"));
        assert!(legacy.allows("vms:traffic:write"));
    }
}
