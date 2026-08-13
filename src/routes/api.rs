use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};

use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::Utc;
use ipnet::IpNet;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use vexa_guest_protocol::Command as GuestCommand;

use crate::{
    error::{AppError, AppResult},
    hypervisor::{
        CreateVmRequest, Firmware, PowerAction, ReinstallVmRequest, ResizeVmRequest, SnapshotRequest, VmImage,
    },
    models::{
        AddressFamily, AdminRole, HypervisorNetworkSecurityPatch, InstallMode, IpAddressRecord,
        IpBlacklistPatch, IpPoolPatch, IpScope, IpStatus, IsoImage, JobStatus, NewAuditEvent,
        NewIpAbuseRecord, NewIpAddress, NewIpBlacklistEntry, NewIpPool, NewJob, NewVm, NewVmFirewallRule, Vm,
        VmFirewallRulePatch, VmNetworkSecurityPatch, VmPatch,
    },
    security::{hash_password, verify_password, vm_password_context},
    services::{
        iso_download,
        updater::{
            read_durable_update_statuses, DurableUpdateOutcome, DurableUpdateStatus, PublicRollbackPoint,
            RollbackPoint, UpdateComponent, UPDATE_REPOSITORY, UPDATE_ROLLBACK_ROOT,
        },
    },
    state::{normalize_guest_locale, validate_ntp_server, validate_timezone_name, AppState},
};

use super::auth::AuthContext;

const DEFAULT_LIMIT: usize = 100;
const MIB_BYTES: u64 = 1024 * 1024;
const GIB_BYTES: u64 = 1024 * MIB_BYTES;
const HOST_MEMORY_RESERVE_BYTES: u64 = 256 * MIB_BYTES;
const HOST_DISK_RESERVE_BYTES: u64 = 2 * GIB_BYTES;
const DEFAULT_CPU_OVERCOMMIT_RATIO: f64 = 4.0;
const DEFAULT_MEMORY_OVERCOMMIT_RATIO: f64 = 1.5;
const MAX_CPU_OVERCOMMIT_RATIO: f64 = 16.0;
const MAX_MEMORY_OVERCOMMIT_RATIO: f64 = 4.0;

#[derive(Clone, Copy, Debug)]
struct CapacityPolicy {
    cpu_overcommit_ratio: f64,
    memory_overcommit_ratio: f64,
}

#[derive(Clone, Copy, Debug)]
struct ComputeCapacity {
    schedulable_vcpus: u64,
    available_vcpus: u64,
    schedulable_memory_bytes: u64,
    available_memory_bytes: u64,
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    pub limit: Option<usize>,
    pub since: Option<i64>,
    pub range: Option<String>,
    pub status: Option<String>,
    pub vm_id: Option<String>,
    pub before_id: Option<i64>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub family: Option<u8>,
    pub scope: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct NetworkRecordQuery {
    pub address: Option<String>,
    pub vm_id: Option<String>,
    #[serde(default)]
    pub unresolved_only: bool,
    #[serde(default)]
    pub active_only: bool,
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageUpdateBody {
    pub component: UpdateComponent,
    pub manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveUpdateBody {
    pub expected_release: String,
    pub expected_manifest_sha256: String,
    pub components: BTreeSet<UpdateComponent>,
    #[serde(default)]
    pub maintenance_impact_accepted: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRollbackBody {
    pub expected_activation_id: String,
    pub expected_previous_release: String,
    #[serde(default)]
    pub maintenance_impact_accepted: bool,
}

pub struct CreateVmBody {
    pub spec: NewVm,
    pub password: Option<String>,
    pub ip_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub start: bool,
    pub install_guest_tools: bool,
    /// Serde's `NewVm` compatibility default is `root`, so retain whether the
    /// API caller actually supplied the field before applying an image-aware
    /// default. An explicit value must never be replaced when the image is
    /// Windows.
    root_username_was_supplied: bool,
}

#[derive(Deserialize)]
struct CreateVmBodyWire {
    #[serde(flatten)]
    spec: NewVm,
    password: Option<String>,
    #[serde(default, alias = "ip_address_ids")]
    ip_addresses: Vec<String>,
    #[serde(default)]
    dns_servers: Vec<String>,
    #[serde(default = "default_true")]
    start: bool,
    #[serde(default)]
    install_guest_tools: bool,
}

impl<'de> Deserialize<'de> for CreateVmBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let root_username_was_supplied = value
            .as_object()
            .is_some_and(|object| object.contains_key("root_username"));
        let wire: CreateVmBodyWire = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            spec: wire.spec,
            password: wire.password,
            ip_addresses: wire.ip_addresses,
            dns_servers: wire.dns_servers,
            start: wire.start,
            install_guest_tools: wire.install_guest_tools,
            root_username_was_supplied,
        })
    }
}

#[derive(Deserialize)]
pub struct SecretBody {
    pub password: String,
}

#[derive(Deserialize)]
pub struct MaintenanceBody {
    pub enabled: bool,
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct DiskProtectionBody {
    pub deletion_lock: bool,
    pub snapshot_before_reinstall: bool,
}

#[derive(Deserialize)]
pub struct AbuseResolutionBody {
    pub resolution: String,
}

#[derive(Deserialize, Default)]
pub struct VmUpdateBody {
    pub hostname: Option<String>,
    pub description: Option<String>,
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    pub disk_gib: Option<u64>,
    #[serde(default, deserialize_with = "crate::models::deserialize_nullable")]
    pub network_limit_mbps: Option<Option<u64>>,
    #[serde(default, deserialize_with = "crate::models::deserialize_nullable")]
    pub traffic_limit_bytes: Option<Option<u64>>,
    pub autostart: Option<bool>,
    #[serde(default, deserialize_with = "crate::models::deserialize_nullable")]
    pub timezone: Option<Option<String>>,
    pub metadata: Option<Value>,
}

#[derive(Deserialize)]
pub struct DnsBody {
    #[serde(alias = "dns")]
    pub dns_servers: Vec<String>,
}

#[derive(Deserialize)]
pub struct SshKeysBody {
    #[serde(default)]
    pub ssh_keys: Vec<String>,
}

#[derive(Deserialize)]
pub struct CreateTokenBody {
    pub expires_at: Option<Value>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub bound_ip: Option<String>,
}

#[derive(Deserialize)]
pub struct IpAddressPatch {
    pub status: Option<IpStatus>,
    pub vm_id: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Deserialize)]
pub struct CreateIpPoolBody {
    #[serde(flatten)]
    pub pool: NewIpPool,
    /// Individual addresses, inclusive `start-end` ranges, or small CIDRs.
    #[serde(default)]
    pub reserved: Vec<String>,
}

#[derive(Deserialize)]
pub struct CompatibilitySetIpBody {
    pub address: String,
    pub status: Option<IpStatus>,
    pub vm_id: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Deserialize)]
pub struct CompatibilityPowerBody {
    #[serde(alias = "id", alias = "name")]
    pub vm_id: String,
    #[serde(default = "default_reboot_action")]
    pub action: String,
}

#[derive(Deserialize)]
pub struct SettingsBody {
    #[serde(flatten)]
    pub values: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
pub struct ApiKeyBody {
    pub name: String,
    #[serde(default, alias = "scopes")]
    pub permissions: Vec<String>,
    pub expires_at: Option<Value>,
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
}

#[derive(Deserialize)]
pub struct CredentialsBody {
    pub current_password: String,
    pub username: Option<String>,
    pub new_password: Option<String>,
}

#[derive(Deserialize)]
pub struct NewIsoBody {
    pub id: Option<String>,
    pub slug: String,
    pub name: String,
    pub version: Option<String>,
    pub os_family: String,
    #[serde(default = "default_architecture")]
    pub architecture: String,
    pub install_mode: Option<InstallMode>,
    pub provisioning_mode: Option<String>,
    #[serde(alias = "url")]
    pub source_url: Option<String>,
    #[serde(alias = "path")]
    pub local_path: Option<String>,
    #[serde(alias = "sha256")]
    pub checksum_sha256: Option<String>,
    pub size_bytes: Option<u64>,
    #[serde(default)]
    #[serde(alias = "guest_agent")]
    pub supports_guest_agent: bool,
    #[serde(default)]
    pub supports_cloud_init: bool,
    #[serde(default)]
    pub uefi: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Deserialize)]
pub struct SnapshotBody {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct ReinstallBody {
    #[serde(alias = "iso_id")]
    pub image_id: String,
    pub password: Option<String>,
    #[serde(default = "default_true")]
    pub start: bool,
    #[serde(default)]
    pub install_guest_tools: bool,
    /// Optional replacement disk size for destructive plan downgrades. Disk
    /// growth remains the resize endpoint's responsibility.
    pub disk_gib: Option<u64>,
}

#[derive(Deserialize)]
pub struct AssignIpBody {
    pub vm_id: String,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Deserialize)]
pub struct AdminCreateBody {
    pub username: String,
    pub password: String,
    #[serde(default = "default_admin_role")]
    pub role: AdminRole,
}

#[derive(Deserialize)]
pub struct AdminPatchBody {
    pub role: Option<AdminRole>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct AdminCredentialUpdateBody {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct IsoPatchBody {
    pub slug: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub os_family: Option<String>,
    pub architecture: Option<String>,
    pub install_mode: Option<InstallMode>,
    pub source_url: Option<String>,
    pub local_path: Option<String>,
    pub checksum_sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub supports_guest_agent: Option<bool>,
    pub supports_cloud_init: Option<bool>,
    pub uefi: Option<bool>,
    pub enabled: Option<bool>,
    pub metadata: Option<Value>,
}

pub async fn healthz(State(state): State<Arc<AppState>>) -> Response {
    let capabilities = state.hypervisor.capabilities().await.ok();
    Json(json!({
        "ok": true,
        "database": "ready",
        "hypervisor_ready": capabilities.as_ref().is_some_and(|item| item.available),
        "backend": capabilities.as_ref().map(|item| &item.backend),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

pub async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    let database_ready = state.db.schema_version().is_ok();
    let hypervisor = state.hypervisor.capabilities().await.ok();
    let ready = database_ready && hypervisor.as_ref().is_some_and(|item| item.available);
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "ready": ready,
            "database_ready": database_ready,
            "hypervisor": hypervisor,
        })),
    )
        .into_response()
}

pub async fn host(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("host:read")?;
    let host = state.host_info.read().await.clone();
    let capabilities = state.hypervisor.capabilities().await?;
    let vms = state.db.list_vms()?;
    let addresses = state.db.list_ip_addresses(None, None, None)?;
    let allocated_vcpus: u32 = vms.iter().map(|vm| vm.vcpus).sum();
    let allocated_ram_bytes: u64 = vms
        .iter()
        .map(|vm| vm.memory_mib.saturating_mul(1024 * 1024))
        .sum();
    let scheduled = vms.iter().filter(|vm| vm.state != crate::models::VmState::Error);
    let scheduled_vcpus = scheduled
        .clone()
        .fold(0u64, |total, vm| total.saturating_add(u64::from(vm.vcpus)));
    let scheduled_memory_bytes = scheduled.fold(0u64, |total, vm| {
        total.saturating_add(vm.memory_mib.saturating_mul(MIB_BYTES))
    });
    let capacity_policy = capacity_policy(&state)?;
    let compute_capacity = compute_capacity(
        u64::from(host.cpu.logical_cores),
        host.memory.total_bytes,
        scheduled_vcpus,
        scheduled_memory_bytes,
        capacity_policy,
    );
    let primary_interface = host
        .primary_interface
        .as_deref()
        .and_then(|name| host.interfaces.iter().find(|interface| interface.name == name));
    let primary_ip = primary_interface
        .and_then(|interface| {
            interface
                .addresses
                .iter()
                .find(|address| address.is_primary)
                .or_else(|| interface.addresses.first())
        })
        .map(|address| address.address.to_string());
    let latest_metric = state
        .db
        .host_metrics(Utc::now().timestamp() - 300, 1)?
        .into_iter()
        .next();
    let mut value = serde_json::to_value(&host)
        .map_err(|error| AppError::Internal(format!("could not encode host: {error}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("host serialization was not an object".into()))?;
    object.insert("cpu_cores".into(), json!(host.cpu.physical_cores));
    object.insert("cpu_threads".into(), json!(host.cpu.logical_cores));
    object.insert("cpu_model".into(), json!(host.cpu.model));
    object.insert("ram_total_bytes".into(), json!(host.memory.total_bytes));
    object.insert("allocated_vcpus".into(), json!(allocated_vcpus));
    object.insert("allocated_ram_bytes".into(), json!(allocated_ram_bytes));
    object.insert(
        "capacity_policy".into(),
        json!({
            "cpu_overcommit_ratio": capacity_policy.cpu_overcommit_ratio,
            "memory_overcommit_ratio": capacity_policy.memory_overcommit_ratio,
            "memory_backing": "virtio-balloon-full-entitlement",
        }),
    );
    object.insert(
        "capabilities".into(),
        json!({
            "reinstall_disk_resize": true,
            "full_memory_entitlement": true,
        }),
    );
    object.insert(
        "schedulable_vcpus".into(),
        json!(compute_capacity.schedulable_vcpus),
    );
    object.insert("available_vcpus".into(), json!(compute_capacity.available_vcpus));
    object.insert(
        "schedulable_memory_bytes".into(),
        json!(compute_capacity.schedulable_memory_bytes),
    );
    object.insert(
        "available_memory_bytes".into(),
        json!(compute_capacity.available_memory_bytes),
    );
    object.insert("listen_address".into(), json!(state.config.bind.ip()));
    object.insert("listen_port".into(), json!(state.config.bind.port()));
    object.insert("public_url".into(), json!(state.config.public_url));
    object.insert("public_interface".into(), json!(host.primary_interface));
    object.insert("primary_ip".into(), json!(primary_ip));
    object.insert(
        "public_gateway".into(),
        json!(host.default_gateway_v4.or(host.default_gateway_v6)),
    );
    object.insert("mtu".into(), json!(primary_interface.and_then(|item| item.mtu)));
    object.insert(
        "network".into(),
        json!({
            "interface": host.primary_interface,
            "online": primary_interface.is_some_and(|item| item.state == "up"),
            "rx_bytes": primary_interface.map(|item| item.rx_bytes).unwrap_or_default(),
            "tx_bytes": primary_interface.map(|item| item.tx_bytes).unwrap_or_default(),
            "rx_bps": latest_metric.as_ref().map(|item| item.network_rx_bps).unwrap_or_default(),
            "tx_bps": latest_metric.as_ref().map(|item| item.network_tx_bps).unwrap_or_default(),
        }),
    );
    object.insert(
        "storage_free_bytes".into(),
        json!(host
            .filesystems
            .iter()
            .find(|item| item.mount_point == "/")
            .or_else(|| host.filesystems.iter().max_by_key(|item| item.total_bytes))
            .map(|item| item.available_bytes)
            .unwrap_or_default()),
    );
    object.insert(
        "ip_addresses".into(),
        json!(host
            .interfaces
            .iter()
            .filter(|item| !item.is_loopback)
            .flat_map(|item| item.addresses.iter().map(|address| json!({
                "address": address.address,
                "prefix_length": address.prefix_len,
                "scope": if is_private_address(address.address) { "private" } else { "public" },
                "interface": item.name,
                "primary": address.is_primary,
            })))
            .collect::<Vec<_>>()),
    );
    object.insert("hypervisor".into(), json!(capabilities));
    object.insert("kvm_available".into(), json!(host.cpu.kvm_device_available));
    object.insert(
        "ip_capacity".into(),
        json!({
            "total": addresses.len(),
            "used": addresses.iter().filter(|ip| ip.status == IpStatus::Used).count(),
            "free": addresses.iter().filter(|ip| ip.status == IpStatus::Free).count(),
            "reserved": addresses.iter().filter(|ip| ip.status == IpStatus::Reserved).count(),
            "ipv4": addresses.iter().filter(|ip| ip.family == AddressFamily::V4).count(),
            "ipv6": addresses.iter().filter(|ip| ip.family == AddressFamily::V6).count(),
        }),
    );
    object.insert(
        "services".into(),
        json!([
            {"name":"Vexa-VM", "status":"healthy", "healthy":true},
            {"name":"SQLite", "status":"healthy", "healthy":true},
            {"name":"Hypervisor", "status": if capabilities.available {"healthy"} else {"unavailable"}, "healthy": capabilities.available},
            {"name":"KVM device", "status": if host.cpu.kvm_device_available {"healthy"} else {"unavailable"}, "healthy": host.cpu.kvm_device_available}
        ]),
    );
    Ok(Json(json!({ "host": value })).into_response())
}

pub async fn host_metrics(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListQuery>,
) -> AppResult<Response> {
    auth.require("host:read")?;
    let now = Utc::now().timestamp();
    let since = query
        .since
        .unwrap_or_else(|| now - parse_range(query.range.as_deref()));
    let mut samples = state.db.host_metrics(since, query.limit.unwrap_or(1_000))?;
    samples.reverse();
    let current = samples.last().cloned();
    let value = if let Some(metric) = current {
        json!({
            "sampled_at": metric.sampled_at,
            "cpu": {"usage_pct": metric.cpu_percent, "history": samples.iter().map(|item| item.cpu_percent).collect::<Vec<_>>()},
            "memory": {"total_bytes": metric.memory_total_bytes, "used_bytes": metric.memory_used_bytes, "history": samples.iter().map(|item| if item.memory_total_bytes == 0 { 0.0 } else { item.memory_used_bytes as f64 * 100.0 / item.memory_total_bytes as f64 }).collect::<Vec<_>>()},
            "storage": {"total_bytes": metric.disk_total_bytes, "used_bytes": metric.disk_used_bytes, "read_bps": metric.disk_read_bps, "write_bps": metric.disk_write_bps},
            "network": {"rx_bytes": metric.network_rx_bytes, "tx_bytes": metric.network_tx_bytes, "rx_bps": metric.network_rx_bps, "tx_bps": metric.network_tx_bps},
            "uptime_seconds": metric.uptime_seconds,
            "samples": samples,
        })
    } else {
        json!({ "samples": [], "stale": true })
    };
    Ok(Json(json!({ "metrics": value })).into_response())
}

pub async fn list_vms(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let mut items = Vec::new();
    for vm in state.db.list_vms()? {
        items.push(enrich_vm(&state, vm)?);
    }
    Ok(Json(json!({ "items": items, "page": {"next_cursor": null} })).into_response())
}

pub async fn get_vm(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    Ok(Json(json!({ "vm": enrich_vm(&state, vm)? })).into_response())
}

pub async fn create_vm(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(mut input): Json<CreateVmBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let idempotency_key = idempotency_key(&headers)?;
    let request_fingerprint = create_vm_request_fingerprint(&input)?;
    if let Some(response) =
        replay_create_vm_request(&state, idempotency_key.as_deref(), &request_fingerprint)?
    {
        return Ok(response);
    }
    apply_vm_defaults(&state, &mut input)?;
    let builtin_routeros = input
        .spec
        .iso_id
        .as_deref()
        .map(|id| state.db.get_iso(id))
        .transpose()?
        .flatten()
        .is_some_and(|image| crate::services::guest_tools::is_builtin_routeros_image(&image));
    if builtin_routeros && input.spec.root_username.eq_ignore_ascii_case("admin") {
        return Err(AppError::Validation(
            "RouterOS reserves its insecure factory 'admin' account; use 'vexa-admin' or another administrator name"
                .into(),
        ));
    }
    if input.spec.mac_address.is_none() {
        input.spec.mac_address = Some(random_mac());
    }
    if input.spec.bridge.is_none() {
        input.spec.bridge = Some(state.config.network_bridge.clone());
    }
    let routed_network_created =
        crate::services::routed_network::configure_new_vm(&state, &mut input.spec, &input.ip_addresses)
            .await?;
    if builtin_routeros && !routed_network_created {
        return Err(AppError::Validation(
            "automatic RouterOS credentials require a routed public IPv4 /32".into(),
        ));
    }
    let guest_tools_install = if input.install_guest_tools {
        let image_id = input.spec.iso_id.as_deref().ok_or_else(|| {
            AppError::Validation("Vexa Guest Tools requires a compatible cloud image".into())
        })?;
        let image = state
            .db
            .get_iso(image_id)?
            .ok_or_else(|| AppError::NotFound("ISO image".into()))?;
        if crate::services::guest_tools::is_builtin_routeros_image(&image) {
            None
        } else {
            Some(crate::services::guest_tools::require_installable(
                &state.config,
                &image,
            )?)
        }
    } else {
        None
    };
    let mut request = build_create_request(&state, &input.spec, input.start)?;
    let manual_install = request.image.is_manual_installer();
    if manual_install && input.password.is_some() {
        return Err(AppError::Validation(
            "manual installer ISOs cannot provision a guest password; set it inside the installer".into(),
        ));
    }
    let supplied_password = input
        .password
        .as_deref()
        .map(str::trim)
        .filter(|password| !password.is_empty())
        .map(str::to_owned);
    let provisions_password = !manual_install;
    let generated_password = provisions_password && supplied_password.is_none();
    let password = provisions_password.then(|| supplied_password.unwrap_or_else(random_guest_password));
    if let Some(password) = password.as_deref() {
        validate_guest_password(&input.spec.root_username, password)?;
    }

    // The `creating` VM row is the durable reservation counted by
    // `validate_create_capacity`. Keep this guard from the idempotency/name
    // rechecks through job publication (or provisional-row cleanup) so two
    // simultaneous creates cannot both validate against the same snapshot.
    // Request parsing and image/password validation above stay outside the
    // critical section. No hypervisor work runs in this request and this
    // handler never waits for the background worker.
    let create_reservation_guard = state.vm_create_reservation_lock.lock().await;
    if let Some(response) =
        replay_create_vm_request(&state, idempotency_key.as_deref(), &request_fingerprint)?
    {
        return Ok(response);
    }
    if let Some(existing) = state.db.get_vm(&input.spec.name)? {
        let guidance = if existing.state == crate::models::VmState::Error {
            "delete the failed VM record before retrying"
        } else {
            "choose a different VM name"
        };
        return Err(AppError::Conflict(format!(
            "VM '{}' already exists; {guidance}",
            input.spec.name
        )));
    }
    request.initial_memory_mib = Some(validate_create_capacity(&state, &input.spec, input.start).await?);
    let vm = match password.as_deref() {
        Some(password) => state
            .db
            .create_vm_with_password(&input.spec, password, &state.security)?,
        None => state.db.create_vm(&input.spec)?,
    };
    // There are deliberately no await points after the provisional row is
    // inserted. Besides keeping the critical section short, this prevents
    // request cancellation from stranding a half-published reservation. Every
    // fallible related write is folded into one cleanup path.
    let publish_result = (|| -> AppResult<crate::models::Job> {
        if let Some(install) = guest_tools_install {
            let secret = crate::services::guest_tools::new_secret();
            state.db.configure_vm_guest_tools(
                &vm.id,
                install.platform,
                install.provisioner,
                &secret,
                &state.config.guest_tools_version,
                &state.security,
            )?;
            request.guest_tools_socket =
                Some(crate::services::guest_tools::socket_path(&state.config, &vm.id)?);
        }
        for (index, address_or_id) in input.ip_addresses.iter().enumerate() {
            let address = state
                .db
                .get_ip_address(address_or_id)?
                .map(|record| record.address)
                .unwrap_or_else(|| address_or_id.clone());
            state.db.assign_ip(&address, &vm.id, index == 0)?;
        }
        state
            .db
            .replace_dns_servers(None, Some(&vm.id), &input.dns_servers)?;

        let payload = json!({
            "request": request,
            "ip_addresses": input.ip_addresses.clone(),
            "dns_servers": input.dns_servers.clone(),
            "request_fingerprint": request_fingerprint,
        });
        enqueue(&state, &auth, "vm.create", Some(&vm.id), payload, idempotency_key)
    })();

    let job = match publish_result {
        Ok(job) => job,
        Err(error) => {
            if let Err(cleanup_error) = state.db.delete_vm(&vm.id) {
                tracing::error!(
                    vm_id = %vm.id,
                    error = %cleanup_error,
                    "failed to remove a provisional VM after create publication failed"
                );
            }
            return Err(error);
        }
    };
    drop(create_reservation_guard);
    audit(
        &state,
        &auth,
        "vm.create",
        "vm",
        Some(&vm.id),
        true,
        json!({
            "name": vm.name,
            "job_id": job.id,
        }),
    );
    let mut response = (
        StatusCode::ACCEPTED,
        Json(json!({
            "vm": vm,
            "operation": job,
            "generated_password": if generated_password { password } else { None },
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn replay_create_vm_request(
    state: &AppState,
    idempotency_key: Option<&str>,
    request_fingerprint: &str,
) -> AppResult<Option<Response>> {
    let Some(existing) = idempotency_key
        .map(|key| state.db.job_by_idempotency_key(key))
        .transpose()?
        .flatten()
    else {
        return Ok(None);
    };
    let matches_original = existing.kind == "vm.create"
        && existing
            .payload
            .get("request_fingerprint")
            .and_then(Value::as_str)
            == Some(request_fingerprint);
    if !matches_original {
        return Err(AppError::Conflict(
            "idempotency key was already used for a different request".into(),
        ));
    }
    let vm_id = existing
        .vm_id
        .as_deref()
        .ok_or_else(|| AppError::Conflict("the original job has no VM".into()))?;
    let vm = state
        .db
        .get_vm(vm_id)?
        .ok_or_else(|| AppError::Conflict("the original VM no longer exists".into()))?;
    let mut response = (
        StatusCode::ACCEPTED,
        Json(json!({ "vm": vm, "operation": existing, "replayed": true })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(Some(response))
}

pub async fn patch_vm(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<VmUpdateBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let idempotency_key = idempotency_key(&headers)?;
    let current = required_vm(&state, &id)?;
    let resize = ResizeVmRequest {
        vcpus: input.vcpus,
        memory_mib: input.memory_mib,
        disk_gib: input.disk_gib,
        network_limit_mbps: input.network_limit_mbps,
    };
    if resize.disk_gib.is_some_and(|disk| disk < current.disk_gib) {
        return Err(AppError::Validation("VM disks cannot be shrunk".into()));
    }
    if let Some(Some(timezone)) = input.timezone.as_ref() {
        validate_timezone_name(timezone)?;
    }
    if input.metadata.as_ref().is_some_and(|value| !value.is_object()) {
        return Err(AppError::Validation("VM metadata must be a JSON object".into()));
    }
    let requested_hostname = input.hostname.clone();
    if let Some(hostname) = requested_hostname.as_deref() {
        GuestCommand::SetHostname {
            hostname: hostname.to_owned(),
        }
        .validate()
        .map_err(|error| AppError::Validation(error.to_string()))?;
    }
    if resize.vcpus.is_some()
        || resize.memory_mib.is_some()
        || resize.disk_gib.is_some()
        || resize.network_limit_mbps.is_some()
    {
        crate::hypervisor::validate_resize_request(&resize)?;
    }
    let traffic_limit_changed = input.traffic_limit_bytes.is_some();
    let patch = VmPatch {
        hostname: input.hostname,
        description: input.description,
        traffic_limit_bytes: input.traffic_limit_bytes,
        autostart: input.autostart,
        timezone: input.timezone,
        metadata: input.metadata,
        ..VmPatch::default()
    };
    let vm = if traffic_limit_changed {
        let _traffic_guard = state.traffic_lock.lock().await;
        let vm = state.db.patch_vm(&id, &patch)?;
        crate::services::traffic::reconcile_vm_locked(&state, &vm.id, false).await?;
        vm
    } else {
        state.db.patch_vm(&id, &patch)?
    };
    let operation = if resize.vcpus.is_some()
        || resize.memory_mib.is_some()
        || resize.disk_gib.is_some()
        || resize.network_limit_mbps.is_some()
    {
        Some(enqueue(
            &state,
            &auth,
            "vm.resize",
            Some(&vm.id),
            json!({ "request": resize }),
            idempotency_key,
        )?)
    } else {
        None
    };
    let guest_tools = if let Some(hostname) = requested_hostname {
        Some(
            crate::services::guest_tools::try_apply(&state, &vm, GuestCommand::SetHostname { hostname })
                .await,
        )
    } else {
        None
    };
    audit(
        &state,
        &auth,
        "vm.update",
        "vm",
        Some(&vm.id),
        true,
        json!({ "guest_tools": &guest_tools }),
    );
    Ok(Json(json!({
        "vm": enrich_vm(&state, vm)?,
        "operation": operation,
        "guest_tools": guest_tools,
    }))
    .into_response())
}

/// Enable or clear a control-plane maintenance window. Administrators retain
/// access; customer-token mutations are blocked until the window is cleared.
pub async fn set_vm_maintenance(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<MaintenanceBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let reason = input.reason.unwrap_or_default().trim().to_owned();
    if reason.len() > 500 {
        return Err(AppError::Validation(
            "maintenance reason must be 500 characters or fewer".into(),
        ));
    }
    let mut metadata = if vm.metadata.is_object() {
        vm.metadata.clone()
    } else {
        json!({})
    };
    metadata.as_object_mut().expect("object created above").insert(
        "maintenance".into(),
        json!({
            "enabled": input.enabled,
            "reason": reason.clone(),
            "changed_at": Utc::now().timestamp(),
            "changed_by": auth.actor_id.clone(),
        }),
    );
    let vm = state.db.patch_vm(
        &vm.id,
        &VmPatch {
            metadata: Some(metadata),
            ..VmPatch::default()
        },
    )?;
    audit(
        &state,
        &auth,
        if input.enabled {
            "vm.maintenance.enable"
        } else {
            "vm.maintenance.disable"
        },
        "vm",
        Some(&vm.id),
        true,
        json!({ "reason": reason }),
    );
    Ok(Json(json!({ "vm": enrich_vm(&state, vm)? })).into_response())
}

pub async fn set_vm_disk_protection(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<DiskProtectionBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let mut metadata = if vm.metadata.is_object() {
        vm.metadata.clone()
    } else {
        json!({})
    };
    metadata.as_object_mut().expect("object created above").insert(
        "disk_protection".into(),
        json!({
            "deletion_lock": input.deletion_lock,
            "snapshot_before_reinstall": input.snapshot_before_reinstall,
            "changed_at": Utc::now().timestamp(),
            "changed_by": auth.actor_id.clone(),
        }),
    );
    let vm = state.db.patch_vm(
        &vm.id,
        &VmPatch {
            metadata: Some(metadata),
            ..VmPatch::default()
        },
    )?;
    audit(
        &state,
        &auth,
        "vm.disk_protection.update",
        "vm",
        Some(&vm.id),
        true,
        json!({
            "deletion_lock": input.deletion_lock,
            "snapshot_before_reinstall": input.snapshot_before_reinstall,
        }),
    );
    Ok(Json(json!({ "vm": enrich_vm(&state, vm)? })).into_response())
}

pub async fn reset_vm_traffic(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let previous_usage_bytes = vm.traffic_used_bytes;
    let _traffic_guard = state.traffic_lock.lock().await;
    let vm = crate::services::traffic::reset_usage_locked(&state, &vm.id).await?;
    let quota = crate::services::traffic::reconcile_vm_locked(&state, &vm.id, false).await?;
    audit(
        &state,
        &auth,
        "vm.traffic.reset",
        "vm",
        Some(&vm.id),
        true,
        json!({ "previous_usage_bytes": previous_usage_bytes }),
    );
    Ok(Json(json!({ "vm": enrich_vm(&state, vm)?, "traffic_quota": quota })).into_response())
}

pub async fn delete_vm(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let idempotency_key = idempotency_key(&headers)?;
    if let Some(existing) = idempotency_key
        .as_deref()
        .map(|key| state.db.job_by_idempotency_key(key))
        .transpose()?
        .flatten()
    {
        let matches_target = existing.kind == "vm.delete"
            && (existing.payload.get("target_vm_id").and_then(Value::as_str) == Some(id.as_str())
                || existing.payload.get("target_vm_name").and_then(Value::as_str) == Some(id.as_str())
                || existing.vm_id.as_deref() == Some(id.as_str()));
        if !matches_target {
            return Err(AppError::Conflict(
                "idempotency key was already used for a different request".into(),
            ));
        }
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "operation": existing, "replayed": true })),
        )
            .into_response());
    }
    let vm = required_vm(&state, &id)?;
    if vm
        .metadata
        .pointer("/disk_protection/deletion_lock")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(AppError::Conflict(
            "VM deletion is locked; disable disk protection before deleting it".into(),
        ));
    }
    let job = state.db.enqueue_delete_job(&NewJob {
        kind: "vm.delete".into(),
        vm_id: Some(vm.id.clone()),
        payload: json!({
            "delete_storage": true,
            "target_vm_id": vm.id.clone(),
            "target_vm_name": vm.name.clone(),
        }),
        idempotency_key,
        run_after: None,
        // Domain deletion, seed unlink, directory durability, and database
        // release form one idempotent workflow. Bounded worker retries let a
        // transient cleanup error finish without dropping DB ownership of the
        // credential-bearing seed.
        max_attempts: 3,
        actor_type: Some(auth.actor_type.into()),
        actor_id: Some(auth.actor_id.clone()),
    })?;
    audit(
        &state,
        &auth,
        "vm.delete.request",
        "vm",
        Some(&vm.id),
        true,
        json!({ "job_id": job.id }),
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "operation": job }))).into_response())
}

pub async fn vm_action(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((id, action)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    auth.require("vms:power")?;
    let vm = required_vm(&state, &id)?;
    if vm.libvirt_uuid.is_none()
        && matches!(
            vm.state,
            crate::models::VmState::Creating | crate::models::VmState::Error
        )
    {
        return Err(AppError::Conflict(
            "the VM has no hypervisor domain; delete the failed record and create it again".into(),
        ));
    }
    let action = parse_power_action(&action)?;
    let job = enqueue(
        &state,
        &auth,
        "vm.power",
        Some(&vm.id),
        json!({ "action": action }),
        idempotency_key(&headers)?,
    )?;
    audit(
        &state,
        &auth,
        "vm.power",
        "vm",
        Some(&vm.id),
        true,
        json!({ "job_id": job.id }),
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "operation": job }))).into_response())
}

/// Compatibility endpoint for `POST /api/vms/reboot`. New integrations should
/// use `POST /api/v1/vms/{id}/actions/{action}`.
pub async fn compatibility_power_action(
    state: State<Arc<AppState>>,
    auth: Extension<AuthContext>,
    headers: HeaderMap,
    Json(input): Json<CompatibilityPowerBody>,
) -> AppResult<Response> {
    vm_action(state, auth, Path((input.vm_id, input.action)), headers).await
}

/// Path-shaped compatibility action used by `/api/vms/{id}/reboot`.
pub async fn compatibility_reboot_path(
    state: State<Arc<AppState>>,
    auth: Extension<AuthContext>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    vm_action(state, auth, Path((id, "reboot".into())), headers).await
}

pub async fn reinstall_vm(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ReinstallBody>,
) -> AppResult<Response> {
    auth.require("vms:reinstall")?;
    let vm = required_vm(&state, &id)?;
    let idempotency_key = idempotency_key(&headers)?;
    let replacement_disk_gib = input.disk_gib.unwrap_or(vm.disk_gib);
    if !(1..=vm.disk_gib).contains(&replacement_disk_gib) {
        return Err(AppError::Validation(format!(
            "reinstall disk size must be between 1 GiB and the current {} GiB; use VM resize for disk growth",
            vm.disk_gib
        )));
    }
    let request_fingerprint = reinstall_request_fingerprint(
        &vm.id,
        &input.image_id,
        input.start,
        input.install_guest_tools,
        replacement_disk_gib,
        input
            .password
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
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
            Json(json!({ "operation": existing, "replayed": true })),
        )
            .into_response());
    }
    let image_record = state
        .db
        .get_iso(&input.image_id)?
        .ok_or_else(|| AppError::NotFound("ISO image".into()))?;
    let image = vm_image_from_iso(image_record.clone())?;
    let manual_install = image.is_manual_installer();
    if manual_install && input.password.is_some() {
        return Err(AppError::Validation(
            "manual installer ISOs cannot provision a guest password; set it inside the installer".into(),
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
    if !manual_install && password_envelope.is_none() && state.db.vm_password_envelope(&vm.id)?.is_none() {
        return Err(AppError::Validation(
            "an automated reinstall requires a guest password because this VM has no stored credential"
                .into(),
        ));
    }
    let current_guest_tools = state.db.vm_guest_tools(&vm.id)?;
    let builtin_guest_integration = crate::services::guest_tools::is_builtin_routeros_image(&image_record);
    let wants_guest_tools = input.install_guest_tools && !builtin_guest_integration;
    let disable_guest_tools_after_success =
        current_guest_tools.as_ref().is_some_and(|record| record.enabled) && !wants_guest_tools;
    let guest_tools_stage = stage_reinstall_guest_tools(
        &state,
        &vm,
        &image_record,
        wants_guest_tools,
        &request_fingerprint,
    )?;
    let guest_tools_socket = guest_tools_stage.as_ref().map(|stage| stage.socket_path.clone());
    let payload = json!({
        "request": ReinstallVmRequest {
            image,
            disk_gib: replacement_disk_gib,
            cloud_init_iso: None,
            guest_tools_socket,
            start: input.start,
        },
        "clear_password_after_success": manual_install,
        "request_fingerprint": request_fingerprint,
        "_guest_tools_rotation_generation": guest_tools_stage.as_ref().map(|stage| &stage.generation),
        "guest_tools_new_configuration": guest_tools_stage.as_ref().is_some_and(|stage| stage.new_configuration),
        "disable_guest_tools_after_success": disable_guest_tools_after_success,
        "replacement_iso_id": image_record.id.clone(),
        "replacement_os_family": image_record.os_family.clone(),
        "replacement_root_username": guest_administrator_default(&image_record.os_family),
        "replacement_disk_gib": replacement_disk_gib,
    });
    let job = match state.db.enqueue_reinstall_job(
        &NewJob {
            kind: "vm.reinstall".into(),
            vm_id: Some(vm.id.clone()),
            payload,
            idempotency_key,
            run_after: None,
            max_attempts: 1,
            actor_type: Some(auth.actor_type.into()),
            actor_id: Some(auth.actor_id.clone()),
        },
        password_envelope.as_deref(),
        if input.start {
            crate::models::VmState::Running
        } else {
            crate::models::VmState::Stopped
        },
    ) {
        Ok(job) => job,
        Err(error) => {
            if let Some(stage) = guest_tools_stage.as_ref() {
                cleanup_uncommitted_guest_tools_stage(&state, &vm.id, stage);
            }
            return Err(error);
        }
    };
    audit(
        &state,
        &auth,
        "vm.reinstall.request",
        "vm",
        Some(&vm.id),
        true,
        json!({ "job_id": job.id }),
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "operation": job }))).into_response())
}

pub async fn vm_metrics(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    let since = query
        .since
        .unwrap_or_else(|| Utc::now().timestamp() - parse_range(query.range.as_deref()));
    let mut items = state.db.vm_metrics(&vm.id, since, query.limit.unwrap_or(2_000))?;
    items.reverse();
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn reveal_vm_password(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:password:read")?;
    let vm = required_vm(&state, &id)?;
    let password = state
        .db
        .decrypt_vm_password(&vm.id, &state.security)?
        .ok_or_else(|| AppError::NotFound("VM password".into()))?;
    audit(
        &state,
        &auth,
        "vm.password.reveal",
        "vm",
        Some(&vm.id),
        true,
        json!({}),
    );
    let mut response = Json(json!({ "password": password, "hide_after_seconds": 30 })).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    Ok(response)
}

pub async fn update_vm_password(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<SecretBody>,
) -> AppResult<Response> {
    auth.require("vms:password:write")?;
    let vm = required_vm(&state, &id)?;
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
    audit(
        &state,
        &auth,
        "vm.password.update",
        "vm",
        Some(&vm.id),
        true,
        json!({ "guest_tools": &applied }),
    );
    Ok(Json(json!({
        "updated": updated,
        "guest_agent_applied": applied.applied,
        "guest_tools": applied,
    }))
    .into_response())
}

pub async fn update_vm_dns(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<DnsBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let items = state
        .db
        .replace_dns_servers(None, Some(&vm.id), &input.dns_servers)?;
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
    audit(
        &state,
        &auth,
        "vm.dns.update",
        "vm",
        Some(&vm.id),
        true,
        json!({ "count": items.len(), "guest_tools": &applied }),
    );
    Ok(Json(json!({
        "items": items,
        "guest_agent_applied": applied.applied,
        "guest_tools": applied,
    }))
    .into_response())
}

pub async fn get_vm_dns(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    Ok(Json(json!({
        "items": state.db.dns_servers(None, Some(&vm.id))?
    }))
    .into_response())
}

pub async fn get_vm_ssh_keys(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    let keys = vm
        .metadata
        .get("ssh_keys")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(Json(json!({ "items": keys })).into_response())
}

pub async fn update_vm_ssh_keys(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<SshKeysBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let keys = normalize_ssh_keys(input.ssh_keys)?;
    let mut metadata = vm.metadata.clone();
    metadata
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("VM metadata is not an object".into()))?
        .insert("ssh_keys".into(), json!(keys));
    state.db.patch_vm(
        &vm.id,
        &VmPatch {
            metadata: Some(metadata),
            ..VmPatch::default()
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
    audit(
        &state,
        &auth,
        "vm.ssh_keys.update",
        "vm",
        Some(&vm.id),
        true,
        json!({ "count": keys.len(), "guest_tools": &applied }),
    );
    Ok(Json(json!({
        "updated": true,
        "count": keys.len(),
        "guest_agent_applied": applied.applied,
        "guest_tools": applied,
    }))
    .into_response())
}

pub async fn get_vm_guest_tools(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    let status = crate::services::guest_tools::admin_status_for_vm(&vm, state.db.vm_guest_tools(&vm.id)?);
    Ok(Json(json!({ "guest_tools": status })).into_response())
}

pub async fn probe_vm_guest_tools(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    let result = crate::services::guest_tools::probe(&state, &vm).await;
    audit(
        &state,
        &auth,
        "vm.guest_tools.probe",
        "vm",
        Some(&vm.id),
        result.applied,
        json!({ "guest_tools": &result }),
    );
    let status = crate::services::guest_tools::admin_status_for_vm(&vm, state.db.vm_guest_tools(&vm.id)?);
    Ok(Json(json!({ "result": result, "guest_tools": status })).into_response())
}

pub async fn create_status_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<CreateTokenBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let token = state.security.issue_customer_token();
    let scopes = if input.scopes.is_empty() {
        default_customer_scopes()
    } else {
        normalize_customer_scopes(input.scopes)
    };
    let expires_at = parse_optional_timestamp(input.expires_at.as_ref())?
        .unwrap_or_else(|| Utc::now().timestamp() + 7 * 24 * 60 * 60);
    let record = state.db.create_customer_link(
        &vm.id,
        token.hash(),
        &scopes,
        input.bound_ip.as_deref(),
        expires_at,
    )?;
    let url = format!("{}/status/{}", state.config.public_url, token.expose());
    audit(
        &state,
        &auth,
        "status_token.create",
        "vm",
        Some(&vm.id),
        true,
        json!({ "token_id": record.id }),
    );
    let mut response = Json(json!({ "token": token.expose(), "url": url, "record": record })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub async fn revoke_status_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((vm_id, token_id)): Path<(String, String)>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &vm_id)?;
    state
        .db
        .revoke_customer_token_for_vm(&vm.id, &token_id, Utc::now().timestamp())?;
    audit(
        &state,
        &auth,
        "status_token.revoke",
        "vm",
        Some(&vm.id),
        true,
        json!({ "token_id": token_id }),
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn create_vnc_token(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<CreateTokenBody>,
) -> AppResult<Response> {
    auth.require("vms:vnc")?;
    if !state.setting_bool("console", "vnc_enabled")?.unwrap_or(true) {
        return Err(AppError::Conflict("VNC console access is disabled".into()));
    }
    let vm = required_vm(&state, &id)?;
    state.hypervisor.vnc_target(&vm.name).await?;
    let token = state.security.issue_vnc_link_token();
    let now = Utc::now().timestamp();
    let record = state
        .db
        .create_vnc_link(&vm.id, token.hash(), input.bound_ip.as_deref(), now)?;
    let url = format!("{}/vnc/{}", state.config.public_url, token.expose());
    audit(
        &state,
        &auth,
        "vnc_token.create",
        "vm",
        Some(&vm.id),
        true,
        json!({ "token_id": record.id }),
    );
    let mut response =
        Json(json!({ "token": token.expose(), "url": url, "expires_at": record.expires_at })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub async fn get_vm_network_security(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    let profile = state
        .db
        .vm_network_security(&vm.id)?
        .ok_or_else(|| AppError::NotFound("VM network security profile".into()))?;
    let rules = state.db.list_vm_firewall_rules(&vm.id)?;
    Ok(Json(json!({ "profile": profile, "rules": rules })).into_response())
}

pub async fn patch_vm_network_security(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<VmNetworkSecurityPatch>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    state.db.patch_vm_network_security(&vm.id, &input)?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    let profile = state
        .db
        .vm_network_security(&vm.id)?
        .ok_or_else(|| AppError::NotFound("VM network security profile".into()))?;
    audit(
        &state,
        &auth,
        "vm.network_security.update",
        "vm",
        Some(&vm.id),
        true,
        json!({
            "revision": profile.revision,
            "firewall_enabled": profile.firewall_enabled,
            "ddos_enabled": profile.ddos_enabled,
        }),
    );
    Ok(Json(json!({ "profile": profile, "enforcement": enforcement })).into_response())
}

pub async fn list_vm_firewall_rules(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    Ok(Json(json!({ "items": state.db.list_vm_firewall_rules(&vm.id)? })).into_response())
}

pub async fn create_vm_firewall_rule(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<NewVmFirewallRule>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let rule = state
        .db
        .create_vm_firewall_rule_owned(&vm.id, &input, "admin", Some(&auth.actor_id))?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    audit(
        &state,
        &auth,
        "vm.firewall_rule.create",
        "vm",
        Some(&vm.id),
        true,
        json!({ "rule_id": rule.id, "enabled": rule.enabled }),
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({ "rule": rule, "enforcement": enforcement })),
    )
        .into_response())
}

pub async fn patch_vm_firewall_rule(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((id, rule_id)): Path<(String, String)>,
    Json(input): Json<VmFirewallRulePatch>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let rule = state.db.patch_vm_firewall_rule(&vm.id, &rule_id, &input)?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    audit(
        &state,
        &auth,
        "vm.firewall_rule.update",
        "vm",
        Some(&vm.id),
        true,
        json!({ "rule_id": rule.id, "enabled": rule.enabled }),
    );
    Ok(Json(json!({ "rule": rule, "enforcement": enforcement })).into_response())
}

pub async fn delete_vm_firewall_rule(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((id, rule_id)): Path<(String, String)>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    state.db.delete_vm_firewall_rule(&vm.id, &rule_id)?;
    let enforcement = crate::services::firewall::reconcile_vm_fail_closed(&state, &vm).await?;
    audit(
        &state,
        &auth,
        "vm.firewall_rule.delete",
        "vm",
        Some(&vm.id),
        true,
        json!({ "rule_id": rule_id }),
    );
    Ok(Json(json!({ "deleted": true, "enforcement": enforcement })).into_response())
}

pub async fn get_hypervisor_network_security(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("network:read")?;
    Ok(Json(json!({ "profile": state.db.hypervisor_network_security()? })).into_response())
}

pub async fn patch_hypervisor_network_security(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<HypervisorNetworkSecurityPatch>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let previous = state.db.hypervisor_network_security()?;
    state
        .db
        .patch_hypervisor_network_security(&input, Some(&auth.actor_id))?;
    let enforcement = match crate::services::firewall::reconcile(&state).await {
        Ok(summary) => summary,
        Err(apply_error) => {
            let rollback = state.db.patch_hypervisor_network_security(
                &HypervisorNetworkSecurityPatch {
                    ip_ownership_guard_enabled: Some(previous.ip_ownership_guard_enabled),
                    bcp38_enabled: Some(previous.bcp38_enabled),
                },
                Some(&auth.actor_id),
            );
            let rollback_apply = match rollback {
                Ok(_) => crate::services::firewall::reconcile(&state).await.map(|_| ()),
                Err(error) => Err(error),
            };
            return Err(AppError::Conflict(match rollback_apply {
                Ok(()) => format!(
                    "host network-security policy could not be applied; the previous settings were restored: {apply_error}"
                ),
                Err(rollback_error) => format!(
                    "host network-security policy could not be applied and restoring the previous rules also failed: {apply_error}; rollback: {rollback_error}"
                ),
            }));
        }
    };
    let profile = state.db.hypervisor_network_security()?;
    audit(
        &state,
        &auth,
        "hypervisor.network_security.update",
        "hypervisor_network",
        None,
        true,
        json!({
            "ip_ownership_guard_enabled": profile.ip_ownership_guard_enabled,
            "bcp38_enabled": profile.bcp38_enabled,
            "revision": profile.revision,
        }),
    );
    Ok(Json(json!({ "profile": profile, "enforcement": enforcement })).into_response())
}

pub async fn list_ip_blacklist(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<NetworkRecordQuery>,
) -> AppResult<Response> {
    auth.require("network:read")?;
    Ok(Json(json!({ "items": state.db.list_ip_blacklist_entries(query.active_only)? })).into_response())
}

pub async fn create_ip_blacklist(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(mut input): Json<NewIpBlacklistEntry>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    input.created_by = Some(auth.actor_id.clone());
    let record = state.db.create_ip_blacklist_entry(&input)?;
    audit(
        &state,
        &auth,
        "ip.blacklist.create",
        "ip_blacklist",
        Some(&record.id),
        true,
        json!({ "cidr": record.cidr, "reason": record.reason }),
    );
    Ok((StatusCode::CREATED, Json(json!({ "record": record }))).into_response())
}

pub async fn patch_ip_blacklist(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<IpBlacklistPatch>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let record = state.db.patch_ip_blacklist_entry(&id, &input)?;
    audit(
        &state,
        &auth,
        "ip.blacklist.update",
        "ip_blacklist",
        Some(&record.id),
        true,
        json!({ "enabled": record.enabled }),
    );
    Ok(Json(json!({ "record": record })).into_response())
}

pub async fn delete_ip_blacklist(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    state.db.delete_ip_blacklist_entry(&id)?;
    audit(
        &state,
        &auth,
        "ip.blacklist.delete",
        "ip_blacklist",
        Some(&id),
        true,
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn list_ip_abuse_records(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<NetworkRecordQuery>,
) -> AppResult<Response> {
    auth.require("audit:read")?;
    let items = state.db.list_ip_abuse_records(
        query.address.as_deref(),
        query.vm_id.as_deref(),
        query.unresolved_only,
        query.limit.unwrap_or(DEFAULT_LIMIT),
    )?;
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn create_ip_abuse_record(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<NewIpAbuseRecord>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    if let Some(vm_id) = input.vm_id.as_deref() {
        required_vm(&state, vm_id)?;
    }
    let record = state.db.record_ip_abuse(&input)?;
    audit(
        &state,
        &auth,
        "ip.abuse.reported",
        "ip_abuse",
        Some(&record.address),
        true,
        json!({
            "record_id": record.id,
            "vm_id": record.vm_id,
            "category": record.category,
            "severity": record.severity
        }),
    );
    Ok((StatusCode::CREATED, Json(json!({ "record": record }))).into_response())
}

pub async fn resolve_ip_abuse_record(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<AbuseResolutionBody>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let record = state
        .db
        .resolve_ip_abuse_record(&id, Some(&auth.actor_id), &input.resolution)?;
    audit(
        &state,
        &auth,
        "ip.abuse.status_changed",
        "ip_abuse",
        Some(&record.address),
        true,
        json!({ "record_id": record.id, "resolution": record.resolution }),
    );
    Ok(Json(json!({ "record": record })).into_response())
}

pub async fn list_ip_pools(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("network:read")?;
    Ok(Json(json!({ "items": state.db.list_ip_pools()? })).into_response())
}

pub async fn create_ip_pool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<CreateIpPoolBody>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let (addresses, sparse) = planned_pool_addresses(&input.pool, &input.reserved)?;
    let pool = state.db.create_ip_pool(&input.pool)?;
    let prefix_length = network_prefix(&pool.cidr)?;
    let mut materialized = 0_usize;
    for (address, status) in addresses {
        if state
            .db
            .get_ip_address(&address.to_string())?
            .is_some_and(|existing| existing.status == IpStatus::Main)
        {
            continue;
        }
        let record = NewIpAddress {
            pool_id: Some(pool.id.clone()),
            address: address.to_string(),
            prefix_length,
            scope: pool.scope,
            status,
            gateway: pool.gateway.clone(),
            reverse_dns: None,
            metadata: json!({ "materialized_from_pool": true }),
        };
        if let Err(error) = state.db.upsert_ip_address(&record) {
            let _ = state.db.delete_ip_pool_with_unassigned_addresses(&pool.id);
            return Err(error);
        }
        materialized += 1;
    }
    let network_security = if state.db.hypervisor_network_security()?.ip_ownership_guard_enabled {
        match crate::services::firewall::reconcile(&state).await {
            Ok(summary) => Some(summary),
            Err(apply_error) => {
                let rollback = state.db.delete_ip_pool_with_unassigned_addresses(&pool.id);
                let rollback_apply = match rollback {
                    Ok(()) => crate::services::firewall::reconcile(&state).await.map(|_| ()),
                    Err(error) => Err(error),
                };
                return Err(AppError::Conflict(match rollback_apply {
                    Ok(()) => format!(
                        "the managed IP pool could not be protected; its inventory was rolled back: {apply_error}"
                    ),
                    Err(rollback_error) => format!(
                        "the managed IP pool could not be protected and rollback also failed: {apply_error}; rollback: {rollback_error}"
                    ),
                }));
            }
        }
    } else {
        None
    };
    audit(
        &state,
        &auth,
        "network.pool.create",
        "ip_pool",
        Some(&pool.id),
        true,
        json!({
            "cidr": pool.cidr,
            "materialized_addresses": materialized,
        }),
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "pool": pool,
            "materialized_addresses": materialized,
            "sparse": sparse,
            "network_security": network_security,
        })),
    )
        .into_response())
}

pub async fn get_ip_pool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("network:read")?;
    let pool = state
        .db
        .get_ip_pool(&id)?
        .ok_or_else(|| AppError::NotFound("IP pool".into()))?;
    Ok(Json(json!({ "pool": pool })).into_response())
}

pub async fn patch_ip_pool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<IpPoolPatch>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let pool = state.db.patch_ip_pool(&id, &input)?;
    audit(
        &state,
        &auth,
        "network.pool.update",
        "ip_pool",
        Some(&pool.id),
        true,
        json!({}),
    );
    Ok(Json(json!({ "pool": pool })).into_response())
}

pub async fn delete_ip_pool(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    state.db.delete_ip_pool(&id)?;
    if state.db.hypervisor_network_security()?.ip_ownership_guard_enabled {
        crate::services::firewall::reconcile(&state)
            .await
            .map_err(|error| {
                AppError::Conflict(format!(
                    "the pool was deleted, but the stricter previous ownership rules could not be refreshed: {error}"
                ))
            })?;
    }
    audit(
        &state,
        &auth,
        "network.pool.delete",
        "ip_pool",
        Some(&id),
        true,
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn list_ip_addresses(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListQuery>,
) -> AppResult<Response> {
    auth.require("network:read")?;
    let family = query
        .family
        .map(|value| AddressFamily::from_i64(i64::from(value)))
        .transpose()
        .map_err(AppError::Validation)?;
    let scope = query
        .scope
        .as_deref()
        .map(str::parse::<IpScope>)
        .transpose()
        .map_err(AppError::Validation)?;
    let status = query
        .status
        .as_deref()
        .map(str::parse::<IpStatus>)
        .transpose()
        .map_err(AppError::Validation)?;
    let items = address_values_with_blacklist(&state, state.db.list_ip_addresses(family, scope, status)?)?;
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn create_ip_address(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<NewIpAddress>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let address = state.db.upsert_ip_address(&input)?;
    audit(
        &state,
        &auth,
        "network.address.create",
        "ip_address",
        Some(&address.id),
        true,
        json!({ "address": address.address }),
    );
    Ok((StatusCode::CREATED, Json(json!({ "address": address }))).into_response())
}

pub async fn patch_ip_address(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(address): Path<String>,
    Json(input): Json<IpAddressPatch>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let current = state
        .db
        .get_ip_address(&address)?
        .ok_or_else(|| AppError::NotFound("IP address".into()))?;
    let resolved_address = current.address.clone();
    let previous_vm_id = current.assigned_vm_id.clone();
    let record = if let Some(vm_id) = input.vm_id.as_deref() {
        state.db.assign_ip(&resolved_address, vm_id, input.primary)?
    } else if input.status == Some(IpStatus::Free) {
        let existing = state.db.list_ip_addresses(None, None, None)?;
        if existing
            .iter()
            .find(|item| item.address == resolved_address)
            .and_then(|item| item.assigned_vm_id.as_ref())
            .is_some()
        {
            state.db.release_ip(&resolved_address)?
        } else {
            state.db.set_ip_status(&resolved_address, IpStatus::Free)?
        }
    } else if let Some(status) = input.status {
        state.db.set_ip_status(&resolved_address, status)?
    } else {
        return Err(AppError::Validation("status or vm_id is required".into()));
    };
    let affected_vm_id = input.vm_id.as_deref().or(previous_vm_id.as_deref());
    let network_security = reconcile_ownership_after_address_change(&state, affected_vm_id).await?;
    let guest_tools = if let Some(vm_id) = affected_vm_id {
        let vm = required_vm(&state, vm_id)?;
        Some(crate::services::guest_tools::apply_network_inventory(&state, &vm).await?)
    } else {
        None
    };
    audit(
        &state,
        &auth,
        "network.address.update",
        "ip_address",
        Some(&record.id),
        true,
        json!({ "address": record.address, "status": record.status, "guest_tools": &guest_tools }),
    );
    Ok(Json(json!({
        "address": record,
        "network_security": network_security,
        "guest_agent_applied": guest_tools.as_ref().is_some_and(|result| result.applied),
        "guest_tools": guest_tools,
    }))
    .into_response())
}

pub async fn get_ip_address(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("network:read")?;
    let address = state
        .db
        .get_ip_address(&id)?
        .ok_or_else(|| AppError::NotFound("IP address".into()))?;
    Ok(Json(json!({ "address": address })).into_response())
}

pub async fn assign_ip_address(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<AssignIpBody>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let current = state
        .db
        .get_ip_address(&id)?
        .ok_or_else(|| AppError::NotFound("IP address".into()))?;
    let address = state
        .db
        .assign_ip(&current.address, &input.vm_id, input.primary)?;
    let network_security = reconcile_ownership_after_address_change(&state, Some(&input.vm_id)).await?;
    let vm = required_vm(&state, &input.vm_id)?;
    let guest_tools = crate::services::guest_tools::apply_network_inventory(&state, &vm).await?;
    audit(
        &state,
        &auth,
        "network.address.assign",
        "ip_address",
        Some(&address.id),
        true,
        json!({ "vm_id": input.vm_id, "guest_tools": &guest_tools }),
    );
    Ok(Json(json!({
        "address": address,
        "network_security": network_security,
        "guest_agent_applied": guest_tools.applied,
        "guest_tools": guest_tools,
    }))
    .into_response())
}

pub async fn release_ip_address(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let current = state
        .db
        .get_ip_address(&id)?
        .ok_or_else(|| AppError::NotFound("IP address".into()))?;
    let previous_vm_id = current.assigned_vm_id.clone();
    let address = state.db.release_ip(&current.address)?;
    let network_security =
        reconcile_ownership_after_address_change(&state, previous_vm_id.as_deref()).await?;
    let guest_tools = if let Some(vm_id) = previous_vm_id.as_deref() {
        let vm = required_vm(&state, vm_id)?;
        Some(crate::services::guest_tools::apply_network_inventory(&state, &vm).await?)
    } else {
        None
    };
    audit(
        &state,
        &auth,
        "network.address.release",
        "ip_address",
        Some(&address.id),
        true,
        json!({ "guest_tools": &guest_tools }),
    );
    Ok(Json(json!({
        "address": address,
        "network_security": network_security,
        "guest_agent_applied": guest_tools.as_ref().is_some_and(|result| result.applied),
        "guest_tools": guest_tools,
    }))
    .into_response())
}

pub async fn delete_ip_address(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    state.db.delete_ip_address(&id)?;
    audit(
        &state,
        &auth,
        "network.address.delete",
        "ip_address",
        Some(&id),
        true,
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Compatibility endpoint for `POST /api/set-ip`.
pub async fn compatibility_set_ip(
    state: State<Arc<AppState>>,
    auth: Extension<AuthContext>,
    Json(input): Json<CompatibilitySetIpBody>,
) -> AppResult<Response> {
    patch_ip_address(
        state,
        auth,
        Path(input.address),
        Json(IpAddressPatch {
            status: input.status,
            vm_id: input.vm_id,
            primary: input.primary,
        }),
    )
    .await
}

pub async fn list_isos(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("isos:read")?;
    let items = state
        .db
        .list_isos(true)?
        .into_iter()
        .map(|image| admin_iso_value(&state.config, image))
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(json!({ "items": items })).into_response())
}

fn admin_iso_value(config: &crate::config::Config, image: IsoImage) -> AppResult<Value> {
    let available = iso_is_ready(&image);
    let guest_tools = crate::services::guest_tools::compatibility(config, &image);
    let mut value = serde_json::to_value(image)
        .map_err(|error| AppError::Internal(format!("could not encode ISO image: {error}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("ISO image serialization was not an object".into()))?;
    object.insert("available".into(), json!(available));
    object.insert(
        "status".into(),
        json!(if available { "ready" } else { "missing" }),
    );
    object.insert("guest_tools".into(), json!(guest_tools));
    Ok(value)
}

pub async fn get_iso(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("isos:read")?;
    let image = state
        .db
        .get_iso(&id)?
        .ok_or_else(|| AppError::NotFound("ISO image".into()))?;
    Ok(Json(json!({
        "image": admin_iso_value(&state.config, image)?,
    }))
    .into_response())
}

pub async fn create_iso(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(mut input): Json<NewIsoBody>,
) -> AppResult<Response> {
    auth.require("isos:write")?;
    let explicit_id = input
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    input.id = explicit_id.clone();
    let _create_operation = explicit_id
        .as_deref()
        .map(iso_download::ImageOperationGuard::acquire)
        .transpose()?;
    if let Some(id) = explicit_id.as_deref() {
        if state.db.get_iso(id)?.is_some() {
            return Err(AppError::Conflict(
                "an ISO catalog entry with that id already exists".into(),
            ));
        }
    }
    if let Some(path) = input.local_path.as_deref() {
        validate_local_image_path(&state, path)?;
    }
    input.checksum_sha256 = input
        .checksum_sha256
        .as_deref()
        .map(iso_download::validate_sha256)
        .transpose()?;
    if input.source_url.is_some() {
        let normalized_url =
            iso_download::validate_source_url(input.source_url.as_deref().expect("checked above"))?
                .to_string();
        input.source_url = Some(normalized_url);
        let checksum = input.checksum_sha256.as_deref().ok_or_else(|| {
            AppError::Validation(
                "a trusted SHA-256 is required before a remote image can be downloaded".into(),
            )
        })?;
        iso_download::validate_sha256(checksum)?;
    }
    clear_image_verification_metadata(&mut input.metadata);
    let now = Utc::now().timestamp();
    let install_mode = if let Some(mode) = input.install_mode {
        mode
    } else {
        match input.provisioning_mode.as_deref().unwrap_or("manual") {
            "cloud-init" | "cloud_init" => InstallMode::CloudInit,
            "automatic" => InstallMode::Automatic,
            "manual" | "manual-install" => InstallMode::Manual,
            _ => return Err(AppError::Validation("provisioning mode is invalid".into())),
        }
    };
    let image = state.db.upsert_iso(&IsoImage {
        id: input.id.unwrap_or_default(),
        slug: input.slug,
        name: input.name,
        version: input.version,
        os_family: input.os_family,
        architecture: input.architecture,
        install_mode,
        source_url: input.source_url,
        local_path: input.local_path,
        checksum_sha256: input.checksum_sha256,
        size_bytes: input.size_bytes,
        supports_guest_agent: input.supports_guest_agent,
        supports_cloud_init: input.supports_cloud_init,
        uefi: input.uefi,
        enabled: input.enabled,
        metadata: input.metadata,
        created_at: now,
        updated_at: now,
    })?;
    audit(
        &state,
        &auth,
        "iso.create",
        "iso",
        Some(&image.id),
        true,
        json!({ "slug": image.slug }),
    );
    Ok((StatusCode::CREATED, Json(json!({ "image": image }))).into_response())
}

pub async fn patch_iso(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<IsoPatchBody>,
) -> AppResult<Response> {
    auth.require("isos:write")?;
    let source_url_changed = input.source_url.is_some();
    let local_path_changed = input.local_path.is_some();
    let checksum_changed = input.checksum_sha256.is_some();
    let size_changed = input.size_bytes.is_some();
    let metadata_changed = input.metadata.is_some();
    let (_operation, mut image) = acquire_iso_operation(&state, &id)?;
    let previous_checksum = image.checksum_sha256.clone();
    let previous_size = image.size_bytes;
    if let Some(value) = input.slug {
        image.slug = value;
    }
    if let Some(value) = input.name {
        image.name = value;
    }
    if let Some(value) = input.version {
        image.version = Some(value);
    }
    if let Some(value) = input.os_family {
        image.os_family = value;
    }
    if let Some(value) = input.architecture {
        image.architecture = value;
    }
    if let Some(value) = input.install_mode {
        image.install_mode = value;
    }
    if let Some(value) = input.source_url {
        image.source_url = Some(iso_download::validate_source_url(&value)?.to_string());
    }
    if let Some(value) = input.local_path {
        validate_local_image_path(&state, &value)?;
        image.local_path = Some(value);
    }
    if let Some(value) = input.checksum_sha256 {
        image.checksum_sha256 = Some(iso_download::validate_sha256(&value)?);
    }
    if let Some(value) = input.size_bytes {
        image.size_bytes = Some(value);
    }
    if let Some(value) = input.supports_guest_agent {
        image.supports_guest_agent = value;
    }
    if let Some(value) = input.supports_cloud_init {
        image.supports_cloud_init = value;
    }
    if let Some(value) = input.uefi {
        image.uefi = value;
    }
    if let Some(value) = input.enabled {
        image.enabled = value;
    }
    if let Some(value) = input.metadata {
        image.metadata = value;
    }
    let checksum_value_changed = checksum_changed && previous_checksum != image.checksum_sha256;
    let size_value_changed = size_changed && previous_size != image.size_bytes;
    let downloaded_remote_integrity_changed =
        image.source_url.is_some() && (checksum_value_changed || size_value_changed);
    if source_url_changed
        || local_path_changed
        || checksum_value_changed
        || size_value_changed
        || metadata_changed
    {
        clear_stale_image_verification(
            &mut image.local_path,
            &mut image.size_bytes,
            &mut image.metadata,
            (!source_url_changed || local_path_changed) && !downloaded_remote_integrity_changed,
            size_changed || (!source_url_changed && !local_path_changed),
        );
    }
    if source_url_changed {
        let checksum = image.checksum_sha256.as_deref().ok_or_else(|| {
            AppError::Validation(
                "a trusted SHA-256 is required before a remote image can be downloaded".into(),
            )
        })?;
        iso_download::validate_sha256(checksum)?;
    }
    image.updated_at = Utc::now().timestamp();
    let image = state.db.upsert_iso(&image)?;
    audit(
        &state,
        &auth,
        "iso.update",
        "iso",
        Some(&image.id),
        true,
        json!({}),
    );
    Ok(Json(json!({ "image": image })).into_response())
}

fn clear_image_verification_metadata(metadata: &mut Value) {
    let Some(metadata) = metadata.as_object_mut() else {
        *metadata = json!({});
        return;
    };
    for key in ["verified_at", "downloaded_at", "source", "download_error"] {
        metadata.remove(key);
    }
}

fn clear_stale_image_verification(
    local_path: &mut Option<String>,
    size_bytes: &mut Option<u64>,
    metadata: &mut Value,
    preserve_local_path: bool,
    preserve_size: bool,
) {
    if !preserve_local_path {
        *local_path = None;
    }
    if !preserve_size {
        *size_bytes = None;
    }
    clear_image_verification_metadata(metadata);
}

fn acquire_iso_operation(
    state: &AppState,
    id_or_slug: &str,
) -> AppResult<(iso_download::ImageOperationGuard, IsoImage)> {
    // Resolve aliases before taking the stable-id lock, then re-read while the
    // lock is held so a mutation that won the race cannot be overwritten.
    let initial = state
        .db
        .get_iso(id_or_slug)?
        .ok_or_else(|| AppError::NotFound("ISO image".into()))?;
    let operation = iso_download::ImageOperationGuard::acquire(&initial.id)?;
    let current = state
        .db
        .get_iso(&initial.id)?
        .ok_or_else(|| AppError::NotFound("ISO image".into()))?;
    Ok((operation, current))
}

pub async fn verify_iso(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("isos:write")?;
    let (mut operation, mut image) = acquire_iso_operation(&state, &id)?;
    // Mark the catalog entry unavailable before starting I/O. A failed,
    // cancelled, or interrupted verification must never leave stale integrity
    // metadata that would permit provisioning from unchecked bytes.
    clear_image_verification_metadata(&mut image.metadata);
    image.updated_at = Utc::now().timestamp();
    image = state.db.upsert_iso(&image)?;
    let expected_checksum = image
        .checksum_sha256
        .as_deref()
        .map(iso_download::validate_sha256)
        .transpose()?;
    let local_file_exists = image
        .local_path
        .as_deref()
        .is_some_and(|path| PathBuf::from(path).is_file());
    let mut downloaded_artifact = None;
    let (size, checksum) = if local_file_exists {
        let local_path = image.local_path.as_deref().expect("checked above");
        validate_local_image_path(&state, local_path)?;
        let path = PathBuf::from(local_path);
        let verified = tokio::task::spawn_blocking(move || verify_local_image(&path))
            .await
            .map_err(|error| AppError::Internal(format!("image verification task failed: {error}")))??;
        if expected_checksum
            .as_deref()
            .is_some_and(|expected| !expected.eq_ignore_ascii_case(&verified.1))
        {
            return Err(AppError::Conflict("image SHA-256 checksum does not match".into()));
        }
        verified
    } else {
        let source_url = image
            .source_url
            .as_deref()
            .ok_or_else(|| AppError::Conflict("image has no local file or remote source URL".into()))?;
        let expected_checksum = expected_checksum.as_deref().ok_or_else(|| {
            AppError::Conflict("a trusted SHA-256 must be set before downloading a remote image".into())
        })?;
        let downloaded = iso_download::download_and_verify(
            &mut operation,
            source_url,
            expected_checksum,
            image.size_bytes,
            &state.config.iso_storage,
        )
        .await?;
        image.local_path = Some(downloaded.path.to_string_lossy().into_owned());
        let verified = (downloaded.size_bytes, downloaded.sha256.clone());
        downloaded_artifact = Some(downloaded);
        verified
    };
    image.checksum_sha256 = Some(checksum.clone());
    image.size_bytes = Some(size);
    image.updated_at = Utc::now().timestamp();
    if !image.metadata.is_object() {
        image.metadata = json!({});
    }
    if matches!(
        image.install_mode,
        InstallMode::CloudInit | InstallMode::Automatic
    ) {
        let local_path = image
            .local_path
            .as_deref()
            .expect("verified automatic image has a local path");
        // Cloud images are frequently published with a generic `.img` suffix
        // even when their on-disk representation is qcow2. Record the actual
        // format from the file header, not its filename, so qemu-img receives
        // the correct source format during provisioning.
        image.metadata["format"] = json!(automatic_disk_format(FsPath::new(local_path))?);
    }
    image.metadata["verified_at"] = json!(image.updated_at);
    if downloaded_artifact.is_some() {
        image.metadata["downloaded_at"] = json!(image.updated_at);
        image.metadata["source"] = json!("remote_download");
    }
    let image = match state.db.upsert_iso(&image) {
        Ok(image) => {
            if let Some(downloaded) = downloaded_artifact.as_mut() {
                downloaded.retain();
            }
            image
        }
        Err(error) => return Err(error),
    };
    audit(
        &state,
        &auth,
        "iso.verify",
        "iso",
        Some(&image.id),
        true,
        json!({ "size_bytes": size }),
    );
    Ok(Json(json!({ "image": image, "sha256": checksum, "size_bytes": size })).into_response())
}

fn verify_local_image(path: &std::path::Path) -> AppResult<(u64, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Validation("image file is too large".into()))?;
        digest.update(&buffer[..read]);
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

struct UploadArtifactCleanup {
    paths: Vec<PathBuf>,
}

impl UploadArtifactCleanup {
    fn new(partial_path: PathBuf, final_path: PathBuf) -> Self {
        Self {
            paths: vec![partial_path, final_path],
        }
    }

    fn retain(&mut self) {
        self.paths.clear();
    }
}

impl Drop for UploadArtifactCleanup {
    fn drop(&mut self) {
        for path in self.paths.drain(..) {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub async fn upload_iso(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> AppResult<Response> {
    auth.require("isos:write")?;
    let mut transfer = iso_download::ImageOperationGuard::acquire(&format!("upload:{}", Uuid::new_v4()))?;
    transfer.begin_image_transfer()?;
    let declared_size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared_size.is_some_and(|size| size > iso_download::MAX_REMOTE_IMAGE_BYTES) {
        return Err(AppError::Validation(
            "multipart image request exceeds 16 GiB".into(),
        ));
    }
    iso_download::ensure_storage_capacity(
        &state.config.iso_storage,
        declared_size.unwrap_or(iso_download::MAX_REMOTE_IMAGE_BYTES),
    )
    .await?;
    let mut fields = BTreeMap::<String, String>::new();
    let mut uploaded: Option<(UploadArtifactCleanup, PathBuf, u64, String)> = None;
    let mut part_count = 0_u8;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| AppError::Validation(format!("invalid multipart upload: {error}")))?
    {
        part_count = part_count.saturating_add(1);
        if part_count > 32 {
            return Err(AppError::Validation(
                "multipart upload may contain at most 32 parts".into(),
            ));
        }
        let name = field.name().unwrap_or_default().to_owned();
        if name.len() > 64 {
            return Err(AppError::Validation(
                "multipart field names may contain at most 64 bytes".into(),
            ));
        }
        if let Some(original_name) = field.file_name().map(ToOwned::to_owned) {
            if uploaded.is_some() {
                return Err(AppError::Validation("only one image file may be uploaded".into()));
            }
            let safe_name = safe_upload_name(&original_name)?;
            let final_path = state
                .config
                .iso_storage
                .join(format!("{}-{safe_name}", Uuid::new_v4()));
            let partial_path = final_path.with_extension("part");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial_path)?;
            let cleanup = UploadArtifactCleanup::new(partial_path.clone(), final_path.clone());
            let mut file = tokio::fs::File::from_std(file);
            let mut size = 0_u64;
            let mut digest = Sha256::new();
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|error| AppError::Validation(format!("upload stream failed: {error}")))?
            {
                size = size.saturating_add(chunk.len() as u64);
                if size > iso_download::MAX_REMOTE_IMAGE_BYTES {
                    return Err(AppError::Validation("image upload exceeds 16 GiB".into()));
                }
                digest.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.sync_all().await?;
            drop(file);
            uploaded = Some((cleanup, final_path, size, format!("{:x}", digest.finalize())));
        } else if !name.is_empty() {
            let mut value = Vec::new();
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|error| AppError::Validation(format!("invalid form field: {error}")))?
            {
                if value.len().saturating_add(chunk.len()) > 16 * 1024 {
                    return Err(AppError::Validation(
                        "multipart text fields may contain at most 16 KiB".into(),
                    ));
                }
                value.extend_from_slice(&chunk);
            }
            let value = String::from_utf8(value)
                .map_err(|_| AppError::Validation("multipart text fields must use UTF-8".into()))?;
            fields.insert(name, value);
        }
    }

    let (mut cleanup, path, size_bytes, checksum) =
        uploaded.ok_or_else(|| AppError::Validation("file is required".into()))?;
    if let Some(expected) = fields.get("sha256").filter(|value| !value.is_empty()) {
        if !expected.eq_ignore_ascii_case(&checksum) {
            return Err(AppError::Validation(
                "uploaded image SHA-256 does not match".into(),
            ));
        }
    }
    let slug = match required_form_field(&fields, "slug") {
        Ok(value) => value.to_owned(),
        Err(error) => return Err(error),
    };
    let display_name = match required_form_field(&fields, "name") {
        Ok(value) => value.to_owned(),
        Err(error) => return Err(error),
    };
    let mode = match fields.get("provisioning_mode").map(String::as_str) {
        Some("cloud-init" | "cloud_init") => InstallMode::CloudInit,
        Some("automatic") => InstallMode::Automatic,
        _ => InstallMode::Manual,
    };
    let now = Utc::now().timestamp();
    let partial_path = path.with_extension("part");
    tokio::fs::rename(&partial_path, &path).await?;
    let image_record = IsoImage {
        id: String::new(),
        slug,
        name: display_name,
        version: None,
        os_family: fields.get("os_family").cloned().unwrap_or_default(),
        architecture: fields
            .get("architecture")
            .cloned()
            .unwrap_or_else(default_architecture),
        install_mode: mode,
        source_url: None,
        local_path: Some(path.to_string_lossy().into_owned()),
        checksum_sha256: Some(checksum),
        size_bytes: Some(size_bytes),
        supports_guest_agent: fields.contains_key("guest_agent"),
        supports_cloud_init: matches!(mode, InstallMode::CloudInit),
        uefi: fields.contains_key("uefi"),
        enabled: true,
        metadata: json!({
            "source": "upload",
            "verified_at": now,
            "guest_tools_provisioner": fields
                .get("guest_tools_provisioner")
                .map(String::as_str)
                .filter(|value| !value.is_empty()),
            "virtio_serial_driver": fields
                .contains_key("signed_virtio_serial_driver")
                .then_some("installed_signed"),
        }),
        created_at: now,
        updated_at: now,
    };
    let image = state.db.upsert_iso(&image_record)?;
    cleanup.retain();
    audit(
        &state,
        &auth,
        "iso.upload",
        "iso",
        Some(&image.id),
        true,
        json!({ "size_bytes": size_bytes }),
    );
    Ok((StatusCode::CREATED, Json(json!({ "image": image }))).into_response())
}

pub async fn delete_iso(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("isos:write")?;
    let (_operation, image) = acquire_iso_operation(&state, &id)?;
    state.db.delete_iso(&image.id)?;
    audit(
        &state,
        &auth,
        "iso.delete",
        "iso",
        Some(&image.id),
        true,
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn update_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("updates:read")?;
    let executor_statuses = read_durable_update_statuses()?;
    let latest_executor_status = executor_statuses.first().cloned();
    let rollback_point = eligible_update_rollback_point(&executor_statuses);
    let Some(updater) = state.updater.as_ref() else {
        return Ok(Json(json!({
            "enabled": false,
            "repository": UPDATE_REPOSITORY,
            "current_version": env!("CARGO_PKG_VERSION"),
            "activation_executor_available": false,
            "reason": state.updater_disabled_reason.as_deref(),
            "executor_statuses": executor_statuses,
            "latest_executor_status": latest_executor_status,
            "rollback_point": rollback_point,
        }))
        .into_response());
    };
    Ok(Json(json!({
        "enabled": true,
        "repository": UPDATE_REPOSITORY,
        "current_version": env!("CARGO_PKG_VERSION"),
        // The root helper is deliberately not invoked by the web process.
        // A packaged executor consumes approval-bound spool entries.
        "activation_executor_available": update_executor_available(),
        "state": updater.snapshot().await,
        "executor_statuses": executor_statuses,
        "latest_executor_status": latest_executor_status,
        "rollback_point": rollback_point,
    }))
    .into_response())
}

pub async fn check_updates(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("updates:write")?;
    let updater = required_update_coordinator(&state)?;
    let result = updater.check_latest(env!("CARGO_PKG_VERSION")).await?;
    audit(
        &state,
        &auth,
        "update.check",
        "release",
        Some(&result.release.tag),
        true,
        json!({
            "repository": UPDATE_REPOSITORY,
            "manifest_sha256": result.release.manifest_sha256,
            "signer_key_id": result.release.signer_key_id,
            "update_available": result.update_available,
        }),
    );
    Ok(Json(json!({ "check": result })).into_response())
}

pub async fn stage_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<StageUpdateBody>,
) -> AppResult<Response> {
    auth.require("updates:write")?;
    let updater = required_update_coordinator(&state)?;
    let staged = updater
        .stage_component(&input.manifest_sha256, input.component)
        .await?;
    audit(
        &state,
        &auth,
        "update.stage",
        "release_component",
        Some(staged.component.as_str()),
        true,
        json!({
            "release": staged.release,
            "version": staged.version,
            "sha256": staged.sha256,
            "size_bytes": staged.size_bytes,
        }),
    );
    Ok(Json(json!({ "staged": staged })).into_response())
}

pub async fn approve_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<ApproveUpdateBody>,
) -> AppResult<Response> {
    auth.require("updates:write")?;
    if auth
        .admin
        .as_ref()
        .map_or(true, |admin| admin.role != AdminRole::SuperAdmin)
    {
        return Err(AppError::Forbidden);
    }
    if input.components.is_empty() {
        return Err(AppError::Validation(
            "select at least one verified update component".into(),
        ));
    }
    if !update_executor_available() {
        return Err(AppError::Conflict(
            "the privileged signed-update executor is not installed and active on this node".into(),
        ));
    }
    let updater = required_update_coordinator(&state)?;
    let queued = updater
        .queue_activation(
            &auth.actor_id,
            &input.expected_release,
            &input.expected_manifest_sha256,
            input.components,
            input.maintenance_impact_accepted,
        )
        .await?;
    audit(
        &state,
        &auth,
        "update.activation.approve",
        "update_request",
        Some(&queued.request_id),
        true,
        json!({
            "release": queued.release,
            "components": queued.components,
            "expires_at": queued.expires_at,
        }),
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "request": queued }))).into_response())
}

pub async fn approve_rollback(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<ApproveRollbackBody>,
) -> AppResult<Response> {
    auth.require("updates:write")?;
    if auth
        .admin
        .as_ref()
        .map_or(true, |admin| admin.role != AdminRole::SuperAdmin)
    {
        return Err(AppError::Forbidden);
    }
    if !input.maintenance_impact_accepted {
        return Err(AppError::Validation(
            "the administrator must accept the rollback maintenance impact".into(),
        ));
    }
    if !update_executor_available() {
        return Err(AppError::Conflict(
            "the privileged signed-update executor is not installed and active on this node".into(),
        ));
    }

    // Status documents are root-owned, bounded and schema-validated by the
    // updater service. Client values are used only as stale-view guards; no
    // snapshot path, digest, release, size or component is client-selectable.
    let statuses = read_durable_update_statuses()?;
    let public_point = eligible_update_rollback_point(&statuses)
        .ok_or_else(|| AppError::Conflict("no eligible application rollback point is available".into()))?;
    if input.expected_activation_id != public_point.activation_id
        || input.expected_previous_release != public_point.previous_release
    {
        return Err(AppError::Conflict(
            "the rollback point changed; reload update status and review it again".into(),
        ));
    }

    let components = public_point
        .components
        .iter()
        .map(|component| match component.as_str() {
            "vexa-vm" => Ok(UpdateComponent::VexaVm),
            _ => Err(AppError::Conflict(
                "the durable rollback point contains an unsupported component".into(),
            )),
        })
        .collect::<AppResult<BTreeSet<_>>>()?;
    let point = RollbackPoint {
        activation_id: public_point.activation_id.clone(),
        release: public_point.release.clone(),
        previous_release: public_point.previous_release.clone(),
        manifest_sha256: public_point.manifest_sha256.clone(),
        snapshot_path: PathBuf::from(UPDATE_ROLLBACK_ROOT)
            .join(format!("{}.sqlite3", public_point.activation_id)),
        snapshot_sha256: public_point.snapshot_sha256.clone(),
        snapshot_size_bytes: public_point.snapshot_size_bytes,
        components,
    };
    let updater = required_update_coordinator(&state)?;
    let queued = updater
        .queue_rollback(
            &point,
            &auth.actor_id,
            &input.expected_activation_id,
            &input.expected_previous_release,
            true,
        )
        .await?;
    audit(
        &state,
        &auth,
        "update.rollback.approve",
        "update_request",
        Some(&queued.request_id),
        true,
        json!({
            "activation_id": point.activation_id,
            "release": point.release,
            "restore_release": point.previous_release,
            "components": point.components,
            "expires_at": queued.expires_at,
            "maintenance_impact_accepted": true,
        }),
    );
    Ok((StatusCode::ACCEPTED, Json(json!({ "request": queued }))).into_response())
}

pub async fn list_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("settings:read")?;
    let items = state.db.list_settings(false)?;
    let mut values: BTreeMap<_, _> = items.into_iter().map(|item| (item.key, item.value)).collect();
    values.insert(
        "runtime".into(),
        json!({
            "bind": state.config.bind,
            "public_url": state.config.public_url.clone(),
            "libvirt_uri": state.config.libvirt_uri.clone(),
            "vm_storage": state.config.vm_storage.clone(),
            "iso_storage": state.config.iso_storage.clone(),
            "cloud_init_storage": state.config.cloud_init_storage.clone(),
            "network_bridge": state.config.network_bridge.clone(),
            "hypervisor_mode": match state.config.hypervisor_mode {
                crate::config::HypervisorMode::Auto => "auto",
                crate::config::HypervisorMode::Libvirt => "libvirt",
                crate::config::HypervisorMode::Mock => "mock",
            },
            "vnc_ttl_seconds": state.config.vnc_ttl.as_secs(),
            "secure_cookies": state.config.secure_cookies,
            "environment_owned": true,
        }),
    );
    if let Some(admin) = auth.admin.as_ref() {
        values.insert("admin_username".into(), json!(admin.username.clone()));
    }
    Ok(Json(json!({
        "settings": values,
        "writable_sections": ["general", "network", "console", "security"],
    }))
    .into_response())
}

pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<SettingsBody>,
) -> AppResult<Response> {
    auth.require("settings:write")?;
    let mut merged_values = BTreeMap::new();
    for (key, patch) in &input.values {
        let mut merged = state
            .db
            .get_setting(key)?
            .map(|record| record.value)
            .unwrap_or_else(|| json!({}));
        let merged_object = merged
            .as_object_mut()
            .ok_or_else(|| AppError::Internal(format!("stored setting section '{key}' is not an object")))?;
        let patch_object = patch
            .as_object()
            .ok_or_else(|| AppError::Validation(format!("setting section '{key}' must be an object")))?;
        merged_object.extend(patch_object.clone());
        validate_setting_section(key, &merged)?;
        if key == "general" {
            validate_capacity_policy_change(&state, &merged).await?;
        }
        merged_values.insert(key.clone(), merged);
    }
    for (key, value) in &merged_values {
        if key == "network" {
            if let Some(dns) = value.get("dns_servers").and_then(Value::as_array).map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            }) {
                state.db.set_network_setting_and_default_dns(
                    value,
                    &dns,
                    auth.admin.as_ref().map(|admin| admin.id.as_str()),
                )?;
                continue;
            }
        }
        state.db.set_setting(
            key,
            value,
            false,
            auth.admin.as_ref().map(|admin| admin.id.as_str()),
        )?;
    }
    audit(
        &state,
        &auth,
        "settings.update",
        "node",
        None,
        true,
        json!({ "keys": merged_values.keys().collect::<Vec<_>>() }),
    );
    list_settings(State(state), Extension(auth)).await
}

async fn validate_capacity_policy_change(state: &AppState, general: &Value) -> AppResult<()> {
    let cpu_ratio = general
        .get("cpu_overcommit_ratio")
        .and_then(Value::as_f64)
        .unwrap_or(DEFAULT_CPU_OVERCOMMIT_RATIO);
    let memory_ratio = general
        .get("memory_overcommit_ratio")
        .and_then(Value::as_f64)
        .unwrap_or(DEFAULT_MEMORY_OVERCOMMIT_RATIO);
    let host = state.host_info.read().await.clone();
    let scheduled = state
        .db
        .list_vms()?
        .into_iter()
        .filter(|vm| vm.state != crate::models::VmState::Error)
        .collect::<Vec<_>>();
    let allocated_vcpus = scheduled
        .iter()
        .fold(0u64, |total, vm| total.saturating_add(u64::from(vm.vcpus)));
    let allocated_memory_bytes = scheduled.iter().fold(0u64, |total, vm| {
        total.saturating_add(vm.memory_mib.saturating_mul(MIB_BYTES))
    });
    let capacity = compute_capacity(
        u64::from(host.cpu.logical_cores),
        host.memory.total_bytes,
        0,
        0,
        CapacityPolicy {
            cpu_overcommit_ratio: cpu_ratio,
            memory_overcommit_ratio: memory_ratio,
        },
    );
    if allocated_vcpus > capacity.schedulable_vcpus {
        return Err(AppError::Conflict(format!(
            "CPU ratio {:.2}x provides {} vCPU but {} vCPU is already allocated",
            cpu_ratio, capacity.schedulable_vcpus, allocated_vcpus
        )));
    }
    if allocated_memory_bytes > capacity.schedulable_memory_bytes {
        return Err(AppError::Conflict(format!(
            "memory ratio {:.2}x provides {} MiB but {} MiB is already allocated",
            memory_ratio,
            capacity.schedulable_memory_bytes / MIB_BYTES,
            allocated_memory_bytes / MIB_BYTES
        )));
    }
    Ok(())
}

fn validate_setting_section(section: &str, value: &Value) -> AppResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| AppError::Validation(format!("setting section '{section}' must be an object")))?;
    let allowed: &[&str] = match section {
        "general" => &[
            "node_name",
            "locale",
            "timezone",
            "ntp_servers",
            "sample_interval_seconds",
            "metrics_retention_days",
            "cpu_overcommit_ratio",
            "memory_overcommit_ratio",
        ],
        "network" => &[
            "default_bridge",
            "default_port_limit_mbps",
            "default_traffic_quota_bytes",
            "dns_servers",
        ],
        "console" => &["vnc_enabled"],
        "security" => &["session_lifetime_minutes", "login_rate_limit", "api_rate_limit"],
        "account" => {
            return Err(AppError::Validation(
                "administrator credentials require /api/v1/admin/credentials".into(),
            ))
        }
        _ => {
            return Err(AppError::Conflict(format!(
                "setting section '{section}' is environment-owned and requires a service restart"
            )))
        }
    };
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(AppError::Validation(format!(
            "setting '{section}.{key}' is unsupported"
        )));
    }
    match section {
        "general" => {
            validate_optional_text(object.get("node_name"), "general.node_name", 128)?;
            validate_optional_text(object.get("locale"), "general.locale", 32)?;
            validate_optional_text(object.get("timezone"), "general.timezone", 128)?;
            validate_string_array(object.get("ntp_servers"), "general.ntp_servers", false)?;
            if let Some(locale) = object.get("locale").and_then(Value::as_str) {
                normalize_guest_locale(locale)?;
            }
            if let Some(timezone) = object.get("timezone").and_then(Value::as_str) {
                validate_timezone_name(timezone)?;
            }
            if let Some(servers) = object.get("ntp_servers").and_then(Value::as_array) {
                for server in servers.iter().filter_map(Value::as_str) {
                    validate_ntp_server(server)?;
                }
            }
            validate_u64_range(
                object.get("sample_interval_seconds"),
                5,
                3600,
                "general.sample_interval_seconds",
            )?;
            validate_u64_range(
                object.get("metrics_retention_days"),
                1,
                3650,
                "general.metrics_retention_days",
            )?;
            validate_f64_range(
                object.get("cpu_overcommit_ratio"),
                1.0,
                MAX_CPU_OVERCOMMIT_RATIO,
                "general.cpu_overcommit_ratio",
            )?;
            validate_f64_range(
                object.get("memory_overcommit_ratio"),
                1.0,
                MAX_MEMORY_OVERCOMMIT_RATIO,
                "general.memory_overcommit_ratio",
            )?;
        }
        "network" => {
            if let Some(bridge) = object.get("default_bridge") {
                let bridge = bridge
                    .as_str()
                    .ok_or_else(|| AppError::Validation("network.default_bridge must be text".into()))?;
                if bridge.is_empty()
                    || bridge.len() > 15
                    || !bridge
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                {
                    return Err(AppError::Validation(
                        "network.default_bridge is not a valid Linux interface name".into(),
                    ));
                }
            }
            validate_u64_range(
                object.get("default_port_limit_mbps"),
                1,
                100_000,
                "network.default_port_limit_mbps",
            )?;
            if let Some(quota) = object.get("default_traffic_quota_bytes") {
                if !quota.is_null() && quota.as_u64().is_none() {
                    return Err(AppError::Validation(
                        "network.default_traffic_quota_bytes must be a non-negative integer or null".into(),
                    ));
                }
            }
            validate_string_array(object.get("dns_servers"), "network.dns_servers", true)?;
        }
        "console" => {
            if object.get("vnc_enabled").is_some_and(|value| !value.is_boolean()) {
                return Err(AppError::Validation("console.vnc_enabled must be boolean".into()));
            }
        }
        "security" => {
            validate_u64_range(
                object.get("session_lifetime_minutes"),
                5,
                1440,
                "security.session_lifetime_minutes",
            )?;
            validate_u64_range(
                object.get("login_rate_limit"),
                1,
                1000,
                "security.login_rate_limit",
            )?;
            validate_u64_range(
                object.get("api_rate_limit"),
                10,
                100_000,
                "security.api_rate_limit",
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_optional_text(value: Option<&Value>, name: &str, maximum: usize) -> AppResult<()> {
    if let Some(value) = value {
        let value = value
            .as_str()
            .ok_or_else(|| AppError::Validation(format!("{name} must be text")))?;
        if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
            return Err(AppError::Validation(format!("{name} is invalid")));
        }
    }
    Ok(())
}

fn validate_u64_range(value: Option<&Value>, minimum: u64, maximum: u64, name: &str) -> AppResult<()> {
    if let Some(value) = value {
        let value = value
            .as_u64()
            .ok_or_else(|| AppError::Validation(format!("{name} must be an integer")))?;
        if !(minimum..=maximum).contains(&value) {
            return Err(AppError::Validation(format!(
                "{name} must be between {minimum} and {maximum}"
            )));
        }
    }
    Ok(())
}

fn validate_f64_range(value: Option<&Value>, minimum: f64, maximum: f64, name: &str) -> AppResult<()> {
    if let Some(value) = value {
        let value = value
            .as_f64()
            .filter(|value| value.is_finite())
            .ok_or_else(|| AppError::Validation(format!("{name} must be a finite number")))?;
        if !(minimum..=maximum).contains(&value) {
            return Err(AppError::Validation(format!(
                "{name} must be between {minimum} and {maximum}"
            )));
        }
    }
    Ok(())
}

fn validate_string_array(value: Option<&Value>, name: &str, ip_addresses: bool) -> AppResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let values = value
        .as_array()
        .ok_or_else(|| AppError::Validation(format!("{name} must be an array")))?;
    if values.len() > 32 {
        return Err(AppError::Validation(format!("{name} has too many entries")));
    }
    for value in values {
        let value = value
            .as_str()
            .ok_or_else(|| AppError::Validation(format!("{name} entries must be text")))?;
        if value.is_empty() || value.len() > 253 || value.chars().any(char::is_control) {
            return Err(AppError::Validation(format!("{name} contains an invalid entry")));
        }
        if ip_addresses && value.parse::<IpAddr>().is_err() {
            return Err(AppError::Validation(format!("{name} must contain IP addresses")));
        }
    }
    Ok(())
}

pub async fn update_credentials(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<CredentialsBody>,
) -> AppResult<Response> {
    let admin = auth.admin.as_ref().ok_or(AppError::Forbidden)?;
    let stored = state
        .db
        .admin_auth_by_username(&admin.username)?
        .ok_or(AppError::Unauthorized)?;
    if !verify_password(&input.current_password, &stored.password_hash)? {
        return Err(AppError::Unauthorized);
    }
    let password_hash = input.new_password.as_deref().map(hash_password).transpose()?;
    state
        .db
        .update_admin_credentials(&admin.id, input.username.as_deref(), password_hash.as_deref())?;
    state.db.revoke_admin_sessions(&admin.id)?;
    audit(
        &state,
        &auth,
        "admin.credentials.update",
        "admin",
        Some(&admin.id),
        true,
        json!({ "username_changed": input.username.is_some(), "password_changed": input.new_password.is_some() }),
    );
    Ok(Json(json!({ "updated": true, "reauthenticate": true })).into_response())
}

pub async fn list_api_keys(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("api_keys:read")?;
    Ok(Json(json!({ "items": state.db.list_api_keys()? })).into_response())
}

pub async fn create_api_key(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<ApiKeyBody>,
) -> AppResult<Response> {
    auth.require("api_keys:write")?;
    if input.permissions.is_empty() {
        return Err(AppError::Validation(
            "at least one API permission is required".into(),
        ));
    }
    const GRANTABLE_PERMISSIONS: &[&str] = &[
        "*",
        "host:read",
        "vms:read",
        "vms:write",
        "vms:power",
        "vms:reinstall",
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
        "admins:write",
        "api_keys:read",
        "api_keys:write",
        "audit:read",
        "updates:read",
        "updates:write",
        "jobs:read",
        "jobs:write",
    ];
    let mut permissions = input
        .permissions
        .iter()
        .map(|permission| permission.trim())
        .filter(|permission| !permission.is_empty())
        .collect::<Vec<_>>();
    permissions.sort_unstable();
    permissions.dedup();
    if permissions.is_empty()
        || permissions
            .iter()
            .any(|permission| !GRANTABLE_PERMISSIONS.contains(permission))
    {
        return Err(AppError::Validation(
            "one or more API key permissions are unsupported".into(),
        ));
    }
    if permissions.iter().any(|permission| !auth.allows(permission)) {
        return Err(AppError::Forbidden);
    }
    let permissions = permissions.into_iter().map(str::to_owned).collect::<Vec<_>>();
    let token = state.security.issue_api_key();
    let record = state.db.create_api_key(
        &input.name,
        token.hash(),
        token.prefix(),
        &permissions,
        &input.ip_allowlist,
        auth.admin.as_ref().map(|admin| admin.id.as_str()),
        parse_optional_timestamp(input.expires_at.as_ref())?,
    )?;
    audit(
        &state,
        &auth,
        "api_key.create",
        "api_key",
        Some(&record.id),
        true,
        json!({ "prefix": record.prefix }),
    );
    let mut response = (
        StatusCode::CREATED,
        Json(json!({
            "record": record,
            "key": token.expose(),
            "token": token.expose()
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub async fn revoke_api_key(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("api_keys:write")?;
    state.db.revoke_api_key(&id, Utc::now().timestamp())?;
    audit(
        &state,
        &auth,
        "api_key.revoke",
        "api_key",
        Some(&id),
        true,
        json!({}),
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn list_jobs(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListQuery>,
) -> AppResult<Response> {
    auth.require("jobs:read")?;
    let status = query
        .status
        .as_deref()
        .map(str::parse::<JobStatus>)
        .transpose()
        .map_err(AppError::Validation)?;
    let items = state.db.list_jobs(
        status,
        query.vm_id.as_deref(),
        query.limit.unwrap_or(DEFAULT_LIMIT),
    )?;
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn get_job(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("jobs:read")?;
    let job = state
        .db
        .get_job(&id)?
        .ok_or_else(|| AppError::NotFound("job".into()))?;
    Ok(Json(json!({ "operation": job })).into_response())
}

pub async fn cancel_job(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("jobs:write")?;
    state.db.cancel_job(&id, Utc::now().timestamp())?;
    audit(&state, &auth, "job.cancel", "job", Some(&id), true, json!({}));
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn auth_me(Extension(auth): Extension<AuthContext>) -> AppResult<Response> {
    Ok(Json(json!({
        "actor_type": auth.actor_type,
        "actor_id": auth.actor_id,
        "admin": auth.admin,
        "permissions": auth.permissions,
    }))
    .into_response())
}

pub async fn list_admins(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("admins:read")?;
    Ok(Json(json!({ "items": state.db.list_admins()? })).into_response())
}

pub async fn create_admin(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<AdminCreateBody>,
) -> AppResult<Response> {
    auth.require("admins:write")?;
    if input.password.len() < 12 {
        return Err(AppError::Validation(
            "administrator password must contain at least 12 characters".into(),
        ));
    }
    let password_hash = hash_password(&input.password)?;
    let admin = state
        .db
        .create_admin(&input.username, &password_hash, input.role)?;
    audit(
        &state,
        &auth,
        "admin.create",
        "admin",
        Some(&admin.id),
        true,
        json!({ "role": admin.role }),
    );
    Ok((StatusCode::CREATED, Json(json!({ "admin": admin }))).into_response())
}

pub async fn get_admin(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("admins:read")?;
    let admin = state
        .db
        .admin_by_id(&id)?
        .ok_or_else(|| AppError::NotFound("admin".into()))?;
    Ok(Json(json!({ "admin": admin })).into_response())
}

pub async fn patch_admin(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<AdminPatchBody>,
) -> AppResult<Response> {
    auth.require("admins:write")?;
    let admin = state.db.update_admin_access(&id, input.role, input.enabled)?;
    if input.enabled == Some(false) {
        state.db.revoke_admin_sessions(&admin.id)?;
    }
    audit(
        &state,
        &auth,
        "admin.update",
        "admin",
        Some(&admin.id),
        true,
        json!({ "role": admin.role, "enabled": admin.enabled }),
    );
    Ok(Json(json!({ "admin": admin })).into_response())
}

pub async fn update_admin_credentials(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(input): Json<AdminCredentialUpdateBody>,
) -> AppResult<Response> {
    auth.require("admins:write")?;
    if input.username.is_none() && input.password.is_none() {
        return Err(AppError::Validation("username or password is required".into()));
    }
    if input
        .password
        .as_deref()
        .is_some_and(|password| password.len() < 12)
    {
        return Err(AppError::Validation(
            "administrator password must contain at least 12 characters".into(),
        ));
    }
    let password_hash = input.password.as_deref().map(hash_password).transpose()?;
    state
        .db
        .update_admin_credentials(&id, input.username.as_deref(), password_hash.as_deref())?;
    state.db.revoke_admin_sessions(&id)?;
    audit(
        &state,
        &auth,
        "admin.credentials.update",
        "admin",
        Some(&id),
        true,
        json!({ "username_changed": input.username.is_some(), "password_changed": input.password.is_some() }),
    );
    Ok(Json(json!({ "updated": true, "sessions_revoked": true })).into_response())
}

pub async fn delete_admin(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("admins:write")?;
    if auth.admin.as_ref().is_some_and(|admin| admin.id == id) {
        return Err(AppError::Conflict(
            "the current administrator cannot delete itself".into(),
        ));
    }
    state.db.delete_admin(&id)?;
    audit(&state, &auth, "admin.delete", "admin", Some(&id), true, json!({}));
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub async fn default_dns(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> AppResult<Response> {
    auth.require("network:read")?;
    Ok(Json(json!({ "items": state.db.dns_servers(None, None)? })).into_response())
}

pub async fn update_default_dns(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<DnsBody>,
) -> AppResult<Response> {
    auth.require("network:write")?;
    let network = state
        .db
        .get_setting("network")?
        .map(|record| record.value)
        .unwrap_or_else(|| json!({}));
    if !network.is_object() {
        return Err(AppError::Internal(
            "stored setting section 'network' is not an object".into(),
        ));
    }
    let (_, items) = state.db.set_network_setting_and_default_dns(
        &network,
        &input.dns_servers,
        auth.admin.as_ref().map(|admin| admin.id.as_str()),
    )?;
    audit(
        &state,
        &auth,
        "dns.defaults.update",
        "node",
        None,
        true,
        json!({ "count": items.len() }),
    );
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListQuery>,
) -> AppResult<Response> {
    auth.require("audit:read")?;
    let items = state.db.list_audit(
        query.before_id,
        query.resource_type.as_deref(),
        query.resource_id.as_deref(),
        query.limit.unwrap_or(DEFAULT_LIMIT),
    )?;
    Ok(Json(json!({ "items": items })).into_response())
}

pub async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<SnapshotBody>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &id)?;
    let request = SnapshotRequest {
        name: input.name,
        description: input.description,
    };
    crate::hypervisor::validate_snapshot_name(&request.name)?;
    let request_value = serde_json::to_value(&request)
        .map_err(|error| AppError::Internal(format!("could not encode snapshot request: {error}")))?;
    let idempotency_key = idempotency_key(&headers)?;
    if let Some(existing) = idempotency_key
        .as_deref()
        .map(|key| state.db.job_by_idempotency_key(key))
        .transpose()?
        .flatten()
    {
        if existing.kind != "vm.snapshot.create"
            || existing.vm_id.as_deref() != Some(vm.id.as_str())
            || existing.payload.get("request") != Some(&request_value)
        {
            return Err(AppError::Conflict(
                "idempotency key was already used for a different request".into(),
            ));
        }
        let snapshot_id = existing
            .payload
            .get("snapshot_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::Conflict("original snapshot record is missing".into()))?;
        let record = state
            .db
            .list_snapshots(&vm.id)?
            .into_iter()
            .find(|snapshot| snapshot.id == snapshot_id)
            .ok_or_else(|| AppError::Conflict("original snapshot record no longer exists".into()))?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "snapshot": record, "operation": existing, "replayed": true })),
        )
            .into_response());
    }
    let record = state.db.create_snapshot(
        &vm.id,
        &request.name,
        request.description.as_deref().unwrap_or(""),
        false,
        &json!({}),
    )?;
    let job = match enqueue(
        &state,
        &auth,
        "vm.snapshot.create",
        Some(&vm.id),
        json!({ "request": request, "snapshot_id": record.id }),
        idempotency_key,
    ) {
        Ok(job) => job,
        Err(error) => {
            let _ = state.db.delete_snapshot_record(&record.id);
            return Err(error);
        }
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "snapshot": record, "operation": job })),
    )
        .into_response())
}

pub async fn list_snapshots(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    auth.require("vms:read")?;
    let vm = required_vm(&state, &id)?;
    Ok(Json(json!({ "items": state.db.list_snapshots(&vm.id)? })).into_response())
}

pub async fn revert_snapshot(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((vm_id, snapshot_id)): Path<(String, String)>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &vm_id)?;
    let snapshot = state
        .db
        .list_snapshots(&vm.id)?
        .into_iter()
        .find(|item| item.id == snapshot_id)
        .ok_or_else(|| AppError::NotFound("snapshot".into()))?;
    let info = state.hypervisor.revert_snapshot(&vm.name, &snapshot.name).await?;
    let libvirt_uuid = info.uuid.as_ref().map(ToString::to_string);
    state.db.set_vm_state(
        &vm.id,
        power_state_to_model(info.state),
        None,
        libvirt_uuid.as_deref(),
        None,
    )?;
    audit(
        &state,
        &auth,
        "snapshot.revert",
        "snapshot",
        Some(&snapshot.id),
        true,
        json!({ "vm_id": vm.id }),
    );
    Ok(Json(json!({ "vm": info })).into_response())
}

pub async fn delete_snapshot(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((vm_id, snapshot_id)): Path<(String, String)>,
) -> AppResult<Response> {
    auth.require("vms:write")?;
    let vm = required_vm(&state, &vm_id)?;
    let snapshot = state
        .db
        .list_snapshots(&vm.id)?
        .into_iter()
        .find(|item| item.id == snapshot_id)
        .ok_or_else(|| AppError::NotFound("snapshot".into()))?;
    state.hypervisor.delete_snapshot(&vm.name, &snapshot.name).await?;
    state.db.delete_snapshot_record(&snapshot.id)?;
    audit(
        &state,
        &auth,
        "snapshot.delete",
        "snapshot",
        Some(&snapshot.id),
        true,
        json!({ "vm_id": vm.id }),
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn enrich_vm(state: &AppState, vm: Vm) -> AppResult<Value> {
    let addresses = state.db.vm_ip_addresses(&vm.id)?;
    let dns = state.db.dns_servers(None, Some(&vm.id))?;
    let metrics = state
        .db
        .vm_metrics(&vm.id, Utc::now().timestamp() - 24 * 60 * 60, 1)?
        .into_iter()
        .next();
    let mut value = serde_json::to_value(&vm)
        .map_err(|error| AppError::Internal(format!("could not encode VM: {error}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("VM serialization was not an object".into()))?;
    let public_ipv4 = addresses
        .iter()
        .filter(|ip| ip.scope == IpScope::Public && ip.family == AddressFamily::V4)
        .map(|ip| ip.address.clone())
        .collect::<Vec<_>>();
    let public_ipv6 = addresses
        .iter()
        .filter(|ip| ip.scope == IpScope::Public && ip.family == AddressFamily::V6)
        .map(|ip| ip.address.clone())
        .collect::<Vec<_>>();
    let private_ipv4 = addresses
        .iter()
        .filter(|ip| ip.scope == IpScope::Private && ip.family == AddressFamily::V4)
        .map(|ip| ip.address.clone())
        .collect::<Vec<_>>();
    let private_ipv6 = addresses
        .iter()
        .filter(|ip| ip.scope == IpScope::Private && ip.family == AddressFamily::V6)
        .map(|ip| ip.address.clone())
        .collect::<Vec<_>>();
    object.insert("public_ipv4".into(), json!(public_ipv4));
    object.insert("public_ipv6".into(), json!(public_ipv6));
    object.insert("private_ipv4".into(), json!(private_ipv4));
    object.insert("private_ipv6".into(), json!(private_ipv6));
    object.insert("addresses".into(), json!(addresses));
    object.insert(
        "dns_servers".into(),
        json!(dns.iter().map(|item| &item.address).collect::<Vec<_>>()),
    );
    object.insert("dns".into(), json!(dns));
    object.insert("metrics".into(), json!(metrics));
    object.insert(
        "password_present".into(),
        json!(state.db.vm_password_envelope(&vm.id)?.is_some()),
    );
    object.insert(
        "status_tokens".into(),
        json!(state.db.list_customer_tokens(&vm.id)?),
    );
    object.insert("ram_mb".into(), json!(vm.memory_mib));
    object.insert("disk_gb".into(), json!(vm.disk_gib));
    object.insert("cpu".into(), json!(vm.vcpus));
    object.insert(
        "traffic_quota".into(),
        serde_json::to_value(crate::services::traffic::quota_status(state, &vm)?)
            .map_err(|error| AppError::Internal(format!("could not encode traffic quota: {error}")))?,
    );
    object.insert(
        "guest_tools".into(),
        crate::services::guest_tools::admin_status_for_vm(&vm, state.db.vm_guest_tools(&vm.id)?),
    );
    Ok(value)
}

fn required_vm(state: &AppState, id: &str) -> AppResult<Vm> {
    state
        .db
        .get_vm(id)?
        .ok_or_else(|| AppError::NotFound("VM".into()))
}

pub(crate) fn normalize_ssh_keys(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut keys = Vec::new();
    for value in values {
        let key = value.trim();
        if key.is_empty() {
            continue;
        }
        if key.len() > 16 * 1024
            || key.chars().any(|character| matches!(character, '\r' | '\n'))
            || !(key.starts_with("ssh-") || key.starts_with("ecdsa-") || key.starts_with("sk-"))
        {
            return Err(AppError::Validation(
                "one or more SSH public keys are invalid".into(),
            ));
        }
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.to_owned());
        }
        if keys.len() > 64 {
            return Err(AppError::Validation(
                "at most 64 SSH public keys are allowed".into(),
            ));
        }
    }
    GuestCommand::SetSshKeys {
        username: "root".into(),
        authorized_keys: keys.clone(),
    }
    .validate()
    .map_err(|error| AppError::Validation(error.to_string()))?;
    Ok(keys)
}

pub(crate) fn validate_guest_password(username: &str, password: &str) -> AppResult<()> {
    if password.len() < 8 {
        return Err(AppError::Validation(
            "guest password must contain at least 8 characters".into(),
        ));
    }
    GuestCommand::SetPassword {
        username: username.to_owned(),
        password: password.to_owned(),
    }
    .validate()
    .map_err(|error| AppError::Validation(error.to_string()))
}

fn build_create_request(state: &AppState, spec: &NewVm, start: bool) -> AppResult<CreateVmRequest> {
    let image = if let Some(iso_id) = spec.iso_id.as_deref() {
        let image = state
            .db
            .get_iso(iso_id)?
            .ok_or_else(|| AppError::NotFound("ISO image".into()))?;
        vm_image_from_iso(image)?
    } else {
        VmImage::Blank
    };
    let firmware = if spec.firmware.eq_ignore_ascii_case("uefi") {
        Firmware::Uefi
    } else {
        Firmware::Bios
    };
    let request = CreateVmRequest {
        name: spec.name.clone(),
        vcpus: spec.vcpus,
        memory_mib: spec.memory_mib,
        initial_memory_mib: None,
        disk_gib: spec.disk_gib,
        image,
        cloud_init_iso: None,
        guest_tools_socket: None,
        bridge: if spec
            .metadata
            .pointer("/routed_network/managed_by")
            .and_then(Value::as_str)
            == Some("vexa-vm")
        {
            None
        } else {
            spec.bridge.clone()
        },
        tap_name: spec.tap_name.clone(),
        mac_address: spec.mac_address.clone().unwrap_or_else(random_mac),
        network_limit_mbps: spec.network_limit_mbps,
        firmware,
        machine_type: spec.machine_type.clone().unwrap_or_else(|| "q35".into()),
        autostart: spec.autostart,
        start,
    };
    crate::hypervisor::validate_create_request(&request)?;
    Ok(request)
}

/// Reserve enough host capacity for the control plane before a guest is queued.
/// This is deliberately enforced at the API boundary as well as in the panel,
/// so an API client cannot create a domain that the KVM node cannot safely run.
async fn validate_create_capacity(state: &AppState, spec: &NewVm, start: bool) -> AppResult<u64> {
    // The in-process mock deliberately permits oversized fixtures so the HTTP
    // lifecycle suite can exercise resource-management endpoints on any CI host.
    // Real KVM/libvirt deployments always use the checks below.
    if state.config.hypervisor_mode == crate::config::HypervisorMode::Mock {
        return Ok(spec.memory_mib);
    }
    let host = state.host_info.read().await.clone();
    let vms = state.db.list_vms()?;
    let scheduled = vms.iter().filter(|vm| vm.state != crate::models::VmState::Error);
    let allocated_vcpus = scheduled
        .clone()
        .fold(0u64, |total, vm| total.saturating_add(u64::from(vm.vcpus)));
    let allocated_memory_bytes = scheduled.fold(0u64, |total, vm| {
        total.saturating_add(vm.memory_mib.saturating_mul(MIB_BYTES))
    });
    let policy = capacity_policy(state)?;
    let capacity = compute_capacity(
        u64::from(host.cpu.logical_cores),
        host.memory.total_bytes,
        allocated_vcpus,
        allocated_memory_bytes,
        policy,
    );
    if u64::from(spec.vcpus) > capacity.available_vcpus {
        return Err(AppError::Validation(format!(
            "requested {} vCPU exceeds this node's overcommit capacity of {} vCPU (CPU ratio {:.2}x)",
            spec.vcpus, capacity.available_vcpus, policy.cpu_overcommit_ratio
        )));
    }

    let requested_memory = spec.memory_mib.saturating_mul(MIB_BYTES);
    if requested_memory > capacity.available_memory_bytes {
        return Err(AppError::Validation(format!(
            "requested {} MiB memory exceeds this node's configured overcommit capacity of {} MiB (memory ratio {:.2}x; 256 MiB remains reserved for the host)",
            spec.memory_mib,
            capacity.available_memory_bytes / MIB_BYTES,
            policy.memory_overcommit_ratio,
        )));
    }

    let metrics = state.host_detector.sample().await?;
    if start {
        if metrics.memory.available_bytes <= HOST_MEMORY_RESERVE_BYTES {
            return Err(AppError::Validation(format!(
                "the host memory reserve is exhausted; at least {} MiB must remain available before another VM can start",
                HOST_MEMORY_RESERVE_BYTES / MIB_BYTES
            )));
        }
    }
    let storage = metrics
        .filesystems
        .iter()
        .filter(|filesystem| state.config.vm_storage.starts_with(&filesystem.mount_point))
        .max_by_key(|filesystem| filesystem.mount_point.len())
        .or_else(|| {
            metrics
                .filesystems
                .iter()
                .find(|filesystem| filesystem.mount_point == "/")
        })
        .ok_or_else(|| AppError::Validation("could not determine free VM storage capacity".into()))?;
    // Existing disk files are already reflected by filesystem free space. A
    // queued/running create job may not have allocated its disk yet, so its
    // `creating` row must additionally reserve the full requested capacity.
    // The create mutex guarantees a prior request publishes that row before
    // the next request takes this snapshot.
    let pending_disk_reservations = pending_create_disk_reservations(&vms);
    let available_disk = storage
        .available_bytes
        .saturating_sub(HOST_DISK_RESERVE_BYTES)
        .saturating_sub(pending_disk_reservations);
    let requested_disk = spec.disk_gib.saturating_mul(GIB_BYTES);
    if requested_disk > available_disk {
        return Err(AppError::Validation(format!(
            "requested {} GiB disk exceeds this node's safe unreserved capacity of {} GiB (2 GiB is reserved for the host and queued creates are counted)",
            spec.disk_gib,
            available_disk / GIB_BYTES
        )));
    }
    // The ratio expands admission capacity; it must never reduce what the
    // guest sees. VirtIO balloon support remains attached for statistics and
    // entitlement recovery, but its boot target equals the full allocation.
    Ok(spec.memory_mib)
}

fn capacity_policy(state: &AppState) -> AppResult<CapacityPolicy> {
    let cpu_overcommit_ratio = state
        .setting_f64("general", "cpu_overcommit_ratio")?
        .filter(|ratio| (1.0..=MAX_CPU_OVERCOMMIT_RATIO).contains(ratio))
        .unwrap_or(DEFAULT_CPU_OVERCOMMIT_RATIO);
    let memory_overcommit_ratio = state
        .setting_f64("general", "memory_overcommit_ratio")?
        .filter(|ratio| (1.0..=MAX_MEMORY_OVERCOMMIT_RATIO).contains(ratio))
        .unwrap_or(DEFAULT_MEMORY_OVERCOMMIT_RATIO);
    Ok(CapacityPolicy {
        cpu_overcommit_ratio,
        memory_overcommit_ratio,
    })
}

fn compute_capacity(
    host_vcpus: u64,
    host_memory_bytes: u64,
    allocated_vcpus: u64,
    allocated_memory_bytes: u64,
    policy: CapacityPolicy,
) -> ComputeCapacity {
    let schedulable_vcpus = scaled_capacity(host_vcpus, policy.cpu_overcommit_ratio);
    let physical_guest_memory = host_memory_bytes.saturating_sub(HOST_MEMORY_RESERVE_BYTES);
    let schedulable_memory_bytes = scaled_capacity(physical_guest_memory, policy.memory_overcommit_ratio);
    ComputeCapacity {
        schedulable_vcpus,
        available_vcpus: schedulable_vcpus.saturating_sub(allocated_vcpus),
        schedulable_memory_bytes,
        available_memory_bytes: schedulable_memory_bytes.saturating_sub(allocated_memory_bytes),
    }
}

fn scaled_capacity(physical: u64, ratio: f64) -> u64 {
    ((physical as f64) * ratio).floor().min(u64::MAX as f64) as u64
}

fn pending_create_disk_reservations(vms: &[Vm]) -> u64 {
    vms.iter()
        .filter(|vm| vm.state == crate::models::VmState::Creating)
        .fold(0u64, |total, vm| {
            total.saturating_add(vm.disk_gib.saturating_mul(GIB_BYTES))
        })
}

fn apply_vm_defaults(state: &AppState, input: &mut CreateVmBody) -> AppResult<()> {
    let selected_image = input
        .spec
        .iso_id
        .as_deref()
        .map(|id| state.db.get_iso(id))
        .transpose()?
        .flatten();
    apply_guest_identity_defaults(
        input,
        selected_image.as_ref().map(|image| image.os_family.as_str()),
    );
    if input.spec.metadata.is_null() {
        input.spec.metadata = json!({});
    } else if !input.spec.metadata.is_object() {
        return Err(AppError::Validation("VM metadata must be a JSON object".into()));
    }
    if input.spec.machine_type.is_none() {
        input.spec.machine_type = Some("q35".into());
    }
    if input.spec.firmware.trim().is_empty() || input.spec.firmware.eq_ignore_ascii_case("auto") {
        let image_requires_uefi = selected_image.as_ref().is_some_and(|image| image.uefi);
        input.spec.firmware = if image_requires_uefi { "uefi" } else { "bios" }.into();
    }
    if input.spec.network_limit_mbps.is_none() {
        input.spec.network_limit_mbps = state.setting_u64("network", "default_port_limit_mbps")?;
    }
    if input.spec.traffic_limit_bytes.is_none() {
        input.spec.traffic_limit_bytes = state.setting_u64("network", "default_traffic_quota_bytes")?;
    }
    if input.spec.bridge.is_none() {
        input.spec.bridge = state
            .setting("network", "default_bridge")?
            .and_then(|value| value.as_str().map(str::to_owned))
            .or_else(|| Some(state.config.network_bridge.clone()));
    }
    if input.spec.timezone.is_none() {
        input.spec.timezone = state
            .setting("general", "timezone")?
            .and_then(|value| value.as_str().map(str::to_owned));
    }
    if let Some(timezone) = input.spec.timezone.as_deref() {
        validate_timezone_name(timezone)?;
    }
    if input.dns_servers.is_empty() {
        input.dns_servers = state.setting_strings("network", "dns_servers")?;
        if input.dns_servers.is_empty() {
            input.dns_servers = state
                .db
                .dns_servers(None, None)?
                .into_iter()
                .map(|server| server.address)
                .collect();
        }
    }
    Ok(())
}

fn apply_guest_identity_defaults(input: &mut CreateVmBody, image_os_family: Option<&str>) {
    // The selected catalog image is authoritative. Besides preventing a
    // caller-supplied mismatch from choosing the wrong first-boot seed, this
    // gives omitted API fields the same behavior as the image-aware panel.
    if let Some(os_family) = image_os_family {
        input.spec.os_family = os_family.to_owned();
    }
    if !input.root_username_was_supplied {
        input.spec.root_username = guest_administrator_default(&input.spec.os_family).into();
    }
}

pub(super) fn guest_administrator_default(os_family: &str) -> &'static str {
    let family = os_family.to_ascii_lowercase();
    if family.contains("windows") {
        "Administrator"
    } else if family.contains("routeros") || family.contains("mikrotik") {
        "vexa-admin"
    } else {
        "root"
    }
}

/// Fingerprint the stable, non-secret portion of a create request before the
/// server generates a MAC address or an automatic-image password. This keeps retries with the
/// same Idempotency-Key replayable without persisting a password verifier that
/// could be attacked offline.
fn create_vm_request_fingerprint(input: &CreateVmBody) -> AppResult<String> {
    let value = json!({
        "spec": &input.spec,
        "ip_addresses": &input.ip_addresses,
        "dns_servers": &input.dns_servers,
        "start": input.start,
        "install_guest_tools": input.install_guest_tools,
        "root_username_supplied": input.root_username_was_supplied,
        "password_supplied": input
            .password
            .as_deref()
            .is_some_and(|password| !password.trim().is_empty()),
    });
    let encoded = serde_json::to_vec(&value)
        .map_err(|error| AppError::Internal(format!("could not fingerprint VM create request: {error}")))?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

pub(super) fn reinstall_request_fingerprint(
    vm_id: &str,
    image_id: &str,
    start: bool,
    install_guest_tools: bool,
    disk_gib: u64,
    password_supplied: bool,
) -> AppResult<String> {
    let encoded = serde_json::to_vec(&json!({
        "vm_id": vm_id,
        "image_id": image_id,
        "start": start,
        "install_guest_tools": install_guest_tools,
        "disk_gib": disk_gib,
        "password_supplied": password_supplied,
    }))
    .map_err(|error| AppError::Internal(format!("could not fingerprint VM reinstall request: {error}")))?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

pub(super) struct ReinstallGuestToolsStage {
    pub generation: String,
    pub socket_path: PathBuf,
    pub new_configuration: bool,
}

/// Prepare a reinstall with a fresh, generation-bound channel key. The only
/// exception is an exact retry of the failed request which already armed a
/// generation that may be present on guest media. Even first-time enablement
/// uses the two-phase path, so an unpublished key is never treated as active.
pub(super) fn stage_reinstall_guest_tools(
    state: &AppState,
    vm: &Vm,
    image: &IsoImage,
    enabled: bool,
    request_fingerprint: &str,
) -> AppResult<Option<ReinstallGuestToolsStage>> {
    if !enabled {
        return Ok(None);
    }
    let install = crate::services::guest_tools::require_installable(&state.config, image)?;
    if let Some(rotation) = state
        .db
        .reusable_vm_guest_tools_rotation(&vm.id, request_fingerprint)?
    {
        if rotation.platform != install.platform
            || rotation.provisioner != install.provisioner
            || rotation.desired_version != state.config.guest_tools_version
        {
            return Err(AppError::Conflict(format!(
                "failed reinstall {} armed Guest Tools for a different image platform or version",
                rotation.origin_job_id
            )));
        }
        return Ok(Some(ReinstallGuestToolsStage {
            generation: rotation.generation,
            socket_path: crate::services::guest_tools::socket_path(&state.config, &vm.id)?,
            new_configuration: false,
        }));
    }
    let current = state.db.vm_guest_tools(&vm.id)?;
    let new_configuration = !current.as_ref().is_some_and(|record| record.enabled);
    if new_configuration {
        let placeholder_secret = crate::services::guest_tools::new_secret();
        state.db.configure_vm_guest_tools(
            &vm.id,
            install.platform,
            install.provisioner,
            &placeholder_secret,
            &state.config.guest_tools_version,
            &state.security,
        )?;
    }
    let fresh_secret = crate::services::guest_tools::new_secret();
    let generation = match state.db.stage_vm_guest_tools_rotation(
        &vm.id,
        install.platform,
        install.provisioner,
        &fresh_secret,
        &state.config.guest_tools_version,
        &state.security,
    ) {
        Ok(generation) => generation,
        Err(error) => {
            if new_configuration {
                let _ = state.db.delete_vm_guest_tools_configuration(&vm.id);
            }
            return Err(error);
        }
    };
    let socket_path = match crate::services::guest_tools::socket_path(&state.config, &vm.id) {
        Ok(path) => path,
        Err(error) => {
            let stage = ReinstallGuestToolsStage {
                generation,
                socket_path: PathBuf::new(),
                new_configuration,
            };
            cleanup_uncommitted_guest_tools_stage(state, &vm.id, &stage);
            return Err(error);
        }
    };
    Ok(Some(ReinstallGuestToolsStage {
        generation,
        socket_path,
        new_configuration,
    }))
}

pub(super) fn cleanup_uncommitted_guest_tools_stage(
    state: &AppState,
    vm_id: &str,
    stage: &ReinstallGuestToolsStage,
) {
    if state
        .db
        .discard_vm_guest_tools_rotation(vm_id, &stage.generation)
        .is_ok()
        && stage.new_configuration
    {
        let _ = state.db.delete_vm_guest_tools_configuration(vm_id);
    }
}

pub(super) fn vm_image_from_iso(image: IsoImage) -> AppResult<VmImage> {
    if !iso_is_ready(&image) {
        return Err(AppError::Conflict(
            "selected image is disabled, missing, or has not passed verification".into(),
        ));
    }
    let architecture = image.architecture.trim().to_ascii_lowercase();
    let architecture_matches = match std::env::consts::ARCH {
        "x86_64" => matches!(architecture.as_str(), "x86_64" | "amd64"),
        "aarch64" => matches!(architecture.as_str(), "aarch64" | "arm64"),
        host => architecture == host,
    };
    if !architecture_matches {
        return Err(AppError::Conflict(format!(
            "image architecture '{}' does not match this {} host",
            image.architecture,
            std::env::consts::ARCH
        )));
    }
    let path = image
        .local_path
        .map(PathBuf::from)
        .ok_or_else(|| AppError::Conflict("selected image is not available locally".into()))?;
    if image.install_mode == InstallMode::Automatic
        && image.os_family.to_ascii_lowercase().contains("windows")
        && image
            .metadata
            .get("unattended_installer")
            .and_then(Value::as_bool)
            == Some(true)
    {
        let driver_iso = image
            .metadata
            .get("virtio_driver_iso")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                AppError::Conflict("automatic Windows installer has no verified virtio driver ISO".into())
            })?;
        let image_index = image
            .metadata
            .get("windows_image_index")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (1..=64).contains(value))
            .unwrap_or(2);
        let driver_version = image
            .metadata
            .get("windows_driver_version")
            .and_then(Value::as_str)
            .unwrap_or("2k22")
            .trim()
            .to_owned();
        if driver_version.is_empty()
            || driver_version.len() > 16
            || !driver_version.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(AppError::Conflict(
                "automatic Windows installer driver version is invalid".into(),
            ));
        }
        return Ok(VmImage::UnattendedWindowsIso {
            path,
            driver_iso,
            image_index,
            driver_version,
        });
    }
    if image.install_mode == InstallMode::Automatic
        && (image.os_family.eq_ignore_ascii_case("routeros")
            || image
                .metadata
                .get("preconfigured_appliance")
                .and_then(Value::as_bool)
                == Some(true))
    {
        if automatic_disk_format(&path)? != "raw" {
            return Err(AppError::Conflict(
                "preconfigured appliance image must be a raw disk".into(),
            ));
        }
        return Ok(VmImage::ApplianceRaw { path });
    }
    Ok(match image.install_mode {
        InstallMode::Manual => VmImage::InstallerIso { path },
        InstallMode::CloudInit | InstallMode::Automatic => {
            // Do not infer a virtual disk format from `.img`: Ubuntu and
            // other vendors use that suffix for both raw and qcow2 images.
            // The qcow2 magic is authoritative and makes existing verified
            // catalog entries safe even if they pre-date format metadata.
            let format = automatic_disk_format(&path)?;
            match format.as_str() {
                "raw" => VmImage::Raw { path },
                "qcow" | "qcow2" => VmImage::Qcow2 { path },
                _ => unreachable!("automatic_disk_format only returns raw or qcow2"),
            }
        }
    })
}

fn automatic_disk_format(path: &FsPath) -> AppResult<String> {
    let mut image = File::open(path).map_err(|error| {
        AppError::Conflict(format!(
            "automatic image '{}' cannot be read: {error}",
            path.display()
        ))
    })?;
    let mut magic = [0_u8; 4];
    let bytes_read = image.read(&mut magic).map_err(|error| {
        AppError::Conflict(format!(
            "automatic image '{}' cannot be read: {error}",
            path.display()
        ))
    })?;
    if bytes_read == magic.len() && magic == *b"QFI\xfb" {
        Ok("qcow2".into())
    } else {
        Ok("raw".into())
    }
}

pub(super) fn iso_is_ready(image: &IsoImage) -> bool {
    image.enabled
        && image
            .local_path
            .as_deref()
            .is_some_and(|path| std::path::Path::new(path).is_file())
        && image.checksum_sha256.is_some()
        && image
            .metadata
            .get("verified_at")
            .and_then(Value::as_i64)
            .is_some()
}

fn power_state_to_model(state: crate::hypervisor::VmPowerState) -> crate::models::VmState {
    match state {
        crate::hypervisor::VmPowerState::Running => crate::models::VmState::Running,
        crate::hypervisor::VmPowerState::Paused | crate::hypervisor::VmPowerState::Suspended => {
            crate::models::VmState::Paused
        }
        crate::hypervisor::VmPowerState::ShuttingDown | crate::hypervisor::VmPowerState::ShutOff => {
            crate::models::VmState::Stopped
        }
        crate::hypervisor::VmPowerState::Crashed => crate::models::VmState::Error,
        crate::hypervisor::VmPowerState::Unknown => crate::models::VmState::Unknown,
    }
}

fn enqueue(
    state: &AppState,
    auth: &AuthContext,
    kind: &str,
    vm_id: Option<&str>,
    payload: Value,
    idempotency_key: Option<String>,
) -> AppResult<crate::models::Job> {
    state.db.enqueue_job(&NewJob {
        kind: kind.into(),
        vm_id: vm_id.map(ToOwned::to_owned),
        payload,
        idempotency_key,
        run_after: None,
        max_attempts: 1,
        actor_type: Some(auth.actor_type.into()),
        actor_id: Some(auth.actor_id.clone()),
    })
}

fn audit(
    state: &AppState,
    auth: &AuthContext,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    success: bool,
    details: Value,
) {
    if let Err(error) = state.db.append_audit(&NewAuditEvent {
        actor_type: auth.actor_type.into(),
        actor_id: Some(auth.actor_id.clone()),
        action: action.into(),
        resource_type: resource_type.into(),
        resource_id: resource_id.map(ToOwned::to_owned),
        request_id: auth.request_id.clone(),
        source_ip: auth.source_ip.clone(),
        user_agent: auth.user_agent.clone(),
        success,
        details,
    }) {
        tracing::warn!(error = %error, "could not persist audit event");
    }
}

/// Mark address inventory entries that cannot currently be allocated. Keeping
/// this in the API response prevents the panel from offering a free-looking
/// address that a broader active blacklist CIDR will reject at assignment
/// time; the database remains the final authority for the actual assignment.
fn address_values_with_blacklist(state: &AppState, items: Vec<IpAddressRecord>) -> AppResult<Vec<Value>> {
    let networks = state
        .db
        .list_ip_blacklist_entries(true)?
        .into_iter()
        .map(|entry| {
            entry
                .cidr
                .parse::<IpNet>()
                .map_err(|_| AppError::Internal(format!("stored blacklist CIDR is invalid: {}", entry.cidr)))
        })
        .collect::<AppResult<Vec<_>>>()?;
    let pool_enabled = state
        .db
        .list_ip_pools()?
        .into_iter()
        .map(|pool| (pool.id, pool.enabled))
        .collect::<BTreeMap<_, _>>();
    address_values_with_allocation_status(items, &networks, &pool_enabled)
}

fn address_values_with_allocation_status(
    items: Vec<IpAddressRecord>,
    networks: &[IpNet],
    pool_enabled: &BTreeMap<String, bool>,
) -> AppResult<Vec<Value>> {
    items
        .into_iter()
        .map(|item| {
            let address = item
                .address
                .parse::<IpAddr>()
                .map_err(|_| AppError::Internal(format!("stored IP address is invalid: {}", item.address)))?;
            let blacklisted = networks.iter().any(|network| network.contains(&address));
            // An imported routed pool is deliberately disabled: it remains
            // visible as complete node inventory, while ordinary bridged VM
            // creation must never offer one of its free-looking addresses.
            // A dangling pool reference also fails closed. Assigned records
            // are not filtered, so existing ownership remains visible.
            let enabled_pool = item
                .pool_id
                .as_ref()
                .map(|pool_id| pool_enabled.get(pool_id).copied().unwrap_or(false))
                .unwrap_or(true);
            let assignable = item.status == IpStatus::Free && !blacklisted && enabled_pool;
            let mut value = serde_json::to_value(item).map_err(|error| {
                AppError::Internal(format!("could not encode IP address inventory: {error}"))
            })?;
            let object = value
                .as_object_mut()
                .ok_or_else(|| AppError::Internal("IP address did not encode as an object".into()))?;
            object.insert("blacklisted".into(), Value::Bool(blacklisted));
            object.insert("pool_enabled".into(), Value::Bool(enabled_pool));
            object.insert("assignable".into(), Value::Bool(assignable));
            Ok(value)
        })
        .collect()
}

/// Both the managed-subnet ownership guard and BCP38 depend on the exact
/// current allocation map. Apply a change immediately instead of leaving an
/// ownership window until the periodic reconciler runs. If the atomic update
/// fails, the affected active VM is contained by the normal fail-closed path.
async fn reconcile_ownership_after_address_change(
    state: &AppState,
    vm_id: Option<&str>,
) -> AppResult<Option<crate::services::firewall::FirewallApplySummary>> {
    let host_policy = state.db.hypervisor_network_security()?;
    let ownership_guard_active =
        host_policy.ip_ownership_guard_enabled && !state.db.list_ip_pools()?.is_empty();
    if !ownership_guard_active && !host_policy.bcp38_enabled {
        return Ok(None);
    }
    let Some(vm_id) = vm_id else {
        return Ok(None);
    };
    let vm = required_vm(state, vm_id)?;
    crate::services::firewall::reconcile_vm_fail_closed(state, &vm)
        .await
        .map(Some)
}

const MAX_MATERIALIZED_POOL_ADDRESSES: u128 = 4096;

fn planned_pool_addresses(
    pool: &NewIpPool,
    reserved_specs: &[String],
) -> AppResult<(Vec<(IpAddr, IpStatus)>, bool)> {
    let network: IpNet = pool
        .cidr
        .parse()
        .map_err(|_| AppError::Validation("IP pool CIDR is invalid".into()))?;
    let mut reserved = BTreeSet::new();
    if let Some(gateway) = pool.gateway.as_deref() {
        let gateway: IpAddr = gateway
            .parse()
            .map_err(|_| AppError::Validation("IP pool gateway is invalid".into()))?;
        reserved.insert(gateway);
    }
    for specification in reserved_specs {
        for item in specification
            .split([',', '\n', '\r'])
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            expand_reserved_spec(item, &mut reserved)?;
        }
    }
    if let Some(address) = reserved.iter().find(|address| !network.contains(*address)) {
        return Err(AppError::Validation(format!(
            "reserved address {address} is outside the IP pool"
        )));
    }

    let (family, first, last) = network_bounds(&network);
    let capacity = last.saturating_sub(first).saturating_add(1);
    let sparse = capacity > MAX_MATERIALIZED_POOL_ADDRESSES;
    let reserve_ipv4_edges = match &network {
        IpNet::V4(network) => network.prefix_len() <= 30,
        IpNet::V6(_) => false,
    };
    let mut planned = BTreeMap::new();
    if !sparse {
        for number in first..=last {
            let address = numbered_ip(family, number);
            let unusable_ipv4_edge = reserve_ipv4_edges && (number == first || number == last);
            let status = if reserved.contains(&address) || unusable_ipv4_edge {
                IpStatus::Reserved
            } else {
                IpStatus::Free
            };
            planned.insert(address, status);
        }
    } else {
        for address in reserved {
            planned.insert(address, IpStatus::Reserved);
        }
    }
    Ok((planned.into_iter().collect(), sparse))
}

fn expand_reserved_spec(specification: &str, addresses: &mut BTreeSet<IpAddr>) -> AppResult<()> {
    if let Ok(address) = specification.parse::<IpAddr>() {
        addresses.insert(address);
        return Ok(());
    }
    if let Ok(network) = specification.parse::<IpNet>() {
        let (family, first, last) = network_bounds(&network);
        insert_numbered_range(family, first, last, addresses)?;
        return Ok(());
    }
    if let Some((first, last)) = specification.split_once('-') {
        let first: IpAddr = first
            .trim()
            .parse()
            .map_err(|_| AppError::Validation(format!("invalid reserved range: {specification}")))?;
        let last: IpAddr = last
            .trim()
            .parse()
            .map_err(|_| AppError::Validation(format!("invalid reserved range: {specification}")))?;
        let (first_family, first) = numbered_address(first);
        let (last_family, last) = numbered_address(last);
        if first_family != last_family || first > last {
            return Err(AppError::Validation(format!(
                "invalid reserved range: {specification}"
            )));
        }
        insert_numbered_range(first_family, first, last, addresses)?;
        return Ok(());
    }
    Err(AppError::Validation(format!(
        "invalid reserved address, range, or CIDR: {specification}"
    )))
}

fn insert_numbered_range(
    family: AddressFamily,
    first: u128,
    last: u128,
    addresses: &mut BTreeSet<IpAddr>,
) -> AppResult<()> {
    let size = last.saturating_sub(first).saturating_add(1);
    if size > MAX_MATERIALIZED_POOL_ADDRESSES {
        return Err(AppError::Validation(
            "a reserved range may contain at most 4096 addresses".into(),
        ));
    }
    for number in first..=last {
        addresses.insert(numbered_ip(family, number));
    }
    Ok(())
}

fn numbered_address(address: IpAddr) -> (AddressFamily, u128) {
    match address {
        IpAddr::V4(address) => (AddressFamily::V4, u128::from(u32::from(address))),
        IpAddr::V6(address) => (AddressFamily::V6, u128::from(address)),
    }
}

fn is_private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

fn numbered_ip(family: AddressFamily, number: u128) -> IpAddr {
    match family {
        AddressFamily::V4 => IpAddr::V4(Ipv4Addr::from(number as u32)),
        AddressFamily::V6 => IpAddr::V6(Ipv6Addr::from(number)),
    }
}

fn network_bounds(network: &IpNet) -> (AddressFamily, u128, u128) {
    match network {
        IpNet::V4(network) => (
            AddressFamily::V4,
            u128::from(u32::from(network.network())),
            u128::from(u32::from(network.broadcast())),
        ),
        IpNet::V6(network) => {
            let first = u128::from(network.network());
            let host_bits = 128_u32.saturating_sub(u32::from(network.prefix_len()));
            let host_mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1_u128 << host_bits) - 1
            };
            (AddressFamily::V6, first, first | host_mask)
        }
    }
}

fn network_prefix(cidr: &str) -> AppResult<u8> {
    cidr.parse::<IpNet>()
        .map(|network| network.prefix_len())
        .map_err(|_| AppError::Internal("stored IP pool CIDR is invalid".into()))
}

fn parse_power_action(value: &str) -> AppResult<PowerAction> {
    match value {
        "start" | "on" => Ok(PowerAction::Start),
        "shutdown" | "stop" | "off" => Ok(PowerAction::Shutdown),
        "force-off" | "hard-stop" => Ok(PowerAction::ForceOff),
        "reboot" => Ok(PowerAction::Reboot),
        "reset" | "hard-reboot" | "force-reboot" => Ok(PowerAction::Reset),
        "suspend" | "pause" => Ok(PowerAction::Suspend),
        "resume" => Ok(PowerAction::Resume),
        _ => Err(AppError::Validation("unsupported power action".into())),
    }
}

pub(super) fn idempotency_key(headers: &HeaderMap) -> AppResult<Option<String>> {
    let Some(value) = headers.get("idempotency-key") else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map(str::trim)
        .map_err(|_| AppError::Validation("Idempotency-Key is not valid text".into()))?;
    if !(8..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err(AppError::Validation(
            "Idempotency-Key must contain 8-128 safe printable ASCII characters".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

fn parse_range(range: Option<&str>) -> i64 {
    match range.unwrap_or("1h") {
        "15m" => 15 * 60,
        "6h" => 6 * 60 * 60,
        "24h" | "1d" => 24 * 60 * 60,
        "7d" => 7 * 24 * 60 * 60,
        _ => 60 * 60,
    }
}

fn parse_optional_timestamp(value: Option<&Value>) -> AppResult<Option<i64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() || value.as_str() == Some("") {
        return Ok(None);
    }
    if let Some(number) = value.as_i64() {
        return Ok(Some(number));
    }
    let text = value
        .as_str()
        .ok_or_else(|| AppError::Validation("expires_at must be a timestamp".into()))?;
    if let Ok(number) = text.parse::<i64>() {
        return Ok(Some(number));
    }
    if let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(text) {
        return Ok(Some(timestamp.timestamp()));
    }
    if let Ok(timestamp) = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M") {
        return Ok(Some(timestamp.and_utc().timestamp()));
    }
    Err(AppError::Validation(
        "expires_at must be Unix seconds or an ISO-8601 date-time".into(),
    ))
}

fn random_mac() -> String {
    let mut tail = [0_u8; 3];
    OsRng.fill_bytes(&mut tail);
    format!("52:54:00:{:02x}:{:02x}:{:02x}", tail[0], tail[1], tail[2])
}

fn random_guest_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^*-_";
    let mut bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

fn safe_upload_name(value: &str) -> AppResult<String> {
    let name = std::path::Path::new(value)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::Validation("upload filename is invalid".into()))?;
    if name.is_empty()
        || name.len() > 180
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AppError::Validation(
            "upload filename contains unsupported characters".into(),
        ));
    }
    let extension = std::path::Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "iso" | "qcow" | "qcow2" | "raw" | "img") {
        return Err(AppError::Validation(
            "image extension must be iso, qcow, qcow2, raw, or img".into(),
        ));
    }
    Ok(name.to_owned())
}

fn validate_local_image_path(state: &AppState, value: &str) -> AppResult<()> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(AppError::Validation("local image path must be absolute".into()));
    }
    let allowed = state
        .config
        .iso_storage
        .canonicalize()
        .unwrap_or_else(|_| state.config.iso_storage.clone());
    let resolved = if path.exists() {
        path.canonicalize()
            .map_err(|_| AppError::Validation("local image path could not be resolved".into()))?
    } else {
        let parent = path
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .ok_or_else(|| AppError::Validation("local image parent does not exist".into()))?;
        parent.join(
            path.file_name()
                .ok_or_else(|| AppError::Validation("local image filename is missing".into()))?,
        )
    };
    if !resolved.starts_with(&allowed) {
        return Err(AppError::Validation(
            "local image path must be inside VEXA_ISO_STORAGE".into(),
        ));
    }
    Ok(())
}

fn required_form_field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> AppResult<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Validation(format!("form field '{name}' is required")))
}

fn required_update_coordinator(
    state: &AppState,
) -> AppResult<Arc<crate::services::updater::UpdateCoordinator>> {
    state.updater.clone().ok_or_else(|| {
        AppError::Conflict(
            state
                .updater_disabled_reason
                .clone()
                .unwrap_or_else(|| "signed updates are disabled on this node".into()),
        )
    })
}

/// A rollback is offered only while the newest helper operation is the
/// successful activation that produced it. A running, failed, recovery or
/// subsequent rollback operation makes older points ineligible even if a stale
/// status file remains on disk.
fn eligible_update_rollback_point(statuses: &[DurableUpdateStatus]) -> Option<PublicRollbackPoint> {
    let latest = statuses.first()?;
    if statuses
        .get(1)
        .is_some_and(|next| next.updated_at == latest.updated_at)
    {
        // Durable timestamps have one-second resolution. Do not guess which
        // of two equally recent privileged operations is authoritative.
        return None;
    }
    if latest.operation.as_deref() != Some("activate") || latest.outcome != DurableUpdateOutcome::Succeeded {
        return None;
    }
    latest.rollback_point.clone()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateExecutorReady {
    schema_version: u32,
    ready: bool,
    helper_schema: u32,
}

fn update_executor_available() -> bool {
    const READY_PATH: &str = "/run/vexa-vm/update-executor.ready";
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0002_0000); // Linux O_NOFOLLOW.
    }
    let Ok(file) = options.open(READY_PATH) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 4096 {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return false;
        }
    }
    serde_json::from_reader::<_, UpdateExecutorReady>(file)
        .is_ok_and(|marker| marker.schema_version == 1 && marker.ready && marker.helper_schema == 1)
}

fn default_customer_scopes() -> Vec<String> {
    [
        "read",
        "vm:read",
        "metrics:read",
        "power",
        "power:write",
        "dns",
        "dns:write",
        "password",
        "password:read",
        "password:write",
        "ssh:write",
        "reinstall",
        "reinstall:write",
        "vnc",
        "console:write",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn normalize_customer_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut normalized = BTreeSet::new();
    for scope in scopes {
        let scope = scope.trim();
        if scope.is_empty() {
            continue;
        }
        normalized.insert(scope.to_owned());
        let canonical = match scope {
            "vm:power" | "power" => Some("power:write"),
            "vm:reinstall" | "reinstall" => Some("reinstall:write"),
            "vm:dns" | "dns" => Some("dns:write"),
            "vm:password:read" | "password" => Some("password:read"),
            "vm:password:write" => Some("password:write"),
            "vm:vnc" | "vnc" | "console" => Some("console:write"),
            "vm:firewall" | "firewall" => Some("firewall:write"),
            _ => None,
        };
        if let Some(canonical) = canonical {
            normalized.insert(canonical.into());
        }
        if matches!(scope, "vm:firewall" | "firewall" | "firewall:write") {
            normalized.insert("firewall:read".into());
        }
    }
    normalized.into_iter().collect()
}

fn default_true() -> bool {
    true
}

fn default_architecture() -> String {
    std::env::consts::ARCH.into()
}

fn default_admin_role() -> AdminRole {
    AdminRole::Admin
}

fn default_reboot_action() -> String {
    "reboot".into()
}

#[cfg(test)]
mod image_catalog_tests {
    use super::*;

    fn address_for_allocation_test(
        address: &str,
        pool_id: Option<&str>,
        status: IpStatus,
        assigned_vm_id: Option<&str>,
    ) -> IpAddressRecord {
        IpAddressRecord {
            id: format!("address-{address}"),
            pool_id: pool_id.map(str::to_owned),
            address: address.into(),
            family: AddressFamily::V4,
            prefix_length: 32,
            scope: IpScope::Public,
            status,
            gateway: Some("203.0.113.1".into()),
            assigned_vm_id: assigned_vm_id.map(str::to_owned),
            primary_for_vm: assigned_vm_id.is_some(),
            reverse_dns: None,
            metadata: json!({}),
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn disabled_pool_addresses_are_visible_but_never_offered_for_new_allocation() {
        let items = vec![
            address_for_allocation_test("203.0.113.2", Some("legacy-routed"), IpStatus::Free, None),
            address_for_allocation_test("203.0.113.3", Some("ordinary-bridge"), IpStatus::Free, None),
            address_for_allocation_test(
                "203.0.113.4",
                Some("legacy-routed"),
                IpStatus::Used,
                Some("existing-vm"),
            ),
        ];
        let pools = BTreeMap::from([("legacy-routed".into(), false), ("ordinary-bridge".into(), true)]);
        let values = address_values_with_allocation_status(items, &[], &pools).unwrap();

        assert_eq!(values.len(), 3, "disabled-pool inventory must remain visible");
        assert_eq!(values[0]["pool_enabled"], json!(false));
        assert_eq!(values[0]["assignable"], json!(false));
        assert_eq!(values[1]["pool_enabled"], json!(true));
        assert_eq!(values[1]["assignable"], json!(true));
        assert_eq!(values[2]["assignable"], json!(false));
        assert_eq!(values[2]["assigned_vm_id"], json!("existing-vm"));
    }

    fn vm_create_body(os_family: &str, root_username: Option<&str>) -> CreateVmBody {
        let mut value = json!({
            "name": "identity-default-test",
            "hostname": "identity-default-test",
            "os_family": os_family,
            "iso_id": null,
            "vcpus": 1,
            "memory_mib": 512,
            "disk_gib": 5,
            "firmware": "bios"
        });
        if let Some(username) = root_username {
            value["root_username"] = json!(username);
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn vm_create_uses_image_aware_administrator_default_without_overwriting_input() {
        let mut windows = vm_create_body("linux", None);
        assert!(!windows.root_username_was_supplied);
        apply_guest_identity_defaults(&mut windows, Some("Windows Server 2025"));
        assert_eq!(windows.spec.os_family, "Windows Server 2025");
        assert_eq!(windows.spec.root_username, "Administrator");

        let mut linux = vm_create_body("", None);
        apply_guest_identity_defaults(&mut linux, Some("Ubuntu Linux"));
        assert_eq!(linux.spec.root_username, "root");

        let mut deliberate = vm_create_body("linux", Some("deployment-admin"));
        assert!(deliberate.root_username_was_supplied);
        apply_guest_identity_defaults(&mut deliberate, Some("windows"));
        assert_eq!(deliberate.spec.os_family, "windows");
        assert_eq!(deliberate.spec.root_username, "deployment-admin");

        let omitted_fingerprint = create_vm_request_fingerprint(&vm_create_body("windows", None)).unwrap();
        let explicit_fingerprint =
            create_vm_request_fingerprint(&vm_create_body("windows", Some("root"))).unwrap();
        assert_ne!(omitted_fingerprint, explicit_fingerprint);
    }

    #[test]
    fn explicit_empty_guest_administrator_is_not_silently_defaulted() {
        let mut input = vm_create_body("windows", Some(""));
        apply_guest_identity_defaults(&mut input, Some("windows"));
        assert!(input.spec.root_username.is_empty());
        assert!(validate_guest_password(&input.spec.root_username, "ValidPassword123!").is_err());
    }

    #[test]
    fn only_provisional_creates_add_an_unmaterialized_disk_reservation() {
        let database = crate::db::Database::open_in_memory().unwrap();

        let mut provisional = vm_create_body("linux", None).spec;
        provisional.name = "pending-capacity".into();
        provisional.hostname = "pending-capacity".into();
        provisional.disk_gib = 7;
        database.create_vm(&provisional).unwrap();

        let mut materialized = vm_create_body("linux", None).spec;
        materialized.name = "materialized-capacity".into();
        materialized.hostname = "materialized-capacity".into();
        materialized.disk_gib = 11;
        let materialized = database.create_vm(&materialized).unwrap();
        database
            .set_vm_state(
                &materialized.id,
                crate::models::VmState::Running,
                Some(crate::models::VmState::Running),
                Some("00000000-0000-0000-0000-000000000001"),
                None,
            )
            .unwrap();

        let mut failed = vm_create_body("linux", None).spec;
        failed.name = "failed-capacity".into();
        failed.hostname = "failed-capacity".into();
        failed.disk_gib = 13;
        let failed = database.create_vm(&failed).unwrap();
        database
            .set_vm_state(
                &failed.id,
                crate::models::VmState::Error,
                Some(crate::models::VmState::Stopped),
                None,
                None,
            )
            .unwrap();

        let vms = database.list_vms().unwrap();
        assert_eq!(pending_create_disk_reservations(&vms), 7 * GIB_BYTES);
    }

    #[test]
    fn overcommit_capacity_is_bounded_without_reducing_guest_entitlements() {
        let policy = CapacityPolicy {
            cpu_overcommit_ratio: 4.0,
            memory_overcommit_ratio: 2.0,
        };
        let capacity = compute_capacity(
            8,
            HOST_MEMORY_RESERVE_BYTES + (32 * GIB_BYTES),
            20,
            40 * GIB_BYTES,
            policy,
        );
        assert_eq!(capacity.schedulable_vcpus, 32);
        assert_eq!(capacity.available_vcpus, 12);
        assert_eq!(capacity.schedulable_memory_bytes, 64 * GIB_BYTES);
        assert_eq!(capacity.available_memory_bytes, 24 * GIB_BYTES);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn simultaneous_creates_publish_only_one_overlapping_capacity_reservation() {
        let root = tempfile::tempdir().unwrap();
        let vm_storage = root.path().join("vms");
        std::fs::create_dir_all(&vm_storage).unwrap();
        let config = crate::config::Config {
            bind: "127.0.0.1:18081".parse().unwrap(),
            public_url: "http://127.0.0.1:18081".into(),
            database_path: root.path().join("vexa.db"),
            template_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates"),
            static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
            master_key: [0x71; 32],
            bootstrap_admin: "capacity-admin".into(),
            bootstrap_password: Some("CapacityAdmin!234".into()),
            secure_cookies: false,
            hypervisor_mode: crate::config::HypervisorMode::Libvirt,
            libvirt_uri: "qemu:///system".into(),
            vm_storage,
            iso_storage: root.path().join("isos"),
            cloud_init_storage: root.path().join("cloud-init"),
            guest_tools_socket_dir: root.path().join("guest-tools-sockets"),
            guest_tools_linux_x86_64_artifact: None,
            guest_tools_windows_x86_64_artifact: None,
            guest_tools_version: "0.1.0".into(),
            // This unit exercises admission serialization only; use a real
            // local interface so routed-network validation cannot become the
            // contested rejection under test.
            network_bridge: "lo".into(),
            public_interface: None,
            vnc_ttl: std::time::Duration::from_secs(600),
            metrics_interval: std::time::Duration::from_secs(5),
        }
        .validate()
        .unwrap();
        let state = AppState::initialize(config).await.unwrap();
        let mut general = state.db.get_setting("general").unwrap().unwrap().value;
        general["cpu_overcommit_ratio"] = json!(1.0);
        general["memory_overcommit_ratio"] = json!(1.0);
        state.db.set_setting("general", &general, false, None).unwrap();
        {
            // Make CPU the deterministic contested dimension independently of
            // the machine running the test. Each request fits by itself; the
            // second must observe the first request's `creating` row.
            let mut host = state.host_info.write().await;
            host.cpu.logical_cores = 1;
            host.memory.total_bytes = host.memory.total_bytes.max(1024 * MIB_BYTES);
        }
        let auth = AuthContext {
            actor_type: "admin",
            actor_id: "capacity-admin".into(),
            admin: None,
            permissions: vec!["vms:write".into()],
            session_hash: None,
            source_ip: Some("127.0.0.1".into()),
            user_agent: Some("capacity-test".into()),
            request_id: Some("capacity-test".into()),
        };
        let body = |name: &str| {
            serde_json::from_value::<CreateVmBody>(json!({
                "name": name,
                "hostname": name,
                "os_family": "linux",
                "iso_id": null,
                "vcpus": 1,
                "memory_mib": 256,
                "disk_gib": 1,
                "start": false
            }))
            .unwrap()
        };
        let first_body = body("capacity-one");
        let second_body = body("capacity-two");

        // Hold the gate until both handler futures have been scheduled. This
        // removes timing dependence from the test and proves that no
        // provisional row can appear before the serialized admission window.
        let gate = state.vm_create_reservation_lock.lock().await;
        let first_state = state.clone();
        let first_auth = auth.clone();
        let first = tokio::spawn(async move {
            create_vm(
                State(first_state),
                Extension(first_auth),
                HeaderMap::new(),
                Json(first_body),
            )
            .await
        });
        let second_state = state.clone();
        let second = tokio::spawn(async move {
            create_vm(
                State(second_state),
                Extension(auth),
                HeaderMap::new(),
                Json(second_body),
            )
            .await
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(state.db.list_vms().unwrap().is_empty());
        drop(gate);

        let results = [first.await.unwrap(), second.await.unwrap()];
        let mut accepted = 0;
        let mut rejected_for_capacity = 0;
        for result in results {
            match result {
                Ok(response) => {
                    assert_eq!(response.status(), StatusCode::ACCEPTED);
                    accepted += 1;
                }
                Err(AppError::Validation(message)) => {
                    assert!(message.contains("vCPU"), "unexpected rejection: {message}");
                    rejected_for_capacity += 1;
                }
                Err(error) => panic!("unexpected create result: {error}"),
            }
        }
        assert_eq!(accepted, 1);
        assert_eq!(rejected_for_capacity, 1);
        let existing = state.db.list_vms().unwrap();
        assert_eq!(existing.len(), 1);

        // Free the synthetic CPU allocation, then force a related-record
        // publication error after the next provisional row is inserted. The
        // common cleanup path must remove that row before releasing the gate.
        state
            .db
            .set_vm_state(
                &existing[0].id,
                crate::models::VmState::Error,
                Some(crate::models::VmState::Stopped),
                None,
                None,
            )
            .unwrap();
        let mut cleanup_body = body("capacity-cleanup");
        cleanup_body.ip_addresses.push("not-an-ip-address".into());
        let cleanup_result = create_vm(
            State(state.clone()),
            Extension(AuthContext {
                actor_type: "admin",
                actor_id: "capacity-admin".into(),
                admin: None,
                permissions: vec!["vms:write".into()],
                session_hash: None,
                source_ip: Some("127.0.0.1".into()),
                user_agent: Some("capacity-test".into()),
                request_id: Some("capacity-cleanup-test".into()),
            }),
            HeaderMap::new(),
            Json(cleanup_body),
        )
        .await;
        assert!(matches!(cleanup_result, Err(AppError::Validation(_))));
        assert!(state.db.get_vm("capacity-cleanup").unwrap().is_none());
        assert_eq!(state.db.list_vms().unwrap().len(), 1);
    }

    fn successful_activation_status(updated_at: i64) -> DurableUpdateStatus {
        DurableUpdateStatus {
            schema_version: 1,
            request_id: "73c1539d-4a69-47d3-b10b-3f966e9fcba2".into(),
            operation: Some("activate".into()),
            release: Some("1.2.0".into()),
            phase: "complete".into(),
            progress_percent: 100,
            outcome: DurableUpdateOutcome::Succeeded,
            message: "activation completed".into(),
            started_at: updated_at - 10,
            updated_at,
            completed_at: Some(updated_at),
            package_changes: Vec::new(),
            rollback: crate::services::updater::DurableRollbackStatus {
                available: true,
                attempted: false,
                succeeded: false,
                previous_release: Some("1.1.0".into()),
                snapshot_sha256: Some("1".repeat(64)),
            },
            rollback_point: Some(PublicRollbackPoint {
                activation_id: "73c1539d-4a69-47d3-b10b-3f966e9fcba2".into(),
                release: "1.2.0".into(),
                previous_release: "1.1.0".into(),
                manifest_sha256: "2".repeat(64),
                snapshot_sha256: "1".repeat(64),
                snapshot_size_bytes: 4096,
                components: vec!["vexa-vm".into()],
            }),
        }
    }

    #[test]
    fn only_the_newest_successful_activation_exposes_rollback() {
        let activation = successful_activation_status(100);
        assert_eq!(
            eligible_update_rollback_point(std::slice::from_ref(&activation))
                .unwrap()
                .previous_release,
            "1.1.0"
        );

        let mut running = successful_activation_status(101);
        running.request_id = "3d046d89-503a-4de7-b0da-328bcc440d47".into();
        running.operation = Some("rollback".into());
        running.outcome = DurableUpdateOutcome::Running;
        running.completed_at = None;
        running.rollback_point = None;
        assert!(eligible_update_rollback_point(&[running, activation]).is_none());
    }

    #[test]
    fn equally_recent_executor_statuses_fail_closed() {
        let activation = successful_activation_status(100);
        let mut other = activation.clone();
        other.request_id = "3d046d89-503a-4de7-b0da-328bcc440d47".into();
        assert!(eligible_update_rollback_point(&[activation, other]).is_none());
    }

    #[test]
    fn qcow_upload_names_are_supported_consistently() {
        assert_eq!(safe_upload_name("debian.qcow").unwrap(), "debian.qcow");
        assert_eq!(safe_upload_name("debian.qcow2").unwrap(), "debian.qcow2");
        assert!(safe_upload_name("debian.qcow.tar").is_err());
    }

    #[test]
    fn changing_image_content_clears_verification_metadata() {
        let mut local_path = Some("/managed/old.iso".into());
        let mut size_bytes = Some(4096);
        let mut metadata = json!({
            "verified_at": 1,
            "downloaded_at": 2,
            "source": "remote_download",
            "download_error": "old failure",
            "release": "stable"
        });
        clear_stale_image_verification(&mut local_path, &mut size_bytes, &mut metadata, false, false);
        assert_eq!(local_path, None);
        assert_eq!(size_bytes, None);
        assert_eq!(metadata, json!({ "release": "stable" }));

        local_path = Some("/managed/new.iso".into());
        size_bytes = Some(8192);
        clear_stale_image_verification(&mut local_path, &mut size_bytes, &mut metadata, true, true);
        assert_eq!(local_path.as_deref(), Some("/managed/new.iso"));
        assert_eq!(size_bytes, Some(8192));
    }

    #[test]
    fn local_image_verification_hashes_all_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image.iso");
        std::fs::write(&path, b"image bytes").unwrap();
        let (size, checksum) = verify_local_image(&path).unwrap();
        assert_eq!(size, 11);
        assert_eq!(checksum, format!("{:x}", Sha256::digest(b"image bytes")));
    }

    #[test]
    fn automatic_image_format_uses_content_not_img_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let qcow_path = directory.path().join("ubuntu-server.img");
        std::fs::write(&qcow_path, b"QFI\xfb\0\0\0\x03").unwrap();
        assert_eq!(automatic_disk_format(&qcow_path).unwrap(), "qcow2");

        let raw_path = directory.path().join("disk.img");
        std::fs::write(&raw_path, b"raw disk bytes").unwrap();
        assert_eq!(automatic_disk_format(&raw_path).unwrap(), "raw");
    }

    #[test]
    fn routeros_automatic_image_is_a_seedless_appliance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("chr.img");
        std::fs::write(&path, b"routeros raw disk").unwrap();
        let image = IsoImage {
            id: Uuid::new_v4().to_string(),
            slug: "routeros-chr-7".into(),
            name: "MikroTik RouterOS CHR 7".into(),
            version: Some("7.21.4".into()),
            os_family: "routeros".into(),
            architecture: std::env::consts::ARCH.into(),
            install_mode: InstallMode::Automatic,
            source_url: None,
            local_path: Some(path.to_string_lossy().into_owned()),
            checksum_sha256: Some(format!("{:x}", Sha256::digest(b"routeros raw disk"))),
            size_bytes: Some(17),
            supports_guest_agent: true,
            supports_cloud_init: false,
            uefi: false,
            enabled: true,
            metadata: json!({ "verified_at": 1, "preconfigured_appliance": true }),
            created_at: 1,
            updated_at: 1,
        };

        assert!(matches!(
            vm_image_from_iso(image).unwrap(),
            VmImage::ApplianceRaw { .. }
        ));
        assert_eq!(guest_administrator_default("routeros"), "vexa-admin");
    }

    #[test]
    fn automatic_windows_catalog_record_requires_the_pinned_driver_media() {
        let directory = tempfile::tempdir().unwrap();
        let installer = directory.path().join("windows.iso");
        let drivers = directory.path().join("virtio-win.iso");
        std::fs::write(&installer, b"windows installer").unwrap();
        std::fs::write(&drivers, b"virtio drivers").unwrap();
        let image = IsoImage {
            id: Uuid::new_v4().to_string(),
            slug: "windows-server-2022".into(),
            name: "Windows Server 2022".into(),
            version: Some("2022".into()),
            os_family: "windows".into(),
            architecture: std::env::consts::ARCH.into(),
            install_mode: InstallMode::Automatic,
            source_url: None,
            local_path: Some(installer.to_string_lossy().into_owned()),
            checksum_sha256: Some(format!("{:x}", Sha256::digest(b"windows installer"))),
            size_bytes: Some(17),
            supports_guest_agent: true,
            supports_cloud_init: false,
            uefi: true,
            enabled: true,
            metadata: json!({
                "verified_at": 1,
                "unattended_installer": true,
                "virtio_driver_iso": drivers,
                "windows_driver_version": "2k22",
                "windows_image_index": 2
            }),
            created_at: 1,
            updated_at: 1,
        };

        assert!(matches!(
            vm_image_from_iso(image).unwrap(),
            VmImage::UnattendedWindowsIso {
                image_index: 2,
                ref driver_version,
                ..
            } if driver_version == "2k22"
        ));
    }

    #[test]
    fn image_readiness_requires_server_verification_and_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ready.qcow2");
        std::fs::write(&path, b"verified").unwrap();
        let mut image = IsoImage {
            id: Uuid::new_v4().to_string(),
            slug: "ready-image".into(),
            name: "Ready image".into(),
            version: None,
            os_family: "linux".into(),
            architecture: std::env::consts::ARCH.into(),
            install_mode: InstallMode::Automatic,
            source_url: None,
            local_path: Some(path.to_string_lossy().into_owned()),
            checksum_sha256: Some(format!("{:x}", Sha256::digest(b"verified"))),
            size_bytes: Some(8),
            supports_guest_agent: true,
            supports_cloud_init: true,
            uefi: false,
            enabled: true,
            metadata: json!({}),
            created_at: 1,
            updated_at: 1,
        };

        assert!(!iso_is_ready(&image));
        image.metadata["verified_at"] = json!(1);
        assert!(iso_is_ready(&image));
        std::fs::remove_file(path).unwrap();
        assert!(!iso_is_ready(&image));
    }
}
