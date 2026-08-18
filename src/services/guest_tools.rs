use std::{
    fmt, fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use rand::{rngs::OsRng, RngCore};
use reqwest::{redirect::Policy, Client, Method, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use vexa_guest_protocol::{
    read_frame, write_frame, Command, NetworkAddress, Request, Response, ResponseData, MIN_SECRET_BYTES,
};

use crate::{
    config::Config,
    error::{AppError, AppResult},
    models::{
        GuestToolsPlatform, GuestToolsProvisioner, GuestToolsStatus, InstallMode, IsoImage, NewAuditEvent,
        Vm, VmGuestTools,
    },
    state::AppState,
};

const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STALE_RESPONSE_FRAMES: usize = 16;
const CHANNEL_NAME: &str = "com.vexa.guest_tools.0";

#[derive(Clone, Debug, Serialize)]
pub struct GuestToolsCompatibility {
    pub supported: bool,
    pub artifact_available: bool,
    pub platform: Option<GuestToolsPlatform>,
    pub provisioner: Option<GuestToolsProvisioner>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GuestToolsInstall {
    pub platform: GuestToolsPlatform,
    pub provisioner: GuestToolsProvisioner,
    pub artifact_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct GuestApplyResult {
    pub applied: bool,
    pub pending: bool,
    pub mechanism: &'static str,
    pub status: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GuestBootstrapResult {
    pub installed_version: String,
    pub promoted_rotation: bool,
    pub seed_media_retired: bool,
    pub superseded: bool,
}

pub fn compatibility(config: &Config, image: &IsoImage) -> GuestToolsCompatibility {
    let unsupported = |reason: &str| GuestToolsCompatibility {
        supported: false,
        artifact_available: false,
        platform: None,
        provisioner: None,
        reason: Some(reason.into()),
    };
    if is_builtin_routeros_image(image) {
        return GuestToolsCompatibility {
            supported: true,
            artifact_available: true,
            platform: None,
            provisioner: None,
            reason: Some(
                "RouterOS is managed through its built-in QEMU Guest Agent; no third-party binary is injected"
                    .into(),
            ),
        };
    }
    if image.install_mode == InstallMode::Manual
        || (!image.supports_cloud_init && !is_unattended_windows_image(image))
    {
        return unsupported("the image does not declare automated cloud initialization");
    }
    if !matches!(
        image.architecture.to_ascii_lowercase().as_str(),
        "x86_64" | "amd64"
    ) {
        return unsupported("no Guest Tools artifact is configured for this architecture");
    }

    let declared = image
        .metadata
        .get("guest_tools_provisioner")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.trim().to_ascii_lowercase());
    let os = image.os_family.to_ascii_lowercase();
    let (platform, provisioner) = match declared.as_deref() {
        Some("cloud-init" | "cloud_init") => (GuestToolsPlatform::Linux, GuestToolsProvisioner::CloudInit),
        Some("cloudbase-init" | "cloudbase_nocloud" | "cloudbase-init-nocloud") => (
            GuestToolsPlatform::Windows,
            GuestToolsProvisioner::CloudbaseNoCloud,
        ),
        Some("windows-unattend" | "windows_unattend") if is_unattended_windows_image(image) => (
            GuestToolsPlatform::Windows,
            // The persisted enum predates installer-ISO injection. Keep the
            // Windows seed family while metadata identifies the exact path.
            GuestToolsProvisioner::CloudbaseNoCloud,
        ),
        Some(_) => return unsupported("the image declares an unknown Guest Tools provisioner"),
        None if is_linux_family(&os) => (GuestToolsPlatform::Linux, GuestToolsProvisioner::CloudInit),
        None if is_unattended_windows_image(image) => (
            GuestToolsPlatform::Windows,
            GuestToolsProvisioner::CloudbaseNoCloud,
        ),
        None if os.contains("windows") => {
            return unsupported(
                "Windows images must explicitly declare guest_tools_provisioner=cloudbase-init-nocloud",
            )
        }
        None => return unsupported("the image operating-system family is not supported"),
    };

    if platform == GuestToolsPlatform::Windows
        && image
            .metadata
            .get("virtio_serial_driver")
            .and_then(serde_json::Value::as_str)
            != Some("installed_signed")
    {
        return unsupported(
            "Windows images must declare virtio_serial_driver=installed_signed after a trusted, signed virtio-serial driver has been installed",
        );
    }

    let artifact = artifact_path(config, platform);
    let artifact_available = artifact.as_deref().is_some_and(valid_artifact);
    GuestToolsCompatibility {
        supported: true,
        artifact_available,
        platform: Some(platform),
        provisioner: Some(provisioner),
        reason: (!artifact_available).then(|| {
            format!(
                "the {} Guest Tools artifact is not configured or unavailable",
                platform.as_str()
            )
        }),
    }
}

pub fn is_builtin_routeros_image(image: &IsoImage) -> bool {
    image.install_mode == InstallMode::Automatic
        && image.supports_guest_agent
        && (image.os_family.eq_ignore_ascii_case("routeros")
            || image
                .metadata
                .get("guest_tools_integration")
                .and_then(serde_json::Value::as_str)
                == Some("qemu-agent"))
        && image
            .metadata
            .get("preconfigured_appliance")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

fn is_unattended_windows_image(image: &IsoImage) -> bool {
    image.install_mode == InstallMode::Automatic
        && image.os_family.to_ascii_lowercase().contains("windows")
        && image
            .metadata
            .get("unattended_installer")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

pub fn is_routeros_vm(vm: &Vm) -> bool {
    vm.os_family.to_ascii_lowercase().contains("routeros")
}

pub fn require_installable(config: &Config, image: &IsoImage) -> AppResult<GuestToolsInstall> {
    if is_builtin_routeros_image(image) {
        return Err(AppError::Conflict(
            "RouterOS uses its built-in QEMU Guest Agent and does not require a Vexa binary installation"
                .into(),
        ));
    }
    let result = compatibility(config, image);
    if !result.supported || !result.artifact_available {
        return Err(AppError::Conflict(result.reason.unwrap_or_else(|| {
            "Vexa Guest Tools cannot be installed for this image".into()
        })));
    }
    Ok(GuestToolsInstall {
        platform: result.platform.expect("supported image has a platform"),
        provisioner: result.provisioner.expect("supported image has a provisioner"),
        artifact_path: artifact_path(config, result.platform.expect("supported image has a platform"))
            .expect("available artifact has a path"),
    })
}

pub fn artifact_for_platform(config: &Config, platform: GuestToolsPlatform) -> AppResult<PathBuf> {
    artifact_path(config, platform)
        .filter(|path| valid_artifact(path))
        .ok_or_else(|| {
            AppError::Conflict(format!(
                "the {} Guest Tools artifact is not configured or unavailable",
                platform.as_str()
            ))
        })
}

pub fn socket_path(config: &Config, vm_id: &str) -> AppResult<PathBuf> {
    if vm_id.len() > 64
        || vm_id.is_empty()
        || !vm_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(AppError::Validation(
            "VM ID is invalid for a guest channel".into(),
        ));
    }
    Ok(config.guest_tools_socket_dir.join(format!("{vm_id}.sock")))
}

pub fn channel_name() -> &'static str {
    CHANNEL_NAME
}

pub fn new_secret() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let encoded = STANDARD_NO_PAD.encode(bytes);
    bytes.fill(0);
    encoded
}

/// Apply the complete control-plane address inventory inside a running guest.
/// The command is authoritative: addresses removed from Vexa are removed from
/// the managed guest interface, while additions are made immediately.
pub async fn apply_network_inventory(state: &AppState, vm: &Vm) -> AppResult<GuestApplyResult> {
    let records = state.db.vm_ip_addresses(&vm.id)?;
    let dns = state.db.dns_servers(None, Some(&vm.id))?;
    let routed = crate::services::routed_network::effective_plan(state, vm).await?;
    let linux_guest = state
        .db
        .vm_guest_tools(&vm.id)?
        .map(|tools| tools.platform == GuestToolsPlatform::Linux)
        .unwrap_or_else(|| {
            !is_routeros_vm(vm) && !vm.os_family.to_ascii_lowercase().contains("windows")
        });
    let mut addresses = Vec::with_capacity(records.len() + usize::from(routed.is_some()));
    let mut ipv4_gateway = None;
    let mut ipv6_gateway = None;

    if let Some(plan) = routed.as_ref() {
        // Linux selects the first address as the source of the default route.
        // A link-local transit address therefore caused provider egress drops.
        // The gateway remains reachable through the on-link route and the
        // primary provider /32 becomes the source address automatically.
        if !linux_guest {
            addresses.push(NetworkAddress {
                address: IpAddr::V4(plan.guest_address),
                prefix_length: plan.prefix_length,
            });
        }
        ipv4_gateway = Some(IpAddr::V4(plan.gateway));
    }
    for record in records {
        let address = record
            .address
            .parse::<IpAddr>()
            .map_err(|_| AppError::Internal(format!("stored VM address '{}' is invalid", record.address)))?;
        addresses.push(NetworkAddress {
            address,
            prefix_length: record.prefix_length,
        });
        if routed.is_none() {
            if let Some(gateway) = record.gateway.as_deref() {
                let gateway = gateway
                    .parse::<IpAddr>()
                    .map_err(|_| AppError::Internal(format!("stored VM gateway '{gateway}' is invalid")))?;
                if gateway.is_ipv4() {
                    ipv4_gateway.get_or_insert(gateway);
                } else {
                    ipv6_gateway.get_or_insert(gateway);
                }
            }
        }
    }
    let gateways = ipv4_gateway.into_iter().chain(ipv6_gateway).collect();
    let dns_servers = dns
        .into_iter()
        .map(|server| {
            server.address.parse::<IpAddr>().map_err(|_| {
                AppError::Internal(format!("stored DNS address '{}' is invalid", server.address))
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(try_apply(
        state,
        vm,
        Command::SetNetwork {
            interface: None,
            addresses,
            gateways,
            dns_servers,
        },
    )
    .await)
}

pub async fn try_apply(state: &AppState, vm: &Vm, command: Command) -> GuestApplyResult {
    if is_routeros_vm(vm) {
        return routeros_apply(state, vm, command).await;
    }
    let channel_lock = {
        let mut locks = state.guest_tools_locks.lock().await;
        locks
            .entry(vm.id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _channel_guard = channel_lock.lock().await;
    let Some(record) = state.db.vm_guest_tools(&vm.id).ok().flatten() else {
        return pending(
            "Vexa Guest Tools is not installed; the value will apply on the next compatible reinstall",
        );
    };
    if !record.enabled {
        return pending("Vexa Guest Tools is disabled for this VM");
    }
    let client = match state.db.vm_guest_tools_client_secret(&vm.id, &state.security) {
        Ok(Some(client)) => client,
        Ok(None) => return pending("Vexa Guest Tools has no active channel secret"),
        Err(error) => return mark_unavailable(state, &vm.id, &error.to_string()),
    };
    let secret = match decode_channel_secret(client.secret) {
        Ok(secret) => secret,
        Err(error) => return mark_unavailable(state, &vm.id, &error.to_string()),
    };
    let path = match socket_path(&state.config, &vm.id) {
        Ok(path) => path,
        Err(error) => return mark_unavailable(state, &vm.id, &error.to_string()),
    };

    let is_probe = matches!(command, Command::Ping | Command::Health);
    let exchange_timeout = if is_probe {
        Duration::from_secs(3)
    } else {
        Duration::from_secs(8)
    };
    // A completed host request closes QEMU's Unix client and the Windows
    // service reopens its virtio-serial device after a bounded two-second
    // delay. Hold the per-VM channel lock through that grace period before a
    // mutation, so neither a health sweep nor another action can reset the
    // reconnect window. This avoids replaying sensitive or non-idempotent
    // commands after an ambiguously lost response.
    if !is_probe {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let response = tokio::task::spawn_blocking(move || {
        let mut secret = secret;
        let result = exchange(&path, &secret, command, exchange_timeout);
        secret.fill(0);
        result
    })
    .await;
    match response {
        Ok(Ok(data)) => {
            let installed_version = response_version(&data);
            let _ = state.db.update_vm_guest_tools_status(
                &vm.id,
                GuestToolsStatus::Ready,
                installed_version,
                None,
                true,
            );
            GuestApplyResult {
                applied: !is_probe,
                pending: false,
                mechanism: "vexa_guest_tools",
                status: if is_probe { "healthy" } else { "applied" }.into(),
                message: if is_probe {
                    "Authenticated Vexa Guest Tools health check succeeded"
                } else {
                    "Applied inside the running guest through Vexa Guest Tools"
                }
                .into(),
            }
        }
        Ok(Err(GuestExchangeError::Rejected(error))) => mark_rejected(state, &vm.id, &error),
        Ok(Err(GuestExchangeError::Unavailable(error))) => mark_unavailable(state, &vm.id, &error),
        Err(error) => mark_unavailable(state, &vm.id, &format!("guest-tools task failed: {error}")),
    }
}

pub async fn probe(state: &AppState, vm: &Vm) -> GuestApplyResult {
    try_apply(state, vm, Command::Health).await
}

/// Authenticate a newly provisioned agent before its installation is reported
/// ready. A staged reinstall secret is promoted only after the new guest proves
/// possession and reports the exact version that was placed in its seed.
pub async fn bootstrap(
    state: &AppState,
    vm: &Vm,
    expected_generation: Option<&str>,
) -> AppResult<GuestBootstrapResult> {
    if is_routeros_vm(vm) {
        if expected_generation.is_some() {
            return Err(AppError::Conflict(
                "RouterOS built-in integration does not use a Vexa channel-key rotation".into(),
            ));
        }
        routeros_bootstrap(state, vm).await?;
        return Ok(GuestBootstrapResult {
            installed_version: "routeros-qemu-agent".into(),
            promoted_rotation: false,
            seed_media_retired: false,
            superseded: false,
        });
    }
    let channel_lock = {
        let mut locks = state.guest_tools_locks.lock().await;
        locks
            .entry(vm.id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _channel_guard = channel_lock.lock().await;
    let record = state
        .db
        .vm_guest_tools(&vm.id)?
        .ok_or_else(|| AppError::NotFound("VM guest-tools configuration".into()))?;
    if !record.enabled {
        return Err(AppError::Conflict(
            "Vexa Guest Tools is disabled for this VM".into(),
        ));
    }
    let current_generation = state.db.installed_vm_guest_tools_rotation_generation(&vm.id)?;
    if expected_generation != current_generation.as_deref() {
        // A power event or older provisioning parent can leave an already
        // queued bootstrap behind while a newer reinstall changes the active
        // generation. The stale job must become a no-op: it may neither
        // authenticate with another generation nor overwrite current status.
        return Ok(GuestBootstrapResult {
            installed_version: record.installed_version.unwrap_or(record.desired_version),
            promoted_rotation: false,
            seed_media_retired: false,
            superseded: true,
        });
    }
    let client = state
        .db
        .vm_guest_tools_client_secret(&vm.id, &state.security)?
        .ok_or_else(|| AppError::Conflict("VM Guest Tools channel secret is unavailable".into()))?;
    if expected_generation != client.pending_generation.as_deref() {
        return Err(AppError::Conflict(
            "the expected Guest Tools secret rotation is not installed".into(),
        ));
    }
    let mut secret = decode_channel_secret(client.secret)?;
    let path = socket_path(&state.config, &vm.id)?;
    let response = tokio::task::spawn_blocking(move || {
        let result = exchange(&path, &secret, Command::Health, Duration::from_secs(2));
        secret.fill(0);
        result
    })
    .await
    .map_err(|error| AppError::Conflict(format!("Guest Tools bootstrap task failed: {error}")))?
    .map_err(|error| AppError::Conflict(format!("Guest Tools bootstrap failed: {error}")))?;
    let installed_version = match response {
        ResponseData::Health { agent_version, .. } => agent_version,
        _ => {
            return Err(AppError::Conflict(
                "Guest Tools bootstrap returned an unexpected response".into(),
            ))
        }
    };
    if installed_version != client.desired_version {
        return Err(AppError::Conflict(format!(
            "Guest Tools reported version {installed_version}, expected {}",
            client.desired_version
        )));
    }
    // Authentication and the exact artifact-version check are the trusted
    // completion signal. Retire the password/secret-bearing seed before a
    // pending channel key is promoted, so a detach failure remains safely
    // retryable with that same installed generation.
    let seed_media_retired = retire_authenticated_seed_media(state, vm).await?;
    let promoted_rotation = if let Some(generation) = client.pending_generation.as_deref() {
        state
            .db
            .promote_vm_guest_tools_rotation(&vm.id, generation, &installed_version, &state.security)?;
        true
    } else {
        state.db.update_vm_guest_tools_status(
            &vm.id,
            GuestToolsStatus::Ready,
            Some(&installed_version),
            None,
            true,
        )?;
        false
    };
    Ok(GuestBootstrapResult {
        installed_version,
        promoted_rotation,
        seed_media_retired,
        superseded: false,
    })
}

async fn retire_authenticated_seed_media(state: &AppState, vm: &Vm) -> AppResult<bool> {
    let seed_path = state.config.cloud_init_storage.join(format!("{}.iso", vm.id));
    let metadata = match tokio::fs::symlink_metadata(&seed_path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(AppError::Configuration(
            "refusing to retire a provisioning seed that is not a regular file".into(),
        ));
    }

    state.hypervisor.detach_seed_media(&vm.name, &seed_path).await?;
    match tokio::fs::remove_file(&seed_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Persist the directory entry removal where the filesystem supports it.
    if let Ok(directory) = tokio::fs::File::open(&state.config.cloud_init_storage).await {
        let _ = directory.sync_all().await;
    }
    let _ = state.db.append_audit(&NewAuditEvent {
        actor_type: "system".into(),
        actor_id: Some("guest-tools-bootstrap".into()),
        action: "vm.provisioning_seed.retired".into(),
        resource_type: "vm".into(),
        resource_id: Some(vm.id.clone()),
        request_id: None,
        source_ip: None,
        user_agent: None,
        success: true,
        details: serde_json::json!({
            "authenticated_guest_tools": true,
            "live_and_persistent_media_verified_detached": true,
        }),
    });
    Ok(true)
}

#[derive(Debug)]
enum GuestExchangeError {
    Unavailable(String),
    Rejected(String),
}

impl fmt::Display for GuestExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Rejected(message) => formatter.write_str(message),
        }
    }
}

fn exchange(
    path: &Path,
    secret: &[u8],
    command: Command,
    timeout: Duration,
) -> Result<ResponseData, GuestExchangeError> {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(path)
            .map_err(|error| GuestExchangeError::Unavailable(channel_connect_error_message(&error)))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| GuestExchangeError::Unavailable(error.to_string()))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| GuestExchangeError::Unavailable(error.to_string()))?;
        let now = unix_timestamp();
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let nonce = STANDARD_NO_PAD.encode(nonce);
        let expected_command = command.clone();
        let request = Request::signed(uuid::Uuid::new_v4().to_string(), now, nonce, command, secret)
            .map_err(|error| GuestExchangeError::Unavailable(protocol_error(error).to_string()))?;
        write_frame(&mut stream, &request)
            .map_err(|error| GuestExchangeError::Unavailable(protocol_error(error).to_string()))?;
        // Virtio-serial is a continuous byte stream even when the host-side
        // Unix socket reconnects. If a prior request timed out after the guest
        // had already accepted it, that authenticated response can be queued
        // ahead of this request. Discard only frames whose public correlation
        // fields clearly belong to another request; the first matching frame
        // must still pass the full signature, timestamp and AEAD checks.
        let deadline = Instant::now() + timeout;
        let mut stale_response_frames = 0;
        let verified = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(GuestExchangeError::Unavailable(
                    "Vexa Guest Tools channel is unavailable: no matching response arrived before the timeout"
                        .into(),
                ));
            }
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|error| GuestExchangeError::Unavailable(error.to_string()))?;
            let response: Response = read_frame(&mut stream)
                .map_err(|error| GuestExchangeError::Unavailable(protocol_error(error).to_string()))?;
            if response.request_id != request.request_id || response.request_nonce != request.nonce {
                if stale_response_frames == MAX_STALE_RESPONSE_FRAMES {
                    return Err(GuestExchangeError::Unavailable(
                        "Vexa Guest Tools channel returned too many stale responses".into(),
                    ));
                }
                stale_response_frames += 1;
                continue;
            }
            break response
                .verify_and_decrypt(
                    secret,
                    &request.request_id,
                    &request.nonce,
                    &expected_command,
                    request.sent_at,
                    unix_timestamp(),
                    120,
                )
                .map_err(|error| GuestExchangeError::Unavailable(protocol_error(error).to_string()))?;
        };
        if let Some(error) = verified.error {
            return Err(GuestExchangeError::Rejected(format!(
                "Vexa Guest Tools rejected the action: {}",
                error.message
            )));
        }
        verified.data.ok_or_else(|| {
            GuestExchangeError::Unavailable("Vexa Guest Tools response contained no result".into())
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, secret, command, timeout);
        Err(GuestExchangeError::Unavailable(
            "the Vexa host client requires a Unix host".into(),
        ))
    }
}

fn channel_connect_error_message(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound =>
            "Vexa Guest Tools channel is unavailable: the libvirt socket is absent; verify that the domain channel is attached and QEMU is running".into(),
        std::io::ErrorKind::PermissionDenied =>
            "Vexa Guest Tools channel is unavailable: socket access was denied; verify the vexa/QEMU group membership, socket mode, and AppArmor or SELinux policy".into(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset =>
            "Vexa Guest Tools channel is unavailable: QEMU is not accepting the channel connection yet".into(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock =>
            "Vexa Guest Tools channel is unavailable: the channel connection timed out".into(),
        _ => "Vexa Guest Tools channel is unavailable: the host could not connect to the libvirt socket".into(),
    }
}

fn decode_channel_secret(secret: String) -> AppResult<Vec<u8>> {
    let mut encoded = secret.into_bytes();
    let decoded = STANDARD_NO_PAD
        .decode(&encoded)
        .map_err(|_| AppError::Internal("stored Guest Tools channel secret is not valid base64".into()));
    encoded.fill(0);
    let decoded = decoded?;
    if decoded.len() < MIN_SECRET_BYTES {
        return Err(AppError::Internal(
            "stored Guest Tools channel secret is too short".into(),
        ));
    }
    Ok(decoded)
}

fn response_version(data: &ResponseData) -> Option<&str> {
    match data {
        ResponseData::Pong { agent_version } | ResponseData::Health { agent_version, .. } => {
            Some(agent_version)
        }
        ResponseData::Action { .. } => None,
    }
}

fn pending(message: &str) -> GuestApplyResult {
    GuestApplyResult {
        applied: false,
        pending: true,
        mechanism: "provisioning",
        status: "pending".into(),
        message: message.into(),
    }
}

fn mark_unavailable(state: &AppState, vm_id: &str, error: &str) -> GuestApplyResult {
    let _ =
        state
            .db
            .update_vm_guest_tools_status(vm_id, GuestToolsStatus::Unavailable, None, Some(error), false);
    GuestApplyResult {
        applied: false,
        pending: true,
        mechanism: "provisioning",
        status: "pending".into(),
        message: "Guest Tools is not currently reachable; the saved value will apply on the next reinstall"
            .into(),
    }
}

fn mark_rejected(state: &AppState, vm_id: &str, error: &str) -> GuestApplyResult {
    let _ = state
        .db
        .update_vm_guest_tools_status(vm_id, GuestToolsStatus::Ready, None, Some(error), true);
    GuestApplyResult {
        applied: false,
        // Password, hostname, DNS and SSH-key handlers persist their desired
        // value before attempting the live command. A guest-side policy or
        // utility rejection therefore still leaves work for the next
        // compatible reinstall; never present that saved state as complete.
        pending: true,
        mechanism: "vexa_guest_tools",
        status: "rejected".into(),
        message: format!("{error}; the saved value will apply on the next reinstall"),
    }
}

async fn routeros_apply(state: &AppState, vm: &Vm, command: Command) -> GuestApplyResult {
    let is_probe = matches!(command, Command::Ping | Command::Health);
    let result = match command {
        Command::Ping | Command::Health => routeros_health(state, vm)
            .await
            .map(|_| "RouterOS built-in QEMU Guest Agent health check succeeded".to_owned()),
        Command::SetPassword { username, password } => {
            routeros_change_password(state, vm, &username, &password)
                .await
                .map(|_| "Password changed through the protected RouterOS management link".into())
        }
        Command::SetHostname { hostname } => {
            let script = format!("/system identity set name={}\n", routeros_string(&hostname));
            routeros_exec_script(state, vm, &script, true)
                .await
                .map(|_| "RouterOS identity changed through the guest integration".into())
        }
        Command::SetDns { servers, .. } => {
            let servers = servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let script = format!("/ip dns set servers={}\n", routeros_string(&servers));
            routeros_exec_script(state, vm, &script, true)
                .await
                .map(|_| "DNS servers changed through the RouterOS guest integration".into())
        }
        Command::SetNetwork {
            addresses,
            gateways,
            dns_servers,
            ..
        } => {
            let script = routeros_network_script(&addresses, &gateways, &dns_servers);
            routeros_exec_script(state, vm, &script, true)
                .await
                .map(|_| "RouterOS addresses and routes changed through the guest integration".into())
        }
        Command::SetSshKeys { .. } => Err(AppError::Conflict(
            "RouterOS does not expose safe atomic authorized-key replacement through its QEMU Guest Agent"
                .into(),
        )),
        Command::Shutdown => routeros_exec_script(state, vm, "/system shutdown\n", false)
            .await
            .map(|_| "RouterOS shutdown was accepted".into()),
        Command::Reboot => routeros_exec_script(state, vm, "/system reboot\n", false)
            .await
            .map(|_| "RouterOS reboot was accepted".into()),
    };
    match result {
        Ok(message) => GuestApplyResult {
            applied: !is_probe,
            pending: false,
            mechanism: "routeros_qemu_agent",
            status: if is_probe { "healthy" } else { "applied" }.into(),
            message,
        },
        Err(error) => GuestApplyResult {
            applied: false,
            pending: !is_probe,
            mechanism: "routeros_qemu_agent",
            status: "unavailable".into(),
            message: format!("RouterOS built-in guest integration is not currently reachable: {error}"),
        },
    }
}

fn routeros_network_script(
    addresses: &[NetworkAddress],
    gateways: &[IpAddr],
    dns_servers: &[IpAddr],
) -> String {
    let mut script = String::from(
        "/ip address remove [find where comment=\"vexa-vm\"]\n\
         /ipv6 address remove [find where comment=\"vexa-vm\"]\n\
         /ip route remove [find where comment=\"vexa-vm\"]\n\
         /ipv6 route remove [find where comment=\"vexa-vm\"]\n",
    );
    for item in addresses {
        match item.address {
            IpAddr::V4(address) => script.push_str(&format!(
                "/ip address add address={address}/{} interface=ether1 comment=\"vexa-vm\"\n",
                item.prefix_length
            )),
            IpAddr::V6(address) => script.push_str(&format!(
                "/ipv6 address add address={address}/{} interface=ether1 comment=\"vexa-vm\"\n",
                item.prefix_length
            )),
        }
    }
    for gateway in gateways {
        if gateway.is_ipv4() {
            script.push_str(&format!(
                "/ip route add dst-address=0.0.0.0/0 gateway={gateway} comment=\"vexa-vm\"\n"
            ));
        } else {
            script.push_str(&format!(
                "/ipv6 route add dst-address=::/0 gateway={gateway} comment=\"vexa-vm\"\n"
            ));
        }
    }
    if !dns_servers.is_empty() {
        let servers = dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        script.push_str(&format!("/ip dns set servers={}\n", routeros_string(&servers)));
    }
    script
}

async fn routeros_bootstrap(state: &AppState, vm: &Vm) -> AppResult<()> {
    routeros_health(state, vm).await?;
    let addresses = state.db.vm_ip_addresses(&vm.id)?;
    let dns = state.db.dns_servers(None, Some(&vm.id))?;
    let routed = crate::services::routed_network::plan(vm)?;
    let password = state.db.decrypt_vm_password(&vm.id, &state.security)?;
    let mut script = String::from(
        "/ip address remove [find where comment=\"vexa-vm\"]\n\
         /ipv6 address remove [find where comment=\"vexa-vm\"]\n\
         /ip route remove [find where comment=\"vexa-vm\"]\n\
         /ipv6 route remove [find where comment=\"vexa-vm\"]\n",
    );
    script.push_str(&format!(
        "/system identity set name={}\n",
        routeros_string(&vm.hostname)
    ));
    if let Some(routed) = routed.as_ref() {
        script.push_str(&format!(
            "/ip address add address={}/{} interface=ether1 comment=\"vexa-vm\"\n",
            routed.guest_address, routed.prefix_length
        ));
        for address in addresses
            .iter()
            .filter(|address| address.family == crate::models::AddressFamily::V4)
        {
            script.push_str(&format!(
                "/ip address add address={}/{} interface=ether1 comment=\"vexa-vm\"\n",
                address.address, address.prefix_length
            ));
        }
        script.push_str(&format!(
            "/ip route add dst-address=0.0.0.0/0 gateway={} comment=\"vexa-vm\"\n",
            routed.gateway
        ));
    } else {
        let mut gateways = std::collections::BTreeSet::new();
        for address in &addresses {
            match address.family {
                crate::models::AddressFamily::V4 => script.push_str(&format!(
                    "/ip address add address={}/{} interface=ether1 comment=\"vexa-vm\"\n",
                    address.address, address.prefix_length
                )),
                crate::models::AddressFamily::V6 => script.push_str(&format!(
                    "/ipv6 address add address={}/{} interface=ether1 comment=\"vexa-vm\"\n",
                    address.address, address.prefix_length
                )),
            }
            if let Some(gateway) = address.gateway.as_deref() {
                if gateways.insert((address.family.as_i64(), gateway.to_owned())) {
                    match address.family {
                        crate::models::AddressFamily::V4 => script.push_str(&format!(
                            "/ip route add dst-address=0.0.0.0/0 gateway={} comment=\"vexa-vm\"\n",
                            routeros_string(gateway)
                        )),
                        crate::models::AddressFamily::V6 => script.push_str(&format!(
                            "/ipv6 route add dst-address=::/0 gateway={} comment=\"vexa-vm\"\n",
                            routeros_string(gateway)
                        )),
                    }
                }
            }
        }
    }
    let dns = dns
        .iter()
        .map(|server| server.address.as_str())
        .collect::<Vec<_>>()
        .join(",");
    if !dns.is_empty() {
        script.push_str(&format!("/ip dns set servers={}\n", routeros_string(&dns)));
    }
    if password.is_some() {
        let routed = routed.as_ref().ok_or_else(|| {
            AppError::Conflict("automatic RouterOS credentials require Vexa routed IPv4 networking".into())
        })?;
        script.push_str(&format!(
            "/ip service set [find where name=\"www\"] address={}/32 disabled=no port=80\n",
            routed.gateway,
        ));
    }
    routeros_exec_script(state, vm, &script, true).await?;
    if let Some(password) = password {
        let routed = routed.as_ref().expect("password checked routed plan above");
        let provision = routeros_initialize_account(state, vm, routed, &password).await;
        let disable = routeros_disable_rest(state, vm).await;
        provision?;
        disable?;
    }
    Ok(())
}

fn routeros_rest_client() -> AppResult<Client> {
    Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|error| AppError::Internal(format!("could not create RouterOS REST client: {error}")))
}

fn routeros_rest_url(
    routed: &crate::services::routed_network::RoutedIpv4,
    path: &str,
) -> AppResult<reqwest::Url> {
    if !routed.guest_address.is_link_local() || !routed.gateway.is_link_local() {
        return Err(AppError::Configuration(
            "RouterOS management link is not link-local".into(),
        ));
    }
    reqwest::Url::parse(&format!(
        "http://{}/rest/{}",
        routed.guest_address,
        path.trim_start_matches('/')
    ))
    .map_err(|error| AppError::Configuration(format!("RouterOS REST URL is invalid: {error}")))
}

async fn routeros_rest_request(
    client: &Client,
    method: Method,
    url: reqwest::Url,
    username: &str,
    password: &str,
    body: Option<Value>,
) -> AppResult<(StatusCode, Value)> {
    let mut request = client.request(method, url).basic_auth(username, Some(password));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| AppError::Hypervisor(format!("RouterOS REST request failed: {error}")))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| AppError::Hypervisor(format!("RouterOS REST response failed: {error}")))?;
    if bytes.len() > 1024 * 1024 {
        return Err(AppError::Hypervisor(
            "RouterOS REST response exceeded one MiB".into(),
        ));
    }
    let value = if bytes.is_empty() {
        json!([])
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|_| AppError::Hypervisor("RouterOS REST response was not valid JSON".into()))?
    };
    Ok((status, value))
}

async fn routeros_rest_authenticated(
    client: &Client,
    routed: &crate::services::routed_network::RoutedIpv4,
    username: &str,
    password: &str,
) -> AppResult<bool> {
    let (status, _) = routeros_rest_request(
        client,
        Method::GET,
        routeros_rest_url(routed, "system/identity")?,
        username,
        password,
        None,
    )
    .await?;
    Ok(status.is_success())
}

async fn routeros_initialize_account(
    _state: &AppState,
    vm: &Vm,
    routed: &crate::services::routed_network::RoutedIpv4,
    password: &str,
) -> AppResult<()> {
    if vm.root_username.eq_ignore_ascii_case("admin") {
        return Err(AppError::Validation(
            "RouterOS reserves its insecure factory 'admin' account; use 'vexa-admin' or another administrator name"
                .into(),
        ));
    }
    let client = routeros_rest_client()?;
    let desired_ready = routeros_rest_authenticated(&client, routed, &vm.root_username, password).await?;
    if !desired_ready {
        let (status, users) = routeros_rest_request(
            &client,
            Method::GET,
            routeros_rest_url(routed, "user")?,
            "admin",
            "",
            None,
        )
        .await?;
        if !status.is_success() {
            return Err(AppError::Conflict(format!(
                "RouterOS factory-account authentication failed with HTTP {}",
                status.as_u16()
            )));
        }
        let users = users
            .as_array()
            .ok_or_else(|| AppError::Hypervisor("RouterOS user inventory was not an array".into()))?;
        if !users
            .iter()
            .any(|user| user.get("name").and_then(Value::as_str) == Some(vm.root_username.as_str()))
        {
            let (status, _) = routeros_rest_request(
                &client,
                Method::PUT,
                routeros_rest_url(routed, "user")?,
                "admin",
                "",
                Some(json!({
                    "name": vm.root_username,
                    "password": password,
                    "group": "full",
                })),
            )
            .await?;
            if !status.is_success() {
                return Err(AppError::Conflict(format!(
                    "RouterOS administrator creation failed with HTTP {}",
                    status.as_u16()
                )));
            }
        }
        if !routeros_rest_authenticated(&client, routed, &vm.root_username, password).await? {
            return Err(AppError::Conflict(
                "RouterOS did not accept the provisioned administrator credentials".into(),
            ));
        }
    }
    let (status, users) = routeros_rest_request(
        &client,
        Method::GET,
        routeros_rest_url(routed, "user")?,
        &vm.root_username,
        password,
        None,
    )
    .await?;
    if !status.is_success() {
        return Err(AppError::Conflict(
            "RouterOS administrator could not read the user inventory".into(),
        ));
    }
    if let Some(factory) = users.as_array().and_then(|users| {
        users
            .iter()
            .find(|user| user.get("name").and_then(Value::as_str) == Some("admin"))
    }) {
        let id = factory
            .get(".id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::Hypervisor("RouterOS factory user has no ID".into()))?;
        let (status, _) = routeros_rest_request(
            &client,
            Method::POST,
            routeros_rest_url(routed, "user/set")?,
            &vm.root_username,
            password,
            Some(json!({ "numbers": id, "disabled": "yes" })),
        )
        .await?;
        if !status.is_success() {
            return Err(AppError::Conflict(format!(
                "RouterOS factory-account disable failed with HTTP {}",
                status.as_u16()
            )));
        }
    }
    Ok(())
}

async fn routeros_change_password(
    state: &AppState,
    vm: &Vm,
    username: &str,
    password: &str,
) -> AppResult<()> {
    let routed = crate::services::routed_network::plan(vm)?.ok_or_else(|| {
        AppError::Conflict("RouterOS password changes require Vexa routed IPv4 networking".into())
    })?;
    let current = state
        .db
        .decrypt_vm_password(&vm.id, &state.security)?
        .ok_or_else(|| AppError::NotFound("VM password".into()))?;
    let enable = format!(
        "/ip service set [find where name=\"www\"] address={}/32 disabled=no port=80\n",
        routed.gateway
    );
    routeros_exec_script(state, vm, &enable, true).await?;
    let client = routeros_rest_client()?;
    let changed = routeros_rest_request(
        &client,
        Method::POST,
        routeros_rest_url(&routed, "password")?,
        username,
        &current,
        Some(json!({
            "old-password": current,
            "new-password": password,
            "confirm-new-password": password,
        })),
    )
    .await
    .and_then(|(status, _)| {
        if status.is_success() {
            Ok(())
        } else {
            Err(AppError::Conflict(format!(
                "RouterOS password change failed with HTTP {}",
                status.as_u16()
            )))
        }
    });
    let disable = routeros_disable_rest(state, vm).await;
    changed?;
    disable
}

async fn routeros_disable_rest(state: &AppState, vm: &Vm) -> AppResult<()> {
    routeros_exec_script(
        state,
        vm,
        "/ip service set [find where name=\"www\"] disabled=yes\n",
        true,
    )
    .await
}

async fn routeros_health(state: &AppState, vm: &Vm) -> AppResult<()> {
    let response = state
        .hypervisor
        .guest_agent_command(&vm.name, serde_json::json!({ "execute": "guest-info" }))
        .await
        .map_err(|error| AppError::Hypervisor(error.to_string()))?;
    qga_return(&response).map(|_| ())
}

async fn routeros_exec_script(state: &AppState, vm: &Vm, script: &str, wait_for_exit: bool) -> AppResult<()> {
    if script.is_empty() || script.len() > 256 * 1024 {
        return Err(AppError::Validation(
            "RouterOS guest script must contain 1 through 262144 bytes".into(),
        ));
    }
    let response = state
        .hypervisor
        .guest_agent_command(
            &vm.name,
            serde_json::json!({
                "execute": "guest-exec",
                "arguments": {
                    "input-data": STANDARD.encode(script.as_bytes()),
                    "capture-output": true
                }
            }),
        )
        .await
        .map_err(|error| AppError::Hypervisor(error.to_string()))?;
    let returned = qga_return(&response)?;
    let pid = returned
        .get("pid")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .ok_or_else(|| AppError::Hypervisor("RouterOS guest-exec returned no process ID".into()))?;
    if !wait_for_exit {
        return Ok(());
    }
    for _ in 0..60 {
        let response = state
            .hypervisor
            .guest_agent_command(
                &vm.name,
                serde_json::json!({
                    "execute": "guest-exec-status",
                    "arguments": { "pid": pid }
                }),
            )
            .await
            .map_err(|error| AppError::Hypervisor(error.to_string()))?;
        let returned = qga_return(&response)?;
        if returned.get("exited").and_then(serde_json::Value::as_bool) == Some(true) {
            let exit_code = returned
                .get("exitcode")
                .and_then(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                })
                .unwrap_or(-1);
            if exit_code == 0 {
                return Ok(());
            }
            let output = returned
                .get("out-data")
                .and_then(Value::as_str)
                .and_then(|value| STANDARD.decode(value).ok())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            let output = output.split_whitespace().collect::<Vec<_>>().join(" ");
            let output = output.chars().take(300).collect::<String>();
            return Err(AppError::Hypervisor(format!(
                "RouterOS guest script failed with exit code {exit_code}{}",
                if output.is_empty() {
                    String::new()
                } else {
                    format!(": {output}")
                }
            )));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(AppError::Hypervisor(
        "RouterOS guest script did not finish before the 15-second deadline".into(),
    ))
}

fn qga_return(response: &serde_json::Value) -> AppResult<&serde_json::Value> {
    if let Some(error) = response.get("error") {
        let description = error
            .get("desc")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("guest agent rejected the command");
        return Err(AppError::Hypervisor(description.into()));
    }
    response
        .get("return")
        .ok_or_else(|| AppError::Hypervisor("guest agent response contained no return value".into()))
}

/// RouterOS expands `\XX` escapes inside a quoted value. Encoding every UTF-8
/// byte this way avoids script interpolation and keeps credentials inert.
fn routeros_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len().saturating_mul(3).saturating_add(2));
    quoted.push('"');
    for byte in value.as_bytes() {
        quoted.push('\\');
        quoted.push_str(&format!("{byte:02X}"));
    }
    quoted.push('"');
    quoted
}

fn artifact_path(config: &Config, platform: GuestToolsPlatform) -> Option<PathBuf> {
    match platform {
        GuestToolsPlatform::Linux => config.guest_tools_linux_x86_64_artifact.clone(),
        GuestToolsPlatform::Windows => config.guest_tools_windows_x86_64_artifact.clone(),
    }
}

fn valid_artifact(path: &Path) -> bool {
    fs::metadata(path).ok().is_some_and(|metadata| {
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= MAX_ARTIFACT_BYTES
    })
}

fn is_linux_family(value: &str) -> bool {
    [
        "linux", "ubuntu", "debian", "kali", "fedora", "centos", "rhel", "rocky", "alma", "arch", "opensuse",
        "sles",
    ]
    .iter()
    .any(|family| value.contains(family))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn protocol_error(error: impl std::fmt::Display) -> AppError {
    AppError::Conflict(format!("Vexa Guest Tools protocol failed: {error}"))
}

pub fn public_status(record: Option<VmGuestTools>) -> serde_json::Value {
    status_value(record, false)
}

pub fn admin_status(record: Option<VmGuestTools>) -> serde_json::Value {
    status_value(record, true)
}

pub fn public_status_for_vm(vm: &Vm, record: Option<VmGuestTools>) -> serde_json::Value {
    if is_routeros_vm(vm) {
        return routeros_status(vm);
    }
    public_status(record)
}

pub fn admin_status_for_vm(vm: &Vm, record: Option<VmGuestTools>) -> serde_json::Value {
    if is_routeros_vm(vm) {
        return routeros_status(vm);
    }
    admin_status(record)
}

fn routeros_status(vm: &Vm) -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "platform": "routeros",
        "provisioner": "qemu_guest_agent",
        "desired_version": "built-in",
        "installed_version": "built-in",
        "status": if vm.state == crate::models::VmState::Running { "available" } else { "offline" },
        "connected": vm.state == crate::models::VmState::Running,
        "pending_rotation": false,
        "bootstrap_pending": false,
        "message": "Vexa uses the RouterOS built-in QEMU Guest Agent; no third-party service is installed"
    })
}

fn status_value(record: Option<VmGuestTools>, include_error: bool) -> serde_json::Value {
    record.map_or_else(
        || {
            serde_json::json!({
                "enabled": false,
                "status": "disabled",
                "connected": false,
            })
        },
        |record| {
            let mut value = serde_json::json!({
                "enabled": record.enabled,
                "platform": record.platform,
                "provisioner": record.provisioner,
                "desired_version": record.desired_version,
                "installed_version": record.installed_version,
                "status": if record.status == GuestToolsStatus::Ready
                    && record.last_seen_at.is_some_and(|seen| seen >= unix_timestamp() - 300)
                { "ready" } else if record.status == GuestToolsStatus::Ready { "offline" } else { record.status.as_str() },
                "connected": record.status == GuestToolsStatus::Ready
                    && record.last_seen_at.is_some_and(|seen| seen >= unix_timestamp() - 300),
                "last_seen_at": record.last_seen_at,
                "pending_rotation": record.pending_rotation,
                "bootstrap_pending": record.pending_installed,
            });
            if include_error {
                value["last_error"] = serde_json::json!(record.last_error);
            }
            value
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HypervisorMode;
    use serde_json::json;

    fn compatibility_config(windows_artifact: Option<PathBuf>) -> Config {
        Config {
            bind: "127.0.0.1:18080".parse().unwrap(),
            public_url: "http://127.0.0.1:18080".into(),
            database_path: "test.db".into(),
            template_dir: "templates".into(),
            static_dir: "static".into(),
            master_key: [7; 32],
            bootstrap_admin: "admin".into(),
            bootstrap_password: None,
            secure_cookies: false,
            hypervisor_mode: HypervisorMode::Mock,
            libvirt_uri: "qemu:///system".into(),
            vm_storage: "vms".into(),
            iso_storage: "isos".into(),
            cloud_init_storage: "seed".into(),
            guest_tools_socket_dir: "/var/lib/vexa-vm/guest-tools".into(),
            guest_tools_linux_x86_64_artifact: None,
            guest_tools_windows_x86_64_artifact: windows_artifact,
            guest_tools_version: "0.1.0".into(),
            network_bridge: "virbr0".into(),
            public_interface: None,
            vnc_ttl: Duration::from_secs(600),
            metrics_interval: Duration::from_secs(15),
        }
    }

    fn test_image(os_family: &str, metadata: serde_json::Value) -> IsoImage {
        IsoImage {
            id: "image-id".into(),
            slug: "test-image".into(),
            name: "Test image".into(),
            version: Some("1".into()),
            os_family: os_family.into(),
            architecture: "x86_64".into(),
            install_mode: InstallMode::Automatic,
            source_url: None,
            local_path: Some("/images/test.img".into()),
            checksum_sha256: Some("00".repeat(32)),
            size_bytes: Some(1024),
            supports_guest_agent: true,
            supports_cloud_init: false,
            uefi: false,
            enabled: true,
            metadata,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn automatic_windows_installer_accepts_the_native_windows_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("vexa-guest-tools.exe");
        std::fs::write(&artifact, b"PE-test-artifact").unwrap();
        let image = test_image(
            "windows",
            json!({
                "unattended_installer": true,
                "guest_tools_provisioner": "windows-unattend",
                "virtio_serial_driver": "installed_signed"
            }),
        );
        let result = compatibility(&compatibility_config(Some(artifact)), &image);
        assert!(result.supported);
        assert!(result.artifact_available);
        assert_eq!(result.platform, Some(GuestToolsPlatform::Windows));
    }

    #[test]
    fn routeros_uses_its_builtin_qemu_agent_without_an_artifact() {
        let image = test_image(
            "routeros",
            json!({
                "preconfigured_appliance": true,
                "guest_tools_integration": "qemu-agent"
            }),
        );
        let result = compatibility(&compatibility_config(None), &image);
        assert!(result.supported);
        assert!(result.artifact_available);
        assert!(result.platform.is_none());
    }

    #[test]
    fn routeros_values_are_encoded_without_script_interpolation() {
        assert_eq!(routeros_string("a\"$\\"), "\"\\61\\22\\24\\5C\"");
    }

    #[test]
    fn host_and_guest_use_the_same_decoded_hmac_key() {
        let raw = [0x5a_u8; MIN_SECRET_BYTES];
        let encoded = STANDARD_NO_PAD.encode(raw);
        let host_key = decode_channel_secret(encoded.clone()).expect("host decodes secret");
        let guest_key = STANDARD_NO_PAD.decode(encoded).expect("guest decodes secret");
        assert_eq!(host_key, guest_key);

        let request = Request::signed(
            "request-1",
            1_700_000_000,
            STANDARD_NO_PAD.encode([7_u8; 24]),
            Command::Ping,
            &host_key,
        )
        .expect("host signs request");
        let mut replay = vexa_guest_protocol::ReplayCache::new(128);
        let command = request
            .verify_and_decrypt(&guest_key, 1_700_000_000, 120, &mut replay)
            .expect("guest authenticates and decrypts the host request");
        assert!(matches!(command, Command::Ping));
    }

    #[test]
    fn channel_errors_are_actionable_without_exposing_a_socket_path() {
        let denied =
            channel_connect_error_message(&std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(denied.contains("group membership"));
        assert!(denied.contains("AppArmor or SELinux"));
        assert!(!denied.contains("/var/"));

        let missing = channel_connect_error_message(&std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(missing.contains("socket is absent"));
    }

    #[cfg(unix)]
    #[test]
    fn host_exchange_discards_a_timed_out_requests_stale_response() {
        use std::os::unix::net::UnixListener;

        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("guest-tools.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let secret = [0x42_u8; MIN_SECRET_BYTES];
        let guest_secret = secret;
        let guest = std::thread::spawn(move || {
            let (mut channel, _) = listener.accept().unwrap();
            let current: Request = read_frame(&mut channel).unwrap();
            let stale_request = Request::signed(
                "prior-request",
                current.sent_at,
                STANDARD_NO_PAD.encode([0x17_u8; 24]),
                Command::Health,
                &guest_secret,
            )
            .unwrap();
            let health = || ResponseData::Health {
                agent_version: "0.1.0".into(),
                operating_system: "test-linux".into(),
                hostname: "test-vm".into(),
                uptime_seconds: 60,
                capabilities: vec!["health".into()],
            };
            write_frame(
                &mut channel,
                &Response::success(&stale_request, current.sent_at, health(), &guest_secret).unwrap(),
            )
            .unwrap();
            write_frame(
                &mut channel,
                &Response::success(&current, current.sent_at, health(), &guest_secret).unwrap(),
            )
            .unwrap();
        });

        let response = exchange(&socket, &secret, Command::Health, Duration::from_secs(2))
            .expect("matching response follows stale response");
        assert!(matches!(
            response,
            ResponseData::Health {
                agent_version,
                ..
            } if agent_version == "0.1.0"
        ));
        guest.join().unwrap();
    }
}
