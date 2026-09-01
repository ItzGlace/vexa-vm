//! Hypervisor boundary used by the HTTP and job layers.
//!
//! The trait deliberately exposes domain operations instead of libvirt XML or
//! command strings.  This keeps untrusted API values away from process
//! execution and gives development/test builds a useful in-memory backend.

pub mod libvirt;
pub mod mock;

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::error::AppError;

pub type HypervisorResult<T> = Result<T, HypervisorError>;

#[derive(Debug, Error)]
pub enum HypervisorError {
    #[error("hypervisor backend is unavailable: {0}")]
    BackendUnavailable(String),
    #[error("invalid hypervisor request: {0}")]
    InvalidInput(String),
    #[error("VM '{0}' was not found")]
    NotFound(String),
    #[error("hypervisor conflict: {0}")]
    Conflict(String),
    #[error("hypervisor command '{operation}' failed: {message}")]
    CommandFailed { operation: String, message: String },
    #[error("hypervisor command '{0}' timed out")]
    Timeout(String),
    #[error("hypervisor I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("hypervisor returned invalid data: {0}")]
    InvalidResponse(String),
}

impl From<HypervisorError> for AppError {
    fn from(error: HypervisorError) -> Self {
        match error {
            HypervisorError::InvalidInput(message) => Self::Validation(message),
            HypervisorError::NotFound(name) => Self::NotFound(format!("VM '{name}'")),
            HypervisorError::Conflict(message) => Self::Conflict(message),
            other => Self::Hypervisor(other.to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HypervisorCapabilities {
    pub backend: String,
    pub available: bool,
    pub uri: Option<String>,
    pub hypervisor_version: Option<String>,
    pub emulator_version: Option<String>,
    pub kvm_device_available: bool,
    pub supports_live_resize: bool,
    pub supports_snapshots: bool,
    pub supports_vnc: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmPowerState {
    Running,
    Paused,
    ShuttingDown,
    ShutOff,
    Crashed,
    Suspended,
    Unknown,
}

impl VmPowerState {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Running | Self::Paused | Self::ShuttingDown | Self::Suspended
        )
    }
}

impl From<&str> for VmPowerState {
    fn from(value: &str) -> Self {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.contains("running") || normalized == "1" {
            Self::Running
        } else if normalized.contains("paused") || normalized == "3" {
            Self::Paused
        } else if normalized.contains("shut off") || normalized.contains("shutoff") || normalized == "5" {
            Self::ShutOff
        } else if normalized.contains("shutdown") || normalized == "4" {
            Self::ShuttingDown
        } else if normalized.contains("crashed") || normalized == "6" {
            Self::Crashed
        } else if normalized.contains("suspend") || normalized == "7" {
            Self::Suspended
        } else {
            Self::Unknown
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmInfo {
    pub name: String,
    pub uuid: Option<Uuid>,
    pub state: VmPowerState,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_bytes: u64,
    pub disk_path: Option<PathBuf>,
    /// Host-side interface name reported by libvirt (for example `vnet3`).
    /// Security policy must bind to this interface rather than trusting a
    /// guest-controlled source MAC address.
    pub interface_name: Option<String>,
    /// Libvirt interface type reported by `domiflist` (for example `bridge`
    /// or the legacy externally managed `ethernet` topology).
    #[serde(default)]
    pub interface_type: Option<String>,
    pub bridge: Option<String>,
    pub mac_address: Option<String>,
    pub autostart: bool,
    pub persistent: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmStats {
    pub cpu_time_ns: u64,
    pub memory_current_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VmImage {
    Qcow2 {
        path: PathBuf,
    },
    Raw {
        path: PathBuf,
    },
    /// A ready-to-boot raw appliance disk which does not consume cloud-init
    /// metadata. RouterOS CHR is the first supported appliance; its built-in
    /// QEMU Guest Agent completes automatic host-only provisioning.
    ApplianceRaw {
        path: PathBuf,
    },
    InstallerIso {
        path: PathBuf,
    },
    /// A Windows installer ISO paired with a verified virtio-win driver ISO.
    /// Vexa generates an Autounattend answer disk for this variant.
    UnattendedWindowsIso {
        path: PathBuf,
        driver_iso: PathBuf,
        image_index: u32,
        driver_version: String,
    },
    Blank,
}

impl VmImage {
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            Self::Qcow2 { path }
            | Self::Raw { path }
            | Self::ApplianceRaw { path }
            | Self::InstallerIso { path }
            | Self::UnattendedWindowsIso { path, .. } => Some(path),
            Self::Blank => None,
        }
    }

    pub fn is_installer(&self) -> bool {
        matches!(
            self,
            Self::InstallerIso { .. } | Self::UnattendedWindowsIso { .. }
        )
    }

    pub fn is_manual_installer(&self) -> bool {
        matches!(self, Self::InstallerIso { .. })
    }

    pub fn is_unattended_windows(&self) -> bool {
        matches!(self, Self::UnattendedWindowsIso { .. })
    }

    pub fn is_preconfigured_appliance(&self) -> bool {
        matches!(self, Self::ApplianceRaw { .. })
    }

    pub fn driver_iso(&self) -> Option<&PathBuf> {
        match self {
            Self::UnattendedWindowsIso { driver_iso, .. } => Some(driver_iso),
            _ => None,
        }
    }

    pub fn backing_format(&self) -> Option<&'static str> {
        match self {
            Self::Qcow2 { .. } => Some("qcow2"),
            Self::Raw { .. } | Self::ApplianceRaw { .. } => Some("raw"),
            Self::InstallerIso { .. } | Self::UnattendedWindowsIso { .. } | Self::Blank => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Firmware {
    #[default]
    Bios,
    Uefi,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateVmRequest {
    pub name: String,
    pub vcpus: u32,
    /// Maximum guest-visible memory entitlement. `initial_memory_mib` is kept
    /// for backend compatibility and must equal the entitlement in Vexa.
    pub memory_mib: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_memory_mib: Option<u64>,
    pub disk_gib: u64,
    pub image: VmImage,
    pub cloud_init_iso: Option<PathBuf>,
    #[serde(default)]
    pub guest_tools_socket: Option<PathBuf>,
    pub bridge: Option<String>,
    /// A pre-created persistent TAP owned by the local routed-network
    /// reconciler. When present, libvirt must attach it as an unmanaged
    /// ethernet target instead of asking a Linux bridge to create a TAP.
    #[serde(default)]
    pub tap_name: Option<String>,
    pub mac_address: String,
    #[serde(default)]
    pub network_limit_mbps: Option<u64>,
    #[serde(default)]
    pub firmware: Firmware,
    #[serde(default = "default_machine_type")]
    pub machine_type: String,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default = "default_true")]
    pub start: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResizeVmRequest {
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    /// New virtual capacity. Shrinking a disk is intentionally unsupported.
    pub disk_gib: Option<u64>,
    pub network_limit_mbps: Option<Option<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReinstallVmRequest {
    pub image: VmImage,
    pub disk_gib: u64,
    pub cloud_init_iso: Option<PathBuf>,
    #[serde(default)]
    pub guest_tools_socket: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub start: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PowerAction {
    Start,
    Shutdown,
    ForceOff,
    Reboot,
    Reset,
    Suspend,
    Resume,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub name: String,
    pub description: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub current: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VncTarget {
    /// The hypervisor backend must only return a loopback address. The web
    /// layer is responsible for authenticated, same-origin websocket proxying.
    pub host: IpAddr,
    pub port: u16,
}

#[async_trait]
pub trait Hypervisor: Send + Sync {
    async fn capabilities(&self) -> HypervisorResult<HypervisorCapabilities>;
    async fn list_vms(&self) -> HypervisorResult<Vec<VmInfo>>;
    async fn get_vm(&self, name: &str) -> HypervisorResult<VmInfo>;
    async fn create_vm(&self, request: CreateVmRequest) -> HypervisorResult<VmInfo>;
    async fn delete_vm(&self, name: &str, delete_storage: bool) -> HypervisorResult<()>;
    async fn power(&self, name: &str, action: PowerAction) -> HypervisorResult<VmInfo>;
    /// Acknowledge an installer-media firmware prompt immediately after an
    /// unattended guest is started. Backends without a virtual keyboard may
    /// safely keep the default no-op implementation.
    async fn acknowledge_install_media_boot(&self, name: &str) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        Ok(())
    }
    async fn resize(&self, name: &str, request: ResizeVmRequest) -> HypervisorResult<VmInfo>;
    /// Reconcile the running and persistent VirtIO balloon target. The maximum
    /// entitlement remains unchanged and is still reported by VM inventory
    /// and API resource fields.
    async fn set_memory_balloon(&self, name: &str, target_mib: u64) -> HypervisorResult<()> {
        let _ = (name, target_mib);
        Err(HypervisorError::BackendUnavailable(
            "this hypervisor backend does not support live memory ballooning".into(),
        ))
    }
    async fn reinstall(&self, name: &str, request: ReinstallVmRequest) -> HypervisorResult<VmInfo>;
    /// Eject a generated provisioning seed from both the live and persistent
    /// domain definitions. Implementations must verify that the CD-ROM source
    /// is exactly `expected_source`; an unrelated installer must never be
    /// detached merely because it uses a familiar target name.
    async fn detach_seed_media(&self, name: &str, expected_source: &Path) -> HypervisorResult<()>;
    async fn stats(&self, name: &str) -> HypervisorResult<VmStats>;
    /// Enable or disable the VM's primary network link in both its persistent
    /// definition and, when running, the live domain.
    async fn set_network_enabled(&self, name: &str, enabled: bool) -> HypervisorResult<()>;
    /// Ensure persistent VirtIO NIC definitions use multiple vhost queues.
    /// Running domains adopt the persistent definition at their next reboot.
    async fn ensure_network_multiqueue(&self, name: &str, queues: u32) -> HypervisorResult<bool> {
        let _ = (name, queues);
        Ok(false)
    }
    /// Send one structured command to the guest agent without placing the
    /// JSON payload (which may contain an encoded credential) in a process
    /// argument. Backends without a guest-agent transport may keep the
    /// default unsupported implementation.
    async fn guest_agent_command(&self, name: &str, command: Value) -> HypervisorResult<Value> {
        let _ = (name, command);
        Err(HypervisorError::BackendUnavailable(
            "this hypervisor backend does not expose a guest-agent command transport".into(),
        ))
    }
    async fn create_snapshot(&self, name: &str, request: SnapshotRequest) -> HypervisorResult<SnapshotInfo>;
    async fn list_snapshots(&self, name: &str) -> HypervisorResult<Vec<SnapshotInfo>>;
    async fn revert_snapshot(&self, name: &str, snapshot: &str) -> HypervisorResult<VmInfo>;
    async fn delete_snapshot(&self, name: &str, snapshot: &str) -> HypervisorResult<()>;
    async fn vnc_target(&self, name: &str) -> HypervisorResult<VncTarget>;
}

fn default_true() -> bool {
    true
}

fn default_machine_type() -> String {
    "q35".into()
}

pub(crate) fn validate_vm_name(name: &str) -> HypervisorResult<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(HypervisorError::InvalidInput(
            "VM name must contain between 1 and 63 characters".into(),
        ));
    }
    if !name
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(HypervisorError::InvalidInput(
            "VM name may contain only ASCII letters, numbers, '.', '_' and '-', and must start with a letter or number"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_snapshot_name(name: &str) -> HypervisorResult<()> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(HypervisorError::InvalidInput(
            "snapshot name must contain 1-80 safe ASCII characters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_bridge_name(name: &str) -> HypervisorResult<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(HypervisorError::InvalidInput(
            "bridge must be a Linux interface name of at most 15 safe ASCII characters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_mac_address(mac: &str) -> HypervisorResult<()> {
    let parts: Vec<_> = mac.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(HypervisorError::InvalidInput(
            "MAC address must use six colon-separated hexadecimal octets".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_create_request(request: &CreateVmRequest) -> HypervisorResult<()> {
    validate_vm_name(&request.name)?;
    validate_mac_address(&request.mac_address)?;
    if let Some(bridge) = request.bridge.as_deref() {
        validate_bridge_name(bridge)?;
    }
    if let Some(tap_name) = request.tap_name.as_deref() {
        validate_bridge_name(tap_name)?;
        if request.bridge.is_some() {
            return Err(HypervisorError::InvalidInput(
                "bridge and persistent tap modes are mutually exclusive".into(),
            ));
        }
    }
    if !(1..=512).contains(&request.vcpus) {
        return Err(HypervisorError::InvalidInput(
            "vCPU count must be between 1 and 512".into(),
        ));
    }
    if !(256..=16 * 1024 * 1024).contains(&request.memory_mib) {
        return Err(HypervisorError::InvalidInput(
            "memory must be between 256 MiB and 16 TiB".into(),
        ));
    }
    if request
        .initial_memory_mib
        .is_some_and(|value| !(256..=request.memory_mib).contains(&value))
    {
        return Err(HypervisorError::InvalidInput(
            "initial balloon memory must be between 256 MiB and the VM memory entitlement".into(),
        ));
    }
    if !(1..=1024 * 1024).contains(&request.disk_gib) {
        return Err(HypervisorError::InvalidInput(
            "disk capacity must be between 1 GiB and 1 PiB".into(),
        ));
    }
    if request.network_limit_mbps == Some(0) {
        return Err(HypervisorError::InvalidInput(
            "network speed limit must be greater than zero".into(),
        ));
    }
    if !matches!(request.machine_type.as_str(), "q35" | "i440fx") {
        return Err(HypervisorError::InvalidInput(
            "machine type must be q35 or i440fx".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_resize_request(request: &ResizeVmRequest) -> HypervisorResult<()> {
    if request.vcpus.is_none()
        && request.memory_mib.is_none()
        && request.disk_gib.is_none()
        && request.network_limit_mbps.is_none()
    {
        return Err(HypervisorError::InvalidInput(
            "at least one resize value is required".into(),
        ));
    }
    if request.vcpus.is_some_and(|value| !(1..=512).contains(&value)) {
        return Err(HypervisorError::InvalidInput(
            "vCPU count must be between 1 and 512".into(),
        ));
    }
    if request
        .memory_mib
        .is_some_and(|value| !(256..=16 * 1024 * 1024).contains(&value))
    {
        return Err(HypervisorError::InvalidInput(
            "memory must be between 256 MiB and 16 TiB".into(),
        ));
    }
    if request
        .disk_gib
        .is_some_and(|value| !(1..=1024 * 1024).contains(&value))
    {
        return Err(HypervisorError::InvalidInput(
            "disk capacity must be between 1 GiB and 1 PiB".into(),
        ));
    }
    if request.network_limit_mbps == Some(Some(0)) {
        return Err(HypervisorError::InvalidInput(
            "network speed limit must be greater than zero".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names_without_shell_metacharacters() {
        assert!(validate_vm_name("demo-01.example").is_ok());
        assert!(validate_vm_name("--connect").is_err());
        assert!(validate_vm_name("vm;shutdown").is_err());
        assert!(validate_vm_name("vm name").is_err());
    }

    #[test]
    fn parses_libvirt_power_states() {
        assert_eq!(VmPowerState::from("running"), VmPowerState::Running);
        assert_eq!(VmPowerState::from("shut off"), VmPowerState::ShutOff);
        assert_eq!(VmPowerState::from("paused"), VmPowerState::Paused);
    }

    #[test]
    fn accepts_only_public_machine_type_contract_values() {
        let mut request = CreateVmRequest {
            name: "machine-test".into(),
            vcpus: 2,
            memory_mib: 2048,
            initial_memory_mib: None,
            disk_gib: 20,
            image: VmImage::Blank,
            cloud_init_iso: None,
            guest_tools_socket: None,
            bridge: Some("virbr0".into()),
            tap_name: None,
            mac_address: "52:54:00:12:34:56".into(),
            network_limit_mbps: None,
            firmware: Firmware::Bios,
            machine_type: "q35".into(),
            autostart: false,
            start: false,
        };
        assert!(validate_create_request(&request).is_ok());
        request.machine_type = "i440fx".into();
        assert!(validate_create_request(&request).is_ok());
        request.machine_type = "pc-q35-9.0".into();
        assert!(validate_create_request(&request).is_err());
    }
}
