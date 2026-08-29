use std::{collections::HashMap, path::Path, sync::Arc, time::Instant};

use serde_json::{json, Value};
use tera::Tera;
use tokio::sync::{Mutex, RwLock};

use crate::{
    config::{Config, HypervisorMode},
    db::Database,
    error::{AppError, AppResult},
    host::{HostDetector, HostInfo},
    hypervisor::{
        libvirt::{LibvirtConfig, LibvirtHypervisor},
        mock::MockHypervisor,
        Hypervisor,
    },
    models::{HostInventory, IpScope, IpStatus, NewIpAddress},
    rate_limit::RateLimiter,
    security::{hash_password, Security},
    services::updater::{
        load_fixed_trusted_release_keys, ReleaseUpdater, UpdateCoordinator, UPDATE_STAGING_ROOT,
    },
};

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub security: Security,
    pub hypervisor: Arc<dyn Hypervisor>,
    pub host_detector: HostDetector,
    pub host_info: RwLock<HostInfo>,
    pub templates: Tera,
    pub rate_limiter: RateLimiter,
    /// Serializes the capacity check with publication of a provisional VM and
    /// its create job.  A `creating` row is the durable capacity reservation,
    /// so the next request must not sample capacity until that row exists (or
    /// has been removed after a failed enqueue).
    pub vm_create_reservation_lock: Mutex<()>,
    /// Serializes traffic counter updates, quota transitions, and manual
    /// resets so a metrics sample cannot reapply stale usage after a reset.
    pub traffic_lock: Mutex<()>,
    /// Per-VM accounting epochs close the interval-sampling race around a
    /// manual reset. The sampler discards the first counter delta observed in
    /// a new epoch and uses that observation as the new baseline.
    pub traffic_accounting_generations: Mutex<HashMap<String, u64>>,
    /// Serializes checked nftables transactions. VM firewall, DDoS, and the
    /// host-only BCP38 policy share one owned bridge table.
    pub network_security_lock: Mutex<()>,
    /// Each virtio-serial channel accepts one framed conversation at a time,
    /// while unrelated VMs must not block one another on an offline guest.
    pub guest_tools_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Signed updates fail closed when the root-owned public trust store is
    /// absent or invalid; normal VM management remains available.
    pub updater: Option<Arc<UpdateCoordinator>>,
    pub updater_disabled_reason: Option<String>,
    pub started_at: Instant,
}

impl AppState {
    pub async fn initialize(mut config: Config) -> AppResult<Arc<Self>> {
        std::fs::create_dir_all(&config.iso_storage)?;
        std::fs::create_dir_all(&config.cloud_init_storage)?;
        std::fs::create_dir_all(&config.guest_tools_socket_dir)?;
        #[cfg(unix)]
        ensure_guest_tools_socket_directory_mode(&config.guest_tools_socket_dir)?;
        let removed_partials =
            crate::services::iso_download::cleanup_stale_partial_files(&config.iso_storage).await?;
        if removed_partials > 0 {
            tracing::info!(
                removed_partials,
                "removed interrupted image transfer files from managed storage"
            );
        }

        let db = Database::open(&config.database_path)?;
        let security = Security::new(config.master_key);
        config.master_key.fill(0);
        seed_administrator(&db, &config)?;
        config.bootstrap_password = None;

        let template_glob = template_glob(&config.template_dir)?;
        let templates = Tera::new(&template_glob)?;
        let host_detector = HostDetector::new(config.public_interface.clone())?;
        let host_info = host_detector.detect().await?;
        seed_default_settings(&db, &config, &host_info)?;
        persist_host_inventory(&db, &config, &host_info)?;
        persist_host_addresses(&db, &host_info)?;
        let hypervisor = select_hypervisor(&config)?;
        let (updater, updater_disabled_reason) = match load_fixed_trusted_release_keys()
            .and_then(|keys| ReleaseUpdater::new(UPDATE_STAGING_ROOT, keys, false))
        {
            Ok(updater) => (Some(Arc::new(UpdateCoordinator::fixed(updater))), None),
            Err(error) => {
                tracing::warn!(error = %error, "signed panel updates are disabled");
                (
                    None,
                    Some(format!(
                        "Signed updates are unavailable until the root-owned release trust store is configured: {error}"
                    )),
                )
            }
        };

        Ok(Arc::new(Self {
            config: Arc::new(config),
            db,
            security,
            hypervisor,
            host_detector,
            host_info: RwLock::new(host_info),
            templates,
            rate_limiter: RateLimiter::default(),
            vm_create_reservation_lock: Mutex::new(()),
            traffic_lock: Mutex::new(()),
            traffic_accounting_generations: Mutex::new(HashMap::new()),
            network_security_lock: Mutex::new(()),
            guest_tools_locks: Mutex::new(HashMap::new()),
            updater,
            updater_disabled_reason,
            started_at: Instant::now(),
        }))
    }

    pub async fn refresh_host_info(&self) -> AppResult<HostInfo> {
        let info = self.host_detector.detect().await?;
        persist_host_inventory(&self.db, &self.config, &info)?;
        persist_host_addresses(&self.db, &info)?;
        *self.host_info.write().await = info.clone();
        Ok(info)
    }

    pub fn setting(&self, section: &str, key: &str) -> AppResult<Option<Value>> {
        Ok(self
            .db
            .get_setting(section)?
            .and_then(|record| record.value.get(key).cloned()))
    }

    pub fn setting_u64(&self, section: &str, key: &str) -> AppResult<Option<u64>> {
        Ok(self.setting(section, key)?.and_then(|value| value.as_u64()))
    }

    pub fn setting_f64(&self, section: &str, key: &str) -> AppResult<Option<f64>> {
        Ok(self.setting(section, key)?.and_then(|value| value.as_f64()))
    }

    pub fn setting_bool(&self, section: &str, key: &str) -> AppResult<Option<bool>> {
        Ok(self.setting(section, key)?.and_then(|value| value.as_bool()))
    }

    pub fn setting_strings(&self, section: &str, key: &str) -> AppResult<Vec<String>> {
        Ok(self
            .setting(section, key)?
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect())
    }
}

#[cfg(unix)]
fn ensure_guest_tools_socket_directory_mode(path: &Path) -> std::io::Result<()> {
    ensure_guest_tools_socket_directory_mode_with(path, |permissions| {
        std::fs::set_permissions(path, permissions)
    })
}

#[cfg(unix)]
fn ensure_guest_tools_socket_directory_mode_with<F>(path: &Path, set_permissions: F) -> std::io::Result<()>
where
    F: FnOnce(std::fs::Permissions) -> std::io::Result<()>,
{
    use std::os::unix::fs::PermissionsExt;

    // The production unit enables RestrictSUIDSGID. The installer creates
    // this directory with the required mode before systemd starts the
    // unprivileged service, so avoid an unnecessary chmod carrying S_ISGID
    // (which the sandbox correctly rejects). A manually created directory
    // with the wrong mode still fails closed instead of silently weakening
    // the channel boundary.
    let current_mode = std::fs::metadata(path)?.permissions().mode() & 0o7777;
    if current_mode == 0o2770 {
        return Ok(());
    }

    set_permissions(
        // The setgid group directory is shared only with libvirt's QEMU
        // process so it can create the channel listener.
        std::fs::Permissions::from_mode(0o2770),
    )
}

pub(crate) fn normalize_guest_locale(value: &str) -> AppResult<String> {
    match value.trim() {
        "en-US" | "en_US" | "en_US.UTF-8" => Ok("en_US.UTF-8".into()),
        "en-GB" | "en_GB" | "en_GB.UTF-8" => Ok("en_GB.UTF-8".into()),
        "fa-IR" | "fa_IR" | "fa_IR.UTF-8" => Ok("fa_IR.UTF-8".into()),
        _ => Err(AppError::Validation(
            "locale must be en-US, en-GB, or fa-IR".into(),
        )),
    }
}

pub(crate) fn validate_timezone_name(value: &str) -> AppResult<()> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('/')
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+'))
    {
        return Err(AppError::Validation(
            "timezone must be a safe IANA timezone name".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_ntp_server(value: &str) -> AppResult<()> {
    let value = value.trim();
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let hostname = value.strip_suffix('.').unwrap_or(value);
    let valid = !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(AppError::Validation(
            "NTP servers must be valid IP addresses or hostnames".into(),
        ))
    }
}

fn seed_default_settings(db: &Database, config: &Config, host: &HostInfo) -> AppResult<()> {
    let default_dns_servers = db
        .dns_servers(None, None)?
        .into_iter()
        .map(|server| server.address)
        .collect::<Vec<_>>();
    let defaults = [
        (
            "general",
            json!({
                "node_name": host.hostname.clone(),
                "locale": "en-US",
                "timezone": "UTC",
                "ntp_servers": [],
                "sample_interval_seconds": config.metrics_interval.as_secs(),
                "metrics_retention_days": 7,
                "cpu_overcommit_ratio": 4.0,
                "memory_overcommit_ratio": 1.5,
            }),
        ),
        (
            "network",
            json!({
                "default_bridge": config.network_bridge.clone(),
                "default_port_limit_mbps": 10_000,
                "default_traffic_quota_bytes": crate::services::traffic::DEFAULT_ENFORCED_TRAFFIC_QUOTA_BYTES,
                "allow_unlimited_traffic": false,
                "dns_servers": default_dns_servers,
            }),
        ),
        ("console", json!({ "vnc_enabled": true })),
        (
            "security",
            json!({
                "session_lifetime_minutes": 720,
                "login_rate_limit": 8,
                "api_rate_limit": 600,
            }),
        ),
    ];
    for (key, default_value) in defaults {
        match db.get_setting(key)? {
            None => {
                db.set_setting(key, &default_value, false, None)?;
            }
            Some(record) => {
                let mut merged = default_value;
                if let (Some(defaults), Some(existing)) = (merged.as_object_mut(), record.value.as_object()) {
                    defaults.extend(existing.clone());
                }
                if merged != record.value {
                    db.set_setting(key, &merged, false, record.updated_by.as_deref())?;
                }
            }
        }
    }
    let network = db
        .get_setting("network")?
        .ok_or_else(|| AppError::Configuration("network settings were not initialized".into()))?;
    let dns_servers = network
        .value
        .get("dns_servers")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::Configuration("network.dns_servers is not an array".into()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AppError::Configuration("network.dns_servers contains a non-string".into()))
        })
        .collect::<AppResult<Vec<_>>>()?;
    db.set_network_setting_and_default_dns(&network.value, &dns_servers, network.updated_by.as_deref())?;
    Ok(())
}

fn persist_host_addresses(db: &Database, info: &HostInfo) -> AppResult<()> {
    let Some(primary_name) = info.primary_interface.as_deref() else {
        return Ok(());
    };
    let Some(interface) = info
        .interfaces
        .iter()
        .find(|interface| interface.name == primary_name)
    else {
        return Ok(());
    };
    for address in &interface.addresses {
        if address.address.is_loopback() {
            continue;
        }
        let non_public = match address.address {
            std::net::IpAddr::V4(value) => {
                value.is_private() || value.is_link_local() || value.is_unspecified() || value.is_multicast()
            }
            std::net::IpAddr::V6(value) => {
                let first = value.segments()[0];
                value.is_unspecified()
                    || value.is_multicast()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80
            }
        };
        if non_public {
            continue;
        }
        db.upsert_detected_host_address(&NewIpAddress {
            pool_id: None,
            address: address.address.to_string(),
            prefix_length: address.prefix_len,
            scope: IpScope::Public,
            status: IpStatus::Main,
            gateway: None,
            reverse_dns: None,
            metadata: json!({
                "detected_host_address": true,
                "interface": interface.name,
            }),
        })?;
    }
    Ok(())
}

fn seed_administrator(db: &Database, config: &Config) -> AppResult<()> {
    if !db.list_admins()?.is_empty() {
        return Ok(());
    }
    let password = config.bootstrap_password.as_deref().ok_or_else(|| {
        AppError::Configuration(
            "the database has no administrator; set VEXA_BOOTSTRAP_PASSWORD for the first start".into(),
        )
    })?;
    let hash = hash_password(password)?;
    db.bootstrap_admin(&config.bootstrap_admin, &hash)?;
    Ok(())
}

fn select_hypervisor(config: &Config) -> AppResult<Arc<dyn Hypervisor>> {
    let use_libvirt = match config.hypervisor_mode {
        HypervisorMode::Libvirt => true,
        HypervisorMode::Mock => false,
        HypervisorMode::Auto => LibvirtHypervisor::installed(),
    };
    if !use_libvirt {
        return Ok(Arc::new(MockHypervisor::new()));
    }

    let image_roots = vec![config.iso_storage.clone(), config.cloud_init_storage.clone()];
    let backend = LibvirtHypervisor::new(LibvirtConfig::new(
        &config.libvirt_uri,
        &config.vm_storage,
        image_roots,
        &config.network_bridge,
    ))?;
    Ok(Arc::new(backend))
}

fn template_glob(directory: &Path) -> AppResult<String> {
    if !directory.is_dir() {
        return Err(AppError::Configuration(format!(
            "template directory does not exist: {}",
            directory.display()
        )));
    }
    Ok(format!("{}/**/*.html", directory.display()))
}

fn persist_host_inventory(db: &Database, config: &Config, info: &HostInfo) -> AppResult<()> {
    let root_disk_total_bytes = info
        .filesystems
        .iter()
        .find(|filesystem| filesystem.mount_point == "/")
        .map(|filesystem| filesystem.total_bytes)
        .unwrap_or_else(|| {
            info.filesystems
                .iter()
                .map(|filesystem| filesystem.total_bytes)
                .max()
                .unwrap_or_default()
        });
    let addresses = info
        .interfaces
        .iter()
        .filter(|interface| !interface.is_loopback)
        .flat_map(|interface| interface.addresses.iter())
        .map(|address| address.address.to_string())
        .collect();
    let metadata = serde_json::to_value(info)
        .map_err(|error| AppError::Internal(format!("could not encode host inventory: {error}")))?;
    db.upsert_host_inventory(&HostInventory {
        hostname: info.hostname.clone(),
        architecture: info.architecture.clone(),
        kernel: info.kernel_version.clone().unwrap_or_default(),
        cpu_model: info.cpu.model.clone(),
        cpu_cores: info.cpu.logical_cores,
        memory_total_bytes: info.memory.total_bytes,
        root_disk_total_bytes,
        listen_port: config.bind.port(),
        public_interface: info.primary_interface.clone(),
        detected_addresses: addresses,
        metadata: json!({
            "operating_system": info.operating_system,
            "physical_cores": info.cpu.physical_cores,
            "virtualization_supported": info.cpu.virtualization_supported,
            "kvm_device_available": info.cpu.kvm_device_available,
            "warnings": info.warnings,
            "detected": metadata,
        }),
        updated_at: chrono::Utc::now().timestamp(),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        cell::Cell,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::unix::fs::PermissionsExt,
    };

    use chrono::Utc;
    use serde_json::json;

    use super::{ensure_guest_tools_socket_directory_mode_with, persist_host_addresses};
    use crate::{
        db::Database,
        host::{CpuInfo, HostAddress, HostInfo, MemoryInfo, NetworkInterfaceInfo},
        models::{IpScope, IpStatus, NewIpAddress, NewIpPool},
    };

    #[test]
    fn precreated_secure_socket_directory_skips_setgid_chmod() {
        let temporary = tempfile::tempdir().unwrap();
        let socket_directory = temporary.path().join("guest-tools");
        std::fs::create_dir(&socket_directory).unwrap();
        std::fs::set_permissions(&socket_directory, std::fs::Permissions::from_mode(0o2770)).unwrap();

        let calls = Cell::new(0_u32);
        ensure_guest_tools_socket_directory_mode_with(&socket_directory, |_| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "RestrictSUIDSGID rejected chmod",
            ))
        })
        .unwrap();
        assert_eq!(calls.get(), 0);

        std::fs::set_permissions(&socket_directory, std::fs::Permissions::from_mode(0o0770)).unwrap();
        let requested_mode = Cell::new(None);
        ensure_guest_tools_socket_directory_mode_with(&socket_directory, |permissions| {
            calls.set(calls.get() + 1);
            requested_mode.set(Some(permissions.mode() & 0o7777));
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(requested_mode.get(), Some(0o2770));
    }

    #[test]
    fn startup_host_detection_keeps_imported_main_address_ownership() {
        let database = Database::open_in_memory().unwrap();
        let pool = database
            .create_ip_pool(&NewIpPool {
                name: "Imported routed range (allocation disabled)".into(),
                cidr: "203.0.113.0/24".into(),
                scope: IpScope::Public,
                gateway: Some("203.0.113.1".into()),
                bridge: None,
                vlan_id: None,
                mtu: 1500,
                enabled: false,
            })
            .unwrap();
        database
            .upsert_ip_address(&NewIpAddress {
                pool_id: Some(pool.id.clone()),
                address: "203.0.113.10".into(),
                prefix_length: 24,
                scope: IpScope::Public,
                status: IpStatus::Main,
                gateway: Some("203.0.113.1".into()),
                reverse_dns: Some("node.example.test".into()),
                metadata: json!({
                    "legacy_import": {
                        "source": "legacy-controller",
                        "ordinary_allocation_disabled": true
                    }
                }),
            })
            .unwrap();
        let host = HostInfo {
            hostname: "node.example.test".into(),
            operating_system: None,
            kernel_version: None,
            architecture: "x86_64".into(),
            cpu: CpuInfo {
                model: None,
                logical_cores: 1,
                physical_cores: 1,
                current_frequency_mhz: None,
                virtualization_supported: true,
                kvm_device_available: true,
            },
            memory: MemoryInfo::default(),
            primary_interface: Some("eno49".into()),
            default_gateway_v4: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            default_gateway_v6: None,
            interfaces: vec![NetworkInterfaceInfo {
                name: "eno49".into(),
                mac_address: None,
                state: "up".into(),
                mtu: Some(1500),
                speed_mbps: None,
                duplex: None,
                is_loopback: false,
                addresses: vec![
                    HostAddress {
                        address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                        prefix_len: 24,
                        scope: "global".into(),
                        is_primary: true,
                    },
                    HostAddress {
                        address: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)),
                        prefix_len: 30,
                        scope: "link".into(),
                        is_primary: false,
                    },
                    HostAddress {
                        address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                        prefix_len: 64,
                        scope: "link".into(),
                        is_primary: false,
                    },
                ],
                rx_bytes: 0,
                tx_bytes: 0,
            }],
            filesystems: Vec::new(),
            listening_tcp_ports: Vec::new(),
            detected_at: Utc::now(),
            warnings: Vec::new(),
        };

        persist_host_addresses(&database, &host).unwrap();

        let address = database.get_ip_address("203.0.113.10").unwrap().unwrap();
        assert_eq!(address.status, IpStatus::Main);
        assert_eq!(address.pool_id.as_deref(), Some(pool.id.as_str()));
        assert_eq!(address.gateway.as_deref(), Some("203.0.113.1"));
        assert_eq!(address.reverse_dns.as_deref(), Some("node.example.test"));
        assert_eq!(
            address.metadata.pointer("/legacy_import/source"),
            Some(&json!("legacy-controller"))
        );
        assert_eq!(address.metadata["detected_host_address"], true);
        assert_eq!(address.metadata["interface"], "eno49");
        assert!(database.get_ip_address("169.254.0.1").unwrap().is_none());
        assert!(database.get_ip_address("fe80::1").unwrap().is_none());
    }
}
