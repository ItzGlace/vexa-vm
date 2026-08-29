//! Local libvirt/KVM backend implemented through `virsh` and `qemu-img`.
//!
//! There is deliberately no shell fallback. Executables are resolved only
//! from fixed system directories, every process receives an argument vector,
//! VM/interface names are validated, image sources are canonicalized beneath
//! configured roots, and writable disks are derived from the storage root.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex, time::timeout};
use tracing::warn;
use uuid::Uuid;

use super::{
    validate_bridge_name, validate_create_request, validate_resize_request, validate_snapshot_name,
    validate_vm_name, CreateVmRequest, Firmware, Hypervisor, HypervisorCapabilities, HypervisorError,
    HypervisorResult, PowerAction, ReinstallVmRequest, ResizeVmRequest, SnapshotInfo, SnapshotRequest,
    VmImage, VmInfo, VmPowerState, VmStats, VncTarget,
};

const GIB: u64 = 1024 * 1024 * 1024;
const MAX_COMMAND_OUTPUT: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LibvirtConfig {
    pub uri: String,
    pub storage_root: PathBuf,
    pub image_roots: Vec<PathBuf>,
    pub default_bridge: String,
    pub command_timeout: Duration,
}

impl LibvirtConfig {
    pub fn new(
        uri: impl Into<String>,
        storage_root: impl Into<PathBuf>,
        image_roots: Vec<PathBuf>,
        default_bridge: impl Into<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            storage_root: storage_root.into(),
            image_roots,
            default_bridge: default_bridge.into(),
            command_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Clone)]
pub struct LibvirtHypervisor {
    config: Arc<LibvirtConfig>,
    virsh: Option<PathBuf>,
    qemu_img: Option<PathBuf>,
    ip: Option<PathBuf>,
    mutation_lock: Arc<Mutex<()>>,
}

#[derive(Debug)]
struct ProcessOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

impl LibvirtHypervisor {
    pub fn new(config: LibvirtConfig) -> HypervisorResult<Self> {
        validate_uri(&config.uri)?;
        validate_bridge_name(&config.default_bridge)?;
        if !config.storage_root.is_absolute() {
            return Err(HypervisorError::InvalidInput(
                "libvirt storage root must be an absolute path".into(),
            ));
        }
        if config.command_timeout < Duration::from_secs(5) {
            return Err(HypervisorError::InvalidInput(
                "libvirt command timeout cannot be lower than five seconds".into(),
            ));
        }
        for root in &config.image_roots {
            if !root.is_absolute() {
                return Err(HypervisorError::InvalidInput(
                    "every allowed image root must be an absolute path".into(),
                ));
            }
        }
        Ok(Self {
            config: Arc::new(config),
            virsh: find_binary("virsh"),
            qemu_img: find_binary("qemu-img"),
            ip: find_binary("ip"),
            mutation_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn installed() -> bool {
        find_binary("virsh").is_some() && find_binary("qemu-img").is_some()
    }

    async fn ensure_domain(&self, name: &str) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        let output = self.virsh_raw("inspect-domain", &["dominfo", name]).await?;
        if output.success {
            return Ok(());
        }
        if looks_like_missing_domain(&output.stderr) {
            return Err(HypervisorError::NotFound(name.to_owned()));
        }
        Err(command_failure("inspect-domain", &output.stderr))
    }

    async fn domain_exists(&self, name: &str) -> HypervisorResult<bool> {
        validate_vm_name(name)?;
        let output = self.virsh_raw("inspect-domain", &["dominfo", name]).await?;
        if output.success {
            Ok(true)
        } else if looks_like_missing_domain(&output.stderr) {
            Ok(false)
        } else {
            Err(command_failure("inspect-domain", &output.stderr))
        }
    }

    async fn virsh(&self, operation: &str, args: &[&str]) -> HypervisorResult<String> {
        let output = self.virsh_raw(operation, args).await?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(command_failure(operation, &output.stderr))
        }
    }

    async fn virsh_owned(&self, operation: &str, args: &[String]) -> HypervisorResult<String> {
        let references: Vec<_> = args.iter().map(String::as_str).collect();
        self.virsh(operation, &references).await
    }

    async fn virsh_raw(&self, operation: &str, args: &[&str]) -> HypervisorResult<ProcessOutput> {
        let program = self
            .virsh
            .as_deref()
            .ok_or_else(|| HypervisorError::BackendUnavailable("/usr/bin/virsh is not installed".into()))?;
        let mut command = Command::new(program);
        command
            .arg("--connect")
            .arg(&self.config.uri)
            .args(args)
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        run_command(command, operation, self.config.command_timeout).await
    }

    async fn virsh_with_input(
        &self,
        operation: &str,
        args: &[&str],
        input: &[u8],
    ) -> HypervisorResult<String> {
        if input.len() > 1024 * 1024 {
            return Err(HypervisorError::InvalidInput(
                "generated libvirt XML exceeded one MiB".into(),
            ));
        }
        let program = self
            .virsh
            .as_deref()
            .ok_or_else(|| HypervisorError::BackendUnavailable("/usr/bin/virsh is not installed".into()))?;
        let mut command = Command::new(program);
        command
            .arg("--connect")
            .arg(&self.config.uri)
            .args(args)
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            HypervisorError::BackendUnavailable("could not open virsh standard input".into())
        })?;
        stdin.write_all(input).await?;
        drop(stdin);
        let output = timeout(self.config.command_timeout, child.wait_with_output())
            .await
            .map_err(|_| HypervisorError::Timeout(operation.into()))??;
        let output = checked_output(output.status.success(), output.stdout, output.stderr)?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(command_failure(operation, &output.stderr))
        }
    }

    /// Run qemu-agent-command through virsh's interactive stdin. Keeping the
    /// serialized command off argv prevents RouterOS bootstrap passwords from
    /// being exposed in transient process listings.
    async fn qemu_agent_command_private(&self, name: &str, command: &Value) -> HypervisorResult<Value> {
        validate_vm_name(name)?;
        let encoded = serde_json::to_string(command).map_err(|error| {
            HypervisorError::InvalidInput(format!("guest-agent command is not valid JSON: {error}"))
        })?;
        if encoded.len() > 1024 * 1024 || encoded.contains(['\n', '\r', '\'']) {
            return Err(HypervisorError::InvalidInput(
                "guest-agent command exceeded the safe interactive command envelope".into(),
            ));
        }
        let program = self
            .virsh
            .as_deref()
            .ok_or_else(|| HypervisorError::BackendUnavailable("/usr/bin/virsh is not installed".into()))?;
        let mut child = Command::new(program)
            .arg("--quiet")
            .arg("--connect")
            .arg(&self.config.uri)
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            HypervisorError::BackendUnavailable("could not open virsh standard input".into())
        })?;
        stdin
            .write_all(format!("qemu-agent-command {name} '{encoded}'\nquit\n").as_bytes())
            .await?;
        drop(stdin);
        let output = timeout(self.config.command_timeout, child.wait_with_output())
            .await
            .map_err(|_| HypervisorError::Timeout("guest-agent-command".into()))??;
        let output = checked_output(output.status.success(), output.stdout, output.stderr)?;
        if !output.success {
            return Err(command_failure("guest-agent-command", &output.stderr));
        }
        parse_qga_response(&output.stdout)
    }

    async fn qemu_img(&self, operation: &str, args: &[String]) -> HypervisorResult<String> {
        let program = self.qemu_img.as_deref().ok_or_else(|| {
            HypervisorError::BackendUnavailable("/usr/bin/qemu-img is not installed".into())
        })?;
        let mut command = Command::new(program);
        command
            .args(args)
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let output = run_command(command, operation, self.config.command_timeout).await?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(command_failure(operation, &output.stderr))
        }
    }

    async fn ip(&self, operation: &str, args: &[&str]) -> HypervisorResult<String> {
        let program = self
            .ip
            .as_deref()
            .ok_or_else(|| HypervisorError::BackendUnavailable("/usr/sbin/ip is not installed".into()))?;
        let mut command = Command::new(program);
        command
            .args(args)
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let output = run_command(command, operation, self.config.command_timeout).await?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(command_failure(operation, &output.stderr))
        }
    }

    async fn storage_root(&self) -> HypervisorResult<PathBuf> {
        tokio::fs::create_dir_all(&self.config.storage_root).await?;
        let root = tokio::fs::canonicalize(&self.config.storage_root).await?;
        if !root.is_dir() {
            return Err(HypervisorError::InvalidInput(
                "configured VM storage root is not a directory".into(),
            ));
        }
        Ok(root)
    }

    async fn managed_disk_path(&self, name: &str) -> HypervisorResult<PathBuf> {
        validate_vm_name(name)?;
        Ok(self.storage_root().await?.join(format!("{name}.qcow2")))
    }

    async fn validate_source_path(&self, source: &Path) -> HypervisorResult<PathBuf> {
        if !source.is_absolute() {
            return Err(HypervisorError::InvalidInput(
                "image source paths must be absolute".into(),
            ));
        }
        let canonical = tokio::fs::canonicalize(source).await.map_err(|_| {
            HypervisorError::InvalidInput(format!("image source '{}' does not exist", source.display()))
        })?;
        let metadata = tokio::fs::metadata(&canonical).await?;
        if !metadata.is_file() {
            return Err(HypervisorError::InvalidInput(
                "image source must be a regular file".into(),
            ));
        }

        let mut allowed = canonical.starts_with(self.storage_root().await?);
        for root in &self.config.image_roots {
            let Ok(canonical_root) = tokio::fs::canonicalize(root).await else {
                continue;
            };
            if canonical.starts_with(canonical_root) {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(HypervisorError::InvalidInput(format!(
                "image source '{}' is outside configured image roots",
                canonical.display()
            )));
        }
        Ok(canonical)
    }

    async fn validate_managed_existing_disk(&self, path: &Path) -> HypervisorResult<PathBuf> {
        let canonical = tokio::fs::canonicalize(path).await?;
        if !canonical.starts_with(self.storage_root().await?) {
            return Err(HypervisorError::InvalidInput(
                "refusing to modify a disk outside the managed storage root".into(),
            ));
        }
        if !tokio::fs::metadata(&canonical).await?.is_file() {
            return Err(HypervisorError::InvalidInput(
                "managed VM disk is not a regular file".into(),
            ));
        }
        Ok(canonical)
    }

    /// Resolve a disk before destructive cleanup. A partially provisioned
    /// domain may legitimately point at a managed file that has already been
    /// removed; in that case it is still safe to undefine the domain, provided
    /// the existing parent resolves beneath the configured storage root.
    async fn managed_disk_for_deletion(&self, path: &Path) -> HypervisorResult<Option<PathBuf>> {
        match self.validate_managed_existing_disk(path).await {
            Ok(path) => Ok(Some(path)),
            Err(HypervisorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                if !path.is_absolute() {
                    return Err(HypervisorError::InvalidInput(
                        "managed VM disk path must be absolute".into(),
                    ));
                }
                // A dangling symlink is not equivalent to a missing managed
                // disk: its future target could change after validation.
                match tokio::fs::symlink_metadata(path).await {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(HypervisorError::InvalidInput(
                            "refusing to remove a managed disk through a dangling symlink".into(),
                        ));
                    }
                    Ok(_) => {
                        return Err(HypervisorError::InvalidInput(
                            "managed VM disk could not be resolved safely".into(),
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let parent = path.parent().ok_or_else(|| {
                    HypervisorError::InvalidInput("managed VM disk has no parent directory".into())
                })?;
                let canonical_parent = tokio::fs::canonicalize(parent).await?;
                if !canonical_parent.starts_with(self.storage_root().await?) {
                    return Err(HypervisorError::InvalidInput(
                        "refusing to clean up a disk outside the managed storage root".into(),
                    ));
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn ensure_new_disk_target(&self, path: &Path) -> HypervisorResult<()> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(HypervisorError::Conflict(format!(
                "refusing to replace disk symlink '{}'",
                path.display()
            ))),
            Ok(_) => Err(HypervisorError::Conflict(format!(
                "disk '{}' already exists",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn create_disk(&self, image: &VmImage, target: &Path, disk_gib: u64) -> HypervisorResult<()> {
        self.ensure_new_disk_target(target).await?;
        let target = utf8_path(target)?;
        let size = format!("{disk_gib}G");
        let args = match image {
            VmImage::Qcow2 { path } | VmImage::Raw { path } | VmImage::ApplianceRaw { path } => {
                let source = self.validate_source_path(path).await?;
                vec![
                    "create".into(),
                    "-f".into(),
                    "qcow2".into(),
                    "-F".into(),
                    image.backing_format().unwrap_or("qcow2").into(),
                    "-b".into(),
                    utf8_path(&source)?,
                    target,
                    size,
                ]
            }
            VmImage::InstallerIso { path } | VmImage::UnattendedWindowsIso { path, .. } => {
                self.validate_source_path(path).await?;
                vec!["create".into(), "-f".into(), "qcow2".into(), target, size]
            }
            VmImage::Blank => {
                vec!["create".into(), "-f".into(), "qcow2".into(), target, size]
            }
        };
        self.qemu_img("create-disk", &args).await?;
        Ok(())
    }

    async fn build_domain_xml(
        &self,
        request: &CreateVmRequest,
        disk_path: &Path,
    ) -> HypervisorResult<String> {
        let disk_path = xml_escape(&utf8_path(disk_path)?);
        let interface = if let Some(tap_name) = request.tap_name.as_deref() {
            validate_bridge_name(tap_name)?;
            format!(
                "<interface type='ethernet'><mac address='{{mac}}'/><target dev='{}' managed='no'/><model type='virtio'/>{{bandwidth}}</interface>",
                xml_escape(tap_name),
            )
        } else {
            let bridge = request.bridge.as_deref().unwrap_or(&self.config.default_bridge);
            validate_bridge_name(bridge)?;
            format!(
                "<interface type='bridge'><mac address='{{mac}}'/><source bridge='{}'/><target dev='{}'/><model type='virtio'/>{{bandwidth}}</interface>",
                xml_escape(bridge),
                xml_escape(&stable_tap_name(&request.mac_address)?),
            )
        };
        let mac = xml_escape(&request.mac_address.to_ascii_lowercase());
        let name = xml_escape(&request.name);
        let firmware = if request.firmware == Firmware::Uefi {
            " firmware='efi'"
        } else {
            ""
        };
        // QEMU exposes the legacy i440FX family through its stable `pc`
        // alias; `i440fx` is the public API/storage name used by Vexa VM.
        let machine_type = qemu_machine_type(&request.machine_type)?;

        let installer = if request.image.is_installer() {
            let path = request
                .image
                .path()
                .expect("installer image always has a source path");
            let source = self.validate_source_path(path).await?;
            format!(
                "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{}'/><target dev='sdb' bus='sata'/><readonly/></disk>",
                xml_escape(&utf8_path(&source)?)
            )
        } else {
            String::new()
        };
        let driver_media = if let Some(path) = request.image.driver_iso() {
            let source = self.validate_source_path(path).await?;
            format!(
                "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{}'/><target dev='sdd' bus='sata'/><readonly/></disk>",
                xml_escape(&utf8_path(&source)?)
            )
        } else {
            String::new()
        };
        let cloud_init = if let Some(path) = &request.cloud_init_iso {
            let source = self.validate_source_path(path).await?;
            let target = if request.image.is_installer() {
                "sdc"
            } else {
                "sdb"
            };
            format!(
                "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{}'/><target dev='{target}' bus='sata'/><readonly/></disk>",
                xml_escape(&utf8_path(&source)?)
            )
        } else {
            String::new()
        };
        let bandwidth = request.network_limit_mbps.map_or_else(String::new, |mbps| {
            let kilobytes_per_second = mbps.saturating_mul(125);
            format!(
                "<bandwidth><inbound average='{kilobytes_per_second}'/><outbound average='{kilobytes_per_second}'/></bandwidth>"
            )
        });
        let guest_tools_channel = match request.guest_tools_socket.as_deref() {
            Some(path) => guest_tools_channel_xml(path)?,
            None => String::new(),
        };
        // Windows Setup and RouterOS CHR both provide a reliable legacy VGA
        // console before vendor drivers are installed. virtio-gpu can leave
        // their VNC installer console blank during the critical first boot.
        let video_model =
            if request.image.is_unattended_windows() || request.image.is_preconfigured_appliance() {
                "vga"
            } else {
                "virtio"
            };

        let interface = interface
            .replace("{mac}", &mac)
            .replace("{bandwidth}", &bandwidth);
        Ok(format!(
            "<domain type='kvm'>\
             <name>{name}</name>\
             <memory unit='MiB'>{memory}</memory>\
             <currentMemory unit='MiB'>{initial_memory}</currentMemory>\
             <vcpu placement='static'>{vcpus}</vcpu>\
             <cpu mode='host-passthrough' check='none'/>\
             <os{firmware}><type arch='x86_64' machine='{machine_type}'>hvm</type><boot dev='hd'/><boot dev='cdrom'/></os>\
             <features><acpi/><apic/></features>\
             <clock offset='utc'/>\
             <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>restart</on_crash>\
             <devices>\
               <controller type='scsi' model='virtio-scsi'/>\
               <disk type='file' device='disk'><driver name='qemu' type='qcow2' cache='none' io='native' discard='unmap'/><source file='{disk_path}'/><target dev='vda' bus='virtio'/></disk>\
               {installer}{cloud_init}{driver_media}\
               {interface}\
               <serial type='pty'><target port='0'/></serial><console type='pty'><target type='serial' port='0'/></console>\
               <channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>\
               {guest_tools_channel}\
               <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'><listen type='address' address='127.0.0.1'/></graphics>\
               <video><model type='{video_model}' heads='1' primary='yes'/></video>\
               <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>\
               <memballoon model='virtio'><stats period='5'/></memballoon>\
             </devices>\
             </domain>",
            memory = request.memory_mib,
            initial_memory = request.initial_memory_mib.unwrap_or(request.memory_mib),
            vcpus = request.vcpus,
        ))
    }

    async fn inspect_vm(&self, name: &str) -> HypervisorResult<VmInfo> {
        self.ensure_domain(name).await?;
        let dominfo = self.virsh("inspect-domain", &["dominfo", name]).await?;
        let fields = parse_key_values(&dominfo);
        let state = fields
            .get("state")
            .map(String::as_str)
            .map(VmPowerState::from)
            .unwrap_or(VmPowerState::Unknown);
        let uuid = fields.get("uuid").and_then(|value| Uuid::parse_str(value).ok());
        let vcpus = fields
            .get("cpu(s)")
            .and_then(|value| first_u64(value))
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let memory_mib = fields
            .get("max memory")
            .and_then(|value| first_u64(value))
            .map(|kib| kib / 1024)
            .unwrap_or(0);
        let autostart = fields
            .get("autostart")
            .is_some_and(|value| value.eq_ignore_ascii_case("enable"));
        let persistent = fields
            .get("persistent")
            .map(|value| value.eq_ignore_ascii_case("yes"))
            .unwrap_or(true);

        let (disk_target, disk_path) = self.primary_disk(name).await?;
        let disk_bytes = if let Some(target) = disk_target.as_deref() {
            self.disk_capacity(name, target).await.unwrap_or(0)
        } else {
            0
        };
        let (interface_name, interface_type, bridge, mac_address) =
            self.primary_network(name).await.unwrap_or_default();

        Ok(VmInfo {
            name: name.to_owned(),
            uuid,
            state,
            vcpus,
            memory_mib,
            disk_bytes,
            disk_path,
            interface_name,
            interface_type,
            bridge,
            mac_address,
            autostart,
            persistent,
        })
    }

    async fn primary_disk(&self, name: &str) -> HypervisorResult<(Option<String>, Option<PathBuf>)> {
        let output = self
            .virsh("inspect-disks", &["domblklist", name, "--details"])
            .await?;
        for line in output.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 4 && fields[1] == "disk" {
                return Ok((
                    Some(fields[2].to_owned()),
                    Some(PathBuf::from(fields[3..].join(" "))),
                ));
            }
        }
        Ok((None, None))
    }

    async fn disk_capacity(&self, name: &str, target: &str) -> HypervisorResult<u64> {
        let output = self
            // `domblkinfo` reports byte values by default.  The `--bytes`
            // flag belongs to other virsh subcommands and is rejected by
            // libvirt 8.x, which previously caused active VM capacity to be
            // reported as zero.
            .virsh("inspect-disk-capacity", &["domblkinfo", name, target])
            .await?;
        Ok(parse_key_values(&output)
            .get("capacity")
            .and_then(|value| first_u64(value))
            .unwrap_or(0))
    }

    async fn primary_network(
        &self,
        name: &str,
    ) -> HypervisorResult<(Option<String>, Option<String>, Option<String>, Option<String>)> {
        let output = self.virsh("inspect-network", &["domiflist", name]).await?;
        for line in output.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 5 && !matches!(fields[0], "Interface" | "---") {
                return Ok((
                    (fields[0] != "-").then(|| fields[0].into()),
                    (fields[1] != "-").then(|| fields[1].into()),
                    Some(fields[2].into()),
                    Some(fields[4].into()),
                ));
            }
        }
        Ok((None, None, None, None))
    }

    async fn attach_or_change_cdrom(&self, name: &str, target: &str, source: &Path) -> HypervisorResult<()> {
        let source = utf8_path(source)?;
        // Reinstalling an automatic guest replaces its existing cloud-init
        // CD-ROM.  `--insert` only works with an empty tray; `--update` is
        // required when the old seed is still attached.
        let update_args = vec![
            "change-media".into(),
            name.into(),
            target.into(),
            source.clone(),
            "--update".into(),
            "--config".into(),
        ];
        if self
            .virsh_owned("replace-install-media", &update_args)
            .await
            .is_ok()
        {
            return Ok(());
        }
        let insert_args = vec![
            "change-media".into(),
            name.into(),
            target.into(),
            source.clone(),
            "--insert".into(),
            "--config".into(),
        ];
        if self
            .virsh_owned("insert-install-media", &insert_args)
            .await
            .is_ok()
        {
            return Ok(());
        }
        self.virsh_owned(
            "attach-install-media",
            &[
                "attach-disk".into(),
                name.into(),
                source,
                target.into(),
                "--type".into(),
                "cdrom".into(),
                "--mode".into(),
                "readonly".into(),
                "--config".into(),
            ],
        )
        .await?;
        Ok(())
    }

    async fn remove_snapshot_metadata(&self, name: &str) {
        let Ok(snapshots) = self.list_snapshots(name).await else {
            return;
        };
        for snapshot in snapshots {
            let _ = self
                .virsh_owned(
                    "remove-old-snapshot-metadata",
                    &[
                        "snapshot-delete".into(),
                        name.into(),
                        snapshot.name,
                        "--metadata".into(),
                    ],
                )
                .await;
        }
    }
}

#[async_trait]
impl Hypervisor for LibvirtHypervisor {
    async fn capabilities(&self) -> HypervisorResult<HypervisorCapabilities> {
        let kvm_device_available = Path::new("/dev/kvm").exists();
        let Some(_) = self.virsh.as_ref() else {
            return Ok(HypervisorCapabilities {
                backend: "libvirt".into(),
                available: false,
                uri: Some(self.config.uri.clone()),
                hypervisor_version: None,
                emulator_version: None,
                kvm_device_available,
                supports_live_resize: false,
                supports_snapshots: false,
                supports_vnc: false,
                detail: Some("virsh is not installed in a standard system directory".into()),
            });
        };

        let version = self
            .virsh_raw("probe-libvirt", &["version"])
            .await
            .ok()
            .filter(|output| output.success);
        let emulator_version = if let Some(program) = self.qemu_img.as_deref() {
            let mut command = Command::new(program);
            command
                .arg("--version")
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            run_command(command, "probe-qemu-img", self.config.command_timeout)
                .await
                .ok()
                .filter(|output| output.success)
                .and_then(|output| output.stdout.lines().next().map(ToOwned::to_owned))
        } else {
            None
        };
        let available = version.is_some() && self.qemu_img.is_some() && kvm_device_available;
        Ok(HypervisorCapabilities {
            backend: "libvirt".into(),
            available,
            uri: Some(self.config.uri.clone()),
            hypervisor_version: version
                .as_ref()
                .and_then(|output| output.stdout.lines().next().map(ToOwned::to_owned)),
            emulator_version,
            kvm_device_available,
            supports_live_resize: available,
            supports_snapshots: available,
            supports_vnc: available,
            detail: (!available).then(|| {
                if !kvm_device_available {
                    "/dev/kvm is unavailable to the Vexa-VM service".to_owned()
                } else {
                    "libvirt could not be reached or qemu-img is not installed".to_owned()
                }
            }),
        })
    }

    async fn list_vms(&self) -> HypervisorResult<Vec<VmInfo>> {
        let output = self.virsh("list-domains", &["list", "--all", "--name"]).await?;
        let mut result = Vec::new();
        for name in output.lines().map(str::trim).filter(|name| !name.is_empty()) {
            if validate_vm_name(name).is_err() {
                warn!(domain = name, "skipping libvirt domain with an unsafe name");
                continue;
            }
            match self.inspect_vm(name).await {
                Ok(info) => result.push(info),
                Err(error) => {
                    warn!(domain = name, error = %error, "could not inspect libvirt domain");
                }
            }
        }
        result.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(result)
    }

    async fn get_vm(&self, name: &str) -> HypervisorResult<VmInfo> {
        self.inspect_vm(name).await
    }

    async fn create_vm(&self, request: CreateVmRequest) -> HypervisorResult<VmInfo> {
        validate_create_request(&request)?;
        let _guard = self.mutation_lock.lock().await;
        if self.domain_exists(&request.name).await? {
            return Err(HypervisorError::Conflict(format!(
                "VM '{}' already exists",
                request.name
            )));
        }

        let disk_path = self.managed_disk_path(&request.name).await?;
        self.create_disk(&request.image, &disk_path, request.disk_gib)
            .await?;
        let xml = match self.build_domain_xml(&request, &disk_path).await {
            Ok(xml) => xml,
            Err(error) => {
                let _ = tokio::fs::remove_file(&disk_path).await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .virsh_with_input("define-domain", &["define", "/dev/stdin"], xml.as_bytes())
            .await
        {
            let _ = tokio::fs::remove_file(&disk_path).await;
            return Err(error);
        }

        let mut operation_error = None;
        if request.autostart {
            if let Err(error) = self
                .virsh("enable-autostart", &["autostart", &request.name])
                .await
            {
                operation_error = Some(error);
            }
        }
        if operation_error.is_none() && request.start {
            if let Err(error) = self.virsh("start-domain", &["start", &request.name]).await {
                operation_error = Some(error);
            }
        }
        if let Some(error) = operation_error {
            if self
                .virsh("rollback-domain", &["undefine", &request.name, "--nvram"])
                .await
                .is_err()
            {
                let _ = self.virsh("rollback-domain", &["undefine", &request.name]).await;
            }
            let _ = tokio::fs::remove_file(&disk_path).await;
            return Err(error);
        }
        let mut info = self.inspect_vm(&request.name).await?;
        if info.interface_name.is_none() {
            if let Some(tap_name) = request.tap_name.as_deref() {
                info.interface_name = Some(tap_name.to_owned());
                info.interface_type = Some("ethernet".into());
            } else {
                info.interface_name = Some(stable_tap_name(&request.mac_address)?);
                info.interface_type = Some("bridge".into());
                info.bridge = Some(
                    request
                        .bridge
                        .clone()
                        .unwrap_or_else(|| self.config.default_bridge.clone()),
                );
            }
        }
        Ok(info)
    }

    async fn delete_vm(&self, name: &str, delete_storage: bool) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        let _guard = self.mutation_lock.lock().await;
        let vm = self.inspect_vm(name).await?;
        let disk_to_delete = if delete_storage {
            match vm.disk_path.as_deref() {
                Some(path) => self.managed_disk_for_deletion(path).await?,
                None => None,
            }
        } else {
            None
        };
        if vm.state.is_active() {
            self.virsh("force-off-domain", &["destroy", name]).await?;
        }
        let full_undefine = self
            .virsh(
                "undefine-domain",
                &[
                    "undefine",
                    name,
                    "--managed-save",
                    "--snapshots-metadata",
                    "--nvram",
                ],
            )
            .await;
        if full_undefine.is_err() && self.domain_exists(name).await? {
            self.virsh("undefine-domain", &["undefine", name]).await?;
        }

        if let Some(path) = disk_to_delete {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    async fn power(&self, name: &str, action: PowerAction) -> HypervisorResult<VmInfo> {
        validate_vm_name(name)?;
        let _guard = self.mutation_lock.lock().await;
        let current = self.inspect_vm(name).await?;
        match action {
            PowerAction::Start => {
                if current.state == VmPowerState::ShutOff {
                    self.virsh("start-domain", &["start", name]).await?;
                } else if current.state == VmPowerState::Paused {
                    self.virsh("resume-domain", &["resume", name]).await?;
                }
            }
            PowerAction::Shutdown => {
                if current.state.is_active() {
                    self.virsh("shutdown-domain", &["shutdown", name]).await?;
                }
            }
            PowerAction::ForceOff => {
                if current.state.is_active() {
                    self.virsh("force-off-domain", &["destroy", name]).await?;
                }
            }
            PowerAction::Reboot => {
                if !current.state.is_active() {
                    return Err(HypervisorError::Conflict(
                        "a stopped VM cannot be rebooted; start it instead".into(),
                    ));
                }
                self.virsh("reboot-domain", &["reboot", name]).await?;
            }
            PowerAction::Reset => {
                if !current.state.is_active() {
                    return Err(HypervisorError::Conflict(
                        "a stopped VM cannot be reset; start it instead".into(),
                    ));
                }
                self.virsh("reset-domain", &["reset", name]).await?;
            }
            PowerAction::Suspend => {
                if current.state == VmPowerState::Running {
                    self.virsh("suspend-domain", &["suspend", name]).await?;
                } else if current.state != VmPowerState::Paused {
                    return Err(HypervisorError::Conflict(
                        "only a running VM can be suspended".into(),
                    ));
                }
            }
            PowerAction::Resume => {
                if current.state == VmPowerState::Paused {
                    self.virsh("resume-domain", &["resume", name]).await?;
                } else if current.state != VmPowerState::Running {
                    return Err(HypervisorError::Conflict(
                        "only a paused VM can be resumed".into(),
                    ));
                }
            }
        }
        self.inspect_vm(name).await
    }

    async fn acknowledge_install_media_boot(&self, name: &str) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        if !self.inspect_vm(name).await?.state.is_active() {
            return Err(HypervisorError::Conflict(
                "installer boot acknowledgement requires a running VM".into(),
            ));
        }

        // Microsoft UEFI installation media intentionally pauses at "Press
        // any key to boot from CD or DVD". Cover the bounded firmware window
        // with short Enter pulses. Once bootmgr starts loading files these
        // events are ignored, and the sequence ends before Windows Setup can
        // expose an interactive control.
        for _ in 0..12 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            self.virsh(
                "acknowledge-installer-boot",
                &["send-key", name, "--holdtime", "50", "KEY_ENTER"],
            )
            .await?;
        }
        Ok(())
    }

    async fn resize(&self, name: &str, request: ResizeVmRequest) -> HypervisorResult<VmInfo> {
        validate_vm_name(name)?;
        validate_resize_request(&request)?;
        let _guard = self.mutation_lock.lock().await;
        let current = self.inspect_vm(name).await?;
        let active = current.state.is_active();

        if let Some(vcpus) = request.vcpus {
            let value = vcpus.to_string();
            let increase = vcpus >= current.vcpus;
            if increase {
                self.virsh(
                    "set-maximum-vcpus",
                    &["setvcpus", name, &value, "--maximum", "--config"],
                )
                .await?;
            }
            self.virsh("set-vcpus", &["setvcpus", name, &value, "--config"])
                .await?;
            if !increase {
                self.virsh(
                    "set-maximum-vcpus",
                    &["setvcpus", name, &value, "--maximum", "--config"],
                )
                .await?;
            }
            if active {
                let _ = self
                    .virsh("set-live-vcpus", &["setvcpus", name, &value, "--live"])
                    .await;
            }
        }

        if let Some(memory_mib) = request.memory_mib {
            let value = format!("{memory_mib}MiB");
            let increase = memory_mib >= current.memory_mib;
            if increase {
                self.virsh("set-maximum-memory", &["setmaxmem", name, &value, "--config"])
                    .await?;
            }
            self.virsh("set-memory", &["setmem", name, &value, "--config"])
                .await?;
            if !increase {
                self.virsh("set-maximum-memory", &["setmaxmem", name, &value, "--config"])
                    .await?;
            }
            if active {
                let _ = self
                    .virsh("set-live-memory", &["setmem", name, &value, "--live"])
                    .await;
            }
        }

        if let Some(disk_gib) = request.disk_gib {
            let new_bytes = disk_gib.saturating_mul(GIB);
            let (target, disk_path) = self.primary_disk(name).await?;
            let target = target
                .ok_or_else(|| HypervisorError::InvalidResponse("VM has no primary disk target".into()))?;
            let current_bytes = self.disk_capacity(name, &target).await?;
            if new_bytes < current_bytes {
                return Err(HypervisorError::InvalidInput(
                    "disk shrinking is not supported".into(),
                ));
            }
            if new_bytes > current_bytes {
                if active {
                    let size = format!("{disk_gib}G");
                    self.virsh("resize-live-disk", &["blockresize", name, &target, &size])
                        .await?;
                } else {
                    let path = disk_path.ok_or_else(|| {
                        HypervisorError::InvalidResponse("VM has no primary disk path".into())
                    })?;
                    let path = self.validate_managed_existing_disk(&path).await?;
                    self.qemu_img(
                        "resize-offline-disk",
                        &["resize".into(), utf8_path(&path)?, format!("{disk_gib}G")],
                    )
                    .await?;
                }
            }
        }
        if let Some(limit) = request.network_limit_mbps {
            let interface = current
                .mac_address
                .as_deref()
                .ok_or_else(|| HypervisorError::InvalidResponse("VM has no network interface MAC".into()))?;
            let average = limit.map(|mbps| mbps.saturating_mul(125)).unwrap_or(0);
            let inbound = format!("{average},0,0");
            let outbound = inbound.clone();
            self.virsh(
                "set-network-bandwidth",
                &[
                    "domiftune",
                    name,
                    interface,
                    "--inbound",
                    &inbound,
                    "--outbound",
                    &outbound,
                    "--config",
                ],
            )
            .await?;
            if active {
                let _ = self
                    .virsh(
                        "set-live-network-bandwidth",
                        &[
                            "domiftune",
                            name,
                            interface,
                            "--inbound",
                            &inbound,
                            "--outbound",
                            &outbound,
                            "--live",
                        ],
                    )
                    .await;
            }
        }
        self.inspect_vm(name).await
    }

    async fn set_memory_balloon(&self, name: &str, target_mib: u64) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        if !(256..=16 * 1024 * 1024).contains(&target_mib) {
            return Err(HypervisorError::InvalidInput(
                "live balloon target must be between 256 MiB and 16 TiB".into(),
            ));
        }
        let _guard = self.mutation_lock.lock().await;
        let current = self.inspect_vm(name).await?;
        if !current.state.is_active() {
            return Err(HypervisorError::Conflict(
                "memory ballooning requires a running VM".into(),
            ));
        }
        if target_mib > current.memory_mib {
            return Err(HypervisorError::InvalidInput(format!(
                "live balloon target exceeds the VM's {} MiB memory entitlement",
                current.memory_mib
            )));
        }
        let value = format!("{target_mib}MiB");
        self.virsh(
            "set-persistent-memory-balloon",
            &["setmem", name, &value, "--config"],
        )
        .await?;
        self.virsh("set-live-memory-balloon", &["setmem", name, &value, "--live"])
            .await?;
        Ok(())
    }

    async fn reinstall(&self, name: &str, request: ReinstallVmRequest) -> HypervisorResult<VmInfo> {
        validate_vm_name(name)?;
        if !(1..=1024 * 1024).contains(&request.disk_gib) {
            return Err(HypervisorError::InvalidInput(
                "disk capacity must be between 1 GiB and 1 PiB".into(),
            ));
        }
        if let Some(path) = request.image.path() {
            self.validate_source_path(path).await?;
        }
        if let Some(path) = request.image.driver_iso() {
            self.validate_source_path(path).await?;
        }
        if let Some(path) = request.cloud_init_iso.as_deref() {
            self.validate_source_path(path).await?;
        }

        let _guard = self.mutation_lock.lock().await;
        let current = self.inspect_vm(name).await?;
        let disk_path = current
            .disk_path
            .as_deref()
            .ok_or_else(|| HypervisorError::InvalidResponse("VM has no primary disk".into()))?;
        let disk_path = self.validate_managed_existing_disk(disk_path).await?;
        if current.state.is_active() {
            self.virsh("stop-for-reinstall", &["destroy", name]).await?;
        }
        if let Some(path) = request.guest_tools_socket.as_deref() {
            let domain_xml = self
                .virsh("inspect-guest-tools-channel", &["dumpxml", name])
                .await?;
            if !domain_xml.contains("com.vexa.guest_tools.0") {
                let channel_xml = guest_tools_channel_xml(path)?;
                self.virsh_with_input(
                    "attach-guest-tools-channel",
                    &["attach-device", name, "/dev/stdin", "--config"],
                    channel_xml.as_bytes(),
                )
                .await?;
            }
        }

        let suffix = Uuid::new_v4().simple().to_string();
        let root = self.storage_root().await?;
        let new_disk = root.join(format!(".{name}.reinstall-{suffix}.qcow2"));
        let backup_disk = root.join(format!(".{name}.backup-{suffix}.qcow2"));
        self.create_disk(&request.image, &new_disk, request.disk_gib)
            .await?;
        self.remove_snapshot_metadata(name).await;

        if let Err(error) = tokio::fs::rename(&disk_path, &backup_disk).await {
            let _ = tokio::fs::remove_file(&new_disk).await;
            return Err(error.into());
        }
        if let Err(error) = tokio::fs::rename(&new_disk, &disk_path).await {
            let _ = tokio::fs::rename(&backup_disk, &disk_path).await;
            let _ = tokio::fs::remove_file(&new_disk).await;
            return Err(error.into());
        }

        let media_result = async {
            if request.image.is_installer() {
                let path = request
                    .image
                    .path()
                    .expect("installer image always has a source path");
                let source = self.validate_source_path(path).await?;
                self.attach_or_change_cdrom(name, "sdb", &source).await?;
            }
            if let Some(path) = request.cloud_init_iso.as_deref() {
                let source = self.validate_source_path(path).await?;
                let target = if request.image.is_installer() {
                    "sdc"
                } else {
                    "sdb"
                };
                self.attach_or_change_cdrom(name, target, &source).await?;
            }
            if let Some(path) = request.image.driver_iso() {
                let source = self.validate_source_path(path).await?;
                self.attach_or_change_cdrom(name, "sdd", &source).await?;
            }
            if request.start {
                self.virsh("start-reinstalled-domain", &["start", name]).await?;
            }
            Ok::<(), HypervisorError>(())
        }
        .await;

        if let Err(error) = media_result {
            let _ = self.virsh("stop-reinstall-rollback", &["destroy", name]).await;
            let failed_disk = root.join(format!(".{name}.failed-{suffix}.qcow2"));
            let _ = tokio::fs::rename(&disk_path, &failed_disk).await;
            let _ = tokio::fs::rename(&backup_disk, &disk_path).await;
            let _ = tokio::fs::remove_file(&failed_disk).await;
            if current.state.is_active() {
                let _ = self.virsh("restart-after-rollback", &["start", name]).await;
            }
            return Err(error);
        }

        tokio::fs::remove_file(&backup_disk).await?;
        self.inspect_vm(name).await
    }

    async fn detach_seed_media(&self, name: &str, expected_source: &Path) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        let expected_source = self.validate_source_path(expected_source).await?;
        let _guard = self.mutation_lock.lock().await;
        let active = self.inspect_vm(name).await?.state.is_active();

        // Inspect both representations before mutating either. The source
        // match, rather than a hard-coded `sdb`, prevents an installer or an
        // operator-attached CD-ROM from being ejected accidentally.
        let live_target = if active {
            let output = self
                .virsh("inspect-live-seed-media", &["domblklist", name, "--details"])
                .await?;
            seed_cdrom_target(&output, &expected_source)?
        } else {
            None
        };
        let persistent_output = self
            .virsh(
                "inspect-persistent-seed-media",
                &["domblklist", name, "--inactive", "--details"],
            )
            .await?;
        let persistent_target = seed_cdrom_target(&persistent_output, &expected_source)?;

        if let Some(target) = live_target.as_deref() {
            self.virsh(
                "eject-live-seed-media",
                &["change-media", name, target, "--eject", "--live"],
            )
            .await?;
        }
        if let Some(target) = persistent_target.as_deref() {
            self.virsh(
                "eject-persistent-seed-media",
                &["change-media", name, target, "--eject", "--config"],
            )
            .await?;
        }

        // Do not allow the caller to unlink the seed until libvirt confirms
        // that neither the running guest nor its next boot references it.
        if active {
            let output = self
                .virsh("verify-live-seed-eject", &["domblklist", name, "--details"])
                .await?;
            if seed_cdrom_target(&output, &expected_source)?.is_some() {
                return Err(HypervisorError::Conflict(
                    "libvirt kept the provisioning seed attached to the running VM".into(),
                ));
            }
        }
        let output = self
            .virsh(
                "verify-persistent-seed-eject",
                &["domblklist", name, "--inactive", "--details"],
            )
            .await?;
        if seed_cdrom_target(&output, &expected_source)?.is_some() {
            return Err(HypervisorError::Conflict(
                "libvirt kept the provisioning seed in the persistent VM definition".into(),
            ));
        }
        Ok(())
    }

    async fn stats(&self, name: &str) -> HypervisorResult<VmStats> {
        validate_vm_name(name)?;
        // `virsh domstats <name>` already returns a precise not-found error.
        // Avoid a separate domain-existence subprocess on every sample.
        let output = self
            .virsh(
                "domain-stats",
                &[
                    "domstats",
                    "--cpu-total",
                    "--balloon",
                    "--block",
                    "--interface",
                    name,
                ],
            )
            .await?;
        let values = parse_equals_values(&output);
        let (memory_used_bytes, memory_total_bytes) = parse_domain_memory(&values);
        let sum_prefix = |prefix: &str, suffix: &str| -> u64 {
            values
                .iter()
                .filter(|(key, _)| key.starts_with(prefix) && key.ends_with(suffix))
                .filter_map(|(_, value)| value.parse::<u64>().ok())
                .sum()
        };
        Ok(VmStats {
            cpu_time_ns: values
                .get("cpu.time")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            memory_current_bytes: memory_used_bytes,
            memory_available_bytes: memory_total_bytes,
            disk_read_bytes: sum_prefix("block.", ".rd.bytes"),
            disk_write_bytes: sum_prefix("block.", ".wr.bytes"),
            network_rx_bytes: sum_prefix("net.", ".rx.bytes"),
            network_tx_bytes: sum_prefix("net.", ".tx.bytes"),
        })
    }

    async fn set_network_enabled(&self, name: &str, enabled: bool) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        let _guard = self.mutation_lock.lock().await;
        let current = self.inspect_vm(name).await?;
        if current.interface_type.as_deref() == Some("ethernet") {
            let interface = current.interface_name.as_deref().ok_or_else(|| {
                HypervisorError::InvalidResponse(
                    "legacy ethernet VM has no persistent target interface".into(),
                )
            })?;
            validate_bridge_name(interface).map_err(|_| {
                HypervisorError::InvalidResponse(
                    "legacy ethernet VM has an invalid persistent target interface".into(),
                )
            })?;
            let tuntaps = self.ip("inspect-persistent-tap", &["tuntap", "show"]).await?;
            validate_persistent_tap(&tuntaps, interface)?;
            let mac = current.mac_address.as_deref().ok_or_else(|| {
                HypervisorError::InvalidResponse("legacy ethernet VM has no network interface MAC".into())
            })?;
            let link_state = if enabled { "up" } else { "down" };
            self.virsh(
                "set-persistent-network-link",
                &["domif-setlink", name, mac, link_state, "--config"],
            )
            .await?;
            if current.state.is_active() {
                self.virsh(
                    "set-live-network-link",
                    &["domif-setlink", name, mac, link_state],
                )
                .await?;
            }
            self.ip(
                "set-persistent-tap-link",
                &[
                    "link",
                    "set",
                    "dev",
                    interface,
                    link_state,
                ],
            )
            .await?;
            return Ok(());
        }
        let interface = current
            .mac_address
            .as_deref()
            .ok_or_else(|| HypervisorError::InvalidResponse("VM has no network interface MAC".into()))?;
        let link_state = if enabled { "up" } else { "down" };
        self.virsh(
            "set-persistent-network-link",
            &["domif-setlink", name, interface, link_state, "--config"],
        )
        .await?;
        if current.state.is_active() {
            self.virsh(
                "set-live-network-link",
                &["domif-setlink", name, interface, link_state],
            )
            .await?;
        }
        Ok(())
    }

    async fn guest_agent_command(&self, name: &str, command: Value) -> HypervisorResult<Value> {
        self.ensure_domain(name).await?;
        self.qemu_agent_command_private(name, &command).await
    }

    async fn create_snapshot(&self, name: &str, request: SnapshotRequest) -> HypervisorResult<SnapshotInfo> {
        validate_vm_name(name)?;
        validate_snapshot_name(&request.name)?;
        if request
            .description
            .as_deref()
            .is_some_and(|description| description.len() > 500 || description.chars().any(char::is_control))
        {
            return Err(HypervisorError::InvalidInput(
                "snapshot description must be at most 500 printable characters".into(),
            ));
        }
        let _guard = self.mutation_lock.lock().await;
        self.ensure_domain(name).await?;
        let mut args = vec!["snapshot-create-as".into(), name.into(), request.name.clone()];
        if let Some(description) = request.description.as_deref() {
            args.push(format!("--description={description}"));
        }
        args.push("--atomic".into());
        self.virsh_owned("create-snapshot", &args).await?;
        Ok(SnapshotInfo {
            name: request.name,
            description: request.description,
            created_at: Some(Utc::now()),
            current: true,
        })
    }

    async fn list_snapshots(&self, name: &str) -> HypervisorResult<Vec<SnapshotInfo>> {
        validate_vm_name(name)?;
        self.ensure_domain(name).await?;
        let output = self
            .virsh("list-snapshots", &["snapshot-list", name, "--name"])
            .await?;
        let current = self
            .virsh("current-snapshot", &["snapshot-current", name, "--name"])
            .await
            .ok()
            .map(|value| value.trim().to_owned());
        let mut snapshots = Vec::new();
        for snapshot in output.lines().map(str::trim).filter(|item| !item.is_empty()) {
            if validate_snapshot_name(snapshot).is_err() {
                continue;
            }
            let xml = self
                .virsh("inspect-snapshot", &["snapshot-dumpxml", name, snapshot])
                .await
                .unwrap_or_default();
            let created_at = xml_tag(&xml, "creationTime")
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0));
            snapshots.push(SnapshotInfo {
                name: snapshot.into(),
                description: xml_tag(&xml, "description").filter(|value| !value.is_empty()),
                created_at,
                current: current.as_deref() == Some(snapshot),
            });
        }
        Ok(snapshots)
    }

    async fn revert_snapshot(&self, name: &str, snapshot: &str) -> HypervisorResult<VmInfo> {
        validate_vm_name(name)?;
        validate_snapshot_name(snapshot)?;
        let _guard = self.mutation_lock.lock().await;
        let current = self.inspect_vm(name).await?;
        let mut args = vec!["snapshot-revert", name, snapshot];
        if current.state.is_active() {
            args.push("--running");
        }
        self.virsh("revert-snapshot", &args).await?;
        self.inspect_vm(name).await
    }

    async fn delete_snapshot(&self, name: &str, snapshot: &str) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        validate_snapshot_name(snapshot)?;
        let _guard = self.mutation_lock.lock().await;
        self.ensure_domain(name).await?;
        self.virsh("delete-snapshot", &["snapshot-delete", name, snapshot])
            .await?;
        Ok(())
    }

    async fn vnc_target(&self, name: &str) -> HypervisorResult<VncTarget> {
        validate_vm_name(name)?;
        let vm = self.inspect_vm(name).await?;
        if !vm.state.is_active() {
            return Err(HypervisorError::Conflict(
                "VNC is available only while the VM is active".into(),
            ));
        }
        let output = self.virsh("locate-vnc", &["vncdisplay", name]).await?;
        parse_vnc_display(output.trim())
    }
}

async fn run_command(
    mut command: Command,
    operation: &str,
    duration: Duration,
) -> HypervisorResult<ProcessOutput> {
    let output = timeout(duration, command.output())
        .await
        .map_err(|_| HypervisorError::Timeout(operation.into()))??;
    checked_output(output.status.success(), output.stdout, output.stderr)
}

fn checked_output(success: bool, stdout: Vec<u8>, stderr: Vec<u8>) -> HypervisorResult<ProcessOutput> {
    if stdout.len() > MAX_COMMAND_OUTPUT || stderr.len() > MAX_COMMAND_OUTPUT {
        return Err(HypervisorError::InvalidResponse(
            "hypervisor command output exceeded two MiB".into(),
        ));
    }
    Ok(ProcessOutput {
        success,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

fn command_failure(operation: &str, stderr: &str) -> HypervisorError {
    HypervisorError::CommandFailed {
        operation: operation.into(),
        message: bounded_message(stderr),
    }
}

fn bounded_message(message: &str) -> String {
    let normalized = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut result: String = normalized.chars().take(500).collect();
    if result.is_empty() {
        result = "command returned a non-zero exit status".into();
    }
    result
}

fn looks_like_missing_domain(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("failed to get domain")
        || normalized.contains("domain not found")
        || normalized.contains("no domain with matching name")
}

fn validate_persistent_tap(output: &str, expected: &str) -> HypervisorResult<()> {
    validate_bridge_name(expected).map_err(|_| {
        HypervisorError::InvalidResponse(
            "legacy ethernet VM has an invalid persistent target interface".into(),
        )
    })?;
    let prefix = format!("{expected}:");
    let matches = output
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.first().copied() == Some(prefix.as_str())).then_some(fields)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].get(1).copied() != Some("tap") || !matches[0].contains(&"persist") {
        return Err(HypervisorError::InvalidResponse(format!(
            "legacy ethernet target '{expected}' is not exactly one persistent TAP"
        )));
    }
    Ok(())
}

fn validate_uri(uri: &str) -> HypervisorResult<()> {
    if !matches!(uri, "qemu:///system" | "qemu:///session") {
        return Err(HypervisorError::InvalidInput(
            "only local qemu:///system and qemu:///session libvirt URIs are allowed".into(),
        ));
    }
    Ok(())
}

fn qemu_machine_type(value: &str) -> HypervisorResult<&'static str> {
    match value {
        "q35" => Ok("q35"),
        // QEMU documents the stable aliases for its i440FX family as
        // `pc-i440fx` and `pc`; `i440fx` itself is the Vexa API name.
        "i440fx" => Ok("pc"),
        _ => Err(HypervisorError::InvalidInput(
            "machine type must be q35 or i440fx".into(),
        )),
    }
}

fn find_binary(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .into_iter()
        .map(|directory| PathBuf::from(directory).join(name))
        .find(|path| path.is_file())
}

fn utf8_path(path: &Path) -> HypervisorResult<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| HypervisorError::InvalidInput("paths must contain valid UTF-8".into()))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn guest_tools_channel_xml(path: &Path) -> HypervisorResult<String> {
    if !path.is_absolute()
        || path.as_os_str().len() > 240
        || path.extension().and_then(|value| value.to_str()) != Some("sock")
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(HypervisorError::InvalidInput(
            "guest-tools channel path is invalid".into(),
        ));
    }
    Ok(format!(
        "<channel type='unix'><source mode='bind' path='{}'/><target type='virtio' name='com.vexa.guest_tools.0'/></channel>",
        xml_escape(&utf8_path(path)?)
    ))
}

/// Give every managed bridge interface a persistent host-side identity. MAC
/// matching alone is not an anti-spoofing boundary because a guest controls
/// its Ethernet source address. The name is deterministic, within IFNAMSIZ,
/// and unique whenever the already-validated libvirt MAC is unique.
fn stable_tap_name(mac: &str) -> HypervisorResult<String> {
    crate::hypervisor::validate_mac_address(mac)?;
    let compact = mac
        .bytes()
        .filter(|byte| *byte != b':')
        .map(|byte| (byte as char).to_ascii_lowercase())
        .collect::<String>();
    Ok(format!("vx{compact}"))
}

fn parse_key_values(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}

fn parse_equals_values(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            Some((key.to_owned(), value.trim_matches('\'').to_owned()))
        })
        .collect()
}

/// In non-TTY interactive mode virsh echoes both its prompt and the command
/// read from stdin, even with `--quiet`. The QGA reply itself is emitted as a
/// standalone JSON line. Accept exactly one such line so an echoed command,
/// prompt, or unexpected second response can never be mistaken for the reply.
fn parse_qga_response(output: &str) -> HypervisorResult<Value> {
    let mut responses = output.lines().filter_map(|line| {
        let line = line.trim();
        (!line.is_empty())
            .then(|| serde_json::from_str::<Value>(line).ok())
            .flatten()
    });
    let response = responses.next().ok_or_else(|| {
        HypervisorError::InvalidResponse(
            "guest agent returned a response that was not one JSON object".into(),
        )
    })?;
    if responses.next().is_some() {
        return Err(HypervisorError::InvalidResponse(
            "guest agent returned more than one JSON response".into(),
        ));
    }
    Ok(response)
}

/// Return guest-used and guest-total memory in bytes. `balloon.rss` is the
/// QEMU process RSS, not guest memory use, so prefer the guest balloon's
/// total/usable pair and use RSS only when the guest does not publish memory
/// statistics. Clamp that fallback to the assigned balloon size.
fn parse_domain_memory(values: &HashMap<String, String>) -> (Option<u64>, Option<u64>) {
    let kib = |key: &str| values.get(key).and_then(|value| value.parse::<u64>().ok());
    let total_kib = kib("balloon.available")
        .or_else(|| kib("balloon.current"))
        .or_else(|| kib("balloon.maximum"));
    let reclaimable_kib = kib("balloon.usable").or_else(|| kib("balloon.unused"));
    let used_kib = total_kib
        .zip(reclaimable_kib)
        .map(|(total, reclaimable)| total.saturating_sub(reclaimable))
        .or_else(|| kib("balloon.rss").map(|rss| total_kib.map_or(rss, |total| rss.min(total))));
    (
        used_kib.map(|value| value.saturating_mul(1024)),
        total_kib.map(|value| value.saturating_mul(1024)),
    )
}

fn first_u64(value: &str) -> Option<u64> {
    value.split_whitespace().next()?.parse().ok()
}

fn seed_cdrom_target(output: &str, expected_source: &Path) -> HypervisorResult<Option<String>> {
    let mut matched = None;
    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }
        let source = PathBuf::from(fields[3..].join(" "));
        if source.as_path() != expected_source {
            continue;
        }
        if fields[1] != "cdrom" {
            return Err(HypervisorError::Conflict(
                "the provisioning seed source is not attached as a CD-ROM".into(),
            ));
        }
        let target = fields[2];
        if target.is_empty()
            || target.len() > 32
            || target.starts_with('-')
            || !target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(HypervisorError::InvalidResponse(
                "libvirt returned an unsafe seed-media target".into(),
            ));
        }
        if matched.as_deref().is_some_and(|existing| existing != target) {
            return Err(HypervisorError::Conflict(
                "the provisioning seed is attached more than once".into(),
            ));
        }
        matched = Some(target.to_owned());
    }
    Ok(matched)
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let start_marker = format!("<{tag}>");
    let end_marker = format!("</{tag}>");
    let start = xml.find(&start_marker)? + start_marker.len();
    let end = xml[start..].find(&end_marker)? + start;
    Some(
        xml[start..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

fn parse_vnc_display(value: &str) -> HypervisorResult<VncTarget> {
    let value = value.strip_prefix("vnc://").unwrap_or(value).trim();
    let (host_text, display_text) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| HypervisorError::InvalidResponse("invalid bracketed VNC display".into()))?;
        (host, rest.strip_prefix(':').unwrap_or(rest))
    } else if let Some((host, display)) = value.rsplit_once(':') {
        (host, display)
    } else if let Some(display) = value.strip_prefix(':') {
        ("", display)
    } else {
        return Err(HypervisorError::InvalidResponse(
            "libvirt returned an invalid VNC display".into(),
        ));
    };
    let display = display_text
        .split_once(',')
        .map(|(display, _)| display)
        .unwrap_or(display_text)
        .parse::<u16>()
        .map_err(|_| HypervisorError::InvalidResponse("invalid VNC display number".into()))?;
    let port = 5900_u16
        .checked_add(display)
        .ok_or_else(|| HypervisorError::InvalidResponse("VNC display number is out of range".into()))?;
    let host: IpAddr = if host_text.is_empty() || host_text == "localhost" {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host_text
            .parse()
            .map_err(|_| HypervisorError::InvalidResponse("invalid VNC listen address".into()))?
    };
    if !host.is_loopback() {
        return Err(HypervisorError::BackendUnavailable(
            "libvirt VNC is not bound to loopback; refusing to expose it".into(),
        ));
    }
    Ok(VncTarget { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loopback_vnc_displays() {
        assert_eq!(parse_vnc_display(":2").unwrap().port, 5902);
        assert_eq!(parse_vnc_display("127.0.0.1:7").unwrap().port, 5907);
        assert_eq!(parse_vnc_display("[::1]:9").unwrap().port, 5909);
        assert!(parse_vnc_display("0.0.0.0:2").is_err());
    }

    #[test]
    fn derives_guest_memory_from_balloon_stats_instead_of_qemu_rss() {
        let values = parse_equals_values(
            "balloon.current=1048576\nballoon.maximum=2097152\nballoon.available=1000000\nballoon.usable=250000\nballoon.rss=1200000\n",
        );
        assert_eq!(
            parse_domain_memory(&values),
            (Some(750_000 * 1024), Some(1_000_000 * 1024))
        );

        let fallback = parse_equals_values("balloon.current=1048576\nballoon.rss=1200000\n");
        assert_eq!(
            parse_domain_memory(&fallback),
            (Some(1_048_576 * 1024), Some(1_048_576 * 1024))
        );
    }

    #[test]
    fn escapes_generated_xml_values() {
        assert_eq!(xml_escape("a&<'\""), "a&amp;&lt;&apos;&quot;");
    }

    #[test]
    fn rejects_remote_libvirt_uris() {
        assert!(validate_uri("qemu:///system").is_ok());
        assert!(validate_uri("qemu+ssh://host/system").is_err());
    }

    #[test]
    fn maps_public_machine_types_to_qemu_aliases() {
        assert_eq!(qemu_machine_type("q35").unwrap(), "q35");
        assert_eq!(qemu_machine_type("i440fx").unwrap(), "pc");
        assert!(qemu_machine_type("pc-q35-9.0").is_err());
    }

    #[test]
    fn parses_one_qga_reply_from_virsh_interactive_framing() {
        let output = concat!(
            "virsh # qemu-agent-command router-test '{\"execute\":\"guest-info\"}'\n",
            "{\"return\":{\"version\":\"2.10.50\"}}\n",
            "virsh # quit\n",
        );
        assert_eq!(
            parse_qga_response(output).unwrap(),
            serde_json::json!({"return": {"version": "2.10.50"}})
        );
        assert!(parse_qga_response("virsh # quit\n").is_err());
        assert!(parse_qga_response("{}\n{}\n").is_err());
    }

    #[test]
    fn managed_tap_names_are_stable_and_safe() {
        assert_eq!(stable_tap_name("52:54:00:AA:01:ff").unwrap(), "vx525400aa01ff");
        assert!(stable_tap_name("not-a-mac").is_err());
        assert!(stable_tap_name("52:54:00:aa:01:ff").unwrap().len() <= 15);
    }

    #[test]
    fn legacy_link_control_accepts_only_the_exact_persistent_tap() {
        let inventory = "tap-im-vps-3: tap persist user libvirt-qemu\nother: tap persist user libvirt-qemu\n";
        assert!(validate_persistent_tap(inventory, "tap-im-vps-3").is_ok());
        assert!(validate_persistent_tap("tap-im-vps-3: tun persist\n", "tap-im-vps-3").is_err());
        assert!(validate_persistent_tap("tap-im-vps-3: tap\n", "tap-im-vps-3").is_err());
        assert!(validate_persistent_tap("eno49: tap persist\n", "tap-im-vps-3").is_err());
        assert!(validate_persistent_tap(
            "tap-im-vps-3: tap persist\ntap-im-vps-3: tap persist\n",
            "tap-im-vps-3"
        )
        .is_err());
        assert!(validate_persistent_tap(inventory, "../eno49").is_err());
    }

    #[test]
    fn seed_eject_matches_the_exact_cdrom_source() {
        let output = "Type Device Target Source\n---------------------------------------------\nfile disk vda /var/lib/libvirt/images/vm.qcow2\nfile cdrom sdb /var/lib/vexa-vm/cloud-init/vm-1.iso\nfile cdrom sdc /var/lib/vexa-vm/isos/ubuntu.iso\n";
        assert_eq!(
            seed_cdrom_target(output, Path::new("/var/lib/vexa-vm/cloud-init/vm-1.iso"))
                .unwrap()
                .as_deref(),
            Some("sdb")
        );
        assert!(
            seed_cdrom_target(output, Path::new("/var/lib/vexa-vm/cloud-init/other.iso"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn seed_eject_rejects_non_cdrom_and_unsafe_targets() {
        assert!(seed_cdrom_target(
            "file disk vda /var/lib/vexa-vm/cloud-init/vm-1.iso\n",
            Path::new("/var/lib/vexa-vm/cloud-init/vm-1.iso")
        )
        .is_err());
        assert!(seed_cdrom_target(
            "file cdrom --help /var/lib/vexa-vm/cloud-init/vm-1.iso\n",
            Path::new("/var/lib/vexa-vm/cloud-init/vm-1.iso")
        )
        .is_err());
    }

    #[tokio::test]
    async fn permits_cleanup_when_a_managed_disk_is_already_missing() {
        let root = std::env::temp_dir().join(format!("vexa-delete-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let backend =
            LibvirtHypervisor::new(LibvirtConfig::new("qemu:///system", &root, vec![], "virbr0")).unwrap();

        let missing = root.join("missing.qcow2");
        assert!(backend
            .managed_disk_for_deletion(&missing)
            .await
            .unwrap()
            .is_none());

        let outside = root.parent().unwrap().join("outside-missing.qcow2");
        assert!(backend.managed_disk_for_deletion(&outside).await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
