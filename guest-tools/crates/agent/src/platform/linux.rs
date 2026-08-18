use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use vexa_guest_protocol::{Command, NetworkAddress, ResponseData};

use super::{require_user, run_command, ActionOutcome, DeferredAction, Platform};
use crate::config::Policy;

const MANAGED_BEGIN: &str = "# BEGIN VEXA GUEST TOOLS";
const MANAGED_END: &str = "# END VEXA GUEST TOOLS";
const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1024 * 1024;
const MAX_CLOUD_INIT_NETWORK_BYTES: u64 = 1024 * 1024;
const CLOUD_INIT_NETPLAN: &str = "/etc/netplan/50-cloud-init.yaml";
const CLOUD_INIT_NETPLAN_BACKUP: &str = "/etc/netplan/50-cloud-init.yaml.vexa-disabled";
const CLOUD_INIT_NETWORK_DISABLE: &str = "/etc/cloud/cloud.cfg.d/99-vexa-disable-network-config.cfg";
// Linux values from <fcntl.h>. This module is compiled only for Linux.
const O_NONBLOCK: i32 = 0o4000;
const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;

pub struct NativePlatform;

impl NativePlatform {
    pub fn new() -> Self {
        Self
    }

    fn health(&self, policy: &Policy) -> ResponseData {
        let mut capabilities = Vec::new();
        if policy.password && utility_available("chpasswd") {
            capabilities.push("password".into());
        }
        if policy.hostname && utility_available("hostnamectl") {
            capabilities.push("hostname".into());
        }
        if policy.dns && utility_available("systemctl") && utility_available("resolvectl") {
            capabilities.push("dns".into());
        }
        if policy.network && utility_available("netplan") {
            capabilities.push("network".into());
        }
        if policy.ssh_keys
            && ["getent", "runuser", "mkdir", "dd", "chmod", "mv"]
                .iter()
                .all(|utility| utility_available(utility))
        {
            capabilities.push("ssh_keys".into());
        }
        if policy.power && utility_available("systemctl") {
            capabilities.push("shutdown".into());
            capabilities.push("reboot".into());
        }

        ResponseData::Health {
            agent_version: env!("CARGO_PKG_VERSION").into(),
            operating_system: os_description(),
            hostname: fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".into())
                .trim()
                .to_owned(),
            uptime_seconds: uptime_seconds(),
            capabilities,
        }
    }

    fn set_password(&self, username: &str, password: &str) -> Result<()> {
        let payload = format!("{username}:{password}\n");
        run_command("chpasswd", &[], Some(payload.as_bytes()))
    }

    fn set_hostname(&self, hostname: &str) -> Result<()> {
        run_command("hostnamectl", &["set-hostname", hostname], None)
    }

    fn set_dns(&self, interface: Option<&str>, servers: &[IpAddr]) -> Result<()> {
        let directory = Path::new("/etc/systemd/resolved.conf.d");
        fs::create_dir_all(directory).context("failed to create systemd-resolved directory")?;
        let addresses = servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let contents = format!(
            "# Managed by Vexa Guest Tools. Manual changes may be replaced.\n[Resolve]\nDNS={addresses}\n"
        );
        atomic_write_root_owned(&directory.join("90-vexa-guest-tools.conf"), contents.as_bytes())?;
        run_command("systemctl", &["restart", "systemd-resolved.service"], None)?;

        if let Some(interface) = interface {
            let mut arguments = vec!["dns", interface];
            let rendered = servers.iter().map(ToString::to_string).collect::<Vec<_>>();
            arguments.extend(rendered.iter().map(String::as_str));
            run_command("resolvectl", &arguments, None)?;
        }
        Ok(())
    }

    fn set_network(
        &self,
        interface: Option<&str>,
        addresses: &[NetworkAddress],
        gateways: &[IpAddr],
        dns_servers: &[IpAddr],
    ) -> Result<()> {
        let interface = interface
            .map(str::to_owned)
            .or_else(default_route_interface)
            .context("could not identify the guest's default network interface")?;
        validate_linux_interface(&interface)?;
        let path = Path::new("/etc/netplan/90-vexa-guest-tools.yaml");
        let previous = match fs::read(path) {
            Ok(contents) => Some(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("failed to read managed netplan configuration"),
        };
        let cloud_init = disable_generated_cloud_init_network(&interface)?;
        let configuration = render_netplan(&interface, addresses, gateways, dns_servers);
        if let Err(error) = atomic_write_root_owned(path, configuration.as_bytes()) {
            restore_generated_cloud_init_network(cloud_init.as_ref());
            return Err(error).context("failed to write managed netplan configuration");
        }
        if let Err(error) =
            run_command("netplan", &["generate"], None).and_then(|_| run_command("netplan", &["apply"], None))
        {
            restore_managed_netplan(path, previous.as_deref());
            restore_generated_cloud_init_network(cloud_init.as_ref());
            let _ = run_command("netplan", &["generate"], None);
            let _ = run_command("netplan", &["apply"], None);
            return Err(error).context(
                "failed to apply managed netplan configuration; the previous configuration was restored",
            );
        }
        Ok(())
    }

    fn set_ssh_keys(&self, username: &str, keys: &[String]) -> Result<()> {
        let home = user_home(username)?;
        let ssh_directory = home.join(".ssh");
        let authorized_keys = ssh_directory.join("authorized_keys");

        refuse_symlink(&home)?;
        if ssh_directory.exists() {
            refuse_symlink(&ssh_directory)?;
        }
        if authorized_keys.exists() {
            refuse_symlink(&authorized_keys)?;
        }

        let ssh_path = ssh_directory
            .to_str()
            .context("user SSH directory is not valid UTF-8")?;
        run_command(
            "runuser",
            &["-u", username, "--", "mkdir", "-p", "--", ssh_path],
            None,
        )?;
        run_command(
            "runuser",
            &["-u", username, "--", "chmod", "700", "--", ssh_path],
            None,
        )?;
        refuse_symlink(&ssh_directory)?;

        let existing = read_authorized_keys_nofollow(&authorized_keys)?;
        let content = replace_managed_key_block(&existing, keys)?;
        atomic_write_as_user(username, &authorized_keys, content.as_bytes())
    }
}

impl Platform for NativePlatform {
    fn execute(&self, command: &Command, policy: &Policy) -> Result<ActionOutcome> {
        match command {
            Command::Ping => Ok(ActionOutcome::immediate(ResponseData::Pong {
                agent_version: env!("CARGO_PKG_VERSION").into(),
            })),
            Command::Health => Ok(ActionOutcome::immediate(self.health(policy))),
            Command::SetPassword { username, password } => {
                require_enabled(policy.password, "password changes")?;
                require_user(policy, username)?;
                self.set_password(username, password)?;
                Ok(changed("password changed", false))
            }
            Command::SetHostname { hostname } => {
                require_enabled(policy.hostname, "hostname changes")?;
                self.set_hostname(hostname)?;
                Ok(changed("hostname changed", false))
            }
            Command::SetDns { interface, servers } => {
                require_enabled(policy.dns, "DNS changes")?;
                self.set_dns(interface.as_deref(), servers)?;
                Ok(changed("DNS servers changed", false))
            }
            Command::SetNetwork {
                interface,
                addresses,
                gateways,
                dns_servers,
            } => {
                require_enabled(policy.network, "network changes")?;
                self.set_network(interface.as_deref(), addresses, gateways, dns_servers)?;
                Ok(changed("network addresses and routes changed", false))
            }
            Command::SetSshKeys {
                username,
                authorized_keys,
            } => {
                require_enabled(policy.ssh_keys, "SSH key changes")?;
                require_user(policy, username)?;
                self.set_ssh_keys(username, authorized_keys)?;
                Ok(changed("managed SSH keys changed", false))
            }
            Command::Shutdown => {
                require_enabled(policy.power, "power actions")?;
                Ok(deferred("shutdown accepted", DeferredAction::Shutdown))
            }
            Command::Reboot => {
                require_enabled(policy.power, "power actions")?;
                Ok(deferred("reboot accepted", DeferredAction::Reboot))
            }
        }
    }

    fn execute_deferred(&self, action: DeferredAction) -> Result<()> {
        match action {
            DeferredAction::Shutdown => run_command("systemctl", &["poweroff", "--no-block"], None),
            DeferredAction::Reboot => run_command("systemctl", &["reboot", "--no-block"], None),
        }
    }
}

fn validate_linux_interface(interface: &str) -> Result<()> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("network interface name is not safe for netplan");
    }
    Ok(())
}

fn default_route_interface() -> Option<String> {
    let routes = fs::read_to_string("/proc/net/route").unwrap_or_default();
    let interfaces = fs::read_dir("/sys/class/net")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    select_network_interface(&routes, &interfaces)
}

fn select_network_interface(routes: &str, interfaces: &[String]) -> Option<String> {
    if let Some(interface) = routes.lines().skip(1).find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.len() >= 4 && fields[1] == "00000000").then(|| fields[0].to_owned())
    }) {
        return Some(interface);
    }
    let mut candidates = interfaces
        .iter()
        .filter(|interface| interface.as_str() != "lo")
        .filter(|interface| validate_linux_interface(interface).is_ok());
    let interface = candidates.next()?.clone();
    candidates.next().is_none().then_some(interface)
}

#[derive(Debug)]
struct CloudInitNetworkBackup {
    original: Vec<u8>,
    disable_previous: Option<Vec<u8>>,
}

fn disable_generated_cloud_init_network(interface: &str) -> Result<Option<CloudInitNetworkBackup>> {
    let path = Path::new(CLOUD_INIT_NETPLAN);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to inspect cloud-init netplan configuration"),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_CLOUD_INIT_NETWORK_BYTES {
        bail!("cloud-init netplan configuration is not a safe regular file");
    }
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != 0 {
        bail!("cloud-init netplan configuration is not owned by root");
    }
    let original = fs::read(path).context("failed to read cloud-init netplan configuration")?;
    let rendered = std::str::from_utf8(&original)
        .context("cloud-init netplan configuration is not valid UTF-8")?;
    if !is_generated_cloud_init_network(rendered, interface) {
        return Ok(None);
    }
    let backup = Path::new(CLOUD_INIT_NETPLAN_BACKUP);
    if backup.exists() {
        bail!("a prior cloud-init netplan backup already exists");
    }
    let disable_path = Path::new(CLOUD_INIT_NETWORK_DISABLE);
    let disable_previous = match fs::read(disable_path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("failed to read cloud-init network policy"),
    };
    fs::rename(path, backup).context("failed to preserve cloud-init netplan configuration")?;
    if let Some(parent) = disable_path.parent() {
        fs::create_dir_all(parent).context("failed to create cloud-init policy directory")?;
    }
    if let Err(error) = atomic_write_root_owned(disable_path, b"network: {config: disabled}\n") {
        let _ = fs::rename(backup, path);
        return Err(error).context("failed to disable cloud-init network rewrites");
    }
    Ok(Some(CloudInitNetworkBackup {
        original,
        disable_previous,
    }))
}

fn restore_generated_cloud_init_network(backup: Option<&CloudInitNetworkBackup>) {
    let Some(backup_state) = backup else {
        return;
    };
    let path = Path::new(CLOUD_INIT_NETPLAN);
    let preserved = Path::new(CLOUD_INIT_NETPLAN_BACKUP);
    if fs::rename(preserved, path).is_err() {
        let _ = atomic_write_root_owned(path, &backup_state.original);
    }
    let disable_path = Path::new(CLOUD_INIT_NETWORK_DISABLE);
    match backup_state.disable_previous.as_deref() {
        Some(contents) => {
            let _ = atomic_write_root_owned(disable_path, contents);
        }
        None => {
            let _ = fs::remove_file(disable_path);
        }
    }
}

fn is_generated_cloud_init_network(contents: &str, interface: &str) -> bool {
    let preamble = contents.lines().take(8).collect::<Vec<_>>().join(" ").to_ascii_lowercase();
    preamble.contains("generated")
        && preamble.contains("datasource")
        && contents
            .lines()
            .any(|line| line.trim() == format!("{interface}:"))
}

fn render_netplan(
    interface: &str,
    addresses: &[NetworkAddress],
    gateways: &[IpAddr],
    dns_servers: &[IpAddr],
) -> String {
    let mut output = format!(
        "# Managed by Vexa Guest Tools. Manual changes may be replaced.\nnetwork:\n  version: 2\n  ethernets:\n    {interface}:\n      dhcp4: false\n      dhcp6: false\n"
    );
    if addresses.is_empty() {
        output.push_str("      addresses: []\n");
    } else {
        output.push_str("      addresses:\n");
        for item in addresses {
            output.push_str(&format!("        - {}/{}\n", item.address, item.prefix_length));
        }
    }
    if !gateways.is_empty() {
        output.push_str("      routes:\n");
        for gateway in gateways {
            let destination = if gateway.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
            output.push_str(&format!(
                "        - to: {destination}\n          via: {gateway}\n          on-link: true\n"
            ));
        }
    }
    if !dns_servers.is_empty() {
        output.push_str("      nameservers:\n        addresses:\n");
        for server in dns_servers {
            output.push_str(&format!("          - {server}\n"));
        }
    }
    output
}

fn restore_managed_netplan(path: &Path, previous: Option<&[u8]>) {
    match previous {
        Some(contents) => {
            let _ = atomic_write_root_owned(path, contents);
        }
        None => {
            let _ = fs::remove_file(path);
        }
    }
}

fn require_enabled(enabled: bool, operation: &str) -> Result<()> {
    if !enabled {
        bail!("{operation} are disabled by guest policy");
    }
    Ok(())
}

fn changed(message: &str, reboot_required: bool) -> ActionOutcome {
    ActionOutcome::immediate(ResponseData::Action {
        changed: true,
        reboot_required,
        message: message.into(),
    })
}

fn deferred(message: &str, action: DeferredAction) -> ActionOutcome {
    ActionOutcome {
        data: ResponseData::Action {
            changed: true,
            reboot_required: false,
            message: message.into(),
        },
        deferred: Some(action),
    }
}

fn user_home(username: &str) -> Result<PathBuf> {
    let output = std::process::Command::new("getent")
        .args(["passwd", username])
        .output()
        .context("failed to look up local user")?;
    if !output.status.success() {
        bail!("local user does not exist");
    }
    let record = String::from_utf8(output.stdout).context("local user record is not UTF-8")?;
    let home = record
        .trim_end()
        .split(':')
        .nth(5)
        .filter(|value| value.starts_with('/'))
        .context("local user has no valid home directory")?;
    Ok(PathBuf::from(home))
}

fn refuse_symlink(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to write through a symbolic link");
    }
    Ok(())
}

fn read_authorized_keys_nofollow(path: &Path) -> Result<String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read existing {}", path.display()))
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect existing {}", path.display()))?;
    if !metadata.is_file() {
        bail!("refusing to replace a non-regular authorized_keys file");
    }
    if metadata.len() > MAX_AUTHORIZED_KEYS_BYTES {
        bail!("authorized_keys exceeds the 1 MiB safety limit");
    }
    let mut contents = String::with_capacity(metadata.len() as usize);
    file.take(MAX_AUTHORIZED_KEYS_BYTES + 1)
        .read_to_string(&mut contents)
        .with_context(|| format!("failed to read existing {} as UTF-8", path.display()))?;
    if contents.len() as u64 > MAX_AUTHORIZED_KEYS_BYTES {
        bail!("authorized_keys exceeds the 1 MiB safety limit");
    }
    Ok(contents)
}

fn atomic_write_as_user(username: &str, path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("authorized_keys has no parent directory")?;
    refuse_symlink(parent)?;

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".authorized_keys.vexa-{}-{suffix}.tmp",
        std::process::id()
    ));
    let temporary_path = temporary
        .to_str()
        .context("temporary authorized_keys path is not valid UTF-8")?;
    let destination_path = path.to_str().context("authorized_keys path is not valid UTF-8")?;
    let output_argument = format!("of={temporary_path}");

    let write_result = run_command(
        "runuser",
        &[
            "-u",
            username,
            "--",
            "dd",
            &output_argument,
            "status=none",
            "oflag=excl,nofollow",
            "conv=fsync",
        ],
        Some(contents),
    )
    .and_then(|_| {
        run_command(
            "runuser",
            &["-u", username, "--", "chmod", "600", "--", temporary_path],
            None,
        )
    })
    .and_then(|_| sync_regular_file_nofollow(&temporary))
    .and_then(|_| {
        run_command(
            "runuser",
            &[
                "-u",
                username,
                "--",
                "mv",
                "-fT",
                "--",
                temporary_path,
                destination_path,
            ],
            None,
        )
    });

    if let Err(error) = write_result {
        let _ = run_command(
            "runuser",
            &["-u", username, "--", "rm", "-f", "--", temporary_path],
            None,
        );
        return Err(error).context("failed to publish authorized_keys atomically");
    }

    // Persist the rename itself, not just the temporary file's contents.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(parent)
        .with_context(|| format!("failed to open {} for directory sync", parent.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("failed to sync {}", parent.display()))
}

fn sync_regular_file_nofollow(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open {} for sync", path.display()))?;
    if !file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?
        .is_file()
    {
        bail!("refusing to sync a non-regular authorized_keys temporary file");
    }
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))
}

fn utility_available(name: &str) -> bool {
    [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]
    .iter()
    .map(|directory| Path::new(directory).join(name))
    .any(|path| path.is_file())
}

fn replace_managed_key_block(existing: &str, keys: &[String]) -> Result<String> {
    let before = existing.find(MANAGED_BEGIN);
    let after = existing.find(MANAGED_END);
    let mut preserved = match (before, after) {
        (Some(start), Some(end)) if start <= end => {
            let suffix = end + MANAGED_END.len();
            format!("{}{}", &existing[..start], &existing[suffix..])
        }
        (None, None) => existing.to_owned(),
        _ => bail!("authorized_keys contains an incomplete Vexa managed block"),
    };
    while preserved.ends_with('\r') || preserved.ends_with('\n') {
        preserved.pop();
    }
    if !preserved.is_empty() {
        preserved.push('\n');
    }
    preserved.push_str(MANAGED_BEGIN);
    preserved.push('\n');
    for key in keys {
        preserved.push_str(key.trim());
        preserved.push('\n');
    }
    preserved.push_str(MANAGED_END);
    preserved.push('\n');
    Ok(preserved)
}

fn atomic_write_root_owned(path: &Path, contents: &[u8]) -> Result<()> {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("tmp-{}-{suffix}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).context("failed to publish configuration atomically");
    }
    Ok(())
}

fn uptime_seconds() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .map(|value| value.max(0.0) as u64)
        .unwrap_or(0)
}

fn os_description() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').to_owned())
            })
        })
        .unwrap_or_else(|| "Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn managed_keys_preserve_unmanaged_content() {
        let original =
            "ssh-ed25519 AAAA old\n# BEGIN VEXA GUEST TOOLS\nssh-rsa AAAA stale\n# END VEXA GUEST TOOLS\n";
        let result = replace_managed_key_block(
            original,
            &["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample".into()],
        )
        .expect("replace keys");
        assert!(result.contains("ssh-ed25519 AAAA old"));
        assert!(!result.contains("stale"));
        assert_eq!(result.matches(MANAGED_BEGIN).count(), 1);
    }

    #[test]
    fn disabled_policy_reports_no_capabilities() {
        let policy = Policy {
            password: false,
            hostname: false,
            dns: false,
            network: false,
            ssh_keys: false,
            power: false,
            allowed_users: Vec::new(),
        };
        let ResponseData::Health { capabilities, .. } = NativePlatform::new().health(&policy) else {
            panic!("expected health response");
        };
        assert!(capabilities.is_empty());
    }

    #[test]
    fn managed_netplan_contains_every_address_and_gateway() {
        let rendered = render_netplan(
            "eth0",
            &[
                NetworkAddress {
                    address: "169.254.40.2".parse().unwrap(),
                    prefix_length: 30,
                },
                NetworkAddress {
                    address: "203.0.113.10".parse().unwrap(),
                    prefix_length: 32,
                },
                NetworkAddress {
                    address: "2001:db8::10".parse().unwrap(),
                    prefix_length: 128,
                },
            ],
            &["169.254.40.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            &["1.1.1.1".parse().unwrap()],
        );
        assert!(rendered.contains("203.0.113.10/32"));
        assert!(rendered.contains("2001:db8::10/128"));
        assert!(rendered.contains("to: 0.0.0.0/0"));
        assert!(rendered.contains("to: ::/0"));
        assert!(rendered.contains("- 1.1.1.1"));
    }

    #[test]
    fn interface_selection_prefers_default_route_and_has_single_nic_fallback() {
        let routes = "Iface Destination Gateway Flags\nens3 00000000 00000000 0003\n";
        assert_eq!(
            select_network_interface(routes, &["eth0".into(), "ens3".into()]),
            Some("ens3".into())
        );
        assert_eq!(
            select_network_interface("Iface Destination Gateway Flags\n", &["lo".into(), "eth0".into()]),
            Some("eth0".into())
        );
        assert_eq!(
            select_network_interface(
                "Iface Destination Gateway Flags\n",
                &["lo".into(), "eth0".into(), "eth1".into()]
            ),
            None
        );
    }

    #[test]
    fn only_cloud_init_generated_config_for_the_selected_nic_is_claimed() {
        let generated = "# This file is generated from information provided by the datasource.\nnetwork:\n  ethernets:\n    eth0:\n      dhcp4: true\n";
        assert!(is_generated_cloud_init_network(generated, "eth0"));
        assert!(!is_generated_cloud_init_network(generated, "ens3"));
        assert!(!is_generated_cloud_init_network(
            "# administrator managed\nnetwork:\n  ethernets:\n    eth0:\n",
            "eth0"
        ));
    }

    #[test]
    fn authorized_keys_reader_refuses_symlinks() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "vexa-guest-tools-key-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create test directory");
        let target = directory.join("target");
        let link = directory.join("authorized_keys");
        fs::write(&target, "ssh-ed25519 AAAA test\n").expect("write test key");
        symlink(&target, &link).expect("create test symlink");

        assert!(read_authorized_keys_nofollow(&link).is_err());

        fs::remove_file(&link).expect("remove test symlink");
        fs::remove_file(&target).expect("remove test target");
        fs::remove_dir(&directory).expect("remove test directory");
    }
}
