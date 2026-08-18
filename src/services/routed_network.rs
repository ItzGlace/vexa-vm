//! Per-VM routed networking for provider allocations delivered to the host.
//!
//! A public `/32` cannot be attached to an absent generic bridge. Vexa gives
//! the guest a private link-local transit `/30`, routes its public address to a
//! persistent TAP, and keeps the provider-visible address assigned only inside
//! the guest. All host commands use fixed executables and argument vectors.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use serde_json::{json, Value};
use tokio::{process::Command, time::timeout};

use crate::{
    config::HypervisorMode,
    error::{AppError, AppResult},
    models::{AddressFamily, IpScope, NewVm, Vm, VmPatch},
    state::AppState,
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTPUT: usize = 1024 * 1024;
const MANAGER: &str = "vexa-vm";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedIpv4 {
    pub bridge: String,
    pub tap: String,
    pub guest_address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub prefix_length: u8,
    pub public_interface: String,
    pub mtu: u32,
}

/// Convert a create request to Vexa's routed topology only when its selected
/// Linux bridge is absent and every selected address is a routed public IPv4
/// `/32` from an enabled inventory pool without an explicit bridge.
pub async fn configure_new_vm(
    state: &AppState,
    spec: &mut NewVm,
    selected_addresses: &[String],
) -> AppResult<bool> {
    if state.config.hypervisor_mode == HypervisorMode::Mock {
        return Ok(false);
    }
    let requested_bridge = spec
        .bridge
        .as_deref()
        .unwrap_or(&state.config.network_bridge);
    validate_interface_name(requested_bridge)?;
    if interface_exists(requested_bridge) {
        return Ok(false);
    }

    let mut addresses = Vec::new();
    for address_or_id in selected_addresses {
        let record = state
            .db
            .get_ip_address(address_or_id)?
            .ok_or_else(|| AppError::NotFound(format!("IP address {address_or_id}")))?;
        addresses.push(record);
    }
    if addresses.is_empty() {
        return Err(AppError::Validation(format!(
            "configured bridge '{requested_bridge}' does not exist; select a routed public IPv4 /32 or configure an existing Linux bridge"
        )));
    }
    for address in &addresses {
        if address.family != AddressFamily::V4
            || address.scope != IpScope::Public
            || address.prefix_length != 32
        {
            return Err(AppError::Validation(format!(
                "configured bridge '{requested_bridge}' does not exist and address {} is not a routed public IPv4 /32",
                address.address
            )));
        }
        if let Some(pool_id) = address.pool_id.as_deref() {
            let pool = state
                .db
                .get_ip_pool(pool_id)?
                .ok_or_else(|| AppError::NotFound("IP pool".into()))?;
            if !pool.enabled {
                return Err(AppError::Conflict(format!(
                    "IP pool '{}' is disabled",
                    pool.name
                )));
            }
            if pool.bridge.as_deref().is_some_and(|bridge| !bridge.is_empty()) {
                return Err(AppError::Validation(format!(
                    "IP pool '{}' requires bridge '{}' but that interface does not exist",
                    pool.name,
                    pool.bridge.as_deref().unwrap_or_default()
                )));
            }
        }
    }

    let public_interface = match state.config.public_interface.clone() {
        Some(interface) => interface,
        None => state
            .host_info
            .read()
            .await
            .primary_interface
            .clone()
            .ok_or_else(|| AppError::Configuration("could not detect the public interface".into()))?,
    };
    validate_interface_name(&public_interface)?;
    if !interface_exists(&public_interface) {
        return Err(AppError::Configuration(format!(
            "public interface '{public_interface}' does not exist"
        )));
    }
    let mac = spec
        .mac_address
        .as_deref()
        .ok_or_else(|| AppError::Validation("a MAC address is required before routed networking".into()))?;
    let compact_mac = compact_mac(mac)?;
    let suffix = &compact_mac[compact_mac.len() - 8..];
    let bridge = format!("kbr-vx{suffix}");
    let tap = format!("tap-vx{suffix}");
    validate_interface_name(&bridge)?;
    validate_interface_name(&tap)?;
    if interface_exists(&bridge) || interface_exists(&tap) {
        return Err(AppError::Conflict(
            "the deterministic routed interface name is already in use".into(),
        ));
    }

    let used = host_link_local_subnets().await?;
    let seed = u16::from_str_radix(&compact_mac[compact_mac.len() - 4..], 16)
        .map_err(|_| AppError::Validation("MAC address is invalid".into()))?;
    let (gateway, guest_address) = allocate_transit(seed, &used)?;
    let metadata = spec
        .metadata
        .as_object_mut()
        .ok_or_else(|| AppError::Validation("VM metadata must be a JSON object".into()))?;
    metadata.insert(
        "routed_network".into(),
        json!({
            "managed_by": MANAGER,
            "version": 1,
            "bridge": bridge,
            "tap": tap,
            "guest_address": guest_address,
            "gateway": gateway,
            "prefix_length": 30,
            "public_interface": public_interface,
            "mtu": 1500,
        }),
    );
    spec.bridge = Some(bridge);
    spec.tap_name = Some(tap);
    Ok(true)
}

pub fn plan(vm: &Vm) -> AppResult<Option<RoutedIpv4>> {
    let Some(value) = vm.metadata.get("routed_network") else {
        return Ok(None);
    };
    if value.get("managed_by").and_then(Value::as_str) != Some(MANAGER) {
        return Ok(None);
    }
    let string = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AppError::Configuration(format!("VM routed_network.{key} is missing")))
    };
    let bridge = string("bridge")?;
    let tap = string("tap")?;
    let public_interface = string("public_interface")?;
    validate_interface_name(&bridge)?;
    validate_interface_name(&tap)?;
    validate_interface_name(&public_interface)?;
    if vm.bridge.as_deref() != Some(bridge.as_str()) || vm.tap_name.as_deref() != Some(tap.as_str()) {
        return Err(AppError::Conflict(
            "VM routed-network metadata does not match its stored interfaces".into(),
        ));
    }
    let guest_address = string("guest_address")?
        .parse::<Ipv4Addr>()
        .map_err(|_| AppError::Configuration("VM routed guest address is invalid".into()))?;
    let gateway = string("gateway")?
        .parse::<Ipv4Addr>()
        .map_err(|_| AppError::Configuration("VM routed gateway is invalid".into()))?;
    let prefix_length = value
        .get("prefix_length")
        .and_then(Value::as_u64)
        .and_then(|number| u8::try_from(number).ok())
        .unwrap_or(30);
    let mtu = value
        .get("mtu")
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .unwrap_or(1500);
    if prefix_length != 30
        || !guest_address.is_link_local()
        || !gateway.is_link_local()
        || (u32::from(guest_address) & !3) != (u32::from(gateway) & !3)
        || u32::from(guest_address) != u32::from(gateway) + 1
        || !(576..=9000).contains(&mtu)
    {
        return Err(AppError::Configuration(
            "VM routed link-local transit metadata is invalid".into(),
        ));
    }
    Ok(Some(RoutedIpv4 {
        bridge,
        tap,
        guest_address,
        gateway,
        prefix_length,
        public_interface,
        mtu,
    }))
}

/// Return the persisted routed plan, adopting only an unambiguous legacy
/// libvirt topology. Older Vexa imports predate `routed_network` metadata, so
/// they otherwise never receive host-route reconciliation after an IP change.
pub async fn effective_plan(state: &AppState, vm: &Vm) -> AppResult<Option<RoutedIpv4>> {
    if let Some(plan) = plan(vm)? {
        return Ok(Some(plan));
    }
    if vm.metadata.get("imported_from_libvirt").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let (Some(bridge), Some(tap)) = (vm.bridge.as_deref(), vm.tap_name.as_deref()) else {
        return Ok(None);
    };
    validate_interface_name(bridge)?;
    validate_interface_name(tap)?;
    if !bridge.starts_with("kbr-")
        || !tap.starts_with("tap-")
        || !Path::new("/sys/class/net").join(bridge).join("bridge").is_dir()
        || !interface_exists(tap)
    {
        return Ok(None);
    }
    let master = std::fs::read_link(Path::new("/sys/class/net").join(tap).join("master"))?;
    if master.file_name().and_then(|name| name.to_str()) != Some(bridge) {
        return Ok(None);
    }
    let output = run_ip(&["-4", "-o", "address", "show", "dev", bridge]).await?;
    let mut gateways = output
        .split_whitespace()
        .filter_map(|field| field.split_once('/'))
        .filter(|(_, prefix)| *prefix == "30")
        .filter_map(|(address, _)| address.parse::<Ipv4Addr>().ok())
        .filter(Ipv4Addr::is_link_local)
        .collect::<BTreeSet<_>>();
    if gateways.len() != 1 {
        return Ok(None);
    }
    let gateway = gateways.pop_first().expect("one gateway was checked");
    if u32::from(gateway) & 3 != 1 {
        return Ok(None);
    }
    let guest_address = Ipv4Addr::from(u32::from(gateway) + 1);
    let public_interface = match state.config.public_interface.clone() {
        Some(interface) => interface,
        None => state
            .host_info
            .read()
            .await
            .primary_interface
            .clone()
            .ok_or_else(|| AppError::Configuration("could not detect the public interface".into()))?,
    };
    validate_interface_name(&public_interface)?;
    if !interface_exists(&public_interface) {
        return Err(AppError::Configuration(format!(
            "public interface '{public_interface}' does not exist"
        )));
    }
    let mtu = std::fs::read_to_string(Path::new("/sys/class/net").join(bridge).join("mtu"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| (576..=9000).contains(value))
        .unwrap_or(1500);
    let mut metadata = vm
        .metadata
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::Configuration("VM metadata must be a JSON object".into()))?;
    metadata.insert(
        "routed_network".into(),
        json!({
            "managed_by": MANAGER,
            "version": 1,
            "adopted_legacy_import": true,
            "bridge": bridge,
            "tap": tap,
            "guest_address": guest_address,
            "gateway": gateway,
            "prefix_length": 30,
            "public_interface": public_interface,
            "mtu": mtu,
        }),
    );
    let adopted = state.db.patch_vm(
        &vm.id,
        &VmPatch {
            metadata: Some(Value::Object(metadata)),
            ..VmPatch::default()
        },
    )?;
    plan(&adopted)
}

pub async fn reconcile_vm(state: &AppState, vm: &Vm) -> AppResult<bool> {
    let Some(plan) = effective_plan(state, vm).await? else {
        return Ok(false);
    };
    if !interface_exists(&plan.public_interface) {
        return Err(AppError::Conflict(format!(
            "routed public interface '{}' is unavailable",
            plan.public_interface
        )));
    }
    if std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .unwrap_or_default()
        .trim()
        != "1"
    {
        return Err(AppError::Conflict(
            "IPv4 forwarding is disabled on the hypervisor".into(),
        ));
    }

    if !interface_exists(&plan.bridge) {
        run_ip(&["link", "add", "name", &plan.bridge, "type", "bridge"]).await?;
    } else if !Path::new("/sys/class/net")
        .join(&plan.bridge)
        .join("bridge")
        .is_dir()
    {
        return Err(AppError::Conflict(format!(
            "interface '{}' exists but is not a Linux bridge",
            plan.bridge
        )));
    }
    run_ip(&[
        "link",
        "set",
        "dev",
        &plan.bridge,
        "mtu",
        &plan.mtu.to_string(),
        "up",
    ])
    .await?;
    ensure_bridge_address(&plan).await?;

    if !interface_exists(&plan.tap) {
        run_ip(&[
            "tuntap",
            "add",
            "dev",
            &plan.tap,
            "mode",
            "tap",
            "user",
            "libvirt-qemu",
        ])
        .await?;
    } else {
        let taps = run_ip(&["tuntap", "show"]).await?;
        if !taps.lines().any(|line| {
            line.split_whitespace().next() == Some(format!("{}:", plan.tap).as_str())
                && line.split_whitespace().any(|field| field == "tap")
                && line.split_whitespace().any(|field| field == "persist")
        }) {
            return Err(AppError::Conflict(format!(
                "interface '{}' exists but is not a persistent TAP",
                plan.tap
            )));
        }
    }
    ensure_tap_master(&plan.tap, &plan.bridge).await?;
    run_ip(&[
        "link",
        "set",
        "dev",
        &plan.tap,
        "mtu",
        &plan.mtu.to_string(),
        "up",
    ])
    .await?;

    let mut desired = BTreeSet::new();
    for address in state.db.vm_ip_addresses(&vm.id)? {
        if address.family != AddressFamily::V4 || address.scope != IpScope::Public {
            continue;
        }
        desired.insert(address.address.clone());
    }
    reconcile_public_routes(&desired, &plan.bridge).await?;
    for address in desired {
        ensure_public_route(&address, &plan.bridge).await?;
    }
    Ok(true)
}

pub async fn cleanup_vm(vm: &Vm) -> AppResult<bool> {
    let Some(plan) = plan(vm)? else {
        return Ok(false);
    };
    if interface_exists(&plan.tap) {
        run_ip(&["tuntap", "del", "dev", &plan.tap, "mode", "tap"]).await?;
    }
    if interface_exists(&plan.bridge) {
        run_ip(&["link", "del", "dev", &plan.bridge, "type", "bridge"]).await?;
    }
    Ok(true)
}

fn interface_exists(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).exists()
}

fn validate_interface_name(name: &str) -> AppResult<()> {
    if name.is_empty()
        || name.len() > 15
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(AppError::Validation(
            "network interface names must contain 1-15 safe ASCII characters".into(),
        ));
    }
    Ok(())
}

fn compact_mac(mac: &str) -> AppResult<String> {
    crate::hypervisor::validate_mac_address(mac).map_err(AppError::from)?;
    Ok(mac
        .chars()
        .filter(|character| *character != ':')
        .collect::<String>()
        .to_ascii_lowercase())
}

fn allocate_transit(seed: u16, used: &BTreeSet<u16>) -> AppResult<(Ipv4Addr, Ipv4Addr)> {
    const SUBNETS: u16 = 16_383;
    for probe in 0..SUBNETS {
        let index = 1 + (seed.wrapping_add(probe) % SUBNETS);
        let base = u32::from(index) * 4;
        let base = u16::try_from(base).map_err(|_| {
            AppError::Internal("link-local transit allocation overflowed".into())
        })?;
        if used.contains(&base) {
            continue;
        }
        return Ok((link_local(base + 1), link_local(base + 2)));
    }
    Err(AppError::Conflict(
        "no free link-local /30 remains for routed VM networking".into(),
    ))
}

fn link_local(host: u16) -> Ipv4Addr {
    Ipv4Addr::new(169, 254, (host >> 8) as u8, host as u8)
}

async fn host_link_local_subnets() -> AppResult<BTreeSet<u16>> {
    let output = run_ip(&["-4", "-o", "address", "show"]).await?;
    let mut used = BTreeSet::new();
    for field in output.split_whitespace() {
        let Some((address, prefix)) = field.split_once('/') else {
            continue;
        };
        if prefix != "30" {
            continue;
        }
        let Ok(IpAddr::V4(address)) = address.parse::<IpAddr>() else {
            continue;
        };
        if address.is_link_local() {
            used.insert((u32::from(address) & 0xffff & !3) as u16);
        }
    }
    Ok(used)
}

async fn ensure_bridge_address(plan: &RoutedIpv4) -> AppResult<()> {
    let output = run_ip(&["-4", "-o", "address", "show", "dev", &plan.bridge]).await?;
    let expected = format!("{}/{}", plan.gateway, plan.prefix_length);
    let addresses = output
        .split_whitespace()
        .filter(|field| field.contains('/'))
        .filter_map(|field| field.split_once('/').map(|_| field.to_owned()))
        .collect::<Vec<_>>();
    if addresses.iter().any(|address| address == &expected) {
        return Ok(());
    }
    if !addresses.is_empty() {
        return Err(AppError::Conflict(format!(
            "bridge '{}' already has an unexpected address",
            plan.bridge
        )));
    }
    run_ip(&["address", "add", &expected, "dev", &plan.bridge]).await?;
    Ok(())
}

async fn ensure_tap_master(tap: &str, bridge: &str) -> AppResult<()> {
    let master = Path::new("/sys/class/net").join(tap).join("master");
    match std::fs::read_link(&master) {
        Ok(target) if target.file_name().and_then(|name| name.to_str()) == Some(bridge) => Ok(()),
        Ok(_) => Err(AppError::Conflict(format!(
            "TAP '{tap}' is attached to a different bridge"
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            run_ip(&["link", "set", "dev", tap, "master", bridge]).await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

async fn ensure_public_route(address: &str, bridge: &str) -> AppResult<()> {
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| AppError::Validation("routed public IPv4 address is invalid".into()))?;
    let destination = format!("{address}/32");
    let output = run_ip(&["-4", "-o", "route", "show", &destination]).await?;
    if output.trim().is_empty() {
        run_ip(&["route", "add", &destination, "dev", bridge]).await?;
        return Ok(());
    }
    if output
        .lines()
        .all(|line| route_line_matches(line, &address.to_string(), &destination, bridge))
    {
        return Ok(());
    }
    Err(AppError::Conflict(format!(
        "route {destination} is already owned by another interface"
    )))
}

async fn reconcile_public_routes(desired: &BTreeSet<String>, bridge: &str) -> AppResult<()> {
    let output = run_ip(&["-4", "-o", "route", "show", "dev", bridge]).await?;
    for destination in managed_host_route_destinations(&output) {
        if !desired.contains(&destination.to_string()) {
            let route = format!("{destination}/32");
            run_ip(&["route", "del", &route, "dev", bridge]).await?;
        }
    }
    Ok(())
}

fn managed_host_route_destinations(output: &str) -> BTreeSet<Ipv4Addr> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|destination| match destination.split_once('/') {
            Some((address, "32")) => address.parse::<Ipv4Addr>().ok(),
            Some(_) => None,
            None => destination.parse::<Ipv4Addr>().ok(),
        })
        .collect()
}

fn route_line_matches(line: &str, address: &str, destination: &str, bridge: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    matches!(fields.first().copied(), Some(value) if value == address || value == destination)
        && fields
            .windows(2)
            .any(|pair| pair == ["dev", bridge])
}

async fn run_ip(args: &[&str]) -> AppResult<String> {
    let program = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| AppError::Configuration("iproute2 is not installed".into()))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| AppError::Internal("iproute2 command timed out".into()))??;
    if output.stdout.len() > MAX_OUTPUT || output.stderr.len() > MAX_OUTPUT {
        return Err(AppError::Internal("iproute2 output exceeded its safety bound".into()));
    }
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        return Err(AppError::Conflict(format!(
            "routed network command failed: {}",
            if message.is_empty() { "unknown iproute2 error" } else { &message }
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transit_allocator_is_deterministic_and_skips_used_subnets() {
        let (gateway, guest) = allocate_transit(7, &BTreeSet::new()).unwrap();
        assert_eq!(u32::from(guest), u32::from(gateway) + 1);
        let base = (u32::from(gateway) & 0xffff & !3) as u16;
        let (next_gateway, _) = allocate_transit(7, &BTreeSet::from([base])).unwrap();
        assert_ne!(gateway, next_gateway);
    }

    #[test]
    fn host_route_accepts_iproute2s_implicit_or_explicit_host_prefix() {
        assert!(route_line_matches(
            "203.0.113.74 dev kbr-vx005515bd scope link linkdown",
            "203.0.113.74",
            "203.0.113.74/32",
            "kbr-vx005515bd",
        ));
        assert!(route_line_matches(
            "203.0.113.74/32 dev kbr-vx005515bd scope link",
            "203.0.113.74",
            "203.0.113.74/32",
            "kbr-vx005515bd",
        ));
        assert!(!route_line_matches(
            "203.0.113.74 dev kbr-other scope link",
            "203.0.113.74",
            "203.0.113.74/32",
            "kbr-vx005515bd",
        ));
    }

    #[test]
    fn stale_route_parser_only_returns_host_routes() {
        let routes = "169.254.0.80/30 proto kernel scope link src 169.254.0.81\n\
                      94.182.147.91 dev kbr-test scope link\n\
                      94.182.147.107/32 dev kbr-test scope link\n\
                      203.0.113.0/24 dev kbr-test scope link\n";
        assert_eq!(
            managed_host_route_destinations(routes),
            BTreeSet::from([
                "94.182.147.91".parse().unwrap(),
                "94.182.147.107".parse().unwrap(),
            ])
        );
    }
}
