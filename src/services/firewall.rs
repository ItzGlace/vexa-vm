//! Atomic nftables enforcement for VM forwarding policy.
//!
//! Vexa-VM owns only the `bridge vexa_vm` table. Shared bridges use its forward
//! hook; routed per-VM bridges use its input/output hooks at the L2 boundary.
//! It never changes inet host input/output policy or the administrator's SSH
//! path. Tenant firewall/DDoS and full BCP38 remain opt-in; managed IP ownership
//! is a separate default-on host invariant.

use std::{net::IpAddr, path::Path, process::Stdio, time::Duration};

use ipnet::IpNet;
use serde::Serialize;
use tokio::{io::AsyncWriteExt, process::Command};

use crate::{
    error::{AppError, AppResult},
    hypervisor::{HypervisorError, PowerAction},
    models::{
        AddressFamily, FirewallDirection, FirewallProtocol, PortRange, Vm, VmFirewallRule,
        VmNetworkSecurity, VmState,
    },
    services::network_security::compile_vm_network_policy,
    state::AppState,
};

const TABLE_FAMILY: &str = "bridge";
const TABLE_NAME: &str = "vexa_vm";

#[derive(Clone, Debug, Default, Serialize)]
pub struct FirewallApplySummary {
    pub enforced: bool,
    pub active_vm_policies: usize,
    pub guarded_vms: usize,
    pub ip_ownership_guard_enabled: bool,
    pub bcp38_enabled: bool,
    pub changed: bool,
}

struct DesiredVmPolicy {
    vm: Vm,
    profile: VmNetworkSecurity,
    rules: Vec<VmFirewallRule>,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

/// Reconcile every policy in one checked nftables transaction. The database
/// records desired state first; an apply failure is returned and stored on the
/// affected profile instead of being reported as active.
pub async fn reconcile(state: &AppState) -> AppResult<FirewallApplySummary> {
    let _guard = state.network_security_lock.lock().await;
    let host_policy = state.db.hypervisor_network_security()?;
    let capabilities = state.hypervisor.capabilities().await?;
    if capabilities.backend != "libvirt" {
        return Ok(FirewallApplySummary {
            ip_ownership_guard_enabled: host_policy.ip_ownership_guard_enabled,
            bcp38_enabled: host_policy.bcp38_enabled,
            ..FirewallApplySummary::default()
        });
    }

    let mut managed_subnets = state
        .db
        .list_ip_pools()?
        .into_iter()
        .map(|pool| {
            let network = pool.cidr.parse::<IpNet>().map_err(|_| {
                AppError::Internal(format!("stored IP pool CIDR is invalid: {}", pool.cidr))
            })?;
            if network.addr().is_ipv4() != (pool.family == AddressFamily::V4) {
                return Err(AppError::Internal(format!(
                    "stored IP pool family does not match its CIDR: {}",
                    pool.cidr
                )));
            }
            Ok(network)
        })
        .collect::<AppResult<Vec<_>>>()?;
    managed_subnets.sort_by_key(ToString::to_string);
    managed_subnets.dedup();
    let ownership_guard_active =
        host_policy.ip_ownership_guard_enabled && !managed_subnets.is_empty();
    let mut desired = Vec::new();
    for vm in state.db.list_vms()? {
        let Some(profile) = state.db.vm_network_security(&vm.id)? else {
            continue;
        };
        let rules = state.db.list_vm_firewall_rules(&vm.id)?;
        let addresses = state.db.vm_ip_addresses(&vm.id)?;
        let ipv4 = addresses
            .iter()
            .filter(|item| item.family == AddressFamily::V4)
            .map(|item| item.address.clone())
            .collect();
        let ipv6 = addresses
            .iter()
            .filter(|item| item.family == AddressFamily::V6)
            .map(|item| item.address.clone())
            .collect();
        desired.push(DesiredVmPolicy {
            vm,
            profile,
            rules,
            ipv4,
            ipv6,
        });
    }
    desired.sort_by(|left, right| left.vm.id.cmp(&right.vm.id));

    let active_count = desired
        .iter()
        .filter(|item| {
            item.vm.libvirt_uuid.is_some()
                && (item.profile.firewall_enabled || item.profile.ddos_enabled)
        })
        .count();
    let guarded_count = if ownership_guard_active {
        desired
            .iter()
            .filter(|item| item.vm.libvirt_uuid.is_some())
            .count()
    } else {
        0
    };
    let may_have_owned_table = host_policy.last_applied_at.is_some()
        || desired
            .iter()
            .any(|item| item.profile.last_applied_at.is_some());
    let nft = match nft_binary() {
        Ok(path) => path,
        Err(_)
            if active_count == 0
                && guarded_count == 0
                && !host_policy.bcp38_enabled
                && !may_have_owned_table =>
        {
            // Nothing has ever been applied by Vexa-VM, so an absent nft
            // binary cannot leave stale Vexa-owned rules behind. Keep the
            // disabled revision unapplied: there was no host mutation to do.
            return Ok(FirewallApplySummary::default());
        }
        Err(error) => {
            record_reconcile_failure(state, &desired, host_policy.revision, &error.to_string());
            return Err(error);
        }
    };
    let table_exists = match table_exists(nft).await {
        Ok(exists) => exists,
        Err(error) => {
            record_reconcile_failure(state, &desired, host_policy.revision, &error.to_string());
            return Err(error);
        }
    };
    let script = match render_ruleset(
        &desired,
        host_policy.ip_ownership_guard_enabled,
        host_policy.bcp38_enabled,
        &managed_subnets,
        table_exists,
    ) {
        Ok(script) => script,
        Err(error) => {
            record_reconcile_failure(state, &desired, host_policy.revision, &error.to_string());
            return Err(error);
        }
    };
    let changed = !script.trim().is_empty();
    if changed {
        if let Err(error) = check_and_apply(nft, &script).await {
            let message = error.to_string();
            record_reconcile_failure(state, &desired, host_policy.revision, &message);
            return Err(error);
        }
    }
    for item in &desired {
        state
            .db
            .mark_vm_network_security_applied(&item.vm.id, item.profile.revision, None)?;
    }
    state
        .db
        .mark_hypervisor_network_security_applied(host_policy.revision, None)?;
    Ok(FirewallApplySummary {
        enforced: active_count > 0 || guarded_count > 0 || host_policy.bcp38_enabled,
        active_vm_policies: active_count,
        guarded_vms: guarded_count,
        ip_ownership_guard_enabled: host_policy.ip_ownership_guard_enabled,
        bcp38_enabled: host_policy.bcp38_enabled,
        changed,
    })
}

pub fn vm_policy_enabled(state: &AppState, vm_id: &str) -> AppResult<bool> {
    let profile = state.db.vm_network_security(vm_id)?;
    let host = state.db.hypervisor_network_security()?;
    let ownership_guard_active =
        host.ip_ownership_guard_enabled && !state.db.list_ip_pools()?.is_empty();
    Ok(ownership_guard_active
        || host.bcp38_enabled
        || profile
            .as_ref()
            .is_some_and(|profile| profile.firewall_enabled || profile.ddos_enabled))
}

/// Reconcile the atomic bridge ruleset and fail a protected VM closed if an
/// enabled desired policy cannot be installed. Disabling a policy still
/// returns apply errors, but does not stop a guest whose desired policy is off.
pub async fn reconcile_vm_fail_closed(
    state: &AppState,
    vm: &Vm,
) -> AppResult<FirewallApplySummary> {
    let required = vm_policy_enabled(state, &vm.id)?;
    match reconcile(state).await {
        Ok(summary) => Ok(summary),
        Err(error) if required => {
            if let Err(containment_error) =
                contain_vm_after_policy_failure(state, vm, &error.to_string()).await
            {
                return Err(AppError::Conflict(format!(
                    "enabled network protection could not be applied and the VM could not be contained: {containment_error}"
                )));
            }
            Err(AppError::Conflict(format!(
                "enabled network protection could not be applied; the VM remains stopped: {error}"
            )))
        }
        Err(error) => Err(error),
    }
}

/// A service restart must not leave already-running guests online without a
/// policy the administrator explicitly enabled. This is intentionally called
/// only after the atomic ruleset reconciliation has failed.
pub async fn fail_closed_after_reconcile_failure(
    state: &AppState,
    firewall_error: &str,
) -> AppResult<usize> {
    let mut contained = 0usize;
    let mut failures = Vec::new();
    for vm in state.db.list_vms()? {
        if !vm_policy_enabled(state, &vm.id)? {
            continue;
        }
        match contain_vm_after_policy_failure(state, &vm, firewall_error).await {
            Ok(was_active) => contained += usize::from(was_active),
            Err(error) => failures.push(format!("{}: {error}", vm.id)),
        }
    }
    if failures.is_empty() {
        Ok(contained)
    } else {
        Err(AppError::Hypervisor(format!(
            "{} protected VM(s) could not be contained after policy failure ({})",
            failures.len(),
            failures.join("; ")
        )))
    }
}

async fn contain_vm_after_policy_failure(
    state: &AppState,
    vm: &Vm,
    firewall_error: &str,
) -> Result<bool, String> {
    match state.hypervisor.get_vm(&vm.name).await {
        Ok(info) if info.state.is_active() => {
            state
                .hypervisor
                .power(&vm.name, PowerAction::ForceOff)
                .await
                .map_err(|error| {
                    tracing::error!(
                        vm_id = %vm.id,
                        %firewall_error,
                        stop_error = %error,
                        "network policy failed and VM could not be stopped"
                    );
                    error.to_string()
                })?;
            if let Err(error) = state.db.set_vm_state(
                &vm.id,
                VmState::Stopped,
                Some(VmState::Stopped),
                None,
                None,
            ) {
                tracing::error!(
                    vm_id = %vm.id,
                    %firewall_error,
                    error = %error,
                    "protected VM was stopped but its database state could not be updated"
                );
            }
            tracing::warn!(
                vm_id = %vm.id,
                %firewall_error,
                "stopped protected VM because its network policy could not be applied"
            );
            Ok(true)
        }
        Ok(_) | Err(HypervisorError::NotFound(_)) => Ok(false),
        Err(error) => {
            tracing::error!(
                vm_id = %vm.id,
                %firewall_error,
                inspect_error = %error,
                "network policy failed and VM state could not be verified"
            );
            Err(error.to_string())
        }
    }
}

fn record_reconcile_failure(
    state: &AppState,
    desired: &[DesiredVmPolicy],
    host_revision: u64,
    message: &str,
) {
    // The ruleset is one atomic transaction. A failure also means a requested
    // disable/removal was not applied, so every desired revision must expose
    // the failure rather than only profiles whose switches are currently on.
    for item in desired {
        let _ = state.db.mark_vm_network_security_applied(
            &item.vm.id,
            item.profile.revision,
            Some(message),
        );
    }
    let _ = state
        .db
        .mark_hypervisor_network_security_applied(host_revision, Some(message));
}

fn render_ruleset(
    desired: &[DesiredVmPolicy],
    ip_ownership_guard_enabled: bool,
    bcp38_enabled: bool,
    managed_subnets: &[IpNet],
    table_exists: bool,
) -> AppResult<String> {
    let ownership_guard_active = ip_ownership_guard_enabled && !managed_subnets.is_empty();
    let active = desired
        .iter()
        .filter(|item| {
            item.vm.libvirt_uuid.is_some()
                && (item.vm.tap_name.is_some()
                    || item.vm.state != crate::models::VmState::Stopped
                    || item.profile.firewall_enabled
                    || item.profile.ddos_enabled)
                && (item.profile.firewall_enabled
                    || item.profile.ddos_enabled
                    || ownership_guard_active
                    || bcp38_enabled
                    || item.vm.traffic_limit_bytes.is_some_and(|limit| limit > 0))
        })
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(if table_exists {
            format!("delete table {TABLE_FAMILY} {TABLE_NAME}\n")
        } else {
            String::new()
        });
    }

    let mut script = String::new();
    if table_exists {
        script.push_str(&format!("delete table {TABLE_FAMILY} {TABLE_NAME}\n"));
    }
    script.push_str(&format!("table {TABLE_FAMILY} {TABLE_NAME} {{\n"));
    for (index, item) in active.iter().enumerate() {
        if let Some(limit) = item
            .vm
            .traffic_limit_bytes
            .filter(|limit| *limit > item.vm.traffic_used_bytes)
        {
            script.push_str(&format!(
                "  quota vm{index}_traffic {{ over {limit} bytes used {} bytes; }}\n",
                item.vm.traffic_used_bytes,
            ));
        }
    }
    script.push_str("  chain forward { type filter hook forward priority -10; policy accept;\n");
    for (index, item) in active.iter().enumerate() {
        let interface = validated_interface_name(item.vm.tap_name.as_deref())?;
        // The TAP is the primary host-owned identity. When host BCP38 is
        // enabled, the per-TAP egress chain also pins the Ethernet source MAC;
        // destination MACs must remain unrestricted for broadcast/multicast.
        script.push_str(&format!(
            "    iifname \"{interface}\" jump vm{index}_egress\n"
        ));
        script.push_str(&format!(
            "    oifname \"{interface}\" jump vm{index}_ingress\n"
        ));
    }
    script.push_str("  }\n");
    // Shared bridges traverse the bridge forward hook. Vexa's routed per-VM
    // bridge terminates L2 at the host, so guest egress traverses bridge input
    // and routed ingress traverses bridge output. Scope all three hooks to the
    // same stable host-owned TAP to cover both layouts without touching inet
    // host input/output policy.
    script.push_str("  chain input { type filter hook input priority -10; policy accept;\n");
    for (index, item) in active.iter().enumerate() {
        let interface = validated_interface_name(item.vm.tap_name.as_deref())?;
        script.push_str(&format!(
            "    iifname \"{interface}\" jump vm{index}_egress\n"
        ));
    }
    script.push_str("  }\n");
    script.push_str("  chain output { type filter hook output priority -10; policy accept;\n");
    for (index, item) in active.iter().enumerate() {
        let interface = validated_interface_name(item.vm.tap_name.as_deref())?;
        script.push_str(&format!(
            "    oifname \"{interface}\" jump vm{index}_ingress\n"
        ));
    }
    script.push_str("  }\n");

    for (index, item) in active.iter().enumerate() {
        let compiled = compile_vm_network_policy(&item.profile, &item.rules)?;
        let quota_exceeded = crate::services::traffic::is_exceeded(
            item.vm.traffic_limit_bytes,
            item.vm.traffic_used_bytes,
        );
        script.push_str(&format!("  chain vm{index}_ingress {{\n"));
        if quota_exceeded {
            script.push_str("    counter drop\n");
        } else if item.vm.traffic_limit_bytes.is_some_and(|limit| limit > 0) {
            script.push_str(&format!("    quota name \"vm{index}_traffic\" counter drop\n"));
        }
        if ownership_guard_active {
            render_ip_ownership_guard(
                &mut script,
                FirewallDirection::Ingress,
                managed_subnets,
                &item.ipv4,
                &item.ipv6,
            )?;
        }
        render_ddos_rules(&mut script, &compiled);
        if compiled.firewall_enabled {
            script.push_str("    ct state established,related counter accept\n");
        }
        for rule in compiled
            .rules
            .iter()
            .filter(|rule| rule.direction == FirewallDirection::Ingress)
        {
            render_firewall_rule(&mut script, rule)?;
        }
        if compiled.firewall_enabled && compiled.default_ingress_action.as_str() != "accept" {
            script.push_str(&format!(
                "    counter {}\n",
                compiled.default_ingress_action.as_str()
            ));
        }
        script.push_str("  }\n");

        script.push_str(&format!("  chain vm{index}_egress {{\n"));
        if quota_exceeded {
            script.push_str("    counter drop\n");
        } else if item.vm.traffic_limit_bytes.is_some_and(|limit| limit > 0) {
            script.push_str(&format!("    quota name \"vm{index}_traffic\" counter drop\n"));
        }
        if ownership_guard_active {
            render_ip_ownership_guard(
                &mut script,
                FirewallDirection::Egress,
                managed_subnets,
                &item.ipv4,
                &item.ipv6,
            )?;
        }
        if bcp38_enabled {
            render_bcp38(
                &mut script,
                item.vm.mac_address.as_deref(),
                &item.ipv4,
                &item.ipv6,
            )?;
        }
        if compiled.firewall_enabled {
            script.push_str("    ct state established,related counter accept\n");
        }
        for rule in compiled
            .rules
            .iter()
            .filter(|rule| rule.direction == FirewallDirection::Egress)
        {
            render_firewall_rule(&mut script, rule)?;
        }
        if compiled.firewall_enabled && compiled.default_egress_action.as_str() != "accept" {
            script.push_str(&format!(
                "    counter {}\n",
                compiled.default_egress_action.as_str()
            ));
        }
        script.push_str("  }\n");
    }
    script.push_str("}\n");
    Ok(script)
}

/// Protect only Vexa-managed address ranges. This is deliberately separate
/// from full BCP38: unrelated source addresses are untouched, while packets
/// using a free, reserved, host-owned, or another VM's managed address are
/// rejected at the host-owned TAP boundary. Matching the TAP instead of a
/// guest-selected MAC keeps the policy effective after in-guest MAC changes.
fn render_ip_ownership_guard(
    script: &mut String,
    direction: FirewallDirection,
    managed_subnets: &[IpNet],
    ipv4: &[String],
    ipv6: &[String],
) -> AppResult<()> {
    let assigned_v4 = validated_assigned_addresses(ipv4, true)?;
    let assigned_v6 = validated_assigned_addresses(ipv6, false)?;
    for subnet in managed_subnets {
        let assigned = if subnet.addr().is_ipv4() {
            &assigned_v4
        } else {
            &assigned_v6
        };
        let owned = assigned
            .iter()
            .filter(|address| subnet.contains(*address))
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let (selector, address_selector) = match (direction, subnet.addr().is_ipv4()) {
            (FirewallDirection::Ingress, true) => ("ether type ip ip daddr", "ip daddr"),
            (FirewallDirection::Ingress, false) => ("ether type ip6 ip6 daddr", "ip6 daddr"),
            (FirewallDirection::Egress, true) => ("ether type ip ip saddr", "ip saddr"),
            (FirewallDirection::Egress, false) => ("ether type ip6 ip6 saddr", "ip6 saddr"),
        };
        render_managed_subnet_drop(script, selector, address_selector, subnet, &owned);
        if direction == FirewallDirection::Egress && subnet.addr().is_ipv4() {
            render_managed_subnet_drop(
                script,
                "ether type arp arp saddr ip",
                "arp saddr ip",
                subnet,
                &owned,
            );
        }
    }
    Ok(())
}

fn render_managed_subnet_drop(
    script: &mut String,
    selector: &str,
    address_selector: &str,
    subnet: &IpNet,
    owned: &[String],
) {
    script.push_str("    ");
    script.push_str(selector);
    script.push(' ');
    script.push_str(&subnet.to_string());
    if !owned.is_empty() {
        script.push(' ');
        script.push_str(address_selector);
        script.push_str(" != { ");
        script.push_str(&owned.join(", "));
        script.push_str(" }");
    }
    script.push_str(" counter drop\n");
}

fn validated_assigned_addresses(values: &[String], ipv4: bool) -> AppResult<Vec<IpAddr>> {
    values
        .iter()
        .map(|value| {
            let address = value.parse::<IpAddr>().map_err(|_| {
                AppError::Validation("stored assigned IP address is invalid".into())
            })?;
            if address.is_ipv4() != ipv4 {
                return Err(AppError::Validation(
                    "stored assigned IP address has the wrong family".into(),
                ));
            }
            Ok(address)
        })
        .collect()
}

fn render_ddos_rules(
    script: &mut String,
    policy: &crate::services::network_security::CompiledVmNetworkPolicy,
) {
    let Some(ddos) = policy.ddos.as_ref() else {
        return;
    };
    if ddos.drop_invalid_packets {
        script.push_str("    ct state invalid counter drop\n");
    }
    if let Some(limit) = ddos.syn_rate_limit_pps {
        script.push_str(&format!(
            "    tcp flags & (syn | ack) == syn limit rate over {limit}/second burst {} packets counter drop\n",
            limit.saturating_mul(2).max(1)
        ));
    }
    if let Some(limit) = ddos.udp_rate_limit_pps {
        script.push_str(&format!(
            "    meta l4proto udp limit rate over {limit}/second burst {} packets counter drop\n",
            limit.saturating_mul(2).max(1)
        ));
    }
    if let Some(limit) = ddos.icmp_rate_limit_pps {
        script.push_str(&format!(
            "    meta l4proto {{ icmp, ipv6-icmp }} limit rate over {limit}/second burst {} packets counter drop\n",
            limit.saturating_mul(2).max(1)
        ));
    }
    let new_limit = ddos
        .new_connection_limit_pps
        .or(ddos.port_scan_protection.then_some(50));
    if let Some(limit) = new_limit {
        script.push_str(&format!(
            "    ct state new meta l4proto tcp limit rate over {limit}/second burst {} packets counter drop\n",
            limit.saturating_mul(2).max(1)
        ));
    }
}

fn render_bcp38(
    script: &mut String,
    mac_address: Option<&str>,
    ipv4: &[String],
    ipv6: &[String],
) -> AppResult<()> {
    let mac_address = mac_address.ok_or_else(|| {
        AppError::Conflict("BCP38 requires the VM's configured MAC address".into())
    })?;
    crate::hypervisor::validate_mac_address(mac_address)?;
    // TAP scoping prevents one guest from affecting another chain, while the
    // source-MAC pin prevents FDB poisoning and tenant impersonation on a
    // shared bridge. This rule is emitted only for the explicit host BCP38
    // opt-in, so disabled protection has no packet-processing cost.
    script.push_str(&format!(
        "    ether saddr != {} counter drop\n",
        mac_address.to_ascii_lowercase()
    ));
    let mut allowed_v4 = vec!["0.0.0.0".to_owned()];
    for value in ipv4 {
        let address = value
            .parse::<IpAddr>()
            .map_err(|_| AppError::Validation("stored assigned IPv4 address is invalid".into()))?;
        if !address.is_ipv4() {
            return Err(AppError::Validation(
                "stored assigned IPv4 address has the wrong family".into(),
            ));
        }
        allowed_v4.push(address.to_string());
    }
    let mut allowed_v6 = vec!["::".to_owned(), "fe80::/10".to_owned()];
    for value in ipv6 {
        let address = value
            .parse::<IpAddr>()
            .map_err(|_| AppError::Validation("stored assigned IPv6 address is invalid".into()))?;
        if !address.is_ipv6() {
            return Err(AppError::Validation(
                "stored assigned IPv6 address has the wrong family".into(),
            ));
        }
        allowed_v6.push(address.to_string());
    }
    // Source validation must cover ARP as well as IPv4. Otherwise a guest
    // could pass the IP source check while poisoning the bridge's neighbour
    // cache with an address assigned to another tenant. 0.0.0.0 remains
    // available for RFC 5227 address probes during bootstrap.
    script.push_str(&format!(
        "    ether type arp arp saddr ip != {{ {} }} counter drop\n",
        allowed_v4.join(", ")
    ));
    script.push_str(&format!(
        "    ether type ip ip saddr != {{ {} }} counter drop\n",
        allowed_v4.join(", ")
    ));
    script.push_str(&format!(
        "    ether type ip6 ip6 saddr != {{ {} }} counter drop\n",
        allowed_v6.join(", ")
    ));
    Ok(())
}

fn render_firewall_rule(script: &mut String, rule: &VmFirewallRule) -> AppResult<()> {
    let mut tokens = Vec::new();
    if let Some(source) = rule.source_cidr.as_deref() {
        let parsed: ipnet::IpNet = source
            .parse()
            .map_err(|_| AppError::Validation("stored firewall source CIDR is invalid".into()))?;
        tokens.push(format!(
            "{} saddr {}",
            if parsed.addr().is_ipv4() { "ip" } else { "ip6" },
            parsed
        ));
    }
    if let Some(destination) = rule.destination_cidr.as_deref() {
        let parsed: ipnet::IpNet = destination
            .parse()
            .map_err(|_| AppError::Validation("stored firewall destination CIDR is invalid".into()))?;
        tokens.push(format!(
            "{} daddr {}",
            if parsed.addr().is_ipv4() { "ip" } else { "ip6" },
            parsed
        ));
    }
    match rule.protocol {
        FirewallProtocol::Any => {}
        FirewallProtocol::Tcp => tokens.push("meta l4proto tcp".into()),
        FirewallProtocol::Udp => tokens.push("meta l4proto udp".into()),
        FirewallProtocol::Icmp => tokens.push("meta l4proto icmp".into()),
        FirewallProtocol::Icmpv6 => tokens.push("meta l4proto ipv6-icmp".into()),
    }
    if matches!(rule.protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp) {
        let protocol = rule.protocol.as_str();
        if !rule.source_ports.is_empty() {
            tokens.push(format!("{protocol} sport {}", render_ports(&rule.source_ports)));
        }
        if !rule.destination_ports.is_empty() {
            tokens.push(format!("{protocol} dport {}", render_ports(&rule.destination_ports)));
        }
    }
    if rule.log {
        // A user-controlled logging rule must never be able to turn a packet
        // flood into unbounded kernel logging and disk I/O. The limiter is
        // per rule, preserving useful samples without becoming a DoS vector.
        tokens.push("limit rate 10/second burst 20 packets".into());
        tokens.push("log prefix \"vexa-vm \" flags all".into());
    }
    tokens.push("counter".into());
    tokens.push(rule.action.as_str().into());
    script.push_str("    ");
    script.push_str(&tokens.join(" "));
    script.push('\n');
    Ok(())
}

fn render_ports(ranges: &[PortRange]) -> String {
    let values = ranges
        .iter()
        .map(|range| {
            if range.start == range.end {
                range.start.to_string()
            } else {
                format!("{}-{}", range.start, range.end)
            }
        })
        .collect::<Vec<_>>();
    format!("{{ {} }}", values.join(", "))
}

fn validated_interface_name(value: Option<&str>) -> AppResult<&str> {
    let value = value.ok_or_else(|| {
        AppError::Conflict(
            "VM network protection requires a detected host interface; start the VM and retry"
                .into(),
        )
    })?;
    // Linux IFNAMSIZ includes the NUL terminator. Restrict to a conservative
    // nft-safe subset as defense in depth even though this value comes from
    // virsh rather than an untrusted packet.
    let valid = (1..=15).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));
    if valid {
        Ok(value)
    } else {
        Err(AppError::Validation(
            "stored VM host interface name is invalid".into(),
        ))
    }
}

fn nft_binary() -> AppResult<&'static Path> {
    [Path::new("/usr/sbin/nft"), Path::new("/usr/bin/nft")]
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| AppError::Configuration("nftables is required for network protection".into()))
}

async fn table_exists(nft: &Path) -> AppResult<bool> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(nft)
            .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| AppError::Internal("nftables table inspection timed out".into()))??;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("no such file") || stderr.contains("does not exist") {
        Ok(false)
    } else {
        Err(AppError::Internal(format!(
            "could not inspect Vexa-VM nftables table: {}",
            stderr.trim()
        )))
    }
}

async fn check_and_apply(nft: &Path, script: &str) -> AppResult<()> {
    run_nft(nft, &["--check", "--file", "-"], script).await?;
    run_nft(nft, &["--file", "-"], script).await
}

async fn run_nft(nft: &Path, arguments: &[&str], script: &str) -> AppResult<()> {
    let mut child = Command::new(nft)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| AppError::Internal("could not open nftables input".into()))?;
    stdin.write_all(script.as_bytes()).await?;
    stdin.shutdown().await?;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .map_err(|_| AppError::Internal("nftables apply timed out".into()))??;
    if output.status.success() {
        Ok(())
    } else {
        let message = String::from_utf8_lossy(&output.stderr);
        Err(AppError::Validation(format!(
            "nftables rejected the network policy: {}",
            message.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FirewallAction, VmState};
    use serde_json::json;

    fn vm() -> Vm {
        Vm {
            id: "vm-1".into(),
            name: "test".into(),
            hostname: "test".into(),
            description: String::new(),
            os_family: "linux".into(),
            iso_id: None,
            state: VmState::Stopped,
            desired_state: VmState::Stopped,
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 10,
            disk_format: "qcow2".into(),
            firmware: "bios".into(),
            machine_type: None,
            bridge: Some("br0".into()),
            tap_name: Some("vexa123456".into()),
            mac_address: Some("52:54:00:12:34:56".into()),
            network_limit_mbps: None,
            traffic_limit_bytes: None,
            traffic_used_bytes: 0,
            root_username: "root".into(),
            guest_agent: false,
            autostart: false,
            timezone: None,
            libvirt_uuid: Some("11111111-2222-3333-4444-555555555555".into()),
            vnc_display: None,
            metadata: json!({}),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn profile(enabled: bool) -> VmNetworkSecurity {
        VmNetworkSecurity {
            vm_id: "vm-1".into(),
            firewall_enabled: enabled,
            ddos_enabled: false,
            default_ingress_action: FirewallAction::Accept,
            default_egress_action: FirewallAction::Accept,
            syn_rate_limit_pps: None,
            udp_rate_limit_pps: None,
            icmp_rate_limit_pps: None,
            new_connection_limit_pps: None,
            concurrent_connection_limit: None,
            port_scan_protection: false,
            drop_invalid_packets: false,
            revision: 0,
            applied_revision: None,
            last_applied_at: None,
            last_error: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn completely_disabled_policy_creates_no_table() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec![],
            ipv6: vec![],
        }];
        assert_eq!(render_ruleset(&desired, false, false, &[], false).unwrap(), "");
    }

    #[test]
    fn configured_thresholds_remain_inert_while_ddos_is_disabled() {
        let mut disabled = profile(false);
        disabled.syn_rate_limit_pps = Some(5_000);
        disabled.udp_rate_limit_pps = Some(25_000);
        disabled.icmp_rate_limit_pps = Some(1_000);
        disabled.new_connection_limit_pps = Some(10_000);
        disabled.drop_invalid_packets = true;
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: disabled,
            rules: vec![],
            ipv4: vec![],
            ipv6: vec![],
        }];
        assert_eq!(render_ruleset(&desired, false, false, &[], false).unwrap(), "");
    }

    #[test]
    fn exceeded_quota_is_dropped_even_when_optional_firewall_is_disabled() {
        let mut over_quota = vm();
        over_quota.traffic_limit_bytes = Some(100);
        over_quota.traffic_used_bytes = 100;
        let desired = vec![DesiredVmPolicy {
            vm: over_quota,
            profile: profile(false),
            rules: vec![],
            ipv4: vec![],
            ipv6: vec![],
        }];
        let script = render_ruleset(&desired, false, false, &[], false).unwrap();
        assert!(script.contains("table bridge vexa_vm"));
        assert_eq!(script.matches("counter drop").count(), 2);
        assert!(script.contains("iifname \"vexa123456\""));
        assert!(script.contains("oifname \"vexa123456\""));
    }

    #[test]
    fn finite_quota_uses_one_shared_kernel_byte_counter_for_both_directions() {
        let mut finite = vm();
        finite.traffic_limit_bytes = Some(1_000);
        finite.traffic_used_bytes = 250;
        let desired = vec![DesiredVmPolicy {
            vm: finite,
            profile: profile(false),
            rules: vec![],
            ipv4: vec![],
            ipv6: vec![],
        }];
        let script = render_ruleset(&desired, false, false, &[], false).unwrap();
        assert!(script.contains("quota vm0_traffic { over 1000 bytes used 250 bytes; }"));
        assert_eq!(
            script
                .matches("quota name \"vm0_traffic\" counter drop")
                .count(),
            2
        );
    }

    #[test]
    fn disabling_the_last_policy_only_removes_the_owned_table() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec![],
            ipv6: vec![],
        }];
        assert_eq!(
            render_ruleset(&desired, false, false, &[], true).unwrap(),
            "delete table bridge vexa_vm\n"
        );
    }

    #[test]
    fn enabled_policy_is_scoped_to_bridge_forwarding_and_host_interface() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(true),
            rules: vec![],
            ipv4: vec!["192.0.2.10".into()],
            ipv6: vec![],
        }];
        let script = render_ruleset(&desired, false, false, &[], false).unwrap();
        assert!(script.contains("table bridge vexa_vm"));
        assert!(script.contains("hook forward"));
        assert!(script.contains("iifname \"vexa123456\""));
        assert!(script.contains("oifname \"vexa123456\""));
        assert!(!script.contains("ether saddr 52:54:00:12:34:56"));
        assert_eq!(script.matches("ct state established,related counter accept").count(), 2);
        assert!(script.contains("chain input { type filter hook input"));
        assert!(script.contains("chain output { type filter hook output"));
        assert!(!script.contains("table inet"));
        assert!(!script.contains("arp saddr ip"));
        assert!(!script.contains("ip saddr !="));
    }

    #[test]
    fn ownership_guard_limits_managed_subnets_without_enabling_bcp38() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["192.0.2.10".into()],
            ipv6: vec!["2001:db8::10".into()],
        }];
        let subnets = vec![
            "192.0.2.0/24".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ];
        let script = render_ruleset(&desired, true, false, &subnets, false).unwrap();
        assert!(script.contains(
            "ether type ip ip daddr 192.0.2.0/24 ip daddr != { 192.0.2.10 } counter drop"
        ));
        assert!(script.contains(
            "ether type ip ip saddr 192.0.2.0/24 ip saddr != { 192.0.2.10 } counter drop"
        ));
        assert!(script.contains(
            "ether type arp arp saddr ip 192.0.2.0/24 arp saddr ip != { 192.0.2.10 } counter drop"
        ));
        assert!(script.contains(
            "ether type ip ip daddr 198.51.100.0/24 counter drop"
        ));
        assert!(script.contains(
            "ether type ip6 ip6 daddr 2001:db8::/64 ip6 daddr != { 2001:db8::10 } counter drop"
        ));
        assert!(!script.contains("ether saddr !="));
        assert!(!script.contains("0.0.0.0/0"));
    }

    #[test]
    fn disabled_ownership_guard_leaves_managed_subnets_inert() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["192.0.2.10".into()],
            ipv6: vec![],
        }];
        let subnets = vec!["192.0.2.0/24".parse().unwrap()];
        assert_eq!(
            render_ruleset(&desired, false, false, &subnets, false).unwrap(),
            ""
        );
    }

    #[test]
    fn ownership_guard_rejects_invalid_stored_assignments() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["192.0.2.10 } counter accept".into()],
            ipv6: vec![],
        }];
        let subnets = vec!["192.0.2.0/24".parse().unwrap()];
        assert!(render_ruleset(&desired, true, false, &subnets, false).is_err());
    }

    #[test]
    fn a_host_interface_is_required_for_vm_policy_scoping() {
        let mut guest = vm();
        guest.tap_name = None;
        let desired = vec![DesiredVmPolicy {
            vm: guest,
            profile: profile(true),
            rules: vec![],
            ipv4: vec![],
            ipv6: vec![],
        }];
        assert!(render_ruleset(&desired, false, false, &[], false).is_err());
    }

    #[test]
    fn bcp38_allows_only_assigned_sources_plus_bootstrap_addresses() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["192.0.2.10".into()],
            ipv6: vec!["2001:db8::10".into()],
        }];
        let script = render_ruleset(&desired, false, true, &[], false).unwrap();
        assert!(script.contains("192.0.2.10"));
        assert!(script.contains("2001:db8::10"));
        assert!(script.contains("fe80::/10"));
        assert!(script.contains("ether saddr != 52:54:00:12:34:56 counter drop"));
        assert!(script.contains("ether type arp arp saddr ip !="));
    }

    #[test]
    fn bcp38_requires_a_valid_configured_mac_address() {
        let mut guest = vm();
        guest.mac_address = None;
        let desired = vec![DesiredVmPolicy {
            vm: guest,
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["192.0.2.10".into()],
            ipv6: vec![],
        }];
        assert!(render_ruleset(&desired, false, true, &[], false).is_err());
    }

    #[test]
    fn bcp38_ignores_unprovisioned_database_records_without_a_domain() {
        let mut record = vm();
        record.libvirt_uuid = None;
        record.tap_name = None;
        let desired = vec![DesiredVmPolicy {
            vm: record,
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["192.0.2.10".into()],
            ipv6: vec![],
        }];
        assert_eq!(render_ruleset(&desired, false, true, &[], false).unwrap(), "");
    }

    #[test]
    fn bcp38_rejects_invalid_or_misclassified_stored_addresses() {
        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["192.0.2.10 } counter accept".into()],
            ipv6: vec![],
        }];
        assert!(render_ruleset(&desired, false, true, &[], false).is_err());

        let desired = vec![DesiredVmPolicy {
            vm: vm(),
            profile: profile(false),
            rules: vec![],
            ipv4: vec!["2001:db8::10".into()],
            ipv6: vec![],
        }];
        assert!(render_ruleset(&desired, false, true, &[], false).is_err());
    }

    #[test]
    fn unsafe_host_interface_names_are_rejected_before_rendering() {
        let mut guest = vm();
        guest.tap_name = Some("tap0\" accept".into());
        let desired = vec![DesiredVmPolicy {
            vm: guest,
            profile: profile(true),
            rules: vec![],
            ipv4: vec![],
            ipv6: vec![],
        }];
        assert!(render_ruleset(&desired, false, false, &[], false).is_err());
    }

    #[test]
    fn packet_logging_is_rate_limited() {
        let rule = VmFirewallRule {
            id: "rule-1".into(),
            vm_id: "vm-1".into(),
            priority: 100,
            direction: FirewallDirection::Ingress,
            action: FirewallAction::Drop,
            protocol: FirewallProtocol::Tcp,
            source_cidr: None,
            destination_cidr: None,
            source_ports: vec![],
            destination_ports: vec![PortRange::single(22)],
            log: true,
            enabled: true,
            description: String::new(),
            owner_type: "admin".into(),
            owner_id: None,
            created_at: 0,
            updated_at: 0,
        };
        let mut script = String::new();
        render_firewall_rule(&mut script, &rule).unwrap();
        assert!(script.contains("limit rate 10/second burst 20 packets log prefix"));
    }

    #[test]
    fn descriptions_and_owner_metadata_never_enter_nftables_source() {
        let rule = VmFirewallRule {
            id: "rule-1".into(),
            vm_id: "vm-1".into(),
            priority: 100,
            direction: FirewallDirection::Ingress,
            action: FirewallAction::Drop,
            protocol: FirewallProtocol::Tcp,
            source_cidr: Some("192.0.2.0/24".into()),
            destination_cidr: None,
            source_ports: vec![],
            destination_ports: vec![PortRange::single(22)],
            log: false,
            enabled: true,
            description: "\" } counter accept\nadd table inet injected".into(),
            owner_type: "customer_token\nadd rule".into(),
            owner_id: Some("actor\" }".into()),
            created_at: 0,
            updated_at: 0,
        };
        let mut script = String::new();
        render_firewall_rule(&mut script, &rule).unwrap();
        assert_eq!(
            script,
            "    ip saddr 192.0.2.0/24 meta l4proto tcp tcp dport { 22 } counter drop\n"
        );
    }
}
