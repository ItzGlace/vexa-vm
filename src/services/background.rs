use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};
use tokio::{io::AsyncWriteExt, process::Command, time::MissedTickBehavior};
use tracing::{debug, error, info, warn};

use crate::{
    error::{AppError, AppResult},
    hypervisor::{
        CreateVmRequest, HypervisorError, PowerAction, ReinstallVmRequest, ResizeVmRequest, SnapshotRequest,
        VmPowerState, VmStats,
    },
    models::{
        GuestToolsPlatform, GuestToolsProvisioner, GuestToolsStatus, HostMetric, Job, NewAuditEvent, NewJob,
        NewVm, VmMetric, VmPatch, VmState, STAGED_GUEST_TOOLS_GENERATION_FIELD,
        STAGED_PASSWORD_ENVELOPE_FIELD,
    },
    security::vm_password_context,
    state::{normalize_guest_locale, validate_ntp_server, validate_timezone_name, AppState},
};

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Default)]
struct PreviousVmSample {
    sampled_at: i64,
    stats: VmStats,
    traffic_generation: u64,
}

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(routed_network_loop(state.clone()));
    tokio::spawn(inventory_loop(state.clone()));
    tokio::spawn(metrics_loop(state.clone()));
    tokio::spawn(memory_entitlement_loop(state.clone()));
    tokio::spawn(traffic_quota_loop(state.clone()));
    tokio::spawn(network_security_loop(state.clone()));
    tokio::spawn(guest_tools_health_loop(state.clone()));
    tokio::spawn(update_status_audit_loop(state.clone()));
    tokio::spawn(job_loop(state.clone()));
    tokio::spawn(maintenance_loop(state));
}

async fn memory_entitlement_loop(state: Arc<AppState>) {
    // Repair domains created by older releases quickly. Those releases used
    // the overcommit ratio as a guest-visible boot target, so a 4 GiB VM at
    // 1.5x could incorrectly boot with only about 2.7 GiB. Overcommit is now
    // admission accounting only; every running guest keeps its entitlement.
    tokio::time::sleep(Duration::from_secs(5)).await;
    loop {
        if let Err(error) = restore_memory_entitlements(&state).await {
            warn!(error = %error, "memory entitlement reconciliation failed");
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

async fn restore_memory_entitlements(state: &AppState) -> AppResult<()> {
    for vm in state
        .db
        .list_vms()?
        .into_iter()
        .filter(|vm| vm.state == VmState::Running)
    {
        let stats = match state.hypervisor.stats(&vm.name).await {
            Ok(stats) => stats,
            Err(error) => {
                debug!(vm_id = %vm.id, error = %error, "could not sample VM for balloon reconciliation");
                continue;
            }
        };
        let current_mib = stats
            .memory_available_bytes
            .unwrap_or(vm.memory_mib.saturating_mul(MIB))
            .checked_div(MIB)
            .unwrap_or(vm.memory_mib)
            .clamp(256, vm.memory_mib);
        if !memory_entitlement_needs_restore(current_mib, vm.memory_mib) {
            continue;
        }
        match state.hypervisor.set_memory_balloon(&vm.name, vm.memory_mib).await {
            Ok(()) => {
                info!(vm = %vm.name, current_mib, entitlement_mib = vm.memory_mib, "restored full VM memory entitlement")
            }
            Err(error) => {
                warn!(vm = %vm.name, entitlement_mib = vm.memory_mib, error = %error, "could not restore VM memory entitlement")
            }
        }
    }
    Ok(())
}

fn memory_entitlement_needs_restore(current_mib: u64, entitlement_mib: u64) -> bool {
    current_mib.saturating_add(64) < entitlement_mib
}

async fn routed_network_loop(state: Arc<AppState>) {
    loop {
        match state.db.list_vms() {
            Ok(vms) => {
                for vm in vms {
                    if let Err(error) = crate::services::routed_network::reconcile_vm(&state, &vm).await {
                        warn!(vm_id = %vm.id, error = %error, "routed VM network reconciliation failed");
                    }
                }
            }
            Err(error) => warn!(error = %error, "could not list routed VM networks"),
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn guest_tools_health_loop(state: Arc<AppState>) {
    // Bootstrap jobs own initial readiness. Start regular probes after a short
    // grace period, then bound concurrency so an offline fleet cannot exhaust
    // blocking threads or serialize the sweep for many minutes.
    tokio::time::sleep(Duration::from_secs(60)).await;
    loop {
        let candidates = match state.db.list_vms() {
            Ok(vms) => {
                let mut candidates = Vec::new();
                for vm in vms.into_iter().filter(|vm| vm.state == VmState::Running) {
                    match state.db.vm_guest_tools(&vm.id) {
                        Ok(Some(record)) if record.enabled => {
                            match state.db.installed_vm_guest_tools_rotation_generation(&vm.id) {
                                Ok(generation) => candidates.push((vm, generation)),
                                Err(error) => {
                                    warn!(vm_id = %vm.id, error = %error, "could not inspect Guest Tools rotation for health sweep")
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            warn!(vm_id = %vm.id, error = %error, "could not inspect Guest Tools state for health sweep")
                        }
                    }
                }
                candidates
            }
            Err(error) => {
                warn!(error = %error, "could not list VMs for Guest Tools health sweep");
                Vec::new()
            }
        };
        stream::iter(candidates)
            .for_each_concurrent(Some(16), |(vm, generation)| {
                let state = Arc::clone(&state);
                async move {
                    // Use the version-matched bootstrap path even without a
                    // pending rotation. Besides health, this recovers seed
                    // retirement after a worker crash or externally triggered
                    // autostart; a plain probe has no media-lifecycle step.
                    match crate::services::guest_tools::bootstrap(&state, &vm, generation.as_deref()).await {
                        Ok(result) if result.promoted_rotation => {
                            let _ = state.db.append_audit(&NewAuditEvent {
                                actor_type: "system".into(),
                                actor_id: Some("guest-tools-health".into()),
                                action: "vm.guest_tools.rotation.promoted".into(),
                                resource_type: "vm".into(),
                                resource_id: Some(vm.id.clone()),
                                request_id: None,
                                source_ip: None,
                                user_agent: None,
                                success: true,
                                details: json!({ "installed_version": result.installed_version }),
                            });
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let _ = state.db.update_vm_guest_tools_status(
                                &vm.id,
                                GuestToolsStatus::Unavailable,
                                None,
                                Some(&error.to_string()),
                                false,
                            );
                        }
                    }
                }
            })
            .await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn update_status_audit_loop(state: Arc<AppState>) {
    loop {
        match crate::services::updater::read_durable_update_statuses() {
            Ok(statuses) => {
                for status in statuses.into_iter().filter(|status| status.outcome.is_terminal()) {
                    let request_id = status.request_id.clone();
                    let action = match status.operation.as_deref() {
                        Some("activate" | "recover") => "update.activate",
                        Some("rollback" | "recover_rollback") => "update.rollback",
                        _ => "update.executor",
                    };
                    let outcome = status.outcome.as_str();
                    let details = json!({
                        "operation": &status.operation,
                        "release": &status.release,
                        "outcome": outcome,
                        "phase": &status.phase,
                        "completed_at": status.completed_at,
                        "rollback": &status.rollback,
                    });
                    if let Err(error) = state.db.import_update_status_audit(
                        &request_id,
                        outcome,
                        &NewAuditEvent {
                            actor_type: "system".into(),
                            actor_id: Some("vexa-update-helper".into()),
                            action: action.into(),
                            resource_type: "update_request".into(),
                            resource_id: Some(request_id.clone()),
                            request_id: Some(request_id.clone()),
                            source_ip: None,
                            user_agent: None,
                            success: status.outcome
                                == crate::services::updater::DurableUpdateOutcome::Succeeded,
                            details,
                        },
                    ) {
                        warn!(request_id = %request_id, error = %error, "could not import update helper audit status");
                    }
                }
            }
            Err(error) => warn!(error = %error, "could not read update helper statuses"),
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn network_security_loop(state: Arc<AppState>) {
    loop {
        if let Err(error) = crate::services::firewall::reconcile(&state).await {
            warn!(error = %error, "network security policy reconciliation failed");
            if let Err(containment_error) =
                crate::services::firewall::fail_closed_after_reconcile_failure(&state, &error.to_string())
                    .await
            {
                error!(
                    error = %containment_error,
                    "one or more protected VMs could not be contained"
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn traffic_quota_loop(state: Arc<AppState>) {
    // Reapply every blocked link once after process startup. The persistent
    // database flag records ownership, while libvirt remains authoritative for
    // the actual live/config link state.
    let mut force = true;
    loop {
        if let Err(error) = crate::services::traffic::reconcile_all(&state, force).await {
            warn!(error = %error, "traffic quota sweep failed");
        }
        force = false;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn inventory_loop(state: Arc<AppState>) {
    loop {
        if let Err(error) = reconcile_hypervisor_inventory(&state).await {
            warn!(error = %error, "hypervisor inventory reconciliation failed");
        }
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

async fn reconcile_hypervisor_inventory(state: &AppState) -> AppResult<()> {
    let inventory = state.hypervisor.list_vms().await?;
    let mut stored = state.db.list_vms()?;
    for info in inventory {
        let uuid = info.uuid.as_ref().map(ToString::to_string);
        let by_name = stored
            .iter()
            .find(|vm| vm.name.eq_ignore_ascii_case(&info.name))
            .cloned();
        let by_uuid = uuid.as_deref().and_then(|uuid| {
            stored
                .iter()
                .find(|vm| {
                    vm.libvirt_uuid
                        .as_deref()
                        .is_some_and(|stored| stored.eq_ignore_ascii_case(uuid))
                })
                .cloned()
        });
        if let (Some(named), Some(domain_uuid)) = (&by_name, uuid.as_deref()) {
            if named
                .libvirt_uuid
                .as_deref()
                .is_some_and(|stored_uuid| !stored_uuid.eq_ignore_ascii_case(domain_uuid))
            {
                warn!(
                    domain = %info.name,
                    uuid = domain_uuid,
                    vm_id = %named.id,
                    stored_uuid = named.libvirt_uuid.as_deref().unwrap_or("unknown"),
                    "refusing to replace a database VM identity with a same-name libvirt domain"
                );
                continue;
            }
        }
        if let (Some(named), Some(identified)) = (&by_name, &by_uuid) {
            if named.id != identified.id {
                warn!(
                    domain = %info.name,
                    uuid = uuid.as_deref().unwrap_or("unknown"),
                    name_vm_id = %named.id,
                    uuid_vm_id = %identified.id,
                    "libvirt domain identity conflicts with two database VMs"
                );
                continue;
            }
        }
        if let Some(mut vm) = by_uuid.or(by_name) {
            if vm.name != info.name {
                match state.db.reconcile_vm_name(&vm.id, &info.name) {
                    Ok(renamed) => vm = renamed,
                    Err(error) => {
                        warn!(domain = %info.name, vm_id = %vm.id, error = %error, "could not reconcile libvirt VM name");
                        continue;
                    }
                }
            }
            if let Err(error) = sync_vm_info(state, Some(&vm.id), &info) {
                warn!(domain = %info.name, vm_id = %vm.id, error = %error, "could not synchronize libvirt VM");
            }
            continue;
        }

        if !info.persistent || info.vcpus == 0 || info.memory_mib < 256 || info.disk_bytes == 0 {
            warn!(
                domain = %info.name,
                persistent = info.persistent,
                vcpus = info.vcpus,
                memory_mib = info.memory_mib,
                disk_bytes = info.disk_bytes,
                "skipping libvirt domain that cannot be imported safely"
            );
            continue;
        }
        let disk_format = info
            .disk_path
            .as_deref()
            .and_then(|path| path.extension())
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .filter(|value| matches!(value.as_str(), "raw" | "img" | "qcow" | "qcow2"))
            .unwrap_or_else(|| "qcow2".into());
        let spec = NewVm {
            name: info.name.clone(),
            hostname: info.name.clone(),
            description: "Imported from the local libvirt inventory".into(),
            os_family: "unknown".into(),
            iso_id: None,
            vcpus: info.vcpus,
            memory_mib: info.memory_mib,
            disk_gib: bytes_to_gib_ceil(info.disk_bytes),
            disk_format,
            firmware: "bios".into(),
            machine_type: None,
            bridge: info.bridge.clone(),
            tap_name: info.interface_name.clone(),
            mac_address: info.mac_address.clone(),
            network_limit_mbps: None,
            traffic_limit_bytes: None,
            root_username: "root".into(),
            guest_agent: false,
            autostart: info.autostart,
            timezone: None,
            metadata: json!({
                "imported_from_libvirt": true,
                "imported_at": Utc::now().timestamp(),
                "libvirt_uuid": uuid.clone(),
                "disk_path": info.disk_path.clone(),
                "password_available": false,
            }),
        };
        match state.db.create_vm(&spec) {
            Ok(vm) => {
                if let Err(error) = sync_vm_info(state, Some(&vm.id), &info) {
                    let _ = state.db.delete_vm(&vm.id);
                    warn!(domain = %info.name, error = %error, "could not finish importing libvirt VM");
                    continue;
                }
                info!(domain = %info.name, vm_id = %vm.id, "imported pre-existing libvirt VM");
                if let Some(imported) = state.db.get_vm(&vm.id)? {
                    stored.push(imported);
                }
            }
            Err(error) => {
                warn!(domain = %info.name, error = %error, "could not import libvirt VM");
            }
        }
    }
    Ok(())
}

async fn metrics_loop(state: Arc<AppState>) {
    let mut previous: HashMap<String, PreviousVmSample> = HashMap::new();
    loop {
        if let Err(error) = sample_metrics(&state, &mut previous).await {
            warn!(error = %error, "metrics sample failed");
        }
        let seconds = state
            .setting_u64("general", "sample_interval_seconds")
            .unwrap_or(None)
            .unwrap_or(state.config.metrics_interval.as_secs())
            .clamp(5, 3600);
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }
}

async fn sample_metrics(state: &AppState, previous: &mut HashMap<String, PreviousVmSample>) -> AppResult<()> {
    let host = state.host_detector.sample().await?;
    let primary_interface = state.host_info.read().await.primary_interface.clone();
    let primary_metrics = primary_interface
        .as_deref()
        .and_then(|name| host.interfaces.iter().find(|item| item.name == name));
    let network_rx_bytes = primary_metrics.map(|item| item.rx_bytes).unwrap_or_else(|| {
        host.interfaces
            .iter()
            .filter(|item| item.name != "lo")
            .map(|item| item.rx_bytes)
            .sum()
    });
    let network_tx_bytes = primary_metrics.map(|item| item.tx_bytes).unwrap_or_else(|| {
        host.interfaces
            .iter()
            .filter(|item| item.name != "lo")
            .map(|item| item.tx_bytes)
            .sum()
    });
    let network_rx_bps = primary_metrics
        .map(|item| item.rx_bytes_per_second)
        .unwrap_or_else(|| {
            host.interfaces
                .iter()
                .filter(|item| item.name != "lo")
                .map(|item| item.rx_bytes_per_second)
                .sum()
        });
    let network_tx_bps = primary_metrics
        .map(|item| item.tx_bytes_per_second)
        .unwrap_or_else(|| {
            host.interfaces
                .iter()
                .filter(|item| item.name != "lo")
                .map(|item| item.tx_bytes_per_second)
                .sum()
        });
    let disk_read_bps = host
        .block_devices
        .iter()
        .map(|item| item.read_bytes_per_second)
        .sum();
    let disk_write_bps = host
        .block_devices
        .iter()
        .map(|item| item.write_bytes_per_second)
        .sum();
    let root_filesystem = host
        .filesystems
        .iter()
        .find(|item| item.mount_point == "/")
        .or_else(|| host.filesystems.iter().max_by_key(|item| item.total_bytes));
    let disk_total_bytes = root_filesystem.map(|item| item.total_bytes).unwrap_or_default();
    let disk_used_bytes = root_filesystem.map(|item| item.used_bytes).unwrap_or_default();
    let sampled_at = host.sampled_at.timestamp();
    state.db.insert_host_metric(&HostMetric {
        sampled_at,
        cpu_percent: host.cpu_usage_pct,
        load_one: host.load_1m,
        load_five: host.load_5m,
        load_fifteen: host.load_15m,
        memory_total_bytes: host.memory.total_bytes,
        memory_used_bytes: host.memory_used_bytes,
        swap_total_bytes: host.memory.swap_total_bytes,
        swap_used_bytes: host
            .memory
            .swap_total_bytes
            .saturating_sub(host.memory.swap_free_bytes),
        disk_total_bytes,
        disk_used_bytes,
        disk_read_bps,
        disk_write_bps,
        network_rx_bytes,
        network_tx_bytes,
        network_rx_bps,
        network_tx_bps,
        uptime_seconds: host.uptime_seconds,
        metadata: json!({
            "interfaces": host.interfaces,
            "block_devices": host.block_devices,
            "window_ms": host.window_ms,
        }),
    })?;

    for vm in state.db.list_vms()? {
        // The inventory loop already refreshes domain state, capacity and
        // interface details every five minutes. Re-inspecting all of that for
        // every metrics sample launches several virsh processes per VM and
        // can keep a larger node permanently CPU-bound. The metrics hot path
        // needs only domstats; lifecycle operations and the inventory loop
        // keep the stored VM definition current.
        let Ok(stats) = state.hypervisor.stats(&vm.name).await else {
            continue;
        };
        let prior = previous.get(&vm.id).cloned().unwrap_or_default();
        let elapsed = sampled_at.saturating_sub(prior.sampled_at).max(1) as f64;
        let cpu_percent = if prior.sampled_at == 0 {
            0.0
        } else {
            (stats.cpu_time_ns.saturating_sub(prior.stats.cpu_time_ns) as f64
                / (elapsed * 1_000_000_000.0)
                / f64::from(vm.vcpus.max(1))
                * 100.0)
                .clamp(0.0, 100.0)
        };
        let disk_read_bps = if prior.sampled_at == 0 {
            0.0
        } else {
            delta_rate(stats.disk_read_bytes, prior.stats.disk_read_bytes, elapsed)
        };
        let disk_write_bps = if prior.sampled_at == 0 {
            0.0
        } else {
            delta_rate(stats.disk_write_bytes, prior.stats.disk_write_bytes, elapsed)
        };
        let network_rx_bps = if prior.sampled_at == 0 {
            0.0
        } else {
            delta_rate(stats.network_rx_bytes, prior.stats.network_rx_bytes, elapsed)
        };
        let network_tx_bps = if prior.sampled_at == 0 {
            0.0
        } else {
            delta_rate(stats.network_tx_bytes, prior.stats.network_tx_bytes, elapsed)
        };
        let _traffic_guard = state.traffic_lock.lock().await;
        // Re-read after taking the lock: an administrator may have reset the
        // accounting period while hypervisor statistics were being sampled.
        let Some(current_vm) = state.db.get_vm(&vm.id)? else {
            previous.remove(&vm.id);
            continue;
        };
        let traffic_generation = state
            .traffic_accounting_generations
            .lock()
            .await
            .get(&vm.id)
            .copied()
            .unwrap_or_default();
        let traffic_delta = accounted_traffic_delta(&prior, &stats, traffic_generation);
        let traffic_used_bytes = current_vm.traffic_used_bytes.saturating_add(traffic_delta);
        state.db.insert_vm_metric(&VmMetric {
            vm_id: vm.id.clone(),
            sampled_at,
            cpu_percent,
            memory_used_bytes: stats.memory_current_bytes.unwrap_or_default(),
            memory_total_bytes: stats
                .memory_available_bytes
                .unwrap_or(vm.memory_mib.saturating_mul(1024 * 1024)),
            disk_read_bytes: stats.disk_read_bytes,
            disk_write_bytes: stats.disk_write_bytes,
            disk_read_bps,
            disk_write_bps,
            network_rx_bytes: stats.network_rx_bytes,
            network_tx_bytes: stats.network_tx_bytes,
            network_rx_bps,
            network_tx_bps,
            traffic_used_bytes,
            traffic_limit_bytes: current_vm.traffic_limit_bytes,
            metadata: Value::Null,
        })?;
        if let Err(error) = crate::services::traffic::reconcile_vm_locked(state, &vm.id, false).await {
            warn!(vm_id = %vm.id, vm = %vm.name, error = %error, "traffic quota transition failed");
        }
        drop(_traffic_guard);
        previous.insert(
            vm.id,
            PreviousVmSample {
                sampled_at,
                stats,
                traffic_generation,
            },
        );
    }
    Ok(())
}

fn delta_rate(current: u64, previous: u64, elapsed: f64) -> f64 {
    current.saturating_sub(previous) as f64 / elapsed
}

fn accounted_traffic_delta(prior: &PreviousVmSample, current: &VmStats, traffic_generation: u64) -> u64 {
    if prior.sampled_at == 0 || prior.traffic_generation != traffic_generation {
        return 0;
    }
    // libvirt reports zeroed interface counters while a domain interface is
    // temporarily unavailable (shutdown, rebuild, reconnect, or daemon race).
    // Treat the first non-zero sample after that gap as a fresh baseline. If we
    // subtract zero here, the VM's entire lifetime counter is charged again.
    if (prior.stats.network_rx_bytes == 0 && prior.stats.network_tx_bytes == 0)
        && (current.network_rx_bytes > 0 || current.network_tx_bytes > 0)
    {
        return 0;
    }
    current
        .network_rx_bytes
        .saturating_sub(prior.stats.network_rx_bytes)
        .saturating_add(
            current
                .network_tx_bytes
                .saturating_sub(prior.stats.network_tx_bytes),
        )
}

fn bytes_to_gib_ceil(bytes: u64) -> u64 {
    bytes.saturating_add(GIB - 1).checked_div(GIB).unwrap_or(0).max(1)
}

async fn job_loop(state: Arc<AppState>) {
    let worker_name = format!("vexa-node-{}", std::process::id());
    if let Err(error) = state.db.recover_interrupted_jobs(Utc::now().timestamp()) {
        warn!(error = %error, "interrupted job recovery failed");
    }
    loop {
        match state.db.claim_next_job(&worker_name, Utc::now().timestamp()) {
            Ok(Some(job)) => execute_claimed_job(&state, job).await,
            Ok(None) => tokio::time::sleep(Duration::from_millis(500)).await,
            Err(error) => {
                error!(error = %error, "could not claim job");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn execute_claimed_job(state: &AppState, job: Job) {
    info!(job_id = %job.id, kind = %job.kind, "executing job");
    let result = execute_job(state, &job).await;
    let now = Utc::now().timestamp();
    match result {
        Ok(value) => {
            if let Err(error) = state.db.finish_job(&job.id, &value, now) {
                error!(job_id = %job.id, error = %error, "could not finish job record");
            }
            let bootstrap_superseded = job.kind == "vm.guest_tools.bootstrap"
                && value
                    .pointer("/guest_tools/superseded")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            let _ = state.db.append_audit(&NewAuditEvent {
                actor_type: job.actor_type.clone().unwrap_or_else(|| "system".into()),
                actor_id: job.actor_id.clone(),
                action: if bootstrap_superseded {
                    "vm.guest_tools.bootstrap.superseded".into()
                } else {
                    format!("{}.succeeded", job.kind)
                },
                resource_type: if job.vm_id.is_some() { "vm" } else { "job" }.into(),
                resource_id: job.vm_id.clone().or_else(|| Some(job.id.clone())),
                request_id: None,
                source_ip: None,
                user_agent: None,
                success: true,
                details: json!({
                    "job_id": job.id,
                    "superseded": bootstrap_superseded,
                }),
            });
        }
        Err(error) => {
            if job.kind == "vm.guest_tools.bootstrap" {
                let deadline = job.payload.get("deadline").and_then(Value::as_i64).unwrap_or(now);
                if now < deadline && job.attempts < job.max_attempts {
                    if let Some(vm_id) = job.vm_id.as_deref() {
                        let _ = state.db.update_vm_guest_tools_status(
                            vm_id,
                            GuestToolsStatus::Unavailable,
                            None,
                            Some(&error.to_string()),
                            false,
                        );
                    }
                    if let Err(record_error) =
                        state.db.fail_job(&job.id, &error.to_string(), Some(now + 5), now)
                    {
                        error!(job_id = %job.id, error = %record_error, "could not requeue Guest Tools bootstrap");
                    }
                    return;
                }
                if let Some(vm_id) = job.vm_id.as_deref() {
                    let _ = state.db.update_vm_guest_tools_status(
                        vm_id,
                        GuestToolsStatus::Error,
                        None,
                        Some(&error.to_string()),
                        false,
                    );
                }
            }
            if job.kind == "vm.snapshot.create" {
                if let Some(snapshot_id) = job.payload.get("snapshot_id").and_then(Value::as_str) {
                    let _ = state.db.update_snapshot(
                        snapshot_id,
                        crate::models::SnapshotState::Error,
                        None,
                        None,
                        Some(&json!({ "error": error.to_string() })),
                    );
                }
            }
            if let Some(vm_id) = job.vm_id.as_deref() {
                // A failed reinstall may have already replaced the guest's
                // seed media.  Removing it would leave the rolled-back
                // domain pointing at a missing CD-ROM, so only clean up a
                // seed from a failed first-time creation here.
                if job.kind == "vm.create" {
                    let _ =
                        tokio::fs::remove_file(state.config.cloud_init_storage.join(format!("{vm_id}.iso")))
                            .await;
                }
                if matches!(job.kind.as_str(), "vm.create" | "vm.reinstall") {
                    let _ = state.db.set_vm_state(vm_id, VmState::Error, None, None, None);
                    let guest_tools = state.db.vm_guest_tools(vm_id).ok().flatten();
                    if job.kind == "vm.create"
                        || guest_tools
                            .as_ref()
                            .is_some_and(|record| record.pending_installed)
                    {
                        let _ = state.db.update_vm_guest_tools_status(
                            vm_id,
                            GuestToolsStatus::Error,
                            None,
                            Some(&error.to_string()),
                            false,
                        );
                    }
                }
            }
            // A delete remains idempotent after libvirt has removed the
            // domain: NotFound is accepted and the VM row is retained until
            // all credential-bearing seed cleanup completes. Retry transient
            // hypervisor/filesystem/database failures within the job's bounded
            // attempt budget instead of requiring an operator to rediscover a
            // half-finished deletion.
            let retry_at = (job.kind == "vm.delete"
                && job.attempts < job.max_attempts
                && delete_error_is_retryable(&error))
            .then(|| now.saturating_add(5 * i64::from(job.attempts.max(1))));
            let retry_scheduled = match state.db.fail_job(&job.id, &error.to_string(), retry_at, now) {
                Ok(updated) => updated.status == crate::models::JobStatus::Queued,
                Err(record_error) => {
                    error!(job_id = %job.id, error = %record_error, "could not record failed job attempt");
                    false
                }
            };
            let _ = state.db.append_audit(&NewAuditEvent {
                actor_type: job.actor_type.clone().unwrap_or_else(|| "system".into()),
                actor_id: job.actor_id.clone(),
                action: if retry_scheduled {
                    format!("{}.retry_scheduled", job.kind)
                } else {
                    format!("{}.failed", job.kind)
                },
                resource_type: if job.vm_id.is_some() { "vm" } else { "job" }.into(),
                resource_id: job.vm_id.clone().or_else(|| Some(job.id.clone())),
                request_id: None,
                source_ip: None,
                user_agent: None,
                success: false,
                details: json!({
                    "job_id": job.id,
                    "error": error.to_string(),
                    "attempt": job.attempts,
                    "max_attempts": job.max_attempts,
                    "retry_scheduled": retry_scheduled,
                    "retry_at": retry_at,
                }),
            });
        }
    }
}

async fn execute_job(state: &AppState, job: &Job) -> AppResult<Value> {
    state.db.update_job_progress(&job.id, 10.0)?;
    match job.kind.as_str() {
        "vm.create" => {
            let mut request: CreateVmRequest = payload_field(&job.payload, "request")?;
            // A newly defined guest must not gain network access before the
            // default managed-IP ownership guard and any explicitly enabled
            // firewall/BCP38 policy are present. Define it stopped, persist
            // the stable TAP, reconcile, then honor the requested start state.
            let start_after_provisioning = request.start;
            request.start = false;
            let manual_install = request.image.is_manual_installer();
            let unattended_windows = request.image.is_unattended_windows();
            if manual_install {
                state.db.clear_vm_password(required_vm(state, job)?.id.as_str())?;
            }
            let routed_vm = required_vm(state, job)?;
            crate::services::routed_network::reconcile_vm(state, &routed_vm).await?;
            if request.image.is_unattended_windows() {
                request.cloud_init_iso = Some(
                    build_windows_unattend_seed(state, required_vm(state, job)?, None, &request.image, None)
                        .await?,
                );
            } else if should_build_cloud_init(state, &request.image).await? {
                request.cloud_init_iso =
                    Some(build_cloud_init_seed(state, required_vm(state, job)?, None, None).await?);
            }
            let mut info = state.hypervisor.create_vm(request).await?;
            sync_vm_info(state, job.vm_id.as_deref(), &info)?;
            let vm = required_vm(state, job)?;
            ensure_vm_network_policy(state, &vm).await?;
            if start_after_provisioning {
                info = state.hypervisor.power(&vm.name, PowerAction::Start).await?;
                if unattended_windows {
                    state.hypervisor.acknowledge_install_media_boot(&vm.name).await?;
                }
                sync_vm_info(state, Some(&vm.id), &info)?;
            }
            crate::services::traffic::reconcile_vm(state, &vm.id, true).await?;
            let guest_tools_bootstrap = if start_after_provisioning {
                enqueue_guest_tools_bootstrap(state, job, &vm, None)?
            } else {
                None
            };
            Ok(json!({ "vm": info, "guest_tools_bootstrap": guest_tools_bootstrap }))
        }
        "vm.delete" => {
            // The VM foreign key becomes NULL when the final database delete
            // succeeds. Keep the immutable target in the private job payload
            // so recovery after a crash between that commit and `finish_job`
            // can re-verify the domain and seed are absent before succeeding.
            let target_vm_id = job
                .vm_id
                .as_deref()
                .or_else(|| job.payload.get("target_vm_id").and_then(Value::as_str))
                .ok_or_else(|| AppError::Validation("delete job is missing target_vm_id".into()))?
                .to_owned();
            let vm = state.db.get_vm(&target_vm_id)?;
            let target_vm_name = vm
                .as_ref()
                .map(|vm| vm.name.clone())
                .or_else(|| {
                    job.payload
                        .get("target_vm_name")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .ok_or_else(|| AppError::Validation("delete job is missing target_vm_name".into()))?;
            // Re-read the protection flag inside the worker. A delete may
            // have been queued before an administrator enabled the lock.
            if vm.as_ref().is_some_and(|vm| {
                vm.metadata
                    .pointer("/disk_protection/deletion_lock")
                    .and_then(Value::as_bool)
                    == Some(true)
            }) {
                return Err(AppError::Conflict(
                    "VM deletion is blocked by its disk-protection lock".into(),
                ));
            }
            let delete_storage = job
                .payload
                .get("delete_storage")
                .and_then(Value::as_bool)
                .unwrap_or(true);

            // Serialize the destructive domain/seed transition with seed
            // publication and authenticated Guest Tools retirement. Without
            // this shared per-VM lock, a bootstrap for the old guest could
            // race deletion while a stable `<vm-id>.iso` pathname is being
            // checked or removed.
            let seed_lock = {
                let mut locks = state.guest_tools_locks.lock().await;
                locks
                    .entry(target_vm_id.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone()
            };
            let seed_guard = seed_lock.lock().await;
            match state.hypervisor.delete_vm(&target_vm_name, delete_storage).await {
                Ok(()) | Err(HypervisorError::NotFound(_)) => {}
                Err(error) => return Err(error.into()),
            }
            state.db.update_job_progress(&job.id, 45.0)?;
            if let Some(vm) = vm.as_ref() {
                crate::services::routed_network::cleanup_vm(vm).await?;
            }

            // The VM row is the durable owner of this credential-bearing
            // artifact. A cleanup or directory-sync error must leave that row
            // (and this job) in place so the idempotent delete can retry after
            // the libvirt domain has already disappeared.
            remove_vm_provisioning_seed(&state.config.cloud_init_storage, &target_vm_id).await?;
            state.db.update_job_progress(&job.id, 75.0)?;
            if let Ok(path) = crate::services::guest_tools::socket_path(&state.config, &target_vm_id) {
                let _ = tokio::fs::remove_file(path).await;
            }
            let already_absent = vm.is_none();
            if vm.is_some() {
                state.db.delete_vm(&target_vm_id)?;
            }
            drop(seed_guard);
            state.guest_tools_locks.lock().await.remove(&target_vm_id);
            state
                .traffic_accounting_generations
                .lock()
                .await
                .remove(&target_vm_id);
            Ok(json!({
                "deleted": true,
                "vm_id": target_vm_id,
                "already_absent": already_absent,
            }))
        }
        "vm.power" => {
            let vm = required_vm(state, job)?;
            let action: PowerAction = payload_field(&job.payload, "action")?;
            if matches!(
                action,
                PowerAction::Start | PowerAction::Reboot | PowerAction::Reset | PowerAction::Resume
            ) {
                crate::services::routed_network::reconcile_vm(state, &vm).await?;
                ensure_vm_network_policy(state, &vm).await?;
            }
            let info = state.hypervisor.power(&vm.name, action).await?;
            if action == PowerAction::Start && windows_install_seed_is_present(state, &vm).await {
                state.hypervisor.acknowledge_install_media_boot(&vm.name).await?;
            }
            sync_vm_info(state, Some(&vm.id), &info)?;
            crate::services::traffic::reconcile_vm(state, &vm.id, true).await?;
            let guest_tools_bootstrap = if matches!(
                action,
                PowerAction::Start | PowerAction::Reboot | PowerAction::Reset | PowerAction::Resume
            ) {
                let generation = state.db.installed_vm_guest_tools_rotation_generation(&vm.id)?;
                enqueue_guest_tools_bootstrap(state, job, &vm, generation)?
            } else {
                None
            };
            Ok(json!({ "vm": info, "guest_tools_bootstrap": guest_tools_bootstrap }))
        }
        "vm.resize" => {
            let vm = required_vm(state, job)?;
            let request: ResizeVmRequest = payload_field(&job.payload, "request")?;
            let network_limit_mbps = request.network_limit_mbps;
            let info = state.hypervisor.resize(&vm.name, request).await?;
            if let Some(limit) = network_limit_mbps {
                state.db.patch_vm(
                    &vm.id,
                    &VmPatch {
                        network_limit_mbps: Some(limit),
                        ..VmPatch::default()
                    },
                )?;
            }
            sync_vm_info(state, Some(&vm.id), &info)?;
            Ok(json!({ "vm": info }))
        }
        "vm.reinstall" => {
            let vm = required_vm(state, job)?;
            let replacement_iso_id = job
                .payload
                .get("replacement_iso_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let replacement_os_family = job
                .payload
                .get("replacement_os_family")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let replacement_root_username = job
                .payload
                .get("replacement_root_username")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let replacement_disk_gib = job
                .payload
                .get("replacement_disk_gib")
                .and_then(Value::as_u64);
            let mut provisioning_vm = vm.clone();
            if let Some(value) = replacement_iso_id.as_ref() {
                provisioning_vm.iso_id = Some(value.clone());
            }
            if let Some(value) = replacement_os_family.as_ref() {
                provisioning_vm.os_family = value.clone();
            }
            if let Some(value) = replacement_root_username.as_ref() {
                provisioning_vm.root_username = value.clone();
            }
            crate::services::routed_network::reconcile_vm(state, &vm).await?;
            let mut request: ReinstallVmRequest = payload_field(&job.payload, "request")?;
            // Reinstall replaces the domain definition. Keep it stopped until
            // its stable TAP identity has been synchronized and all enabled
            // forwarding protections have been applied.
            let start_after_provisioning = request.start;
            request.start = false;
            let unattended_windows = request.image.is_unattended_windows();
            if vm
                .metadata
                .pointer("/disk_protection/snapshot_before_reinstall")
                .and_then(Value::as_bool)
                == Some(true)
            {
                let snapshot_name = format!("pre-reinstall-{}", Utc::now().format("%Y%m%d%H%M%S"));
                let record = state.db.create_snapshot(
                    &vm.id,
                    &snapshot_name,
                    "Automatic disk-protection snapshot before reinstall",
                    false,
                    &json!({ "automatic": true, "reason": "pre_reinstall", "job_id": job.id }),
                )?;
                let snapshot_request = SnapshotRequest {
                    name: snapshot_name,
                    description: Some("Automatic disk-protection snapshot before reinstall".into()),
                };
                match state.hypervisor.create_snapshot(&vm.name, snapshot_request).await {
                    Ok(snapshot) => {
                        let metadata = serde_json::to_value(&snapshot).map_err(|error| {
                            AppError::Internal(format!("could not encode automatic snapshot: {error}"))
                        })?;
                        state.db.update_snapshot(
                            &record.id,
                            crate::models::SnapshotState::Ready,
                            None,
                            None,
                            Some(&metadata),
                        )?;
                    }
                    Err(error) => {
                        let message = error.to_string();
                        let _ = state.db.update_snapshot(
                            &record.id,
                            crate::models::SnapshotState::Error,
                            None,
                            None,
                            Some(&json!({ "error": message })),
                        );
                        return Err(error.into());
                    }
                }
            }
            let staged_password = job
                .payload
                .get(STAGED_PASSWORD_ENVELOPE_FIELD)
                .and_then(Value::as_str);
            let clear_password = job
                .payload
                .get("clear_password_after_success")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if clear_password && staged_password.is_some() {
                return Err(AppError::Validation(
                    "manual reinstall job cannot stage a guest password".into(),
                ));
            }
            let guest_tools_generation = job
                .payload
                .get(STAGED_GUEST_TOOLS_GENERATION_FIELD)
                .and_then(Value::as_str)
                .map(str::to_owned);
            if request.image.is_unattended_windows() {
                request.cloud_init_iso = Some(
                    build_windows_unattend_seed(
                        state,
                        provisioning_vm.clone(),
                        staged_password,
                        &request.image,
                        guest_tools_generation.as_deref(),
                    )
                    .await?,
                );
            } else if should_build_cloud_init(state, &request.image).await? {
                request.cloud_init_iso = Some(
                    build_cloud_init_seed(
                        state,
                        provisioning_vm.clone(),
                        staged_password,
                        guest_tools_generation.as_deref(),
                    )
                    .await?,
                );
            } else if let Some(generation) = guest_tools_generation.as_deref() {
                // Arm the new key before entering libvirt's destructive disk
                // replacement. Cloud-image paths arm inside the seed writer,
                // immediately before its atomic publish, because that media
                // itself may be observed by a replacement guest after a crash.
                state
                    .db
                    .mark_vm_guest_tools_rotation_installed(&vm.id, generation)?;
            }
            let mut info = state.hypervisor.reinstall(&vm.name, request).await?;

            // The destructive hypervisor boundary has now been crossed. Make
            // the panel credential match the replacement guest before any
            // inventory, firewall, power, traffic, or bootstrap post-step can
            // fail. Reinstall jobs are not automatically replayed after a
            // post-step error; terminal cleanup removes the private envelope
            // from the job but this committed VM credential intentionally
            // remains authoritative.
            state.db.commit_reinstall_password_after_hypervisor(&job.id)?;
            if replacement_iso_id.is_some()
                || replacement_os_family.is_some()
                || replacement_root_username.is_some()
                || replacement_disk_gib.is_some()
            {
                state.db.patch_vm(
                    &vm.id,
                    &VmPatch {
                        iso_id: replacement_iso_id.map(Some),
                        os_family: replacement_os_family,
                        root_username: replacement_root_username,
                        disk_gib: replacement_disk_gib,
                        ..VmPatch::default()
                    },
                )?;
            }
            if job
                .payload
                .get("disable_guest_tools_after_success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                state.db.retire_vm_guest_tools_after_reinstall(&vm.id)?;
            }
            sync_vm_info(state, Some(&vm.id), &info)?;
            let refreshed = state
                .db
                .get_vm(&vm.id)?
                .ok_or_else(|| AppError::NotFound("VM".into()))?;
            ensure_vm_network_policy(state, &refreshed).await?;
            if start_after_provisioning {
                info = state
                    .hypervisor
                    .power(&refreshed.name, PowerAction::Start)
                    .await?;
                if unattended_windows {
                    state
                        .hypervisor
                        .acknowledge_install_media_boot(&refreshed.name)
                        .await?;
                }
                sync_vm_info(state, Some(&refreshed.id), &info)?;
            }
            crate::services::traffic::reconcile_vm(state, &vm.id, true).await?;
            let guest_tools_bootstrap = if start_after_provisioning {
                enqueue_guest_tools_bootstrap(state, job, &refreshed, guest_tools_generation)?
            } else {
                None
            };
            Ok(json!({ "vm": info, "guest_tools_bootstrap": guest_tools_bootstrap }))
        }
        "vm.guest_tools.bootstrap" => {
            let vm = required_vm(state, job)?;
            if vm.state != VmState::Running {
                return Err(AppError::Conflict(
                    "VM is not running yet; Guest Tools bootstrap will retry".into(),
                ));
            }
            let expected_generation = job.payload.get("expected_generation").and_then(Value::as_str);
            let result = crate::services::guest_tools::bootstrap(state, &vm, expected_generation).await?;
            Ok(json!({ "guest_tools": result }))
        }
        "vm.snapshot.create" => {
            let vm = required_vm(state, job)?;
            let request: SnapshotRequest = payload_field(&job.payload, "request")?;
            let snapshot = state.hypervisor.create_snapshot(&vm.name, request).await?;
            let snapshot_id = job
                .payload
                .get("snapshot_id")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::Validation("snapshot job is missing snapshot_id".into()))?;
            let metadata = serde_json::to_value(&snapshot)
                .map_err(|error| AppError::Internal(format!("could not encode snapshot: {error}")))?;
            state.db.update_snapshot(
                snapshot_id,
                crate::models::SnapshotState::Ready,
                None,
                None,
                Some(&metadata),
            )?;
            Ok(json!({ "snapshot": snapshot }))
        }
        other => Err(AppError::Validation(format!("unsupported job kind: {other}"))),
    }
}

fn enqueue_guest_tools_bootstrap(
    state: &AppState,
    parent_job: &Job,
    vm: &crate::models::Vm,
    expected_generation: Option<String>,
) -> AppResult<Option<Job>> {
    let record = state.db.vm_guest_tools(&vm.id)?;
    let routeros_builtin = vm.os_family.to_ascii_lowercase().contains("routeros");
    if record.is_none() && !routeros_builtin {
        return Ok(None);
    }
    if record.as_ref().is_some_and(|record| !record.enabled) && !routeros_builtin {
        return Ok(None);
    }
    let now = Utc::now().timestamp();
    let windows_guest = vm.os_family.to_ascii_lowercase().contains("windows");
    let bootstrap_window_seconds = if windows_guest { 30 * 60 } else { 10 * 60 };
    let rotation_pending = expected_generation.is_some();
    let bootstrap = state.db.enqueue_guest_tools_bootstrap_job(&NewJob {
        kind: "vm.guest_tools.bootstrap".into(),
        vm_id: Some(vm.id.clone()),
        payload: json!({
            "expected_generation": expected_generation,
            "deadline": now.saturating_add(bootstrap_window_seconds),
            "parent_job_id": parent_job.id,
        }),
        idempotency_key: None,
        run_after: Some(now.saturating_add(3)),
        // Automatic Windows Setup routinely needs longer than the ten-minute
        // Linux/RouterOS first-boot window before the signed serial driver and
        // native service are online. Keep the durable probe retryable for 30
        // minutes without extending the faster appliance path.
        max_attempts: if windows_guest { 361 } else { 121 },
        actor_type: parent_job.actor_type.clone(),
        actor_id: parent_job.actor_id.clone(),
    })?;
    if record
        .as_ref()
        .is_some_and(|record| record.status != GuestToolsStatus::Ready || rotation_pending)
    {
        let _ = state
            .db
            .update_vm_guest_tools_status(&vm.id, GuestToolsStatus::Pending, None, None, false);
    }
    Ok(Some(bootstrap))
}

async fn windows_install_seed_is_present(state: &AppState, vm: &crate::models::Vm) -> bool {
    if !is_windows_os_family(&vm.os_family) {
        return false;
    }
    tokio::fs::metadata(state.config.cloud_init_storage.join(format!("{}.iso", vm.id)))
        .await
        .is_ok()
}

async fn should_build_cloud_init(state: &AppState, image: &crate::hypervisor::VmImage) -> AppResult<bool> {
    if !matches!(
        image,
        crate::hypervisor::VmImage::Qcow2 { .. } | crate::hypervisor::VmImage::Raw { .. }
    ) {
        return Ok(false);
    }
    Ok(state.hypervisor.capabilities().await?.backend == "libvirt")
}

struct GuestToolsSeed {
    platform: GuestToolsPlatform,
    provisioner: GuestToolsProvisioner,
    artifact: Vec<u8>,
    secret: String,
}

async fn load_guest_tools_seed(state: &AppState, vm_id: &str) -> AppResult<Option<GuestToolsSeed>> {
    let Some(record) = state.db.vm_guest_tools(vm_id)? else {
        return Ok(None);
    };
    if !record.enabled {
        return Ok(None);
    }
    let pending = state.db.pending_vm_guest_tools_seed(vm_id, &state.security)?;
    let (platform, provisioner, secret) = if let Some(pending) = pending {
        (pending.platform, pending.provisioner, pending.secret)
    } else {
        let secret = state
            .db
            .decrypt_vm_guest_tools_secret(vm_id, &state.security)?
            .ok_or_else(|| AppError::Conflict("VM Guest Tools channel secret is unavailable".into()))?;
        (record.platform, record.provisioner, secret)
    };
    let artifact_path = crate::services::guest_tools::artifact_for_platform(&state.config, platform)?;
    let artifact = tokio::fs::read(&artifact_path).await.map_err(|error| {
        AppError::Conflict(format!(
            "could not read the configured {} Guest Tools artifact: {error}",
            platform.as_str()
        ))
    })?;
    if artifact.is_empty() || artifact.len() > 64 * 1024 * 1024 {
        return Err(AppError::Conflict(format!(
            "the configured {} Guest Tools artifact must contain 1 through 67108864 bytes",
            platform.as_str()
        )));
    }
    Ok(Some(GuestToolsSeed {
        platform,
        provisioner,
        artifact,
        secret,
    }))
}

async fn build_cloud_init_seed(
    state: &AppState,
    vm: crate::models::Vm,
    staged_password_envelope: Option<&str>,
    guest_tools_generation: Option<&str>,
) -> AppResult<PathBuf> {
    // Share the per-VM Guest Tools lock with authenticated bootstrap. This
    // closes the race where an old bootstrap could otherwise eject/unlink a
    // newly published reinstall seed that reused the VM's stable ISO path.
    let seed_lock = {
        let mut locks = state.guest_tools_locks.lock().await;
        locks
            .entry(vm.id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _seed_guard = seed_lock.lock().await;
    let password = match staged_password_envelope {
        Some(envelope) => state
            .security
            .decrypt_secret(envelope, &vm_password_context(&vm.id))?,
        None => state
            .db
            .decrypt_vm_password(&vm.id, &state.security)?
            .ok_or_else(|| AppError::Conflict("VM has no encrypted guest password".into()))?,
    };
    let guest_tools = load_guest_tools_seed(state, &vm.id).await?;
    let windows_guest = is_windows_os_family(&vm.os_family)
        || guest_tools.as_ref().is_some_and(|tools| {
            tools.platform == GuestToolsPlatform::Windows
                || tools.provisioner == GuestToolsProvisioner::CloudbaseNoCloud
        });
    if windows_guest {
        if guest_tools.as_ref().is_some_and(|tools| {
            tools.platform != GuestToolsPlatform::Windows
                || tools.provisioner != GuestToolsProvisioner::CloudbaseNoCloud
        }) {
            return Err(AppError::Conflict(
                "Windows Guest Tools requires the Cloudbase-Init NoCloud provisioner".into(),
            ));
        }
        return build_cloudbase_seed(state, vm, &password, guest_tools, guest_tools_generation).await;
    }
    let password_hash = cloud_init_password_hash(&password).await?;
    let addresses = state.db.vm_ip_addresses(&vm.id)?;
    let dns = state.db.dns_servers(None, Some(&vm.id))?;
    let routed = crate::services::routed_network::plan(&vm)?;
    let default_timezone = state
        .setting("general", "timezone")?
        .and_then(|value| value.as_str().map(str::to_owned));
    let timezone = vm
        .timezone
        .clone()
        .or(default_timezone)
        .unwrap_or_else(|| "UTC".into());
    validate_timezone_name(&timezone)?;
    let locale = state
        .setting("general", "locale")?
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "en-US".into());
    let locale = normalize_guest_locale(&locale)?;
    let ntp_servers = state.setting_strings("general", "ntp_servers")?;
    for server in &ntp_servers {
        validate_ntp_server(server)?;
    }
    let ssh_keys = vm
        .metadata
        .get("ssh_keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|key| {
            !key.is_empty()
                && key.len() <= 16 * 1024
                && !key.chars().any(|character| matches!(character, '\r' | '\n'))
        })
        .take(64)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let quoted = |value: &str| {
        serde_json::to_string(value)
            .map_err(|error| AppError::Internal(format!("could not encode cloud-init value: {error}")))
    };
    let mut user_data = format!(
        "#cloud-config\ntimezone: {}\nlocale: {}\npreserve_hostname: false\nhostname: {}\nmanage_etc_hosts: true\nssh_pwauth: true\ndisable_root: false\nusers:\n  - name: {}\n    lock_passwd: false\n    hashed_passwd: {}\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n",
        quoted(&timezone)?,
        quoted(&locale)?,
        quoted(&vm.hostname)?,
        quoted(&vm.root_username)?,
        quoted(&password_hash)?,
    );
    if !ssh_keys.is_empty() {
        // Bind keys to the explicitly requested guest administrator instead
        // of relying on distro-specific interpretation of the legacy
        // top-level ssh_authorized_keys alias.
        user_data.push_str("    ssh_authorized_keys:\n");
        for key in &ssh_keys {
            user_data.push_str(&format!("      - {}\n", quoted(key)?));
        }
    }
    user_data.push_str("chpasswd:\n  expire: false\n");
    if !ntp_servers.is_empty() {
        user_data.push_str("ntp:\n  enabled: true\n  servers:\n");
        for server in &ntp_servers {
            user_data.push_str(&format!("    - {}\n", quoted(server)?));
        }
    }
    // Ubuntu cloud images can ship an sshd drop-in that keeps root password
    // login disabled even when cloud-init receives `ssh_pwauth: true` and a
    // root password.  Make the requested login method explicit and restart
    // ssh after cloud-init writes the policy.  Non-root guest accounts retain
    // password SSH while root remains disabled.
    let permit_root_login = if vm.root_username.eq_ignore_ascii_case("root") {
        "yes"
    } else {
        "no"
    };
    user_data.push_str(&format!(
        "write_files:\n  - path: /etc/ssh/sshd_config.d/99-vexa-vm-password-auth.conf\n    owner: root:root\n    permissions: '0600'\n    content: |\n      PasswordAuthentication yes\n      KbdInteractiveAuthentication no\n      PermitRootLogin {permit_root_login}\n"
    ));
    if let Some(routed) = routed.as_ref() {
        let keyfile = networkmanager_routed_keyfile(&vm, routed, &addresses, &dns)?;
        // Cloud-init's network renderer differs across distributions. Keep the
        // portable network-config v2 document below, and also provide a native
        // NetworkManager profile for RHEL-family images. On systems without
        // NetworkManager the profile is inert.
        append_cloud_init_base64_file(
            &mut user_data,
            "/etc/NetworkManager/system-connections/vexa-routed.nmconnection",
            "0600",
            keyfile.as_bytes(),
        );
    }
    let install_guest_tools = guest_tools.is_some();
    if let Some(tools) = guest_tools {
        if tools.platform != GuestToolsPlatform::Linux
            || tools.provisioner != GuestToolsProvisioner::CloudInit
        {
            return Err(AppError::Conflict(
                "Linux Guest Tools requires the cloud-init provisioner".into(),
            ));
        }
        let configuration = serde_json::to_vec(&json!({
            "channel_path": "/dev/virtio-ports/com.vexa.guest_tools.0",
            "secret_file": "/etc/vexa-guest-tools/secret",
            "max_clock_skew_seconds": 120,
            "replay_cache_capacity": 4096,
            "reconnect_delay_seconds": 2,
            "policy": {
                "password": true,
                "hostname": true,
                "dns": true,
                "network": true,
                "ssh_keys": true,
                "power": true,
                "allowed_users": [vm.root_username.clone()],
            }
        }))
        .map_err(|error| {
            AppError::Internal(format!("could not encode Guest Tools configuration: {error}"))
        })?;
        append_cloud_init_base64_file(
            &mut user_data,
            "/usr/local/sbin/vexa-guest-tools",
            "0755",
            &tools.artifact,
        );
        append_cloud_init_base64_file(
            &mut user_data,
            "/etc/vexa-guest-tools/secret",
            "0600",
            format!("base64:{}\n", tools.secret).as_bytes(),
        );
        append_cloud_init_base64_file(
            &mut user_data,
            "/etc/vexa-guest-tools/config.json",
            "0600",
            &configuration,
        );
        append_cloud_init_base64_file(
            &mut user_data,
            "/etc/systemd/system/vexa-guest-tools.service",
            "0644",
            include_bytes!("../../guest-tools/packaging/linux/vexa-guest-tools.service"),
        );
    }
    user_data.push_str("runcmd:\n");
    // Bring up the authenticated control channel first. Network-manager and
    // distribution-specific ssh units can legitimately block or be absent;
    // neither condition may strand an already-armed Guest Tools key.
    if install_guest_tools {
        user_data.push_str(
            "  - [systemctl, daemon-reload]\n  - [systemctl, enable, --now, vexa-guest-tools.service]\n",
        );
    }
    if routed.is_some() {
        user_data.push_str(
            "  - [sh, -c, 'if command -v nmcli >/dev/null 2>&1; then timeout 30s nmcli connection reload && timeout 30s nmcli --wait 20 connection up id vexa-routed ifname eth0; fi']\n",
        );
    }
    user_data.push_str(
        "  - [sh, -c, 'systemctl enable ssh.service 2>/dev/null || systemctl enable sshd.service 2>/dev/null || true; systemctl start --no-block --job-mode=ignore-dependencies ssh.service 2>/dev/null || systemctl start --no-block --job-mode=ignore-dependencies sshd.service 2>/dev/null || true']\n",
    );
    let metadata = format!(
        "instance-id: {}\nlocal-hostname: {}\n",
        quoted(&vm.id)?,
        quoted(&vm.hostname)?,
    );
    let ipv4 = addresses
        .iter()
        .any(|address| address.family == crate::models::AddressFamily::V4);
    let ipv6 = addresses
        .iter()
        .any(|address| address.family == crate::models::AddressFamily::V6);
    let mut configured_addresses = addresses
        .iter()
        .map(|address| format!("{}/{}", address.address, address.prefix_length))
        .collect::<Vec<_>>();
    if let Some(routed) = routed.as_ref() {
        configured_addresses.push(format!("{}/{}", routed.guest_address, routed.prefix_length));
    }
    let routes = if let Some(routed) = routed.as_ref() {
        std::collections::BTreeSet::from([routed.gateway.to_string()])
    } else {
        addresses
            .iter()
            .filter_map(|address| address.gateway.as_deref())
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>()
    };
    let dns_addresses = dns
        .iter()
        .map(|server| server.address.clone())
        .collect::<Vec<_>>();
    let mut network = format!(
        "version: 2\nethernets:\n  eth0:\n    match:\n      macaddress: {}\n    set-name: eth0\n    dhcp4: {}\n    dhcp6: {}\n",
        quoted(vm.mac_address.as_deref().unwrap_or(""))?,
        if ipv4 { "false" } else { "true" },
        if ipv6 { "false" } else { "true" },
    );
    if !configured_addresses.is_empty() {
        network.push_str(&format!(
            "    addresses: {}\n",
            serde_json::to_string(&configured_addresses)
                .map_err(|error| AppError::Internal(format!("could not encode addresses: {error}")))?
        ));
    }
    if !routes.is_empty() {
        network.push_str("    routes:\n");
        for gateway in routes {
            network.push_str(&format!(
                "      - to: default\n        via: {}\n",
                quoted(&gateway)?
            ));
        }
    }
    if !dns_addresses.is_empty() {
        network.push_str(&format!(
            "    nameservers:\n      addresses: {}\n",
            serde_json::to_string(&dns_addresses)
                .map_err(|error| AppError::Internal(format!("could not encode DNS: {error}")))?
        ));
    }

    write_seed_iso(
        state,
        &vm.id,
        &user_data,
        &metadata,
        &network,
        guest_tools_generation,
    )
    .await
}

async fn build_windows_unattend_seed(
    state: &AppState,
    vm: crate::models::Vm,
    staged_password_envelope: Option<&str>,
    image: &crate::hypervisor::VmImage,
    guest_tools_generation: Option<&str>,
) -> AppResult<PathBuf> {
    let crate::hypervisor::VmImage::UnattendedWindowsIso {
        driver_iso,
        image_index,
        driver_version,
        ..
    } = image
    else {
        return Err(AppError::Validation(
            "Windows unattended seed requires an unattended Windows image".into(),
        ));
    };
    let seed_lock = {
        let mut locks = state.guest_tools_locks.lock().await;
        locks
            .entry(vm.id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _seed_guard = seed_lock.lock().await;
    let password = match staged_password_envelope {
        Some(envelope) => state
            .security
            .decrypt_secret(envelope, &vm_password_context(&vm.id))?,
        None => state
            .db
            .decrypt_vm_password(&vm.id, &state.security)?
            .ok_or_else(|| AppError::Conflict("VM has no encrypted guest password".into()))?,
    };
    let addresses = state.db.vm_ip_addresses(&vm.id)?;
    let dns = state.db.dns_servers(None, Some(&vm.id))?;
    let routed = crate::services::routed_network::plan(&vm)?;
    let guest_tools = load_guest_tools_seed(state, &vm.id).await?;
    if guest_tools.as_ref().is_some_and(|tools| {
        tools.platform != GuestToolsPlatform::Windows
            || tools.provisioner != GuestToolsProvisioner::CloudbaseNoCloud
    }) {
        return Err(AppError::Conflict(
            "unattended Windows Guest Tools requires the Windows seed provisioner".into(),
        ));
    }
    let script = windows_first_boot_script(&vm, &addresses, &dns, routed.as_ref(), guest_tools.is_some())?;
    let answer = windows_unattend_xml(
        &vm,
        &password,
        *image_index,
        driver_version,
        vm.firmware.eq_ignore_ascii_case("uefi"),
    )?;
    write_unattend_iso(
        state,
        &vm.id,
        &answer,
        &script,
        driver_iso,
        driver_version,
        guest_tools,
        guest_tools_generation,
    )
    .await
}

fn windows_unattend_xml(
    vm: &crate::models::Vm,
    password: &str,
    image_index: u32,
    driver_version: &str,
    uefi: bool,
) -> AppResult<String> {
    if !(1..=64).contains(&image_index) {
        return Err(AppError::Validation(
            "Windows image index must be between 1 and 64".into(),
        ));
    }
    let hostname = xml_text(&windows_computer_name(&vm.hostname, &vm.id))?;
    let username = xml_text(&vm.root_username)?;
    let password = xml_text(password)?;
    let driver_version = xml_text(driver_version)?;
    let command = xml_text(windows_first_logon_command())?;
    let (partitions, install_partition) = windows_disk_layout(uefi);
    Ok(format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DriverPaths>
        <PathAndCredentials wcm:action="add" wcm:keyValue="1"><Path>E:\$WinPEDriver$</Path></PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="2"><Path>F:\viostor\{driver_version}\amd64</Path></PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="3"><Path>F:\NetKVM\{driver_version}\amd64</Path></PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="4"><Path>F:\vioserial\{driver_version}\amd64</Path></PathAndCredentials>
      </DriverPaths>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add"><DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          {partitions}
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>{image_index}</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>{install_partition}</PartitionID></InstallTo><WillShowUI>OnError</WillShowUI></OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula><FullName>Vexa VM</FullName><Organization>Vexa VM</Organization></UserData>
      <DynamicUpdate><Enable>false</Enable><WillShowUI>OnError</WillShowUI></DynamicUpdate>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><ComputerName>{hostname}</ComputerName><TimeZone>UTC</TimeZone></component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><NetworkLocation>Work</NetworkLocation><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><AdministratorPassword><Value>{password}</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <AutoLogon><Password><Value>{password}</Value><PlainText>true</PlainText></Password><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>{username}</Username></AutoLogon>
      <FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><Description>Configure Vexa VM</Description><RequiresUserInput>false</RequiresUserInput><CommandLine>{command}</CommandLine></SynchronousCommand></FirstLogonCommands>
    </component>
  </settings>
</unattend>
"#
    ))
}

fn windows_first_logon_command() -> &'static str {
    r#"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$m = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=5' | Where-Object { $_.VolumeName -eq 'VEXAUNATTEND' } | Select-Object -First 1; if (-not $m) { throw 'Vexa unattended media was not found.' }; & (Join-Path $m.DeviceID 'VexaTools\FirstBoot.ps1')""#
}

fn windows_disk_layout(uefi: bool) -> (&'static str, u8) {
    if uefi {
        (
            r#"<CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>100</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>"#,
            3,
        )
    } else {
        (
            r#"<CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Active>true</Active><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>"#,
            1,
        )
    }
}

fn windows_computer_name(hostname: &str, stable_id: &str) -> String {
    let valid = !hostname.is_empty()
        && hostname.len() <= 15
        && !hostname.starts_with('-')
        && !hostname.ends_with('-')
        && hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && hostname.bytes().any(|byte| byte.is_ascii_alphabetic());
    if valid {
        return hostname.to_owned();
    }

    let mut prefix = String::new();
    let mut previous_hyphen = false;
    for character in hostname.chars() {
        let normalized = if character.is_ascii_alphanumeric() {
            character.to_ascii_lowercase()
        } else {
            '-'
        };
        if normalized == '-' {
            if prefix.is_empty() || previous_hyphen {
                continue;
            }
            previous_hyphen = true;
        } else {
            previous_hyphen = false;
        }
        prefix.push(normalized);
        if prefix.len() == 8 {
            break;
        }
    }
    while prefix.ends_with('-') {
        prefix.pop();
    }
    if prefix.is_empty() {
        prefix.push_str("vexa");
    } else if !prefix.bytes().any(|byte| byte.is_ascii_alphabetic()) {
        prefix.insert(0, 'v');
        prefix.truncate(8);
    }

    let mut suffix = stable_id
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .map(char::from)
        .take(6)
        .collect::<String>()
        .to_ascii_lowercase();
    suffix.push_str("000000");
    suffix.truncate(6);
    format!("{prefix}-{suffix}")
}

fn windows_first_boot_script(
    vm: &crate::models::Vm,
    addresses: &[crate::models::IpAddressRecord],
    dns: &[crate::models::DnsServer],
    routed: Option<&crate::services::routed_network::RoutedIpv4>,
    install_guest_tools: bool,
) -> AppResult<String> {
    let mut script = String::from(
        "$ErrorActionPreference = 'Stop'\n$media = Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=5\" | Where-Object { $_.VolumeName -eq 'VEXAUNATTEND' -or (Test-Path \"$($_.DeviceID)\\VexaTools\") } | Select-Object -First 1\nif (-not $media) { throw 'Vexa unattended media was not found.' }\n$qga = Join-Path $media.DeviceID 'guest-agent\\qemu-ga-x86_64.msi'\nif (Test-Path -LiteralPath $qga -PathType Leaf) { Start-Process msiexec.exe -ArgumentList @('/i', $qga, '/qn', '/norestart') -Wait }\n",
    );
    if install_guest_tools {
        script.push_str(
            "$tools = Join-Path $media.DeviceID 'VexaTools'\n$installer = Join-Path $tools 'Install-VexaGuestTools.ps1'\n$binary = Join-Path $tools 'vexa-guest-tools.exe'\n$secret = Join-Path $tools 'secret'\nif (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Vexa Guest Tools installer is missing.' }\n& $installer -Binary $binary -SecretFile $secret\n",
        );
    }
    script.push_str(
        "$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface } | Sort-Object ifIndex | Select-Object -First 1\nif (-not $adapter) { throw 'No active hardware network adapter was found.' }\nGet-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue\nSet-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction SilentlyContinue\n",
    );
    if let Some(routed) = routed {
        script.push_str(&format!(
            "New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress '{}' -PrefixLength {} -SkipAsSource $true\n",
            routed.guest_address, routed.prefix_length
        ));
        for address in addresses
            .iter()
            .filter(|address| address.family == crate::models::AddressFamily::V4)
        {
            script.push_str(&format!(
                "New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress '{}' -PrefixLength {}\n",
                ps_literal(&address.address)?,
                address.prefix_length
            ));
        }
        script.push_str(&format!(
            "New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop '{}' -RouteMetric 10\n",
            routed.gateway
        ));
    } else {
        let mut gateways = std::collections::BTreeSet::new();
        for address in addresses {
            let family = match address.family {
                crate::models::AddressFamily::V4 => "IPv4",
                crate::models::AddressFamily::V6 => "IPv6",
            };
            script.push_str(&format!(
                "New-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily {family} -IPAddress '{}' -PrefixLength {}\n",
                ps_literal(&address.address)?, address.prefix_length
            ));
            if let Some(gateway) = address.gateway.as_deref() {
                if gateways.insert((address.family.as_i64(), gateway.to_owned())) {
                    let destination = if address.family == crate::models::AddressFamily::V4 {
                        "0.0.0.0/0"
                    } else {
                        "::/0"
                    };
                    script.push_str(&format!(
                        "New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '{destination}' -NextHop '{}' -RouteMetric 10\n",
                        ps_literal(gateway)?
                    ));
                }
            }
        }
    }
    let dns = dns
        .iter()
        .map(|server| ps_literal(&server.address).map(|address| format!("'{address}'")))
        .collect::<AppResult<Vec<_>>>()?;
    if !dns.is_empty() {
        script.push_str(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @({})\n",
            dns.join(",")
        ));
    }
    script.push_str(&format!(
        "$env:COMPUTERNAME | Out-Null\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0\nEnable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue\nRemove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value '0'\nRemove-Item -Force -ErrorAction SilentlyContinue 'C:\\Windows\\Panther\\unattend.xml','C:\\Windows\\Panther\\Unattend\\unattend.xml'\nRename-Computer -NewName '{}' -Force -ErrorAction SilentlyContinue\nRestart-Computer -Force\n",
        ps_literal(&windows_computer_name(&vm.hostname, &vm.id))?
    ));
    Ok(script)
}

fn ps_literal(value: &str) -> AppResult<String> {
    if value
        .chars()
        .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        return Err(AppError::Validation(
            "Windows provisioning value contains a control character".into(),
        ));
    }
    Ok(value.replace('\'', "''"))
}

fn xml_text(value: &str) -> AppResult<String> {
    if value.chars().any(|character| {
        let code = character as u32;
        code < 0x20 && !matches!(character, '\t' | '\n' | '\r')
    }) {
        return Err(AppError::Validation(
            "Windows answer value contains an XML control character".into(),
        ));
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

async fn write_unattend_iso(
    state: &AppState,
    vm_id: &str,
    answer: &str,
    first_boot_script: &str,
    driver_iso: &Path,
    driver_version: &str,
    guest_tools: Option<GuestToolsSeed>,
    guest_tools_generation: Option<&str>,
) -> AppResult<PathBuf> {
    let root = &state.config.cloud_init_storage;
    tokio::fs::create_dir_all(root).await?;
    let temporary = root.join(format!(".{vm_id}-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir(&temporary).await?;
    set_private_directory_permissions(&temporary).await?;
    let result = async {
        let content = temporary.join("content");
        tokio::fs::create_dir(&content).await?;
        set_private_directory_permissions(&content).await?;
        write_private_file(&content.join("Autounattend.xml"), answer.as_bytes()).await?;

        // Copy only the signed files required during setup into the answer
        // medium. Windows automatically scans `$WinPEDriver$`; keeping the
        // separate vendor ISO attached remains a fallback for recovery.
        let seven_zip = Path::new("/usr/bin/7z");
        if !seven_zip.is_file() {
            return Err(AppError::Hypervisor(
                "7z is required to prepare automatic Windows drivers".into(),
            ));
        }
        let mut extract = Command::new(seven_zip);
        extract
            .args(["x", "-y", "-bd", "-bso0", "-bsp0"])
            .arg(format!("-o{}", content.display()))
            .arg(driver_iso);
        for family in ["viostor", "NetKVM", "vioserial"] {
            for extension in ["inf", "sys", "cat", "dll", "exe"] {
                extract.arg(format!("{family}/{driver_version}/amd64/*.{extension}"));
            }
        }
        extract
            .arg("guest-agent/qemu-ga-x86_64.msi")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let extracted = tokio::time::timeout(Duration::from_secs(120), extract.output())
            .await
            .map_err(|_| AppError::Hypervisor("Windows driver extraction timed out".into()))??;
        if !extracted.status.success() {
            return Err(AppError::Hypervisor(
                "verified Windows driver media did not contain the required driver set".into(),
            ));
        }
        let driver_root = content.join("$WinPEDriver$");
        tokio::fs::create_dir(&driver_root).await?;
        for family in ["viostor", "NetKVM", "vioserial"] {
            let source = content.join(family);
            let destination = driver_root.join(family);
            tokio::fs::rename(&source, &destination).await.map_err(|_| {
                AppError::Hypervisor(format!(
                    "verified Windows driver media is missing {family}/{driver_version}/amd64"
                ))
            })?;
        }
        if !content.join("guest-agent/qemu-ga-x86_64.msi").is_file() {
            return Err(AppError::Hypervisor(
                "verified Windows driver media is missing QEMU Guest Agent".into(),
            ));
        }

        let tools_root = content.join("VexaTools");
        tokio::fs::create_dir(&tools_root).await?;
        write_private_file(&tools_root.join("FirstBoot.ps1"), first_boot_script.as_bytes()).await?;
        if let Some(tools) = guest_tools.as_ref() {
            write_private_file(&tools_root.join("vexa-guest-tools.exe"), &tools.artifact).await?;
            write_private_file(
                &tools_root.join("secret"),
                format!("base64:{}\r\n", tools.secret).as_bytes(),
            )
            .await?;
            write_private_file(
                &tools_root.join("Install-VexaGuestTools.ps1"),
                include_bytes!("../../guest-tools/packaging/windows/Install-VexaGuestTools.ps1"),
            )
            .await?;
        }
        let program = ["/usr/bin/genisoimage", "/usr/bin/mkisofs"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .ok_or_else(|| {
                AppError::Hypervisor("genisoimage is required for Windows unattended images".into())
            })?;
        let output_path = temporary.join("seed.iso");
        let mut command = Command::new(program);
        command
            .current_dir(&content)
            .arg("-quiet")
            .arg("-output")
            .arg(&output_path)
            .args(["-volid", "VEXAUNATTEND", "-joliet", "-rock", "."])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(60), command.output())
            .await
            .map_err(|_| AppError::Hypervisor("Windows answer ISO generation timed out".into()))??;
        if !output.status.success() {
            return Err(AppError::Hypervisor(
                "Windows answer ISO generation failed".into(),
            ));
        }
        set_seed_permissions(&output_path).await?;
        tokio::fs::File::open(&output_path).await?.sync_all().await?;
        let target = root.join(format!("{vm_id}.iso"));
        if guest_tools.is_some() {
            if let Some(generation) = guest_tools_generation {
                state
                    .db
                    .mark_vm_guest_tools_rotation_installed(vm_id, generation)?;
            }
        }
        tokio::fs::rename(&output_path, &target).await?;
        sync_directory(root).await?;
        tokio::fs::remove_dir_all(&temporary).await?;
        sync_directory(root).await?;
        Ok(target)
    }
    .await;
    if result.is_err() {
        if tokio::fs::remove_dir_all(&temporary).await.is_ok() {
            let _ = sync_directory(root).await;
        }
    }
    result
}

fn is_windows_os_family(value: &str) -> bool {
    value.to_ascii_lowercase().contains("windows")
}

fn append_cloud_init_base64_file(user_data: &mut String, path: &str, permissions: &str, contents: &[u8]) {
    user_data.push_str(&format!(
        "  - path: {path}\n    owner: root:root\n    permissions: '{permissions}'\n    encoding: b64\n    content: {}\n",
        STANDARD.encode(contents)
    ));
}

/// Build a NetworkManager keyfile fallback for routed guests.
///
/// The link-local transit address owns the default route while one or more
/// provider addresses remain `/32`s on the same interface. NetworkManager's
/// numbered `addressN` syntax supports that topology without a shell script or
/// distribution-specific network configuration path.
fn networkmanager_routed_keyfile(
    vm: &crate::models::Vm,
    routed: &crate::services::routed_network::RoutedIpv4,
    addresses: &[crate::models::IpAddressRecord],
    dns: &[crate::models::DnsServer],
) -> AppResult<String> {
    let mac = vm
        .mac_address
        .as_deref()
        .ok_or_else(|| AppError::Configuration("routed VM MAC address is missing".into()))?;
    if mac.chars().any(|character| matches!(character, '\r' | '\n')) {
        return Err(AppError::Configuration(
            "routed VM MAC address contains an invalid character".into(),
        ));
    }
    let mut profile = format!(
        "[connection]\nid=vexa-routed\ntype=ethernet\ninterface-name=eth0\nautoconnect=true\nautoconnect-priority=100\n\n[ethernet]\nmac-address={mac}\n\n[ipv4]\nmethod=manual\naddress1={}/{},{}\n",
        routed.guest_address,
        routed.prefix_length,
        routed.gateway,
    );
    let mut index = 2_u32;
    for address in addresses
        .iter()
        .filter(|address| address.family == crate::models::AddressFamily::V4)
    {
        profile.push_str(&format!(
            "address{index}={}/{}\n",
            address.address, address.prefix_length
        ));
        index += 1;
    }
    let dns = dns
        .iter()
        .filter(|server| server.family == crate::models::AddressFamily::V4)
        .map(|server| server.address.as_str())
        .collect::<Vec<_>>();
    if !dns.is_empty() {
        profile.push_str(&format!("dns={};\n", dns.join(";")));
    }
    profile.push_str("never-default=false\nmay-fail=false\n\n[ipv6]\nmethod=auto\nmay-fail=true\n");
    Ok(profile)
}

async fn build_cloudbase_seed(
    state: &AppState,
    vm: crate::models::Vm,
    password: &str,
    tools: Option<GuestToolsSeed>,
    guest_tools_generation: Option<&str>,
) -> AppResult<PathBuf> {
    let addresses = state.db.vm_ip_addresses(&vm.id)?;
    let dns = state.db.dns_servers(None, Some(&vm.id))?;
    let ssh_keys = vm
        .metadata
        .get("ssh_keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|key| {
            !key.is_empty()
                && key.len() <= 16 * 1024
                && !key.chars().any(|character| matches!(character, '\r' | '\n'))
        })
        .take(64)
        .collect::<Vec<_>>();

    let encoded_user = STANDARD.encode(vm.root_username.as_bytes());
    let encoded_password = STANDARD.encode(password.as_bytes());
    let mut user_data = format!(
        r#"#ps1_sysnative
$ErrorActionPreference = 'Stop'
function Decode-Text([string] $Value) {{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value)) }}
function Write-B64([string] $Path, [string] $Value) {{ [IO.File]::WriteAllBytes($Path, [Convert]::FromBase64String($Value)) }}
$bootstrap = $null
$binary = $null
$secret = $null
$installer = $null
$username = Decode-Text '{encoded_user}'
$plainPassword = Decode-Text '{encoded_password}'
try {{
  $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
  Set-LocalUser -Name $username -Password $securePassword -ErrorAction Stop
"#,
    );
    if let Some(tools) = tools {
        let installer_bytes =
            include_bytes!("../../guest-tools/packaging/windows/Install-VexaGuestTools.ps1");
        let encoded_binary = STANDARD.encode(&tools.artifact);
        let encoded_secret = STANDARD.encode(format!("base64:{}\r\n", tools.secret));
        let encoded_installer = STANDARD.encode(installer_bytes);
        user_data.push_str(&format!(
            r#"  $bootstrap = Join-Path $env:ProgramData 'Vexa\Bootstrap'
  New-Item -ItemType Directory -Force -Path $bootstrap | Out-Null
  $bootstrapItem = Get-Item -LiteralPath $bootstrap -Force
  if (($bootstrapItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'Refusing a reparse-point bootstrap directory.' }}
  & icacls.exe $bootstrap '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)(F)' '/grant:r' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'Failed to protect the Vexa bootstrap directory.' }}
  $binary = Join-Path $bootstrap 'vexa-guest-tools.exe'
  $secret = Join-Path $bootstrap 'secret'
  $installer = Join-Path $bootstrap 'Install-VexaGuestTools.ps1'
  Write-B64 $binary '{encoded_binary}'
  Write-B64 $secret '{encoded_secret}'
  Write-B64 $installer '{encoded_installer}'
  & icacls.exe $secret '/inheritance:r' '/grant:r' '*S-1-5-18:(F)' '/grant:r' '*S-1-5-32-544:(F)' | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'Failed to protect the Vexa bootstrap secret.' }}
  & $installer -Binary $binary -SecretFile $secret
"#,
        ));
        if !ssh_keys.is_empty() {
            let encoded_keys = STANDARD.encode(ssh_keys.join("\r\n").as_bytes());
            user_data.push_str(&format!(
                r#"$keyDirectory = Join-Path $env:ProgramData 'Vexa\GuestTools\authorized_keys'
New-Item -ItemType Directory -Force -Path $keyDirectory | Out-Null
$keyPath = Join-Path $keyDirectory $username
[IO.File]::WriteAllText($keyPath, (Decode-Text '{encoded_keys}') + "`r`n")
& icacls.exe $keyPath '/inheritance:r' '/grant:r' '*S-1-5-18:(F)' '/grant:r' '*S-1-5-32-544:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'Failed to protect the Vexa-managed SSH key file.' }}
"#,
            ));
        }
    }
    user_data.push_str(
        r#"} finally {
  $plainPassword = $null
  $securePassword = $null
  foreach ($path in @($binary, $secret, $installer)) {
    if ($null -ne $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
  }
  if ($null -ne $bootstrap) { Remove-Item -LiteralPath $bootstrap -Force -ErrorAction SilentlyContinue }
}
"#,
    );

    let quoted = |value: &str| {
        serde_json::to_string(value)
            .map_err(|error| AppError::Internal(format!("could not encode Cloudbase-Init value: {error}")))
    };
    let metadata = format!(
        "instance-id: {}\nlocal-hostname: {}\n",
        quoted(&vm.id)?,
        quoted(&vm.hostname)?,
    );
    let dns_addresses = dns
        .iter()
        .map(|server| server.address.as_str())
        .collect::<Vec<_>>();
    let mut network = format!(
        "version: 1\nconfig:\n  - type: physical\n    name: Ethernet\n    mac_address: {}\n    subnets:\n",
        quoted(vm.mac_address.as_deref().unwrap_or(""))?,
    );
    let routed = crate::services::routed_network::plan(&vm)?;
    if addresses.is_empty() && routed.is_none() {
        network.push_str("      - type: dhcp4\n      - type: dhcp6\n");
    } else {
        let mut gateway_families = std::collections::BTreeSet::new();
        for address in &addresses {
            let (subnet_type, configured_address, netmask) =
                cloudbase_static_subnet(address.family, &address.address, address.prefix_length)?;
            network.push_str(&format!(
                "      - type: {subnet_type}\n        address: {}\n",
                quoted(&configured_address)?,
            ));
            if let Some(netmask) = netmask {
                network.push_str(&format!("        netmask: {}\n", quoted(&netmask)?));
            }
            if routed.is_none() {
                if let Some(gateway) = address.gateway.as_deref() {
                    if gateway_families.insert(address.family.as_i64()) {
                        network.push_str(&format!("        gateway: {}\n", quoted(gateway)?));
                    }
                }
            }
            if !dns_addresses.is_empty() {
                network.push_str(&format!(
                    "        dns_nameservers: {}\n",
                    serde_json::to_string(&dns_addresses).map_err(|error| {
                        AppError::Internal(format!("could not encode Cloudbase-Init DNS: {error}"))
                    })?
                ));
            }
        }
        if let Some(routed) = routed {
            let (_, configured_address, netmask) = cloudbase_static_subnet(
                crate::models::AddressFamily::V4,
                &routed.guest_address.to_string(),
                routed.prefix_length,
            )?;
            network.push_str(&format!(
                "      - type: static\n        address: {}\n        netmask: {}\n        gateway: {}\n",
                quoted(&configured_address)?,
                quoted(netmask.as_deref().unwrap_or("255.255.255.252"))?,
                quoted(&routed.gateway.to_string())?,
            ));
            if !dns_addresses.is_empty() {
                network.push_str(&format!(
                    "        dns_nameservers: {}\n",
                    serde_json::to_string(&dns_addresses).map_err(|error| {
                        AppError::Internal(format!("could not encode Cloudbase-Init DNS: {error}"))
                    })?
                ));
            }
        }
    }

    write_seed_iso(
        state,
        &vm.id,
        &user_data,
        &metadata,
        &network,
        guest_tools_generation,
    )
    .await
}

/// Cloudbase-Init consumes cloud-init network-config v1. IPv4 masks are most
/// interoperable in dotted notation, while IPv6 must use the `static6` subnet
/// type and carries its prefix in the address value. A bare integer `netmask`
/// is not valid v1 network configuration and left otherwise-correct Windows
/// guests without their configured public address.
fn cloudbase_static_subnet(
    family: crate::models::AddressFamily,
    address: &str,
    prefix_length: u8,
) -> AppResult<(&'static str, String, Option<String>)> {
    match family {
        crate::models::AddressFamily::V4 => {
            let address = address
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| AppError::Validation("Cloudbase-Init IPv4 address is invalid".into()))?;
            if prefix_length > 32 {
                return Err(AppError::Validation(
                    "Cloudbase-Init IPv4 prefix must be between 0 and 32".into(),
                ));
            }
            let mask = if prefix_length == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_length))
            };
            Ok((
                "static",
                address.to_string(),
                Some(std::net::Ipv4Addr::from(mask).to_string()),
            ))
        }
        crate::models::AddressFamily::V6 => {
            let address = address
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| AppError::Validation("Cloudbase-Init IPv6 address is invalid".into()))?;
            if prefix_length > 128 {
                return Err(AppError::Validation(
                    "Cloudbase-Init IPv6 prefix must be between 0 and 128".into(),
                ));
            }
            Ok(("static6", format!("{address}/{prefix_length}"), None))
        }
    }
}

async fn write_seed_iso(
    state: &AppState,
    vm_id: &str,
    user_data: &str,
    metadata: &str,
    network: &str,
    guest_tools_generation: Option<&str>,
) -> AppResult<PathBuf> {
    let root = &state.config.cloud_init_storage;
    tokio::fs::create_dir_all(root).await?;
    let temporary = root.join(format!(".{vm_id}-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir(&temporary).await?;
    set_private_directory_permissions(&temporary).await?;
    let result = async {
        write_private_file(&temporary.join("user-data"), user_data.as_bytes()).await?;
        write_private_file(&temporary.join("meta-data"), metadata.as_bytes()).await?;
        write_private_file(&temporary.join("network-config"), network.as_bytes()).await?;
        let program = ["/usr/bin/genisoimage", "/usr/bin/mkisofs"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .ok_or_else(|| AppError::Hypervisor("genisoimage is required for cloud-init images".into()))?;
        let output_path = temporary.join("seed.iso");
        let mut command = Command::new(program);
        command
            .current_dir(&temporary)
            .args([
                "-quiet",
                "-output",
                "seed.iso",
                "-volid",
                "cidata",
                "-joliet",
                "-rock",
                "user-data",
                "meta-data",
                "network-config",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(60), command.output())
            .await
            .map_err(|_| AppError::Hypervisor("cloud-init ISO generation timed out".into()))??;
        if !output.status.success() {
            return Err(AppError::Hypervisor("cloud-init ISO generation failed".into()));
        }
        // The setgid cloud-init store assigns the `kvm` group to this file.
        // QEMU needs group-read access after libvirt attaches the seed media;
        // the source files in the private temporary directory remain 0600.
        set_seed_permissions(&output_path).await?;
        tokio::fs::File::open(&output_path).await?.sync_all().await?;
        let target = root.join(format!("{vm_id}.iso"));
        if let Some(generation) = guest_tools_generation {
            // Arm before publishing media containing the pending key. If the
            // process dies after this point, recovery must preserve that key even
            // when libvirt has not yet returned from the reinstall operation.
            state
                .db
                .mark_vm_guest_tools_rotation_installed(vm_id, generation)?;
        }
        tokio::fs::rename(&output_path, &target).await?;
        sync_directory(root).await?;
        tokio::fs::remove_dir_all(&temporary).await?;
        sync_directory(root).await?;
        Ok(target)
    }
    .await;
    if result.is_err() {
        if tokio::fs::remove_dir_all(&temporary).await.is_ok() {
            let _ = sync_directory(root).await;
        }
    }
    result
}

/// Produce a guest-compatible SHA-512 crypt value without putting the
/// plaintext password in an argument, process listing, log field, or seed ISO.
async fn cloud_init_password_hash(password: &str) -> AppResult<String> {
    let mut child = Command::new("/usr/bin/openssl")
        .args(["passwd", "-6", "-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| AppError::Hypervisor("openssl is required for cloud-init passwords".into()))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| AppError::Hypervisor("could not open openssl input".into()))?;
    stdin.write_all(password.as_bytes()).await?;
    stdin.shutdown().await?;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .map_err(|_| AppError::Hypervisor("cloud-init password hashing timed out".into()))??;
    if !output.status.success() {
        return Err(AppError::Hypervisor("cloud-init password hashing failed".into()));
    }
    let hash = String::from_utf8(output.stdout)
        .map_err(|_| AppError::Hypervisor("openssl returned an invalid password hash".into()))?;
    let hash = hash.trim();
    if !hash.starts_with("$6$") || hash.len() > 512 {
        return Err(AppError::Hypervisor(
            "openssl returned an unsupported password hash".into(),
        ));
    }
    Ok(hash.to_owned())
}

async fn write_private_file(path: &Path, contents: &[u8]) -> AppResult<()> {
    tokio::fs::write(path, contents).await?;
    set_private_permissions(path).await
}

async fn set_private_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

async fn set_seed_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).await?;
    }
    Ok(())
}

async fn set_private_directory_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

async fn sync_directory(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> { std::fs::File::open(path)?.sync_all() })
            .await
            .map_err(|error| AppError::Internal(format!("directory sync task failed: {error}")))??;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Remove the stable per-VM provisioning seed and durably publish its absence.
///
/// `NotFound` is success because a prior delete attempt (or authenticated
/// Guest Tools retirement) may already have removed the file. When the managed
/// directory still exists we sync it even in that case: this also completes a
/// retry whose previous unlink succeeded but whose directory sync failed.
async fn remove_vm_provisioning_seed(root: &Path, vm_id: &str) -> AppResult<bool> {
    let seed_path = root.join(format!("{vm_id}.iso"));
    let removed = match tokio::fs::remove_file(&seed_path).await {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };

    match tokio::fs::metadata(root).await {
        Ok(metadata) if metadata.is_dir() => sync_directory(root).await?,
        Ok(_) => {
            return Err(AppError::Configuration(
                "cloud-init storage is not a directory".into(),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !removed => {}
        Err(error) => return Err(error.into()),
    }
    Ok(removed)
}

fn delete_error_is_retryable(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Database(_) | AppError::Hypervisor(_) | AppError::Io(_) | AppError::Internal(_)
    )
}

fn payload_field<T: serde::de::DeserializeOwned>(payload: &Value, field: &str) -> AppResult<T> {
    serde_json::from_value(payload.get(field).cloned().unwrap_or(Value::Null))
        .map_err(|error| AppError::Validation(format!("job payload field '{field}' is invalid: {error}")))
}

/// Apply the default ownership guard and every explicitly enabled forwarding
/// policy before a guest becomes network-active. If reconciliation fails, stop
/// an already-active guest so protection fails closed instead of becoming only
/// a panel badge with unfiltered traffic underneath it.
async fn ensure_vm_network_policy(state: &AppState, vm: &crate::models::Vm) -> AppResult<()> {
    if state.hypervisor.capabilities().await?.backend != "libvirt" {
        return Ok(());
    }
    if !crate::services::firewall::vm_policy_enabled(state, &vm.id)? {
        return Ok(());
    }
    crate::services::firewall::reconcile_vm_fail_closed(state, vm).await?;
    Ok(())
}

fn required_vm(state: &AppState, job: &Job) -> AppResult<crate::models::Vm> {
    let id = job
        .vm_id
        .as_deref()
        .ok_or_else(|| AppError::Validation("job is missing vm_id".into()))?;
    state
        .db
        .get_vm(id)?
        .ok_or_else(|| AppError::NotFound("VM".into()))
}

fn sync_vm_info(state: &AppState, vm_id: Option<&str>, info: &crate::hypervisor::VmInfo) -> AppResult<()> {
    let id = vm_id.unwrap_or(&info.name);
    let state_value = map_power_state(info.state);
    let current = state.db.get_vm(id)?;
    let disk_gib = (info.disk_bytes > 0)
        .then(|| bytes_to_gib_ceil(info.disk_bytes))
        .filter(|detected| {
            current
                .as_ref()
                .map_or(true, |stored| *detected >= stored.disk_gib)
        });
    state.db.patch_vm(
        id,
        &VmPatch {
            state: Some(state_value),
            desired_state: Some(state_value),
            vcpus: (info.vcpus > 0).then_some(info.vcpus),
            memory_mib: (info.memory_mib >= 256).then_some(info.memory_mib),
            disk_gib,
            tap_name: Some(info.interface_name.clone()),
            libvirt_uuid: info.uuid.as_ref().map(|value| Some(value.to_string())),
            autostart: Some(info.autostart),
            ..VmPatch::default()
        },
    )?;
    Ok(())
}

fn map_power_state(state: VmPowerState) -> VmState {
    match state {
        VmPowerState::Running => VmState::Running,
        VmPowerState::Paused | VmPowerState::Suspended => VmState::Paused,
        VmPowerState::ShutOff | VmPowerState::ShuttingDown => VmState::Stopped,
        VmPowerState::Crashed => VmState::Error,
        VmPowerState::Unknown => VmState::Unknown,
    }
}

async fn maintenance_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut passes = 0_u64;
    loop {
        interval.tick().await;
        let now = Utc::now().timestamp();
        if let Err(error) = state.db.prune_expired_sessions(now) {
            warn!(error = %error, "session cleanup failed");
        }
        if let Err(error) = state.db.prune_expired_tokens(now) {
            warn!(error = %error, "token cleanup failed");
        }
        passes += 1;
        if passes % 12 == 0 {
            let retention_days = state
                .setting_u64("general", "metrics_retention_days")
                .unwrap_or(None)
                .unwrap_or(7)
                .clamp(1, 3650);
            let retention_seconds = i64::try_from(retention_days)
                .unwrap_or(7)
                .saturating_mul(24 * 60 * 60);
            let _ = state.db.prune_metrics(now.saturating_sub(retention_seconds));
            if let Err(error) = state.refresh_host_info().await {
                warn!(error = %error, "host inventory refresh failed");
            }
        }
    }
}

#[cfg(test)]
mod cloudbase_network_tests {
    use super::{
        accounted_traffic_delta, cloudbase_static_subnet, is_windows_os_family,
        memory_entitlement_needs_restore,
        remove_vm_provisioning_seed, windows_computer_name, windows_disk_layout, windows_first_logon_command,
        PreviousVmSample,
    };
    use crate::hypervisor::VmStats;
    use crate::models::AddressFamily;

    #[test]
    fn memory_entitlement_repair_only_expands_reduced_guests() {
        assert!(memory_entitlement_needs_restore(2731, 4096));
        assert!(!memory_entitlement_needs_restore(4032, 4096));
        assert!(!memory_entitlement_needs_restore(4096, 4096));
    }

    #[test]
    fn cloudbase_ipv4_uses_a_dotted_network_mask() {
        let (kind, address, mask) = cloudbase_static_subnet(AddressFamily::V4, "192.0.2.83", 24).unwrap();
        assert_eq!(kind, "static");
        assert_eq!(address, "192.0.2.83");
        assert_eq!(mask.as_deref(), Some("255.255.255.0"));

        let (_, _, host_mask) = cloudbase_static_subnet(AddressFamily::V4, "198.51.100.7", 32).unwrap();
        assert_eq!(host_mask.as_deref(), Some("255.255.255.255"));
        let (_, _, default_mask) = cloudbase_static_subnet(AddressFamily::V4, "0.0.0.0", 0).unwrap();
        assert_eq!(default_mask.as_deref(), Some("0.0.0.0"));
    }

    #[test]
    fn cloudbase_ipv6_uses_static6_and_cidr_addressing() {
        let (kind, address, mask) = cloudbase_static_subnet(AddressFamily::V6, "2001:db8::83", 64).unwrap();
        assert_eq!(kind, "static6");
        assert_eq!(address, "2001:db8::83/64");
        assert!(mask.is_none());
    }

    #[test]
    fn cloudbase_subnets_reject_wrong_family_and_prefix() {
        assert!(cloudbase_static_subnet(AddressFamily::V4, "2001:db8::1", 24).is_err());
        assert!(cloudbase_static_subnet(AddressFamily::V4, "192.0.2.1", 33).is_err());
        assert!(cloudbase_static_subnet(AddressFamily::V6, "2001:db8::1", 129).is_err());
    }

    #[test]
    fn windows_automatic_images_use_cloudbase_even_without_guest_tools() {
        assert!(is_windows_os_family("Windows Server 2025"));
        assert!(is_windows_os_family("WINDOWS"));
        assert!(!is_windows_os_family("ubuntu"));
    }

    #[test]
    fn windows_computer_names_are_valid_stable_and_collision_scoped() {
        assert_eq!(
            windows_computer_name("win-2022", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "win-2022"
        );
        let shortened =
            windows_computer_name("vexa-verify-windows-p12", "f3cd0496-b494-4b48-b22f-3527f778aaf9");
        assert_eq!(shortened, "vexa-ver-f3cd04");
        assert!(shortened.len() <= 15);
        assert_ne!(
            shortened,
            windows_computer_name("vexa-verify-windows-p12", "a1b2c3d4-b494-4b48-b22f-3527f778aaf9")
        );
        assert!(windows_computer_name("123456789012345", "abcd",)
            .bytes()
            .any(|byte| byte.is_ascii_alphabetic()));
    }

    #[test]
    fn windows_first_logon_uses_a_bounded_script_file_command() {
        let command = windows_first_logon_command();
        assert!(command.len() < 1024);
        assert!(command.contains("VexaTools\\FirstBoot.ps1"));
        assert!(!command.contains("EncodedCommand"));
    }

    #[test]
    fn unattended_windows_uses_a_bootable_layout_for_each_firmware() {
        let (uefi, uefi_target) = windows_disk_layout(true);
        assert!(uefi.contains("<Type>EFI</Type>"));
        assert!(uefi.contains("<Type>MSR</Type>"));
        assert_eq!(uefi_target, 3);

        let (bios, bios_target) = windows_disk_layout(false);
        assert!(bios.contains("<Active>true</Active>"));
        assert!(!bios.contains("<Type>EFI</Type>"));
        assert_eq!(bios_target, 1);
    }

    #[test]
    fn traffic_reset_generation_discards_the_pre_reset_interval() {
        let prior = PreviousVmSample {
            sampled_at: 100,
            stats: VmStats {
                network_rx_bytes: 1_000,
                network_tx_bytes: 2_000,
                ..VmStats::default()
            },
            traffic_generation: 4,
        };
        let current = VmStats {
            network_rx_bytes: 1_125,
            network_tx_bytes: 2_075,
            ..VmStats::default()
        };

        assert_eq!(accounted_traffic_delta(&prior, &current, 4), 200);
        assert_eq!(accounted_traffic_delta(&prior, &current, 5), 0);
    }

    #[test]
    fn traffic_accounting_does_not_recharge_cumulative_counters_after_zero_gap() {
        let unavailable = PreviousVmSample {
            sampled_at: 100,
            stats: VmStats {
                network_rx_bytes: 0,
                network_tx_bytes: 0,
                ..VmStats::default()
            },
            traffic_generation: 4,
        };
        let restored = VmStats {
            network_rx_bytes: 828 * 1024 * 1024 * 1024,
            network_tx_bytes: 829 * 1024 * 1024 * 1024,
            ..VmStats::default()
        };

        assert_eq!(accounted_traffic_delta(&unavailable, &restored, 4), 0);
    }

    #[tokio::test]
    async fn provisioning_seed_delete_is_durable_and_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cloud-init");
        std::fs::create_dir(&root).unwrap();
        let seed = root.join("vm-one.iso");
        std::fs::write(&seed, b"credential-bearing seed").unwrap();

        assert!(remove_vm_provisioning_seed(&root, "vm-one").await.unwrap());
        assert!(!seed.exists());
        // A worker retry after unlink (including one following a failed sync)
        // accepts NotFound and re-syncs the extant managed directory.
        assert!(!remove_vm_provisioning_seed(&root, "vm-one").await.unwrap());
    }

    #[tokio::test]
    async fn provisioning_seed_cleanup_failure_keeps_the_artifact_trackable() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cloud-init");
        std::fs::create_dir(&root).unwrap();
        let unexpected_directory = root.join("vm-two.iso");
        std::fs::create_dir(&unexpected_directory).unwrap();

        assert!(remove_vm_provisioning_seed(&root, "vm-two").await.is_err());
        assert!(unexpected_directory.is_dir());
    }
}
