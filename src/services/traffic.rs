//! Persistent traffic-quota enforcement.
//!
//! Vexa-VM owns only link transitions recorded in `vm_traffic_enforcement`.
//! This prevents an unlimited VM whose interface was disabled by an operator
//! from being brought online accidentally.

use serde::Serialize;
use tracing::warn;

use crate::{
    error::{AppError, AppResult},
    models::{Vm, VmTrafficEnforcement},
    state::AppState,
};

/// Safe quota assigned to legacy/unconfigured VMs unless the node's main
/// administrator has explicitly enabled unlimited traffic.
pub const DEFAULT_ENFORCED_TRAFFIC_QUOTA_BYTES: u64 = 1_099_511_627_776;

#[derive(Clone, Debug, Serialize)]
pub struct TrafficQuotaStatus {
    pub limit_bytes: Option<u64>,
    pub used_bytes: u64,
    pub unlimited: bool,
    pub exceeded: bool,
    pub network_blocked: bool,
    pub blocked_at: Option<i64>,
    pub enforcement_error: Option<String>,
}

pub fn is_exceeded(limit_bytes: Option<u64>, used_bytes: u64) -> bool {
    limit_bytes.is_some_and(|limit| limit > 0 && used_bytes >= limit)
}

pub fn unlimited_allowed(state: &AppState) -> AppResult<bool> {
    Ok(state
        .setting_bool("network", "allow_unlimited_traffic")?
        .unwrap_or(false))
}

pub fn enforced_default_limit(state: &AppState) -> AppResult<u64> {
    Ok(state
        .setting_u64("network", "default_traffic_quota_bytes")?
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_ENFORCED_TRAFFIC_QUOTA_BYTES))
}

pub fn validate_limit(state: &AppState, limit: Option<u64>) -> AppResult<()> {
    if limit.filter(|value| *value > 0).is_none() && !unlimited_allowed(state)? {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

pub fn quota_status(state: &AppState, vm: &Vm) -> AppResult<TrafficQuotaStatus> {
    let enforcement = state.db.vm_traffic_enforcement(&vm.id)?;
    Ok(status_from(vm, enforcement.as_ref()))
}

fn status_from(vm: &Vm, enforcement: Option<&VmTrafficEnforcement>) -> TrafficQuotaStatus {
    let limit = vm.traffic_limit_bytes.filter(|limit| *limit > 0);
    TrafficQuotaStatus {
        limit_bytes: limit,
        used_bytes: vm.traffic_used_bytes,
        unlimited: limit.is_none(),
        exceeded: is_exceeded(limit, vm.traffic_used_bytes),
        network_blocked: enforcement.is_some_and(|record| record.blocked),
        blocked_at: enforcement.and_then(|record| record.blocked_at),
        enforcement_error: enforcement.and_then(|record| record.last_error.clone()),
    }
}

pub async fn reconcile_vm(state: &AppState, vm_id: &str, force: bool) -> AppResult<TrafficQuotaStatus> {
    let _guard = state.traffic_lock.lock().await;
    reconcile_vm_locked(state, vm_id, force).await
}

/// Reconcile while the caller holds `AppState::traffic_lock`.
pub(crate) async fn reconcile_vm_locked(
    state: &AppState,
    vm_id: &str,
    force: bool,
) -> AppResult<TrafficQuotaStatus> {
    let mut vm = state
        .db
        .get_vm(vm_id)?
        .ok_or_else(|| AppError::NotFound("VM".into()))?;
    if vm.traffic_limit_bytes.filter(|limit| *limit > 0).is_none() && !unlimited_allowed(state)? {
        vm = state.db.patch_vm(
            &vm.id,
            &crate::models::VmPatch {
                traffic_limit_bytes: Some(Some(enforced_default_limit(state)?)),
                ..crate::models::VmPatch::default()
            },
        )?;
    }
    let existing = state.db.vm_traffic_enforcement(&vm.id)?;
    let currently_blocked = existing.as_ref().is_some_and(|record| record.blocked);
    let should_block = is_exceeded(vm.traffic_limit_bytes, vm.traffic_used_bytes);
    // A stored flag is not proof of enforcement: a host/network restart or an
    // external link change can bring a blocked TAP back up. Reassert every
    // blocked quota on every sweep, not only once at process startup.
    let needs_transition = should_block != currently_blocked || should_block || (force && currently_blocked);

    if needs_transition {
        let enabled = !should_block;
        match state.hypervisor.set_network_enabled(&vm.name, enabled).await {
            Ok(()) => {
                state.db.set_vm_traffic_enforcement(&vm.id, should_block, None)?;
                crate::services::firewall::reconcile(state).await?;
            }
            Err(error) => {
                let message = error.to_string();
                state
                    .db
                    .set_vm_traffic_enforcement(&vm.id, currently_blocked, Some(&message))?;
                return Err(AppError::Hypervisor(format!(
                    "traffic quota could not {} VM network: {message}",
                    if should_block { "disable" } else { "restore" }
                )));
            }
        }
    } else if existing
        .as_ref()
        .is_some_and(|record| record.last_error.is_some())
    {
        state
            .db
            .set_vm_traffic_enforcement(&vm.id, currently_blocked, None)?;
    }

    let current = state
        .db
        .get_vm(&vm.id)?
        .ok_or_else(|| AppError::NotFound("VM".into()))?;
    quota_status(state, &current)
}

pub async fn reconcile_all(state: &AppState, force: bool) -> AppResult<()> {
    for vm in state.db.list_vms()? {
        if let Err(error) = reconcile_vm(state, &vm.id, force).await {
            warn!(vm_id = %vm.id, vm = %vm.name, error = %error, "traffic quota reconciliation failed");
        }
    }
    Ok(())
}

pub async fn reset_usage_locked(state: &AppState, vm_id: &str) -> AppResult<Vm> {
    let vm = state.db.patch_vm(
        vm_id,
        &crate::models::VmPatch {
            traffic_used_bytes: Some(0),
            ..crate::models::VmPatch::default()
        },
    )?;
    let mut generations = state.traffic_accounting_generations.lock().await;
    let generation = generations.entry(vm.id.clone()).or_default();
    *generation = generation.wrapping_add(1);
    Ok(vm)
}

#[cfg(test)]
mod tests {
    use super::is_exceeded;

    #[test]
    fn zero_and_null_do_not_self_enforce() {
        assert!(!is_exceeded(None, u64::MAX));
        assert!(!is_exceeded(Some(0), u64::MAX));
    }

    #[test]
    fn quota_blocks_only_after_threshold_is_exceeded() {
        assert!(is_exceeded(Some(100), 100));
        assert!(is_exceeded(Some(100), 101));
    }
}
