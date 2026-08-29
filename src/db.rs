//! SQLite persistence behind a single process-wide mutex.
//!
//! The web server is asynchronous, but individual SQLite operations are short
//! and serialized. Long-running libvirt/image work must happen outside these
//! closures and report progress through the durable `jobs` table.

use std::{
    fmt,
    net::IpAddr,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ipnet::IpNet;
use rusqlite::{params, types::Type, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    models::*,
    security::{
        vm_guest_tools_pending_secret_context, vm_guest_tools_secret_context,
        vm_password_context, Security,
    },
    services::network_security::{
        canonical_ip_network, normalize_firewall_rule, validate_vm_network_security,
        MAX_FIREWALL_RULES_PER_VM,
    },
};

const SCHEMA_VERSION: i64 = 10;
const INITIAL_MIGRATION: &str = include_str!("../migrations/0001_init.sql");
const API_KEY_ALLOWLIST_MIGRATION: &str = include_str!("../migrations/0002_api_key_ip_allowlist.sql");
const TRAFFIC_ENFORCEMENT_MIGRATION: &str = include_str!("../migrations/0003_vm_traffic_enforcement.sql");
const NETWORK_SECURITY_MIGRATION: &str = include_str!("../migrations/0004_network_security.sql");
const GUEST_TOOLS_MIGRATION: &str = include_str!("../migrations/0005_guest_tools.sql");
const FIREWALL_RULE_OWNERSHIP_MIGRATION: &str =
    include_str!("../migrations/0006_firewall_rule_ownership.sql");
const GUEST_TOOLS_SECRET_ROTATION_MIGRATION: &str =
    include_str!("../migrations/0007_guest_tools_secret_rotation.sql");
const UPDATE_STATUS_AUDIT_IMPORTS_MIGRATION: &str =
    include_str!("../migrations/0008_update_status_audit_imports.sql");
const NETWORK_SECURITY_SAFE_DEFAULTS_MIGRATION: &str =
    include_str!("../migrations/0009_network_security_safe_defaults.sql");
const IP_OWNERSHIP_GUARD_MIGRATION: &str =
    include_str!("../migrations/0010_ip_ownership_guard.sql");

#[derive(Clone)]
pub struct Database {
    connection: Arc<Mutex<Connection>>,
}

impl fmt::Debug for Database {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Database").finish_non_exhaustive()
    }
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> AppResult<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        Self::from_connection(Connection::open(path)?)
    }

    pub fn open_in_memory() -> AppResult<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> AppResult<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;

        let mut version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(AppError::Configuration(format!(
                "database schema version {version} is newer than supported version {SCHEMA_VERSION}"
            )));
        }
        if version < 1 {
            connection.execute_batch(INITIAL_MIGRATION)?;
            version = 1;
        }
        if version < 2 {
            connection.execute_batch(API_KEY_ALLOWLIST_MIGRATION)?;
            version = 2;
        }
        if version < 3 {
            connection.execute_batch(TRAFFIC_ENFORCEMENT_MIGRATION)?;
            version = 3;
        }
        if version < 4 {
            connection.execute_batch(NETWORK_SECURITY_MIGRATION)?;
            version = 4;
        }
        if version < 5 {
            connection.execute_batch(GUEST_TOOLS_MIGRATION)?;
            version = 5;
        }
        if version < 6 {
            connection.execute_batch(FIREWALL_RULE_OWNERSHIP_MIGRATION)?;
            version = 6;
        }
        if version < 7 {
            connection.execute_batch(GUEST_TOOLS_SECRET_ROTATION_MIGRATION)?;
            version = 7;
        }
        if version < 8 {
            connection.execute_batch(UPDATE_STATUS_AUDIT_IMPORTS_MIGRATION)?;
            version = 8;
        }
        if version < 9 {
            connection.execute_batch(NETWORK_SECURITY_SAFE_DEFAULTS_MIGRATION)?;
            version = 9;
        }
        if version < 10 {
            connection.execute_batch(IP_OWNERSHIP_GUARD_MIGRATION)?;
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn schema_version(&self) -> AppResult<i64> {
        self.with_connection(|connection| {
            connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .map_err(Into::into)
        })
    }

    /// Escape hatch for small, application-specific read operations. Never do
    /// network, filesystem, or hypervisor work while this closure holds the DB.
    pub fn with_connection<T>(&self, operation: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
        let guard = self.lock()?;
        operation(&guard)
    }

    pub fn with_transaction<T>(
        &self,
        behavior: TransactionBehavior,
        operation: impl FnOnce(&Transaction<'_>) -> AppResult<T>,
    ) -> AppResult<T> {
        let mut guard = self.lock()?;
        let transaction = guard.transaction_with_behavior(behavior)?;
        let result = operation(&transaction)?;
        transaction.commit()?;
        Ok(result)
    }

    fn lock(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| AppError::Internal("database mutex was poisoned".into()))
    }

    // --- Administrators and browser sessions ---------------------------------

    pub fn bootstrap_admin(&self, username: &str, password_hash: &str) -> AppResult<Admin> {
        validate_non_empty("username", username)?;
        validate_non_empty("password hash", password_hash)?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let existing: Option<Admin> = transaction
                .query_row(
                    "SELECT id, username, role, enabled, created_at, updated_at, last_login_at
                     FROM admins ORDER BY created_at LIMIT 1",
                    [],
                    row_to_admin,
                )
                .optional()?;
            if let Some(admin) = existing {
                return Ok(admin);
            }
            let id = Uuid::new_v4().to_string();
            let now = unix_now();
            transaction.execute(
                "INSERT INTO admins(id, username, password_hash, role, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'super_admin', 1, ?4, ?4)",
                params![id, username.trim(), password_hash, now],
            )?;
            transaction
                .query_row(
                    "SELECT id, username, role, enabled, created_at, updated_at, last_login_at
                     FROM admins WHERE id = ?1",
                    [&id],
                    row_to_admin,
                )
                .map_err(Into::into)
        })
    }

    pub fn create_admin(&self, username: &str, password_hash: &str, role: AdminRole) -> AppResult<Admin> {
        validate_non_empty("username", username)?;
        validate_non_empty("password hash", password_hash)?;
        let id = Uuid::new_v4().to_string();
        let now = unix_now();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO admins(id, username, password_hash, role, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)",
                params![id, username.trim(), password_hash, role.as_str(), now],
            )?;
            query_admin(connection, &id)?.ok_or_else(|| AppError::NotFound("admin".into()))
        })
    }

    pub fn admin_by_id(&self, id: &str) -> AppResult<Option<Admin>> {
        self.with_connection(|connection| query_admin(connection, id))
    }

    pub fn admin_auth_by_username(&self, username: &str) -> AppResult<Option<AdminAuth>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT id, username, password_hash, role, enabled, created_at, updated_at,
                            last_login_at
                     FROM admins WHERE username = ?1 COLLATE NOCASE",
                    [username],
                    |row| {
                        Ok(AdminAuth {
                            admin: Admin {
                                id: row.get(0)?,
                                username: row.get(1)?,
                                role: enum_column(row, 3)?,
                                enabled: bool_column(row, 4)?,
                                created_at: row.get(5)?,
                                updated_at: row.get(6)?,
                                last_login_at: row.get(7)?,
                            },
                            password_hash: row.get(2)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into)
        })
    }

    pub fn list_admins(&self) -> AppResult<Vec<Admin>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, username, role, enabled, created_at, updated_at, last_login_at
                 FROM admins ORDER BY username COLLATE NOCASE",
            )?;
            let rows = statement.query_map([], row_to_admin)?;
            collect_rows(rows)
        })
    }

    pub fn update_admin_credentials(
        &self,
        id: &str,
        username: Option<&str>,
        password_hash: Option<&str>,
    ) -> AppResult<()> {
        if username.is_none() && password_hash.is_none() {
            return Ok(());
        }
        if let Some(value) = username {
            validate_non_empty("username", value)?;
        }
        if let Some(value) = password_hash {
            validate_non_empty("password hash", value)?;
        }
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE admins
                 SET username = COALESCE(?2, username),
                     password_hash = COALESCE(?3, password_hash),
                     updated_at = ?4
                 WHERE id = ?1",
                    params![id, username.map(str::trim), password_hash, unix_now()],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "admin")
    }

    pub fn set_admin_enabled(&self, id: &str, enabled: bool) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE admins SET enabled = ?2, updated_at = ?3 WHERE id = ?1",
                    params![id, bool_i64(enabled), unix_now()],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "admin")
    }

    pub fn update_admin_access(
        &self,
        id: &str,
        role: Option<AdminRole>,
        enabled: Option<bool>,
    ) -> AppResult<Admin> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current = query_admin(transaction, id)?.ok_or_else(|| AppError::NotFound("admin".into()))?;
            let next_role = role.unwrap_or(current.role);
            let next_enabled = enabled.unwrap_or(current.enabled);
            if current.role == AdminRole::SuperAdmin
                && current.enabled
                && (next_role != AdminRole::SuperAdmin || !next_enabled)
            {
                let remaining: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM admins
                     WHERE role = 'super_admin' AND enabled = 1 AND id <> ?1",
                    [id],
                    |row| row.get(0),
                )?;
                if remaining == 0 {
                    return Err(AppError::Conflict(
                        "at least one enabled super administrator is required".into(),
                    ));
                }
            }
            transaction.execute(
                "UPDATE admins SET role = ?2, enabled = ?3, updated_at = ?4 WHERE id = ?1",
                params![id, next_role.as_str(), bool_i64(next_enabled), unix_now()],
            )?;
            query_admin(transaction, id)?.ok_or_else(|| AppError::NotFound("admin".into()))
        })
    }

    pub fn delete_admin(&self, id: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current = query_admin(transaction, id)?.ok_or_else(|| AppError::NotFound("admin".into()))?;
            if current.role == AdminRole::SuperAdmin && current.enabled {
                let remaining: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM admins
                     WHERE role = 'super_admin' AND enabled = 1 AND id <> ?1",
                    [id],
                    |row| row.get(0),
                )?;
                if remaining == 0 {
                    return Err(AppError::Conflict(
                        "the last enabled super administrator cannot be deleted".into(),
                    ));
                }
            }
            let changed = transaction.execute("DELETE FROM admins WHERE id = ?1", [id])?;
            require_changed(changed, "admin")
        })
    }

    pub fn record_admin_login(&self, id: &str, at: Timestamp) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE admins SET last_login_at = ?2, updated_at = ?2 WHERE id = ?1",
                    params![id, at],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "admin")
    }

    pub fn create_admin_session(
        &self,
        admin_id: &str,
        token_hash: &[u8; 32],
        csrf_hash: &[u8; 32],
        expires_at: Timestamp,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> AppResult<()> {
        let now = unix_now();
        if expires_at <= now {
            return Err(AppError::Validation(
                "session expiry must be in the future".into(),
            ));
        }
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO admin_sessions(
                    token_hash, csrf_hash, admin_id, source_ip, user_agent,
                    created_at, expires_at, last_seen_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6)",
                params![
                    token_hash.as_slice(),
                    csrf_hash.as_slice(),
                    admin_id,
                    source_ip,
                    user_agent,
                    now,
                    expires_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn authenticate_admin_session(
        &self,
        token_hash: &[u8; 32],
        now: Timestamp,
    ) -> AppResult<Option<AdminSession>> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let session = transaction
                .query_row(
                    "SELECT a.id, a.username, a.role, a.enabled, a.created_at, a.updated_at,
                            a.last_login_at, s.created_at, s.expires_at, s.last_seen_at,
                            s.source_ip, s.user_agent
                     FROM admin_sessions s
                     JOIN admins a ON a.id = s.admin_id
                     WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND a.enabled = 1",
                    params![token_hash.as_slice(), now],
                    row_to_admin_session,
                )
                .optional()?;
            if session.is_some() {
                transaction.execute(
                    "UPDATE admin_sessions SET last_seen_at = ?2 WHERE token_hash = ?1",
                    params![token_hash.as_slice(), now],
                )?;
            }
            Ok(session)
        })
    }

    /// Validate that the CSRF credential belongs to the same live browser
    /// session. Both values received by this method are already SHA-256 hashes.
    pub fn verify_admin_session_csrf(
        &self,
        session_hash: &[u8; 32],
        csrf_hash: &[u8; 32],
        now: Timestamp,
    ) -> AppResult<bool> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM admin_sessions s
                        JOIN admins a ON a.id = s.admin_id
                        WHERE s.token_hash = ?1 AND s.csrf_hash = ?2
                          AND s.expires_at > ?3 AND a.enabled = 1
                     )",
                    params![session_hash.as_slice(), csrf_hash.as_slice(), now],
                    |row| row.get::<_, i64>(0),
                )
                .map(|found| found == 1)
                .map_err(Into::into)
        })
    }

    pub fn revoke_admin_session(&self, token_hash: &[u8; 32]) -> AppResult<bool> {
        self.with_connection(|connection| {
            Ok(connection.execute(
                "DELETE FROM admin_sessions WHERE token_hash = ?1",
                [token_hash.as_slice()],
            )? > 0)
        })
    }

    pub fn revoke_admin_sessions(&self, admin_id: &str) -> AppResult<usize> {
        self.with_connection(|connection| {
            connection
                .execute("DELETE FROM admin_sessions WHERE admin_id = ?1", [admin_id])
                .map_err(Into::into)
        })
    }

    pub fn prune_expired_sessions(&self, now: Timestamp) -> AppResult<usize> {
        self.with_connection(|connection| {
            connection
                .execute("DELETE FROM admin_sessions WHERE expires_at <= ?1", [now])
                .map_err(Into::into)
        })
    }

    // --- API credentials ------------------------------------------------------

    // Credential creation mirrors the persisted security fields explicitly;
    // grouping them would obscure which values are hashed, scoped, and bound.
    #[allow(clippy::too_many_arguments)]
    pub fn create_api_key(
        &self,
        name: &str,
        token_hash: &[u8; 32],
        prefix: &str,
        permissions: &[String],
        ip_allowlist: &[String],
        created_by: Option<&str>,
        expires_at: Option<Timestamp>,
    ) -> AppResult<ApiKey> {
        validate_non_empty("API key name", name)?;
        let id = Uuid::new_v4().to_string();
        let now = unix_now();
        if expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(AppError::Validation(
                "API key expiry must be in the future".into(),
            ));
        }
        let permissions_json = json_string(permissions)?;
        let mut normalized_allowlist = Vec::new();
        for cidr in ip_allowlist {
            let network: IpNet = cidr
                .trim()
                .parse()
                .map_err(|_| AppError::Validation(format!("invalid API key CIDR: {cidr}")))?;
            let canonical = network.to_string();
            if !normalized_allowlist.contains(&canonical) {
                normalized_allowlist.push(canonical);
            }
        }
        let ip_allowlist_json = json_string(&normalized_allowlist)?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO api_keys(
                    id, name, token_hash, prefix, permissions_json, ip_allowlist_json,
                    created_by, created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    name.trim(),
                    token_hash.as_slice(),
                    prefix,
                    permissions_json,
                    ip_allowlist_json,
                    created_by,
                    now,
                    expires_at,
                ],
            )?;
            query_api_key(connection, &id)?.ok_or_else(|| AppError::NotFound("API key".into()))
        })
    }

    pub fn authenticate_api_key(&self, token_hash: &[u8; 32], now: Timestamp) -> AppResult<Option<ApiKey>> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let key = transaction
                .query_row(
                    "SELECT id, name, prefix, permissions_json, ip_allowlist_json,
                            created_by, created_at, expires_at, last_used_at, revoked_at
                     FROM api_keys
                     WHERE token_hash = ?1 AND revoked_at IS NULL
                       AND (expires_at IS NULL OR expires_at > ?2)",
                    params![token_hash.as_slice(), now],
                    row_to_api_key,
                )
                .optional()?;
            if key.is_some() {
                transaction.execute(
                    "UPDATE api_keys SET last_used_at = ?2 WHERE token_hash = ?1",
                    params![token_hash.as_slice(), now],
                )?;
            }
            Ok(key)
        })
    }

    pub fn list_api_keys(&self) -> AppResult<Vec<ApiKey>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, name, prefix, permissions_json, ip_allowlist_json,
                        created_by, created_at, expires_at, last_used_at, revoked_at
                 FROM api_keys ORDER BY created_at DESC",
            )?;
            let rows = statement.query_map([], row_to_api_key)?;
            collect_rows(rows)
        })
    }

    pub fn revoke_api_key(&self, id: &str, now: Timestamp) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, ?2) WHERE id = ?1",
                    params![id, now],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "API key")
    }

    // --- Virtual machines -----------------------------------------------------

    pub fn create_vm(&self, spec: &NewVm) -> AppResult<Vm> {
        let id = Uuid::new_v4().to_string();
        self.insert_vm(&id, spec, None)
    }

    /// Encrypt and atomically persist the initial VM password using the VM UUID
    /// as associated data, preventing ciphertext from being swapped between VMs.
    pub fn create_vm_with_password(
        &self,
        spec: &NewVm,
        password: &str,
        security: &Security,
    ) -> AppResult<Vm> {
        validate_non_empty("VM password", password)?;
        let id = Uuid::new_v4().to_string();
        let envelope = security.encrypt_secret(password, &vm_password_context(&id))?;
        self.insert_vm(&id, spec, Some(&envelope))
    }

    fn insert_vm(&self, id: &str, spec: &NewVm, password_envelope: Option<&str>) -> AppResult<Vm> {
        validate_vm_spec(spec)?;
        let now = unix_now();
        let metadata = json_string(&spec.metadata)?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO vms(
                    id, name, hostname, description, os_family, iso_id, state, desired_state,
                    vcpus, memory_mib, disk_gib, disk_format, firmware, machine_type, bridge,
                    tap_name, mac_address, network_limit_mbps, traffic_limit_bytes,
                    root_username, password_envelope, password_updated_at, guest_agent,
                    autostart, timezone, metadata_json, created_at, updated_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, 'creating', 'stopped', ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                    ?23, ?24, ?25, ?25
                 )",
                params![
                    id,
                    spec.name.trim(),
                    spec.hostname.trim(),
                    spec.description,
                    spec.os_family,
                    spec.iso_id,
                    i64::from(spec.vcpus),
                    checked_i64(spec.memory_mib, "memory_mib")?,
                    checked_i64(spec.disk_gib, "disk_gib")?,
                    spec.disk_format,
                    spec.firmware,
                    spec.machine_type,
                    spec.bridge,
                    spec.tap_name,
                    spec.mac_address.as_deref().map(str::to_ascii_lowercase),
                    optional_i64(spec.network_limit_mbps, "network_limit_mbps")?,
                    optional_i64(spec.traffic_limit_bytes, "traffic_limit_bytes")?,
                    spec.root_username,
                    password_envelope,
                    password_envelope.map(|_| now),
                    bool_i64(spec.guest_agent),
                    bool_i64(spec.autostart),
                    spec.timezone,
                    metadata,
                    now,
                ],
            )?;
            query_vm(connection, id)?.ok_or_else(|| AppError::NotFound("VM".into()))
        })
    }

    pub fn get_vm(&self, id_or_name: &str) -> AppResult<Option<Vm>> {
        self.with_connection(|connection| query_vm(connection, id_or_name))
    }

    pub fn list_vms(&self) -> AppResult<Vec<Vm>> {
        self.with_connection(|connection| {
            let sql = format!("SELECT {VM_COLUMNS} FROM vms ORDER BY name COLLATE NOCASE");
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map([], row_to_vm)?;
            collect_rows(rows)
        })
    }

    /// Reconcile a VM name that was changed directly in libvirt. This is not
    /// exposed as an administrator rename operation; it only keeps a row with
    /// a matching libvirt UUID addressable by the hypervisor inventory name.
    pub fn reconcile_vm_name(&self, id: &str, name: &str) -> AppResult<Vm> {
        let name = name.trim();
        if name.is_empty()
            || name.len() > 63
            || !name
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(AppError::Validation("reconciled VM name is invalid".into()));
        }
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let changed = transaction.execute(
                "UPDATE vms SET name = ?2, updated_at = ?3 WHERE id = ?1",
                params![id, name, unix_now()],
            )?;
            require_changed(changed, "VM")?;
            query_vm(transaction, id)?.ok_or_else(|| AppError::NotFound("VM".into()))
        })
    }

    pub fn patch_vm(&self, id_or_name: &str, patch: &VmPatch) -> AppResult<Vm> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let mut vm = query_vm(transaction, id_or_name)?.ok_or_else(|| AppError::NotFound("VM".into()))?;
            if let Some(value) = &patch.iso_id {
                vm.iso_id.clone_from(value);
            }
            if let Some(value) = &patch.os_family {
                validate_non_empty("os_family", value)?;
                vm.os_family = value.trim().into();
            }
            if let Some(value) = &patch.root_username {
                validate_non_empty("root_username", value)?;
                vm.root_username = value.trim().into();
            }
            if let Some(value) = &patch.hostname {
                validate_non_empty("hostname", value)?;
                vm.hostname = value.trim().into();
            }
            if let Some(value) = &patch.description {
                vm.description.clone_from(value);
            }
            if let Some(value) = patch.state {
                vm.state = value;
            }
            if let Some(value) = patch.desired_state {
                vm.desired_state = value;
            }
            if let Some(value) = patch.vcpus {
                if value == 0 {
                    return Err(AppError::Validation("vcpus must be greater than zero".into()));
                }
                vm.vcpus = value;
            }
            if let Some(value) = patch.memory_mib {
                if value < 256 {
                    return Err(AppError::Validation("memory_mib must be at least 256".into()));
                }
                vm.memory_mib = value;
            }
            if let Some(value) = patch.disk_gib {
                if value < vm.disk_gib {
                    return Err(AppError::Validation("VM disks cannot be shrunk".into()));
                }
                vm.disk_gib = value;
            }
            if let Some(value) = &patch.tap_name {
                vm.tap_name.clone_from(value);
            }
            if let Some(value) = patch.network_limit_mbps {
                if value == Some(0) {
                    return Err(AppError::Validation(
                        "network_limit_mbps must be greater than zero".into(),
                    ));
                }
                vm.network_limit_mbps = value;
            }
            if let Some(value) = patch.traffic_limit_bytes {
                vm.traffic_limit_bytes = value;
            }
            if let Some(value) = patch.traffic_used_bytes {
                vm.traffic_used_bytes = value;
            }
            if let Some(value) = patch.guest_agent {
                vm.guest_agent = value;
            }
            if let Some(value) = patch.autostart {
                vm.autostart = value;
            }
            if let Some(value) = &patch.timezone {
                vm.timezone.clone_from(value);
            }
            if let Some(value) = &patch.libvirt_uuid {
                vm.libvirt_uuid.clone_from(value);
            }
            if let Some(value) = patch.vnc_display {
                vm.vnc_display = value;
            }
            if let Some(value) = &patch.metadata {
                vm.metadata.clone_from(value);
            }
            vm.updated_at = unix_now();
            save_vm(transaction, &vm)?;
            Ok(vm)
        })
    }

    pub fn set_vm_state(
        &self,
        id_or_name: &str,
        state: VmState,
        desired_state: Option<VmState>,
        libvirt_uuid: Option<&str>,
        vnc_display: Option<i64>,
    ) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE vms
                 SET state = ?2,
                     desired_state = COALESCE(?3, desired_state),
                     libvirt_uuid = COALESCE(?4, libvirt_uuid),
                     vnc_display = ?5,
                     updated_at = ?6
                 WHERE id = ?1 OR name = ?1 COLLATE NOCASE",
                    params![
                        id_or_name,
                        state.as_str(),
                        desired_state.map(VmState::as_str),
                        libvirt_uuid,
                        vnc_display,
                        unix_now(),
                    ],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "VM")
    }

    pub fn set_vm_password_envelope(&self, vm_id: &str, envelope: &str) -> AppResult<()> {
        validate_non_empty("password envelope", envelope)?;
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE vms
                 SET password_envelope = ?2, password_updated_at = ?3, updated_at = ?3
                 WHERE id = ?1",
                    params![vm_id, envelope, unix_now()],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "VM")
    }

    pub fn clear_vm_password(&self, vm_id: &str) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE vms
                 SET password_envelope = NULL, password_updated_at = NULL, updated_at = ?2
                 WHERE id = ?1",
                    params![vm_id, unix_now()],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "VM")
    }

    pub fn set_vm_password(&self, vm_id: &str, password: &str, security: &Security) -> AppResult<()> {
        validate_non_empty("VM password", password)?;
        let envelope = security.encrypt_secret(password, &vm_password_context(vm_id))?;
        self.set_vm_password_envelope(vm_id, &envelope)
    }

    pub fn vm_password_envelope(&self, vm_id: &str) -> AppResult<Option<String>> {
        self.with_connection(|connection| {
            let value = connection
                .query_row(
                    "SELECT password_envelope FROM vms WHERE id = ?1",
                    [vm_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?;
            Ok(value.flatten())
        })
    }

    pub fn decrypt_vm_password(&self, vm_id: &str, security: &Security) -> AppResult<Option<String>> {
        self.vm_password_envelope(vm_id)?
            .map(|envelope| security.decrypt_secret(&envelope, &vm_password_context(vm_id)))
            .transpose()
    }

    /// Commit the credential carried by a running reinstall job after the
    /// hypervisor has accepted the replacement guest, but before any fallible
    /// post-provisioning work is attempted.
    ///
    /// This deliberately does not remove the staged envelope from the job.
    /// `finish_job`/terminal `fail_job` own that cleanup, while keeping it here
    /// makes this operation idempotent if a worker has to repeat the commit.
    /// A later firewall, start, traffic, or inventory error therefore cannot
    /// roll the panel back to a password that belongs to the destroyed guest.
    pub fn commit_reinstall_password_after_hypervisor(&self, job_id: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let job = query_job(transaction, job_id)?
                .ok_or_else(|| AppError::NotFound("job".into()))?;
            if job.kind != "vm.reinstall" {
                return Err(AppError::Validation(
                    "credential commit requires a vm.reinstall job".into(),
                ));
            }
            if job.status != JobStatus::Running {
                return Err(AppError::Conflict(
                    "reinstall credential can only be committed by its running worker".into(),
                ));
            }
            let vm_id = job
                .vm_id
                .as_deref()
                .ok_or_else(|| AppError::Conflict("reinstall job no longer owns a VM".into()))?;
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

            let now = unix_now();
            let changed = if clear_password {
                transaction.execute(
                    "UPDATE vms
                     SET password_envelope = NULL, password_updated_at = NULL,
                         updated_at = ?2
                     WHERE id = ?1",
                    params![vm_id, now],
                )?
            } else if let Some(envelope) = staged_password {
                validate_non_empty("password envelope", envelope)?;
                transaction.execute(
                    "UPDATE vms
                     SET password_envelope = ?2, password_updated_at = ?3,
                         updated_at = ?3
                     WHERE id = ?1",
                    params![vm_id, envelope, now],
                )?
            } else {
                // No new credential was requested. Still prove the running job
                // owns an extant VM before declaring the boundary committed.
                transaction.query_row(
                    "SELECT 1 FROM vms WHERE id = ?1",
                    [vm_id],
                    |_| Ok(()),
                )?;
                1
            };
            require_changed(changed, "VM")
        })
    }

    pub fn configure_vm_guest_tools(
        &self,
        vm_id: &str,
        platform: GuestToolsPlatform,
        provisioner: GuestToolsProvisioner,
        secret: &str,
        desired_version: &str,
        security: &Security,
    ) -> AppResult<VmGuestTools> {
        validate_non_empty("guest-tools secret", secret)?;
        validate_guest_tools_version("guest-tools version", desired_version)?;
        let envelope = security.encrypt_secret(secret, &vm_guest_tools_secret_context(vm_id))?;
        let now = unix_now();
        self.with_connection(|connection| {
            let changed = connection.execute(
                "INSERT INTO vm_guest_tools(
                    vm_id, enabled, platform, provisioner, secret_envelope,
                    desired_version, status, created_at, updated_at
                 ) VALUES (?1, 1, ?2, ?3, ?4, ?5, 'pending', ?6, ?6)
                 ON CONFLICT(vm_id) DO UPDATE SET
                    enabled = 1, platform = excluded.platform,
                    provisioner = excluded.provisioner,
                    secret_envelope = excluded.secret_envelope,
                    desired_version = excluded.desired_version,
                    installed_version = NULL, status = 'pending',
                    last_seen_at = NULL, last_error = NULL,
                    pending_secret_envelope = NULL,
                    pending_platform = NULL,
                    pending_provisioner = NULL,
                    pending_desired_version = NULL,
                    pending_generation = NULL,
                    pending_installed = 0,
                    updated_at = excluded.updated_at
                 WHERE vm_guest_tools.pending_installed = 0",
                params![
                    vm_id,
                    platform.as_str(),
                    provisioner.as_str(),
                    envelope,
                    desired_version,
                    now,
                ],
            )?;
            if changed == 0 {
                return Err(AppError::Conflict(
                    "an armed Vexa Guest Tools rotation cannot be replaced".into(),
                ));
            }
            query_vm_guest_tools(connection, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM guest-tools configuration".into()))
        })
    }

    pub fn vm_guest_tools(&self, vm_id: &str) -> AppResult<Option<VmGuestTools>> {
        self.with_connection(|connection| query_vm_guest_tools(connection, vm_id))
    }

    /// Remove only the optional tools configuration. This is intended for
    /// rollback when newly enabling tools succeeded but enqueueing the
    /// corresponding reinstall did not. Existing configurations should use
    /// staged rotation and generation-scoped discard instead.
    pub fn delete_vm_guest_tools_configuration(&self, vm_id: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let changed = transaction.execute(
                "DELETE FROM vm_guest_tools
                 WHERE vm_id = ?1 AND pending_installed = 0",
                [vm_id],
            )?;
            if changed == 1 {
                return Ok(());
            }
            let armed = transaction
                .query_row(
                    "SELECT pending_installed FROM vm_guest_tools WHERE vm_id = ?1",
                    [vm_id],
                    |row| bool_column(row, 0),
                )
                .optional()?;
            match armed {
                Some(true) => Err(AppError::Conflict(
                    "an armed Vexa Guest Tools configuration cannot be deleted".into(),
                )),
                _ => Err(AppError::NotFound("VM guest-tools configuration".into())),
            }
        })
    }

    /// Remove Guest Tools after a replacement guest disk and domain
    /// definition were committed without the Vexa channel. At that point an
    /// armed key can no longer belong to the running replacement guest, so it
    /// is safe to retire both active and pending credentials together.
    pub fn retire_vm_guest_tools_after_reinstall(&self, vm_id: &str) -> AppResult<bool> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let changed = transaction.execute(
                "DELETE FROM vm_guest_tools WHERE vm_id = ?1",
                [vm_id],
            )?;
            Ok(changed == 1)
        })
    }

    pub fn decrypt_vm_guest_tools_secret(
        &self,
        vm_id: &str,
        security: &Security,
    ) -> AppResult<Option<String>> {
        let envelope = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT secret_envelope FROM vm_guest_tools WHERE vm_id = ?1 AND enabled = 1",
                    [vm_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(Into::into)
        })?;
        envelope
            .map(|value| {
                security.decrypt_secret(&value, &vm_guest_tools_secret_context(vm_id))
            })
            .transpose()
    }

    /// Stage a fresh channel key for a reinstall while leaving the active key
    /// untouched. Only one generation may be pending for a VM at a time.
    pub fn stage_vm_guest_tools_rotation(
        &self,
        vm_id: &str,
        platform: GuestToolsPlatform,
        provisioner: GuestToolsProvisioner,
        secret: &str,
        desired_version: &str,
        security: &Security,
    ) -> AppResult<String> {
        validate_non_empty("guest-tools secret", secret)?;
        validate_guest_tools_version("guest-tools version", desired_version)?;
        let generation = Uuid::new_v4().to_string();
        let envelope = security.encrypt_secret(
            secret,
            &vm_guest_tools_pending_secret_context(vm_id, &generation),
        )?;
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let changed = transaction.execute(
                "UPDATE vm_guest_tools SET
                    pending_secret_envelope = ?2,
                    pending_platform = ?3,
                    pending_provisioner = ?4,
                    pending_desired_version = ?5,
                    pending_generation = ?6,
                    pending_installed = 0,
                    updated_at = ?7
                 WHERE vm_id = ?1 AND enabled = 1 AND pending_generation IS NULL",
                params![
                    vm_id,
                    envelope,
                    platform.as_str(),
                    provisioner.as_str(),
                    desired_version,
                    generation,
                    now,
                ],
            )?;
            if changed == 1 {
                return Ok(generation.clone());
            }
            let state: Option<(bool, bool)> = transaction
                .query_row(
                    "SELECT enabled, pending_generation IS NOT NULL
                     FROM vm_guest_tools WHERE vm_id = ?1",
                    [vm_id],
                    |row| Ok((bool_column(row, 0)?, bool_column(row, 1)?)),
                )
                .optional()?;
            match state {
                None => Err(AppError::NotFound("VM guest-tools configuration".into())),
                Some((false, _)) => Err(AppError::Conflict("Vexa Guest Tools is disabled".into())),
                Some((true, true)) => Err(AppError::Conflict(
                    "a Vexa Guest Tools key rotation is already pending".into(),
                )),
                Some((true, false)) => Err(AppError::Conflict(
                    "Vexa Guest Tools key rotation could not be staged".into(),
                )),
            }
        })
    }

    /// Read the pending image seed, including its decrypted key. This is an
    /// internal provisioning API and the returned type is not serializable.
    pub fn pending_vm_guest_tools_seed(
        &self,
        vm_id: &str,
        security: &Security,
    ) -> AppResult<Option<PendingVmGuestToolsSeed>> {
        let pending = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT pending_secret_envelope, pending_platform,
                            pending_provisioner, pending_desired_version,
                            pending_generation, pending_installed
                     FROM vm_guest_tools
                     WHERE vm_id = ?1 AND enabled = 1
                       AND pending_generation IS NOT NULL",
                    [vm_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            enum_column(row, 1)?,
                            enum_column(row, 2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            bool_column(row, 5)?,
                        ))
                    },
                )
                .optional()
                .map_err(Into::into)
        })?;
        pending
            .map(
                |(envelope, platform, provisioner, desired_version, generation, installed)| {
                    let secret = security.decrypt_secret(
                        &envelope,
                        &vm_guest_tools_pending_secret_context(vm_id, &generation),
                    )?;
                    Ok(PendingVmGuestToolsSeed {
                        generation,
                        platform,
                        provisioner,
                        desired_version,
                        secret,
                        installed,
                    })
                },
            )
            .transpose()
    }

    /// Switch client authentication to the pending key only after the
    /// reinstall is armed. Before that point, the active guest remains
    /// manageable with its existing key.
    pub fn vm_guest_tools_client_secret(
        &self,
        vm_id: &str,
        security: &Security,
    ) -> AppResult<Option<VmGuestToolsClientSecret>> {
        let selected = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT secret_envelope, desired_version,
                            pending_secret_envelope, pending_desired_version,
                            pending_generation, pending_installed
                     FROM vm_guest_tools WHERE vm_id = ?1 AND enabled = 1",
                    [vm_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            bool_column(row, 5)?,
                        ))
                    },
                )
                .optional()
                .map_err(Into::into)
        })?;
        selected
            .map(|(
                active,
                active_desired_version,
                pending,
                pending_desired_version,
                generation,
                pending_installed,
            )| {
                if pending_installed {
                    let envelope = pending.ok_or_else(|| {
                        AppError::Internal("pending guest-tools key is missing".into())
                    })?;
                    let generation = generation.ok_or_else(|| {
                        AppError::Internal("pending guest-tools generation is missing".into())
                    })?;
                    let desired_version = pending_desired_version.ok_or_else(|| {
                        AppError::Internal("pending guest-tools version is missing".into())
                    })?;
                    let secret = security.decrypt_secret(
                        &envelope,
                        &vm_guest_tools_pending_secret_context(vm_id, &generation),
                    )?;
                    Ok(VmGuestToolsClientSecret {
                        secret,
                        desired_version,
                        pending_generation: Some(generation),
                    })
                } else {
                    let secret = security
                        .decrypt_secret(&active, &vm_guest_tools_secret_context(vm_id))?;
                    Ok(VmGuestToolsClientSecret {
                        secret,
                        desired_version: active_desired_version,
                        pending_generation: None,
                    })
                }
            })
            .transpose()
    }

    /// Return the non-secret generation after it has been armed for reinstall.
    /// Power/start reconciliation can use this to enqueue bootstrap without
    /// decrypting channel-key material.
    pub fn installed_vm_guest_tools_rotation_generation(
        &self,
        vm_id: &str,
    ) -> AppResult<Option<String>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT pending_generation FROM vm_guest_tools
                     WHERE vm_id = ?1 AND enabled = 1 AND pending_installed = 1",
                    [vm_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(Into::into)
        })
    }

    /// Return an armed rotation only when a terminally failed reinstall with
    /// the exact same non-secret request fingerprint originally armed it.
    /// This prevents a new or reconfigured reinstall from silently inheriting
    /// channel-key material that may already exist on an uncertain guest disk.
    pub fn reusable_vm_guest_tools_rotation(
        &self,
        vm_id: &str,
        request_fingerprint: &str,
    ) -> AppResult<Option<ReusableVmGuestToolsRotation>> {
        if request_fingerprint.len() != 64
            || !request_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AppError::Validation(
                "reinstall request fingerprint is invalid".into(),
            ));
        }
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT tools.pending_generation, tools.pending_platform,
                            tools.pending_provisioner, tools.pending_desired_version,
                            jobs.id
                     FROM vm_guest_tools AS tools
                     JOIN jobs
                       ON jobs.vm_id = tools.vm_id
                      AND jobs.kind = 'vm.reinstall'
                      AND jobs.status = 'failed'
                      AND json_extract(
                            jobs.payload_json,
                            '$._guest_tools_rotation_generation'
                          ) = tools.pending_generation
                      AND json_extract(jobs.payload_json, '$.request_fingerprint') = ?2
                     WHERE tools.vm_id = ?1 AND tools.enabled = 1
                       AND tools.pending_installed = 1
                     ORDER BY jobs.finished_at DESC, jobs.created_at DESC
                     LIMIT 1",
                    params![vm_id, request_fingerprint],
                    |row| {
                        Ok(ReusableVmGuestToolsRotation {
                            generation: row.get(0)?,
                            platform: enum_column(row, 1)?,
                            provisioner: enum_column(row, 2)?,
                            desired_version: row.get(3)?,
                            origin_job_id: row.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into)
        })
    }

    /// Arm `generation` immediately before key-bearing guest media is
    /// published or guest-disk mutation can begin. From this point clients
    /// authenticate with the pending key, but the active database key is
    /// retained until an authenticated bootstrap handshake.
    pub fn mark_vm_guest_tools_rotation_installed(
        &self,
        vm_id: &str,
        generation: &str,
    ) -> AppResult<VmGuestTools> {
        validate_guest_tools_rotation_generation(generation)?;
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let changed = transaction.execute(
                "UPDATE vm_guest_tools SET
                    pending_installed = 1,
                    status = 'pending',
                    last_error = NULL,
                    updated_at = ?3
                 WHERE vm_id = ?1 AND enabled = 1
                   AND pending_generation = ?2",
                params![vm_id, generation, now],
            )?;
            if changed == 0 {
                return Err(rotation_generation_conflict(transaction, vm_id));
            }
            query_vm_guest_tools(transaction, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM guest-tools configuration".into()))
        })
    }

    /// Atomically promote an installed generation after an authenticated guest
    /// handshake. The pending envelope is decrypted with generation-bound AAD
    /// and re-encrypted under the stable active-key context.
    pub fn promote_vm_guest_tools_rotation(
        &self,
        vm_id: &str,
        generation: &str,
        installed_version: &str,
        security: &Security,
    ) -> AppResult<VmGuestTools> {
        validate_guest_tools_rotation_generation(generation)?;
        validate_guest_tools_version("installed guest-tools version", installed_version)?;
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let pending = transaction
                .query_row(
                    "SELECT pending_secret_envelope, pending_platform,
                            pending_provisioner, pending_desired_version
                     FROM vm_guest_tools
                     WHERE vm_id = ?1 AND enabled = 1
                       AND pending_generation = ?2 AND pending_installed = 1",
                    params![vm_id, generation],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .optional()?;
            let Some((pending_envelope, platform, provisioner, desired_version)) = pending else {
                return Err(rotation_generation_conflict(transaction, vm_id));
            };
            if installed_version != desired_version {
                return Err(AppError::Conflict(format!(
                    "guest-tools version {installed_version} does not match required version {desired_version}"
                )));
            }
            let secret = security.decrypt_secret(
                &pending_envelope,
                &vm_guest_tools_pending_secret_context(vm_id, generation),
            )?;
            let active_envelope =
                security.encrypt_secret(&secret, &vm_guest_tools_secret_context(vm_id))?;
            let changed = transaction.execute(
                "UPDATE vm_guest_tools SET
                    platform = ?3,
                    provisioner = ?4,
                    secret_envelope = ?5,
                    desired_version = ?6,
                    installed_version = ?6,
                    status = 'ready',
                    last_seen_at = ?7,
                    last_error = NULL,
                    pending_secret_envelope = NULL,
                    pending_platform = NULL,
                    pending_provisioner = NULL,
                    pending_desired_version = NULL,
                    pending_generation = NULL,
                    pending_installed = 0,
                    updated_at = ?7
                 WHERE vm_id = ?1 AND enabled = 1
                   AND pending_generation = ?2 AND pending_installed = 1",
                params![
                    vm_id,
                    generation,
                    platform,
                    provisioner,
                    active_envelope,
                    desired_version,
                    now,
                ],
            )?;
            if changed == 0 {
                return Err(AppError::Conflict(
                    "Vexa Guest Tools rotation changed during promotion".into(),
                ));
            }
            query_vm_guest_tools(transaction, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM guest-tools configuration".into()))
        })
    }

    /// Discard exactly one staged generation before it is armed for install.
    /// Once `pending_installed` is set, retaining the pending key is mandatory:
    /// a crash can make it impossible to prove which key is on the guest disk.
    pub fn discard_vm_guest_tools_rotation(
        &self,
        vm_id: &str,
        generation: &str,
    ) -> AppResult<VmGuestTools> {
        validate_guest_tools_rotation_generation(generation)?;
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let changed = transaction.execute(
                "UPDATE vm_guest_tools SET
                    pending_secret_envelope = NULL,
                    pending_platform = NULL,
                    pending_provisioner = NULL,
                    pending_desired_version = NULL,
                    pending_generation = NULL,
                    pending_installed = 0,
                    updated_at = ?3
                 WHERE vm_id = ?1 AND enabled = 1
                   AND pending_generation = ?2 AND pending_installed = 0",
                params![vm_id, generation, now],
            )?;
            if changed == 0 {
                let armed = transaction
                    .query_row(
                        "SELECT pending_installed FROM vm_guest_tools
                         WHERE vm_id = ?1 AND enabled = 1 AND pending_generation = ?2",
                        params![vm_id, generation],
                        |row| bool_column(row, 0),
                    )
                    .optional()?;
                if armed == Some(true) {
                    return Err(AppError::Conflict(
                        "an armed Vexa Guest Tools rotation cannot be discarded".into(),
                    ));
                }
                return Err(rotation_generation_conflict(transaction, vm_id));
            }
            query_vm_guest_tools(transaction, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM guest-tools configuration".into()))
        })
    }

    pub fn update_vm_guest_tools_status(
        &self,
        vm_id: &str,
        status: GuestToolsStatus,
        installed_version: Option<&str>,
        last_error: Option<&str>,
        contacted: bool,
    ) -> AppResult<VmGuestTools> {
        if let Some(version) = installed_version {
            validate_guest_tools_version("installed guest-tools version", version)?;
        }
        let now = unix_now();
        let bounded_error = last_error.map(|message| message.chars().take(500).collect::<String>());
        self.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE vm_guest_tools SET
                    status = CASE
                        WHEN pending_installed = 1 AND ?2 = 'ready' THEN 'pending'
                        ELSE ?2
                    END,
                    installed_version = CASE
                        WHEN pending_installed = 1 THEN installed_version
                        ELSE COALESCE(?3, installed_version)
                    END,
                    last_seen_at = CASE WHEN ?4 = 1 THEN ?6 ELSE last_seen_at END,
                    last_error = ?5, updated_at = ?6
                 WHERE vm_id = ?1 AND enabled = 1",
                params![
                    vm_id,
                    status.as_str(),
                    installed_version,
                    bool_i64(contacted),
                    bounded_error,
                    now,
                ],
            )?;
            require_changed(changed, "VM guest-tools configuration")?;
            query_vm_guest_tools(connection, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM guest-tools configuration".into()))
        })
    }

    pub fn delete_vm(&self, id_or_name: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let vm = query_vm(transaction, id_or_name)?
                .ok_or_else(|| AppError::NotFound("VM".into()))?;
            let now = unix_now();

            // `ip_addresses` deliberately retains the node's address
            // inventory when a VM is removed. Releasing rows first is also
            // required by its consistency CHECK: ON DELETE SET NULL alone
            // would leave `status = 'used'` with no assigned VM and abort the
            // whole delete. Abuse reports and audit events remain in their
            // historical tables; their optional VM foreign key is allowed to
            // become NULL.
            transaction.execute(
                "UPDATE ip_addresses
                 SET status = 'free', assigned_vm_id = NULL, primary_for_vm = 0,
                     updated_at = ?2
                 WHERE assigned_vm_id = ?1",
                params![vm.id, now],
            )?;
            let changed = transaction.execute("DELETE FROM vms WHERE id = ?1", [&vm.id])?;
            require_changed(changed, "VM")
        })
    }

    // --- Dual-stack address pools and DNS ------------------------------------

    pub fn create_ip_pool(&self, spec: &NewIpPool) -> AppResult<IpPool> {
        validate_non_empty("IP pool name", &spec.name)?;
        let network: IpNet = spec
            .cidr
            .parse()
            .map_err(|_| AppError::Validation("IP pool CIDR is invalid".into()))?;
        let family = family_for_ip(network.addr());
        let gateway = canonical_optional_ip(spec.gateway.as_deref(), Some(family))?;
        if let Some(gateway) = gateway.as_deref() {
            let address: IpAddr = gateway
                .parse()
                .map_err(|_| AppError::Validation("gateway is invalid".into()))?;
            if !network.contains(&address) {
                return Err(AppError::Validation(
                    "IP pool gateway must be inside its CIDR".into(),
                ));
            }
        }
        let id = Uuid::new_v4().to_string();
        let now = unix_now();
        let cidr = network.to_string();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let mut statement = transaction.prepare("SELECT cidr FROM ip_pools")?;
            let existing = statement.query_map([], |row| row.get::<_, String>(0))?;
            for stored_cidr in existing {
                let stored_cidr = stored_cidr?;
                let other: IpNet = stored_cidr
                    .parse()
                    .map_err(|_| AppError::Internal("stored IP pool CIDR is invalid".into()))?;
                if networks_overlap(&network, &other) {
                    return Err(AppError::Conflict(format!(
                        "IP pool {stored_cidr} overlaps an existing range"
                    )));
                }
            }
            drop(statement);
            transaction.execute(
                "INSERT INTO ip_pools(
                    id, name, cidr, family, scope, gateway, bridge, vlan_id, mtu,
                    enabled, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
                params![
                    id,
                    spec.name.trim(),
                    cidr,
                    family.as_i64(),
                    spec.scope.as_str(),
                    gateway,
                    spec.bridge,
                    spec.vlan_id.map(i64::from),
                    i64::from(spec.mtu),
                    bool_i64(spec.enabled),
                    now,
                ],
            )?;
            query_ip_pool(transaction, &id)?.ok_or_else(|| AppError::NotFound("IP pool".into()))
        })
    }

    pub fn list_ip_pools(&self) -> AppResult<Vec<IpPool>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, name, cidr, family, scope, gateway, bridge, vlan_id, mtu,
                        enabled, created_at, updated_at
                 FROM ip_pools ORDER BY scope, family, name COLLATE NOCASE",
            )?;
            let rows = statement.query_map([], row_to_ip_pool)?;
            collect_rows(rows)
        })
    }

    pub fn get_ip_pool(&self, id: &str) -> AppResult<Option<IpPool>> {
        self.with_connection(|connection| query_ip_pool(connection, id))
    }

    pub fn patch_ip_pool(&self, id: &str, patch: &crate::models::IpPoolPatch) -> AppResult<IpPool> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current =
                query_ip_pool(transaction, id)?.ok_or_else(|| AppError::NotFound("IP pool".into()))?;
            let name = patch.name.as_deref().unwrap_or(&current.name).trim();
            validate_non_empty("IP pool name", name)?;
            let network: IpNet = current
                .cidr
                .parse()
                .map_err(|_| AppError::Validation("stored IP pool CIDR is invalid".into()))?;
            let family = family_for_ip(network.addr());
            let gateway = canonical_optional_ip(
                patch.gateway.as_deref().or(current.gateway.as_deref()),
                Some(family),
            )?;
            if let Some(value) = gateway.as_deref() {
                let address: IpAddr = value
                    .parse()
                    .map_err(|_| AppError::Validation("gateway is invalid".into()))?;
                if !network.contains(&address) {
                    return Err(AppError::Validation(
                        "IP pool gateway must be inside its CIDR".into(),
                    ));
                }
            }
            let mtu = patch.mtu.unwrap_or(current.mtu);
            if !(576..=9216).contains(&mtu) {
                return Err(AppError::Validation("MTU must be between 576 and 9216".into()));
            }
            transaction.execute(
                "UPDATE ip_pools
                 SET name = ?2, scope = ?3, gateway = ?4, bridge = ?5,
                     vlan_id = ?6, mtu = ?7, enabled = ?8, updated_at = ?9
                 WHERE id = ?1",
                params![
                    id,
                    name,
                    patch.scope.unwrap_or(current.scope).as_str(),
                    gateway,
                    patch.bridge.as_deref().or(current.bridge.as_deref()),
                    patch.vlan_id.or(current.vlan_id).map(i64::from),
                    i64::from(mtu),
                    bool_i64(patch.enabled.unwrap_or(current.enabled)),
                    unix_now(),
                ],
            )?;
            query_ip_pool(transaction, id)?.ok_or_else(|| AppError::NotFound("IP pool".into()))
        })
    }

    pub fn delete_ip_pool(&self, id: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let addresses: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM ip_addresses WHERE pool_id = ?1",
                [id],
                |row| row.get(0),
            )?;
            if addresses != 0 {
                return Err(AppError::Conflict(
                    "remove the pool's explicit addresses before deleting it".into(),
                ));
            }
            let changed = transaction.execute("DELETE FROM ip_pools WHERE id = ?1", [id])?;
            require_changed(changed, "IP pool")
        })
    }

    /// Roll back a just-created pool and any addresses that have not been
    /// assigned. Main and used addresses are deliberately never removed.
    pub fn delete_ip_pool_with_unassigned_addresses(&self, id: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let protected: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM ip_addresses
                 WHERE pool_id = ?1 AND (status IN ('used', 'main') OR assigned_vm_id IS NOT NULL)",
                [id],
                |row| row.get(0),
            )?;
            if protected != 0 {
                return Err(AppError::Conflict(
                    "pool contains an assigned or host-owned address".into(),
                ));
            }
            transaction.execute("DELETE FROM ip_addresses WHERE pool_id = ?1", [id])?;
            let changed = transaction.execute("DELETE FROM ip_pools WHERE id = ?1", [id])?;
            require_changed(changed, "IP pool")
        })
    }

    pub fn upsert_ip_address(&self, spec: &NewIpAddress) -> AppResult<IpAddressRecord> {
        self.upsert_ip_address_with_policy(spec, false)
    }

    /// Refresh an address detected on the host without discarding protected
    /// control-plane details imported for that same address. Host discovery is
    /// authoritative for the observed prefix/scope and `main` status, but an
    /// existing main row may intentionally belong to an inventory-only pool
    /// and carry its provider gateway, reverse DNS, and migration metadata.
    pub fn upsert_detected_host_address(
        &self,
        spec: &NewIpAddress,
    ) -> AppResult<IpAddressRecord> {
        if spec.status != IpStatus::Main {
            return Err(AppError::Validation(
                "a detected host address must have main status".into(),
            ));
        }
        if !spec
            .metadata
            .get("detected_host_address")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(AppError::Validation(
                "detected host address metadata is missing its detection marker".into(),
            ));
        }
        self.upsert_ip_address_with_policy(spec, true)
    }

    fn upsert_ip_address_with_policy(
        &self,
        spec: &NewIpAddress,
        preserve_existing_main_details: bool,
    ) -> AppResult<IpAddressRecord> {
        let parsed_address: IpAddr = spec
            .address
            .parse()
            .map_err(|_| AppError::Validation("IP address is invalid".into()))?;
        let family = family_for_ip(parsed_address);
        validate_prefix(family, spec.prefix_length)?;
        if spec.status == IpStatus::Used {
            return Err(AppError::Validation(
                "use assign_ip to mark an address as used".into(),
            ));
        }
        let requested_gateway = canonical_optional_ip(spec.gateway.as_deref(), Some(family))?;
        let address = parsed_address.to_string();
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let existing = query_ip_address(transaction, &address)?;
            if let Some(existing) = existing.as_ref() {
                if existing.assigned_vm_id.is_some() || existing.status == IpStatus::Used {
                    return Err(AppError::Conflict(format!(
                        "IP address {address} is already assigned"
                    )));
                }
                if existing.status == IpStatus::Main && spec.status != IpStatus::Main {
                    return Err(AppError::Conflict(
                        "the detected host address is protected".into(),
                    ));
                }
            }
            let preserve = preserve_existing_main_details
                && existing
                    .as_ref()
                    .is_some_and(|record| record.status == IpStatus::Main);
            let (pool_id, gateway, reverse_dns, metadata) = if preserve {
                let existing = existing.as_ref().expect("preserve requires an existing row");
                let mut metadata = existing.metadata.as_object().cloned().ok_or_else(|| {
                    AppError::Conflict(
                        "existing main host-address metadata is not an object and cannot be safely merged"
                            .into(),
                    )
                })?;
                let detected = spec.metadata.as_object().ok_or_else(|| {
                    AppError::Validation("detected host-address metadata must be an object".into())
                })?;
                metadata.extend(detected.clone());
                (
                    existing.pool_id.clone(),
                    existing.gateway.clone(),
                    existing.reverse_dns.clone(),
                    Value::Object(metadata),
                )
            } else {
                (
                    spec.pool_id.clone(),
                    requested_gateway.clone(),
                    spec.reverse_dns.clone(),
                    spec.metadata.clone(),
                )
            };
            if let Some(pool_id) = pool_id.as_deref() {
                let pool = query_ip_pool(transaction, pool_id)?
                    .ok_or_else(|| AppError::NotFound("IP pool".into()))?;
                let network: IpNet = pool
                    .cidr
                    .parse()
                    .map_err(|_| AppError::Internal("stored IP pool CIDR is invalid".into()))?;
                if pool.family != family || pool.scope != spec.scope || !network.contains(&parsed_address) {
                    return Err(AppError::Validation(
                        "address family, scope, and value must match its IP pool".into(),
                    ));
                }
                // The pool CIDR describes the provider-owned inventory range,
                // while an individual address prefix describes how that
                // address is configured inside the guest. Routed provider
                // ranges commonly hand a VM a /32 (or IPv6 /128) from a
                // larger allocation, so requiring equality would silently
                // change the guest's established routing during an import.
                // A member may be more specific than its pool, but never
                // broader than it.
                if spec.prefix_length < network.prefix_len() {
                    return Err(AppError::Validation(
                        "address prefix length cannot be broader than its IP pool".into(),
                    ));
                }
            }
            let metadata = json_string(&metadata)?;
            let id = existing
                .as_ref()
                .map(|record| record.id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            transaction.execute(
                "INSERT INTO ip_addresses(
                    id, pool_id, address, family, prefix_length, scope, status, gateway,
                    reverse_dns, metadata_json, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
                 ON CONFLICT(address) DO UPDATE SET
                    pool_id = excluded.pool_id,
                    family = excluded.family,
                    prefix_length = excluded.prefix_length,
                    scope = excluded.scope,
                    status = excluded.status,
                    gateway = excluded.gateway,
                    assigned_vm_id = NULL,
                    primary_for_vm = 0,
                    reverse_dns = excluded.reverse_dns,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at",
                params![
                    id,
                    pool_id,
                    address,
                    family.as_i64(),
                    i64::from(spec.prefix_length),
                    spec.scope.as_str(),
                    spec.status.as_str(),
                    gateway,
                    reverse_dns,
                    metadata,
                    now,
                ],
            )?;
            query_ip_address(transaction, &address)?.ok_or_else(|| AppError::NotFound("IP address".into()))
        })
    }

    pub fn list_ip_addresses(
        &self,
        family: Option<AddressFamily>,
        scope: Option<IpScope>,
        status: Option<IpStatus>,
    ) -> AppResult<Vec<IpAddressRecord>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, pool_id, address, family, prefix_length, scope, status, gateway,
                        assigned_vm_id, primary_for_vm, reverse_dns, metadata_json,
                        created_at, updated_at
                 FROM ip_addresses
                 WHERE (?1 IS NULL OR family = ?1)
                   AND (?2 IS NULL OR scope = ?2)
                   AND (?3 IS NULL OR status = ?3)
                 ORDER BY family, scope, address",
            )?;
            let rows = statement.query_map(
                params![
                    family.map(AddressFamily::as_i64),
                    scope.map(IpScope::as_str),
                    status.map(IpStatus::as_str),
                ],
                row_to_ip_address,
            )?;
            let mut records = collect_rows(rows)?;
            sort_ip_addresses_numerically(&mut records, false);
            Ok(records)
        })
    }

    pub fn vm_ip_addresses(&self, vm_id: &str) -> AppResult<Vec<IpAddressRecord>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, pool_id, address, family, prefix_length, scope, status, gateway,
                        assigned_vm_id, primary_for_vm, reverse_dns, metadata_json,
                        created_at, updated_at
                 FROM ip_addresses WHERE assigned_vm_id = ?1
                 ORDER BY primary_for_vm DESC, family, address",
            )?;
            let rows = statement.query_map([vm_id], row_to_ip_address)?;
            let mut records = collect_rows(rows)?;
            sort_ip_addresses_numerically(&mut records, true);
            Ok(records)
        })
    }

    pub fn get_ip_address(&self, address_or_id: &str) -> AppResult<Option<IpAddressRecord>> {
        self.with_connection(|connection| query_ip_address(connection, address_or_id))
    }

    pub fn delete_ip_address(&self, address_or_id: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let record = query_ip_address(transaction, address_or_id)?
                .ok_or_else(|| AppError::NotFound("IP address".into()))?;
            if record.status == IpStatus::Main || record.assigned_vm_id.is_some() {
                return Err(AppError::Conflict(
                    "assigned and detected host addresses cannot be deleted".into(),
                ));
            }
            let changed = transaction.execute("DELETE FROM ip_addresses WHERE id = ?1", [&record.id])?;
            require_changed(changed, "IP address")
        })
    }

    pub fn assign_ip(&self, address: &str, vm_id: &str, primary: bool) -> AppResult<IpAddressRecord> {
        let address = canonical_ip(address)?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current = query_ip_address(transaction, &address)?
                .ok_or_else(|| AppError::NotFound("IP address".into()))?;
            // Disabled pools are inventory-only. This is important for
            // imported routed ranges whose addresses are accurate and should
            // remain visible, but whose provisioning topology is not the
            // node's ordinary bridge. Existing ownership may still be
            // reasserted (for example when changing the primary flag), while
            // every new allocation fails closed until an administrator
            // explicitly enables the pool.
            if current.assigned_vm_id.as_deref() != Some(vm_id) {
                if let Some(pool_id) = current.pool_id.as_deref() {
                    let pool = query_ip_pool(transaction, pool_id)?.ok_or_else(|| {
                        AppError::Internal("IP address references a missing pool".into())
                    })?;
                    if !pool.enabled {
                        return Err(AppError::Conflict(format!(
                            "IP address {address} belongs to a disabled pool and cannot be newly assigned"
                        )));
                    }
                }
            }
            let parsed_address = address
                .parse::<IpAddr>()
                .map_err(|_| AppError::Validation("IP address is invalid".into()))?;
            if current.assigned_vm_id.as_deref() != Some(vm_id)
                && ip_is_blacklisted(transaction, parsed_address, unix_now())?
            {
                return Err(AppError::Conflict(format!(
                    "IP address {address} is blacklisted and cannot be assigned"
                )));
            }
            if current.status != IpStatus::Free && current.assigned_vm_id.as_deref() != Some(vm_id) {
                return Err(AppError::Conflict(format!("IP address {address} is not free")));
            }
            if primary {
                transaction.execute(
                    "UPDATE ip_addresses SET primary_for_vm = 0, updated_at = ?3
                     WHERE assigned_vm_id = ?1 AND family = ?2",
                    params![vm_id, current.family.as_i64(), unix_now()],
                )?;
            }
            transaction.execute(
                "UPDATE ip_addresses
                 SET status = 'used', assigned_vm_id = ?2, primary_for_vm = ?3, updated_at = ?4
                 WHERE address = ?1",
                params![address, vm_id, bool_i64(primary), unix_now()],
            )?;
            query_ip_address(transaction, &address)?.ok_or_else(|| AppError::NotFound("IP address".into()))
        })
    }

    pub fn release_ip(&self, address: &str) -> AppResult<IpAddressRecord> {
        let address = canonical_ip(address)?;
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE ip_addresses
                 SET status = 'free', assigned_vm_id = NULL, primary_for_vm = 0, updated_at = ?2
                 WHERE address = ?1 AND status = 'used'",
                    params![address, unix_now()],
                )
                .map_err(Into::into)
        })?;
        if changed == 0 {
            return Err(AppError::Conflict(format!(
                "IP address {address} is not assigned"
            )));
        }
        self.with_connection(|connection| {
            query_ip_address(connection, &address)?.ok_or_else(|| AppError::NotFound("IP address".into()))
        })
    }

    pub fn set_ip_status(&self, address: &str, status: IpStatus) -> AppResult<IpAddressRecord> {
        if status == IpStatus::Used {
            return Err(AppError::Validation(
                "use assign_ip to mark an address as used".into(),
            ));
        }
        let address = canonical_ip(address)?;
        let current = self.with_connection(|connection| query_ip_address(connection, &address))?;
        if current.is_some_and(|record| record.status == IpStatus::Main && status != IpStatus::Main) {
            return Err(AppError::Conflict(
                "the detected host address is protected".into(),
            ));
        }
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE ip_addresses
                 SET status = ?2, assigned_vm_id = NULL, primary_for_vm = 0, updated_at = ?3
                 WHERE address = ?1",
                    params![address, status.as_str(), unix_now()],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "IP address")?;
        self.with_connection(|connection| {
            query_ip_address(connection, &address)?.ok_or_else(|| AppError::NotFound("IP address".into()))
        })
    }

    pub fn replace_dns_servers(
        &self,
        pool_id: Option<&str>,
        vm_id: Option<&str>,
        addresses: &[String],
    ) -> AppResult<Vec<DnsServer>> {
        if pool_id.is_some() && vm_id.is_some() {
            return Err(AppError::Validation(
                "DNS scope cannot be both a pool and a VM".into(),
            ));
        }
        let normalized = normalize_dns_addresses(addresses)?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            transaction.execute(
                "DELETE FROM dns_servers
                 WHERE ((?1 IS NULL AND pool_id IS NULL) OR pool_id = ?1)
                   AND ((?2 IS NULL AND vm_id IS NULL) OR vm_id = ?2)",
                params![pool_id, vm_id],
            )?;
            for (priority, address) in normalized.iter().enumerate() {
                let parsed: IpAddr = address
                    .parse()
                    .map_err(|_| AppError::Validation("DNS server address is invalid".into()))?;
                transaction.execute(
                    "INSERT INTO dns_servers(address, family, priority, pool_id, vm_id)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        address,
                        family_for_ip(parsed).as_i64(),
                        i64::try_from(priority).unwrap_or(i64::MAX),
                        pool_id,
                        vm_id,
                    ],
                )?;
            }
            query_dns_servers(transaction, pool_id, vm_id)
        })
    }

    /// Persist the network setting and its denormalized default-DNS rows in a
    /// single transaction so either API surface cannot leave them out of sync.
    pub fn set_network_setting_and_default_dns(
        &self,
        network: &Value,
        addresses: &[String],
        updated_by: Option<&str>,
    ) -> AppResult<(SettingRecord, Vec<DnsServer>)> {
        let normalized = normalize_dns_addresses(addresses)?;
        let mut network = network.clone();
        let object = network
            .as_object_mut()
            .ok_or_else(|| AppError::Validation("network setting must be an object".into()))?;
        object.insert(
            "dns_servers".into(),
            Value::Array(normalized.iter().cloned().map(Value::String).collect()),
        );
        let value_json = json_string(&network)?;
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            transaction.execute(
                "DELETE FROM dns_servers WHERE pool_id IS NULL AND vm_id IS NULL",
                [],
            )?;
            for (priority, address) in normalized.iter().enumerate() {
                let parsed: IpAddr = address
                    .parse()
                    .map_err(|_| AppError::Validation("DNS server address is invalid".into()))?;
                transaction.execute(
                    "INSERT INTO dns_servers(address, family, priority, pool_id, vm_id)
                     VALUES (?1, ?2, ?3, NULL, NULL)",
                    params![
                        address,
                        family_for_ip(parsed).as_i64(),
                        i64::try_from(priority).unwrap_or(i64::MAX),
                    ],
                )?;
            }
            transaction.execute(
                "INSERT INTO settings(key, value_json, encrypted, updated_by, updated_at)
                 VALUES ('network', ?1, 0, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    encrypted = 0,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at",
                params![value_json, updated_by, now],
            )?;
            let setting = query_setting(transaction, "network")?
                .ok_or_else(|| AppError::NotFound("network setting".into()))?;
            let dns = query_dns_servers(transaction, None, None)?;
            Ok((setting, dns))
        })
    }

    pub fn dns_servers(&self, pool_id: Option<&str>, vm_id: Option<&str>) -> AppResult<Vec<DnsServer>> {
        self.with_connection(|connection| query_dns_servers(connection, pool_id, vm_id))
    }

    // --- IP acquisition blacklist and datacenter abuse records --------------

    pub fn create_ip_blacklist_entry(
        &self,
        spec: &NewIpBlacklistEntry,
    ) -> AppResult<IpBlacklistEntry> {
        validate_non_empty("blacklist reason", &spec.reason)?;
        validate_non_empty("blacklist source", &spec.source)?;
        let network = canonical_ip_network(&spec.cidr)?;
        let now = unix_now();
        if spec.expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(AppError::Validation(
                "blacklist expiration must be in the future".into(),
            ));
        }
        let id = Uuid::new_v4().to_string();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO ip_blacklist(
                    id, cidr, family, reason, source, enabled, expires_at, created_by,
                    metadata_json, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    id,
                    network.to_string(),
                    family_for_ip(network.addr()).as_i64(),
                    spec.reason.trim(),
                    spec.source.trim(),
                    bool_i64(spec.enabled),
                    spec.expires_at,
                    spec.created_by,
                    json_string(&spec.metadata)?,
                    now,
                ],
            )?;
            query_ip_blacklist_entry(connection, &id)?
                .ok_or_else(|| AppError::NotFound("IP blacklist entry".into()))
        })
    }

    pub fn get_ip_blacklist_entry(&self, id_or_cidr: &str) -> AppResult<Option<IpBlacklistEntry>> {
        let normalized = canonical_ip_network(id_or_cidr)
            .ok()
            .map(|network| network.to_string());
        self.with_connection(|connection| {
            query_ip_blacklist_entry(connection, normalized.as_deref().unwrap_or(id_or_cidr))
        })
    }

    pub fn list_ip_blacklist_entries(&self, active_only: bool) -> AppResult<Vec<IpBlacklistEntry>> {
        let now = unix_now();
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, cidr, family, reason, source, enabled, expires_at, created_by,
                        metadata_json, created_at, updated_at
                 FROM ip_blacklist
                 WHERE ?1 = 0 OR (enabled = 1 AND (expires_at IS NULL OR expires_at > ?2))
                 ORDER BY enabled DESC, created_at DESC, cidr",
            )?;
            let rows = statement.query_map(params![bool_i64(active_only), now], row_to_ip_blacklist_entry)?;
            collect_rows(rows)
        })
    }

    pub fn patch_ip_blacklist_entry(
        &self,
        id: &str,
        patch: &IpBlacklistPatch,
    ) -> AppResult<IpBlacklistEntry> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let mut entry = query_ip_blacklist_entry(transaction, id)?
                .ok_or_else(|| AppError::NotFound("IP blacklist entry".into()))?;
            let changed = patch.reason.is_some()
                || patch.source.is_some()
                || patch.enabled.is_some()
                || patch.expires_at.is_some()
                || patch.metadata.is_some();
            if !changed {
                return Ok(entry);
            }
            if let Some(reason) = patch.reason.as_deref() {
                validate_non_empty("blacklist reason", reason)?;
                entry.reason = reason.trim().to_owned();
            }
            if let Some(source) = patch.source.as_deref() {
                validate_non_empty("blacklist source", source)?;
                entry.source = source.trim().to_owned();
            }
            entry.enabled = patch.enabled.unwrap_or(entry.enabled);
            if let Some(expires_at) = patch.expires_at {
                if expires_at.is_some_and(|value| value <= entry.created_at) {
                    return Err(AppError::Validation(
                        "blacklist expiration must be after its creation time".into(),
                    ));
                }
                entry.expires_at = expires_at;
            }
            if let Some(metadata) = patch.metadata.as_ref() {
                entry.metadata.clone_from(metadata);
            }
            transaction.execute(
                "UPDATE ip_blacklist
                 SET reason = ?2, source = ?3, enabled = ?4, expires_at = ?5,
                     metadata_json = ?6, updated_at = ?7 WHERE id = ?1",
                params![
                    entry.id,
                    entry.reason,
                    entry.source,
                    bool_i64(entry.enabled),
                    entry.expires_at,
                    json_string(&entry.metadata)?,
                    unix_now(),
                ],
            )?;
            query_ip_blacklist_entry(transaction, id)?
                .ok_or_else(|| AppError::NotFound("IP blacklist entry".into()))
        })
    }

    pub fn delete_ip_blacklist_entry(&self, id: &str) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute("DELETE FROM ip_blacklist WHERE id = ?1", [id])
                .map_err(Into::into)
        })?;
        require_changed(changed, "IP blacklist entry")
    }

    pub fn ip_is_blacklisted(&self, address: &str, at: Timestamp) -> AppResult<bool> {
        let address = address
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| AppError::Validation("IP address is invalid".into()))?;
        self.with_connection(|connection| ip_is_blacklisted(connection, address, at))
    }

    pub fn record_ip_abuse(&self, spec: &NewIpAbuseRecord) -> AppResult<IpAbuseRecord> {
        validate_non_empty("abuse category", &spec.category)?;
        validate_non_empty("abuse summary", &spec.summary)?;
        if !(1..=10).contains(&spec.severity) {
            return Err(AppError::Validation(
                "abuse severity must be between 1 and 10".into(),
            ));
        }
        let address = canonical_ip(&spec.address)?;
        let parsed = address
            .parse::<IpAddr>()
            .map_err(|_| AppError::Validation("IP address is invalid".into()))?;
        let id = Uuid::new_v4().to_string();
        let now = unix_now();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO ip_abuse_records(
                    id, address, family, vm_id, category, severity, summary, reporter,
                    provider_reference, observed_at, reported_at, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    id,
                    address,
                    family_for_ip(parsed).as_i64(),
                    spec.vm_id,
                    spec.category.trim(),
                    i64::from(spec.severity),
                    spec.summary.trim(),
                    spec.reporter,
                    spec.provider_reference,
                    spec.observed_at.unwrap_or(now),
                    now,
                    json_string(&spec.metadata)?,
                ],
            )?;
            query_ip_abuse_record(connection, &id)?
                .ok_or_else(|| AppError::NotFound("IP abuse record".into()))
        })
    }

    pub fn get_ip_abuse_record(&self, id: &str) -> AppResult<Option<IpAbuseRecord>> {
        self.with_connection(|connection| query_ip_abuse_record(connection, id))
    }

    pub fn list_ip_abuse_records(
        &self,
        address: Option<&str>,
        vm_id: Option<&str>,
        unresolved_only: bool,
        limit: usize,
    ) -> AppResult<Vec<IpAbuseRecord>> {
        let address = address.map(canonical_ip).transpose()?;
        let limit = bounded_limit(limit, 5000);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, address, family, vm_id, category, severity, summary, reporter,
                        provider_reference, observed_at, reported_at, resolved_at,
                        resolved_by, resolution, metadata_json
                 FROM ip_abuse_records
                 WHERE (?1 IS NULL OR address = ?1)
                   AND (?2 IS NULL OR vm_id = ?2)
                   AND (?3 = 0 OR resolved_at IS NULL)
                 ORDER BY observed_at DESC, reported_at DESC LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![address, vm_id, bool_i64(unresolved_only), limit],
                row_to_ip_abuse_record,
            )?;
            collect_rows(rows)
        })
    }

    pub fn resolve_ip_abuse_record(
        &self,
        id: &str,
        resolved_by: Option<&str>,
        resolution: &str,
    ) -> AppResult<IpAbuseRecord> {
        validate_non_empty("abuse resolution", resolution)?;
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE ip_abuse_records
                     SET resolved_at = COALESCE(resolved_at, ?2), resolved_by = ?3,
                         resolution = ?4 WHERE id = ?1",
                    params![id, unix_now(), resolved_by, resolution.trim()],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "IP abuse record")?;
        self.with_connection(|connection| {
            query_ip_abuse_record(connection, id)?
                .ok_or_else(|| AppError::NotFound("IP abuse record".into()))
        })
    }

    // --- Settings and ISO catalog --------------------------------------------

    pub fn set_setting(
        &self,
        key: &str,
        value: &Value,
        encrypted: bool,
        updated_by: Option<&str>,
    ) -> AppResult<SettingRecord> {
        validate_non_empty("setting key", key)?;
        let value_json = json_string(value)?;
        let now = unix_now();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO settings(key, value_json, encrypted, updated_by, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    encrypted = excluded.encrypted,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at",
                params![key, value_json, bool_i64(encrypted), updated_by, now],
            )?;
            query_setting(connection, key)?.ok_or_else(|| AppError::NotFound("setting".into()))
        })
    }

    pub fn get_setting(&self, key: &str) -> AppResult<Option<SettingRecord>> {
        self.with_connection(|connection| query_setting(connection, key))
    }

    pub fn list_settings(&self, include_encrypted: bool) -> AppResult<Vec<SettingRecord>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT key, value_json, encrypted, updated_by, updated_at
                 FROM settings WHERE ?1 = 1 OR encrypted = 0 ORDER BY key",
            )?;
            let rows = statement.query_map([bool_i64(include_encrypted)], row_to_setting)?;
            collect_rows(rows)
        })
    }

    pub fn delete_setting(&self, key: &str) -> AppResult<bool> {
        self.with_connection(|connection| {
            Ok(connection.execute("DELETE FROM settings WHERE key = ?1", [key])? > 0)
        })
    }

    pub fn upsert_iso(&self, image: &IsoImage) -> AppResult<IsoImage> {
        validate_non_empty("ISO slug", &image.slug)?;
        validate_non_empty("ISO name", &image.name)?;
        if image.source_url.is_none() && image.local_path.is_none() {
            return Err(AppError::Validation(
                "an ISO needs a source URL or local path".into(),
            ));
        }
        let id = if image.id.trim().is_empty() {
            Uuid::new_v4().to_string()
        } else {
            image.id.clone()
        };
        let now = unix_now();
        let created_at = if image.created_at <= 0 {
            now
        } else {
            image.created_at
        };
        let metadata = json_string(&image.metadata)?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO iso_images(
                    id, slug, name, version, os_family, architecture, install_mode,
                    source_url, local_path, checksum_sha256, size_bytes,
                    supports_guest_agent, supports_cloud_init, uefi, enabled,
                    metadata_json, created_at, updated_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16, ?17, ?18
                 )
                 ON CONFLICT(id) DO UPDATE SET
                    slug = excluded.slug,
                    name = excluded.name,
                    version = excluded.version,
                    os_family = excluded.os_family,
                    architecture = excluded.architecture,
                    install_mode = excluded.install_mode,
                    source_url = excluded.source_url,
                    local_path = excluded.local_path,
                    checksum_sha256 = excluded.checksum_sha256,
                    size_bytes = excluded.size_bytes,
                    supports_guest_agent = excluded.supports_guest_agent,
                    supports_cloud_init = excluded.supports_cloud_init,
                    uefi = excluded.uefi,
                    enabled = excluded.enabled,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at",
                params![
                    id,
                    image.slug.trim(),
                    image.name.trim(),
                    image.version,
                    image.os_family,
                    image.architecture,
                    image.install_mode.as_str(),
                    image.source_url,
                    image.local_path,
                    image.checksum_sha256,
                    optional_i64(image.size_bytes, "ISO size")?,
                    bool_i64(image.supports_guest_agent),
                    bool_i64(image.supports_cloud_init),
                    bool_i64(image.uefi),
                    bool_i64(image.enabled),
                    metadata,
                    created_at,
                    now,
                ],
            )?;
            query_iso(connection, &id)?.ok_or_else(|| AppError::NotFound("ISO".into()))
        })
    }

    pub fn get_iso(&self, id_or_slug: &str) -> AppResult<Option<IsoImage>> {
        self.with_connection(|connection| query_iso(connection, id_or_slug))
    }

    pub fn list_isos(&self, include_disabled: bool) -> AppResult<Vec<IsoImage>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, slug, name, version, os_family, architecture, install_mode,
                        source_url, local_path, checksum_sha256, size_bytes,
                        supports_guest_agent, supports_cloud_init, uefi, enabled,
                        metadata_json, created_at, updated_at
                 FROM iso_images WHERE ?1 = 1 OR enabled = 1
                 ORDER BY os_family, name COLLATE NOCASE, version",
            )?;
            let rows = statement.query_map([bool_i64(include_disabled)], row_to_iso)?;
            collect_rows(rows)
        })
    }

    pub fn delete_iso(&self, id_or_slug: &str) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "DELETE FROM iso_images WHERE id = ?1 OR slug = ?1 COLLATE NOCASE",
                    [id_or_slug],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "ISO")
    }

    // --- Detected host inventory and time-series metrics ---------------------

    pub fn upsert_host_inventory(&self, inventory: &HostInventory) -> AppResult<()> {
        if inventory.cpu_cores == 0 || inventory.listen_port == 0 {
            return Err(AppError::Validation(
                "host inventory needs CPU cores and a listen port".into(),
            ));
        }
        let addresses = inventory
            .detected_addresses
            .iter()
            .map(|address| canonical_ip(address))
            .collect::<AppResult<Vec<_>>>()?;
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO host_inventory(
                    singleton_id, hostname, architecture, kernel, cpu_model, cpu_cores,
                    memory_total_bytes, root_disk_total_bytes, listen_port, public_interface,
                    detected_addresses_json, metadata_json, updated_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(singleton_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    architecture = excluded.architecture,
                    kernel = excluded.kernel,
                    cpu_model = excluded.cpu_model,
                    cpu_cores = excluded.cpu_cores,
                    memory_total_bytes = excluded.memory_total_bytes,
                    root_disk_total_bytes = excluded.root_disk_total_bytes,
                    listen_port = excluded.listen_port,
                    public_interface = excluded.public_interface,
                    detected_addresses_json = excluded.detected_addresses_json,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at",
                params![
                    inventory.hostname,
                    inventory.architecture,
                    inventory.kernel,
                    inventory.cpu_model,
                    i64::from(inventory.cpu_cores),
                    checked_i64(inventory.memory_total_bytes, "host memory")?,
                    checked_i64(inventory.root_disk_total_bytes, "host disk")?,
                    i64::from(inventory.listen_port),
                    inventory.public_interface,
                    json_string(&addresses)?,
                    json_string(&inventory.metadata)?,
                    inventory.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn host_inventory(&self) -> AppResult<Option<HostInventory>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT hostname, architecture, kernel, cpu_model, cpu_cores,
                            memory_total_bytes, root_disk_total_bytes, listen_port,
                            public_interface, detected_addresses_json, metadata_json, updated_at
                     FROM host_inventory WHERE singleton_id = 1",
                    [],
                    row_to_host_inventory,
                )
                .optional()
                .map_err(Into::into)
        })
    }

    pub fn insert_host_metric(&self, metric: &HostMetric) -> AppResult<()> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO host_metrics(
                    sampled_at, cpu_percent, load_one, load_five, load_fifteen,
                    memory_total_bytes, memory_used_bytes, swap_total_bytes, swap_used_bytes,
                    disk_total_bytes, disk_used_bytes, disk_read_bps, disk_write_bps,
                    network_rx_bytes, network_tx_bytes, network_rx_bps, network_tx_bps,
                    uptime_seconds, metadata_json
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16, ?17, ?18, ?19
                 )
                 ON CONFLICT(sampled_at) DO UPDATE SET
                    cpu_percent = excluded.cpu_percent,
                    load_one = excluded.load_one,
                    load_five = excluded.load_five,
                    load_fifteen = excluded.load_fifteen,
                    memory_total_bytes = excluded.memory_total_bytes,
                    memory_used_bytes = excluded.memory_used_bytes,
                    swap_total_bytes = excluded.swap_total_bytes,
                    swap_used_bytes = excluded.swap_used_bytes,
                    disk_total_bytes = excluded.disk_total_bytes,
                    disk_used_bytes = excluded.disk_used_bytes,
                    disk_read_bps = excluded.disk_read_bps,
                    disk_write_bps = excluded.disk_write_bps,
                    network_rx_bytes = excluded.network_rx_bytes,
                    network_tx_bytes = excluded.network_tx_bytes,
                    network_rx_bps = excluded.network_rx_bps,
                    network_tx_bps = excluded.network_tx_bps,
                    uptime_seconds = excluded.uptime_seconds,
                    metadata_json = excluded.metadata_json",
                params![
                    metric.sampled_at,
                    metric.cpu_percent,
                    metric.load_one,
                    metric.load_five,
                    metric.load_fifteen,
                    checked_i64(metric.memory_total_bytes, "memory total")?,
                    checked_i64(metric.memory_used_bytes, "memory used")?,
                    checked_i64(metric.swap_total_bytes, "swap total")?,
                    checked_i64(metric.swap_used_bytes, "swap used")?,
                    checked_i64(metric.disk_total_bytes, "disk total")?,
                    checked_i64(metric.disk_used_bytes, "disk used")?,
                    metric.disk_read_bps,
                    metric.disk_write_bps,
                    checked_i64(metric.network_rx_bytes, "network RX")?,
                    checked_i64(metric.network_tx_bytes, "network TX")?,
                    metric.network_rx_bps,
                    metric.network_tx_bps,
                    checked_i64(metric.uptime_seconds, "uptime")?,
                    json_string(&metric.metadata)?,
                ],
            )?;
            Ok(())
        })
    }

    pub fn host_metrics(&self, since: Timestamp, limit: usize) -> AppResult<Vec<HostMetric>> {
        let limit = bounded_limit(limit, 10_000);
        self.with_connection(|connection| {
            let latest: Option<Timestamp> = connection.query_row(
                "SELECT MAX(sampled_at) FROM host_metrics WHERE sampled_at >= ?1",
                [since],
                |row| row.get(0),
            )?;
            let bucket_seconds = metric_bucket_seconds(since, latest, limit);
            let mut statement = connection.prepare(
                "WITH selected(sampled_at) AS (
                    SELECT MAX(sampled_at)
                      FROM host_metrics
                     WHERE sampled_at >= ?1
                     GROUP BY ((sampled_at - ?1) / ?2)
                     ORDER BY MAX(sampled_at) DESC
                     LIMIT ?3
                 )
                 SELECT metrics.sampled_at, metrics.cpu_percent, metrics.load_one,
                        metrics.load_five, metrics.load_fifteen,
                        metrics.memory_total_bytes, metrics.memory_used_bytes,
                        metrics.swap_total_bytes, metrics.swap_used_bytes,
                        metrics.disk_total_bytes, metrics.disk_used_bytes,
                        metrics.disk_read_bps, metrics.disk_write_bps,
                        metrics.network_rx_bytes, metrics.network_tx_bytes,
                        metrics.network_rx_bps, metrics.network_tx_bps,
                        metrics.uptime_seconds, metrics.metadata_json
                   FROM host_metrics AS metrics
                   JOIN selected USING(sampled_at)
                  ORDER BY metrics.sampled_at DESC",
            )?;
            let rows = statement.query_map(
                params![since, bucket_seconds, limit],
                row_to_host_metric,
            )?;
            collect_rows(rows)
        })
    }

    pub fn insert_vm_metric(&self, metric: &VmMetric) -> AppResult<()> {
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO vm_metrics(
                    vm_id, sampled_at, cpu_percent, memory_used_bytes, memory_total_bytes,
                    disk_read_bytes, disk_write_bytes, disk_read_bps, disk_write_bps,
                    network_rx_bytes, network_tx_bytes, network_rx_bps, network_tx_bps,
                    traffic_used_bytes, traffic_limit_bytes, metadata_json
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16
                 )
                 ON CONFLICT(vm_id, sampled_at) DO UPDATE SET
                    cpu_percent = excluded.cpu_percent,
                    memory_used_bytes = excluded.memory_used_bytes,
                    memory_total_bytes = excluded.memory_total_bytes,
                    disk_read_bytes = excluded.disk_read_bytes,
                    disk_write_bytes = excluded.disk_write_bytes,
                    disk_read_bps = excluded.disk_read_bps,
                    disk_write_bps = excluded.disk_write_bps,
                    network_rx_bytes = excluded.network_rx_bytes,
                    network_tx_bytes = excluded.network_tx_bytes,
                    network_rx_bps = excluded.network_rx_bps,
                    network_tx_bps = excluded.network_tx_bps,
                    traffic_used_bytes = excluded.traffic_used_bytes,
                    traffic_limit_bytes = excluded.traffic_limit_bytes,
                    metadata_json = excluded.metadata_json",
                params![
                    metric.vm_id,
                    metric.sampled_at,
                    metric.cpu_percent,
                    checked_i64(metric.memory_used_bytes, "VM memory used")?,
                    checked_i64(metric.memory_total_bytes, "VM memory total")?,
                    checked_i64(metric.disk_read_bytes, "VM disk read")?,
                    checked_i64(metric.disk_write_bytes, "VM disk write")?,
                    metric.disk_read_bps,
                    metric.disk_write_bps,
                    checked_i64(metric.network_rx_bytes, "VM network RX")?,
                    checked_i64(metric.network_tx_bytes, "VM network TX")?,
                    metric.network_rx_bps,
                    metric.network_tx_bps,
                    checked_i64(metric.traffic_used_bytes, "VM traffic used")?,
                    optional_i64(metric.traffic_limit_bytes, "VM traffic limit")?,
                    json_string(&metric.metadata)?,
                ],
            )?;
            connection.execute(
                "UPDATE vms SET traffic_used_bytes = ?2, updated_at = MAX(updated_at, ?3)
                 WHERE id = ?1",
                params![
                    metric.vm_id,
                    checked_i64(metric.traffic_used_bytes, "VM traffic used")?,
                    metric.sampled_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn vm_metrics(&self, vm_id: &str, since: Timestamp, limit: usize) -> AppResult<Vec<VmMetric>> {
        let limit = bounded_limit(limit, 10_000);
        self.with_connection(|connection| {
            let latest: Option<Timestamp> = connection.query_row(
                "SELECT MAX(sampled_at) FROM vm_metrics WHERE vm_id = ?1 AND sampled_at >= ?2",
                params![vm_id, since],
                |row| row.get(0),
            )?;
            let bucket_seconds = metric_bucket_seconds(since, latest, limit);
            let mut statement = connection.prepare(
                "WITH selected(vm_id, sampled_at) AS (
                    SELECT vm_id, MAX(sampled_at)
                      FROM vm_metrics
                     WHERE vm_id = ?1 AND sampled_at >= ?2
                     GROUP BY ((sampled_at - ?2) / ?3)
                     ORDER BY MAX(sampled_at) DESC
                     LIMIT ?4
                 )
                 SELECT metrics.vm_id, metrics.sampled_at, metrics.cpu_percent,
                        metrics.memory_used_bytes, metrics.memory_total_bytes,
                        metrics.disk_read_bytes, metrics.disk_write_bytes,
                        metrics.disk_read_bps, metrics.disk_write_bps,
                        metrics.network_rx_bytes, metrics.network_tx_bytes,
                        metrics.network_rx_bps, metrics.network_tx_bps,
                        metrics.traffic_used_bytes, metrics.traffic_limit_bytes,
                        metrics.metadata_json
                   FROM vm_metrics AS metrics
                   JOIN selected
                     ON selected.vm_id = metrics.vm_id
                    AND selected.sampled_at = metrics.sampled_at
                  ORDER BY metrics.sampled_at DESC",
            )?;
            let rows = statement.query_map(
                params![vm_id, since, bucket_seconds, limit],
                row_to_vm_metric,
            )?;
            collect_rows(rows)
        })
    }

    pub fn vm_traffic_enforcement(&self, vm_id: &str) -> AppResult<Option<VmTrafficEnforcement>> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT vm_id, blocked, blocked_at, last_error, updated_at
                     FROM vm_traffic_enforcement WHERE vm_id = ?1",
                    [vm_id],
                    |row| {
                        Ok(VmTrafficEnforcement {
                            vm_id: row.get(0)?,
                            blocked: row.get::<_, i64>(1)? != 0,
                            blocked_at: row.get(2)?,
                            last_error: row.get(3)?,
                            updated_at: row.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(Into::into)
        })
    }

    /// Record the link state actually applied by Vexa-VM. Failed transitions
    /// leave `blocked` unchanged so a later reconciliation retries them.
    pub fn set_vm_traffic_enforcement(
        &self,
        vm_id: &str,
        blocked: bool,
        last_error: Option<&str>,
    ) -> AppResult<VmTrafficEnforcement> {
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let blocked_at = if blocked {
                transaction
                    .query_row(
                        "SELECT blocked_at FROM vm_traffic_enforcement WHERE vm_id = ?1",
                        [vm_id],
                        |row| row.get::<_, Option<i64>>(0),
                    )
                    .optional()?
                    .flatten()
                    .or(Some(now))
            } else {
                None
            };
            transaction.execute(
                "INSERT INTO vm_traffic_enforcement(vm_id, blocked, blocked_at, last_error, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(vm_id) DO UPDATE SET
                    blocked = excluded.blocked,
                    blocked_at = excluded.blocked_at,
                    last_error = excluded.last_error,
                    updated_at = excluded.updated_at",
                params![vm_id, bool_i64(blocked), blocked_at, last_error, now],
            )?;
            transaction
                .query_row(
                    "SELECT vm_id, blocked, blocked_at, last_error, updated_at
                     FROM vm_traffic_enforcement WHERE vm_id = ?1",
                    [vm_id],
                    |row| {
                        Ok(VmTrafficEnforcement {
                            vm_id: row.get(0)?,
                            blocked: row.get::<_, i64>(1)? != 0,
                            blocked_at: row.get(2)?,
                            last_error: row.get(3)?,
                            updated_at: row.get(4)?,
                        })
                    },
                )
                .map_err(Into::into)
        })
    }

    // --- VM policy and host IP-ownership security ----------------------------

    pub fn vm_network_security(&self, vm_id: &str) -> AppResult<Option<VmNetworkSecurity>> {
        self.with_connection(|connection| query_vm_network_security(connection, vm_id))
    }

    pub fn patch_vm_network_security(
        &self,
        vm_id: &str,
        patch: &VmNetworkSecurityPatch,
    ) -> AppResult<VmNetworkSecurity> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let mut profile = query_vm_network_security(transaction, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM network security profile".into()))?;
            let changed = patch.firewall_enabled.is_some()
                || patch.ddos_enabled.is_some()
                || patch.default_ingress_action.is_some()
                || patch.default_egress_action.is_some()
                || patch.syn_rate_limit_pps.is_some()
                || patch.udp_rate_limit_pps.is_some()
                || patch.icmp_rate_limit_pps.is_some()
                || patch.new_connection_limit_pps.is_some()
                || patch.concurrent_connection_limit.is_some()
                || patch.port_scan_protection.is_some()
                || patch.drop_invalid_packets.is_some();
            if !changed {
                return Ok(profile);
            }

            profile.firewall_enabled = patch.firewall_enabled.unwrap_or(profile.firewall_enabled);
            profile.ddos_enabled = patch.ddos_enabled.unwrap_or(profile.ddos_enabled);
            profile.default_ingress_action = patch
                .default_ingress_action
                .unwrap_or(profile.default_ingress_action);
            profile.default_egress_action = patch
                .default_egress_action
                .unwrap_or(profile.default_egress_action);
            if let Some(value) = patch.syn_rate_limit_pps {
                profile.syn_rate_limit_pps = value;
            }
            if let Some(value) = patch.udp_rate_limit_pps {
                profile.udp_rate_limit_pps = value;
            }
            if let Some(value) = patch.icmp_rate_limit_pps {
                profile.icmp_rate_limit_pps = value;
            }
            if let Some(value) = patch.new_connection_limit_pps {
                profile.new_connection_limit_pps = value;
            }
            if let Some(value) = patch.concurrent_connection_limit {
                profile.concurrent_connection_limit = value;
            }
            profile.port_scan_protection = patch
                .port_scan_protection
                .unwrap_or(profile.port_scan_protection);
            profile.drop_invalid_packets = patch
                .drop_invalid_packets
                .unwrap_or(profile.drop_invalid_packets);
            validate_vm_network_security(&profile)?;

            let now = unix_now();
            transaction.execute(
                "UPDATE vm_network_security
                 SET firewall_enabled = ?2, ddos_enabled = ?3,
                     default_ingress_action = ?4, default_egress_action = ?5,
                     syn_rate_limit_pps = ?6, udp_rate_limit_pps = ?7,
                     icmp_rate_limit_pps = ?8, new_connection_limit_pps = ?9,
                     concurrent_connection_limit = ?10, port_scan_protection = ?11,
                     drop_invalid_packets = ?12, revision = revision + 1,
                     last_error = NULL, updated_at = ?13
                 WHERE vm_id = ?1",
                params![
                    vm_id,
                    bool_i64(profile.firewall_enabled),
                    bool_i64(profile.ddos_enabled),
                    profile.default_ingress_action.as_str(),
                    profile.default_egress_action.as_str(),
                    optional_i64(profile.syn_rate_limit_pps.map(u64::from), "SYN rate limit")?,
                    optional_i64(profile.udp_rate_limit_pps.map(u64::from), "UDP rate limit")?,
                    optional_i64(profile.icmp_rate_limit_pps.map(u64::from), "ICMP rate limit")?,
                    optional_i64(
                        profile.new_connection_limit_pps.map(u64::from),
                        "new connection rate limit",
                    )?,
                    optional_i64(
                        profile.concurrent_connection_limit.map(u64::from),
                        "concurrent connection limit",
                    )?,
                    bool_i64(profile.port_scan_protection),
                    bool_i64(profile.drop_invalid_packets),
                    now,
                ],
            )?;
            query_vm_network_security(transaction, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM network security profile".into()))
        })
    }

    /// Record a successful or failed reconciliation of one exact revision.
    /// Stale workers cannot mark a newer policy as applied.
    pub fn mark_vm_network_security_applied(
        &self,
        vm_id: &str,
        revision: u64,
        error: Option<&str>,
    ) -> AppResult<VmNetworkSecurity> {
        let stored_revision = checked_i64(revision, "network security revision")?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current = query_vm_network_security(transaction, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM network security profile".into()))?;
            if current.revision != revision {
                return Err(AppError::Conflict(
                    "network security policy changed before it could be applied".into(),
                ));
            }
            let now = unix_now();
            transaction.execute(
                "UPDATE vm_network_security
                 SET applied_revision = CASE WHEN ?3 IS NULL THEN ?2 ELSE applied_revision END,
                     last_applied_at = CASE WHEN ?3 IS NULL THEN ?4 ELSE last_applied_at END,
                     last_error = ?3, updated_at = ?4
                 WHERE vm_id = ?1",
                params![vm_id, stored_revision, error, now],
            )?;
            query_vm_network_security(transaction, vm_id)?
                .ok_or_else(|| AppError::NotFound("VM network security profile".into()))
        })
    }

    pub fn create_vm_firewall_rule(
        &self,
        vm_id: &str,
        spec: &NewVmFirewallRule,
    ) -> AppResult<VmFirewallRule> {
        self.create_vm_firewall_rule_owned(vm_id, spec, "admin", None)
    }

    pub fn create_vm_firewall_rule_owned(
        &self,
        vm_id: &str,
        spec: &NewVmFirewallRule,
        owner_type: &str,
        owner_id: Option<&str>,
    ) -> AppResult<VmFirewallRule> {
        if !matches!(owner_type, "admin" | "customer_token" | "system") {
            return Err(AppError::Validation(
                "firewall rule owner type is invalid".into(),
            ));
        }
        if owner_type == "customer_token" && owner_id.is_none() {
            return Err(AppError::Validation(
                "customer firewall rules require an owner ID".into(),
            ));
        }
        let spec = normalize_firewall_rule(spec)?;
        let id = Uuid::new_v4().to_string();
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            if query_vm_network_security(transaction, vm_id)?.is_none() {
                return Err(AppError::NotFound("VM network security profile".into()));
            }
            let rule_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM vm_firewall_rules WHERE vm_id = ?1",
                [vm_id],
                |row| row.get(0),
            )?;
            if rule_count >= MAX_FIREWALL_RULES_PER_VM {
                return Err(AppError::Conflict(format!(
                    "a VM cannot have more than {MAX_FIREWALL_RULES_PER_VM} firewall rules"
                )));
            }
            transaction.execute(
                "INSERT INTO vm_firewall_rules(
                    id, vm_id, priority, direction, action, protocol, source_cidr,
                    destination_cidr, source_ports_json, destination_ports_json,
                    log, enabled, description, owner_type, owner_id, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16)",
                params![
                    id,
                    vm_id,
                    i64::from(spec.priority),
                    spec.direction.as_str(),
                    spec.action.as_str(),
                    spec.protocol.as_str(),
                    spec.source_cidr,
                    spec.destination_cidr,
                    json_string(&spec.source_ports)?,
                    json_string(&spec.destination_ports)?,
                    bool_i64(spec.log),
                    bool_i64(spec.enabled),
                    spec.description,
                    owner_type,
                    owner_id,
                    now,
                ],
            )?;
            bump_vm_network_security_revision(transaction, vm_id, now)?;
            query_vm_firewall_rule(transaction, vm_id, &id)?
                .ok_or_else(|| AppError::NotFound("VM firewall rule".into()))
        })
    }

    pub fn list_vm_firewall_rules(&self, vm_id: &str) -> AppResult<Vec<VmFirewallRule>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, vm_id, priority, direction, action, protocol, source_cidr,
                        destination_cidr, source_ports_json, destination_ports_json,
                        log, enabled, description, owner_type, owner_id, created_at, updated_at
                 FROM vm_firewall_rules WHERE vm_id = ?1
                 ORDER BY direction, priority, created_at, id",
            )?;
            let rows = statement.query_map([vm_id], row_to_vm_firewall_rule)?;
            collect_rows(rows)
        })
    }

    pub fn get_vm_firewall_rule(
        &self,
        vm_id: &str,
        rule_id: &str,
    ) -> AppResult<Option<VmFirewallRule>> {
        self.with_connection(|connection| query_vm_firewall_rule(connection, vm_id, rule_id))
    }

    pub fn patch_vm_firewall_rule(
        &self,
        vm_id: &str,
        rule_id: &str,
        patch: &VmFirewallRulePatch,
    ) -> AppResult<VmFirewallRule> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current = query_vm_firewall_rule(transaction, vm_id, rule_id)?
                .ok_or_else(|| AppError::NotFound("VM firewall rule".into()))?;
            let changed = patch.priority.is_some()
                || patch.direction.is_some()
                || patch.action.is_some()
                || patch.protocol.is_some()
                || patch.source_cidr.is_some()
                || patch.destination_cidr.is_some()
                || patch.source_ports.is_some()
                || patch.destination_ports.is_some()
                || patch.log.is_some()
                || patch.enabled.is_some()
                || patch.description.is_some();
            if !changed {
                return Ok(current);
            }
            let spec = normalize_firewall_rule(&NewVmFirewallRule {
                priority: patch.priority.unwrap_or(current.priority),
                direction: patch.direction.unwrap_or(current.direction),
                action: patch.action.unwrap_or(current.action),
                protocol: patch.protocol.unwrap_or(current.protocol),
                source_cidr: patch
                    .source_cidr
                    .clone()
                    .unwrap_or_else(|| current.source_cidr.clone()),
                destination_cidr: patch
                    .destination_cidr
                    .clone()
                    .unwrap_or_else(|| current.destination_cidr.clone()),
                source_ports: patch
                    .source_ports
                    .clone()
                    .unwrap_or_else(|| current.source_ports.clone()),
                destination_ports: patch
                    .destination_ports
                    .clone()
                    .unwrap_or_else(|| current.destination_ports.clone()),
                log: patch.log.unwrap_or(current.log),
                enabled: patch.enabled.unwrap_or(current.enabled),
                description: patch
                    .description
                    .clone()
                    .unwrap_or_else(|| current.description.clone()),
            })?;
            let now = unix_now();
            transaction.execute(
                "UPDATE vm_firewall_rules
                 SET priority = ?3, direction = ?4, action = ?5, protocol = ?6,
                     source_cidr = ?7, destination_cidr = ?8, source_ports_json = ?9,
                     destination_ports_json = ?10, log = ?11, enabled = ?12,
                     description = ?13, updated_at = ?14
                 WHERE vm_id = ?1 AND id = ?2",
                params![
                    vm_id,
                    rule_id,
                    i64::from(spec.priority),
                    spec.direction.as_str(),
                    spec.action.as_str(),
                    spec.protocol.as_str(),
                    spec.source_cidr,
                    spec.destination_cidr,
                    json_string(&spec.source_ports)?,
                    json_string(&spec.destination_ports)?,
                    bool_i64(spec.log),
                    bool_i64(spec.enabled),
                    spec.description,
                    now,
                ],
            )?;
            bump_vm_network_security_revision(transaction, vm_id, now)?;
            query_vm_firewall_rule(transaction, vm_id, rule_id)?
                .ok_or_else(|| AppError::NotFound("VM firewall rule".into()))
        })
    }

    pub fn delete_vm_firewall_rule(&self, vm_id: &str, rule_id: &str) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let changed = transaction.execute(
                "DELETE FROM vm_firewall_rules WHERE vm_id = ?1 AND id = ?2",
                params![vm_id, rule_id],
            )?;
            require_changed(changed, "VM firewall rule")?;
            bump_vm_network_security_revision(transaction, vm_id, unix_now())
        })
    }

    pub fn hypervisor_network_security(&self) -> AppResult<HypervisorNetworkSecurity> {
        self.with_connection(query_hypervisor_network_security)
    }

    pub fn patch_hypervisor_network_security(
        &self,
        patch: &HypervisorNetworkSecurityPatch,
        updated_by: Option<&str>,
    ) -> AppResult<HypervisorNetworkSecurity> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current = query_hypervisor_network_security(transaction)?;
            let ip_ownership_guard_enabled = patch
                .ip_ownership_guard_enabled
                .unwrap_or(current.ip_ownership_guard_enabled);
            let bcp38_enabled = patch.bcp38_enabled.unwrap_or(current.bcp38_enabled);
            if ip_ownership_guard_enabled == current.ip_ownership_guard_enabled
                && bcp38_enabled == current.bcp38_enabled
            {
                return Ok(current);
            }
            transaction.execute(
                "UPDATE hypervisor_network_security
                 SET ip_ownership_guard_enabled = ?1, bcp38_enabled = ?2,
                     revision = revision + 1, last_error = NULL,
                     updated_by = ?3, updated_at = ?4 WHERE singleton_id = 1",
                params![
                    bool_i64(ip_ownership_guard_enabled),
                    bool_i64(bcp38_enabled),
                    updated_by,
                    unix_now(),
                ],
            )?;
            query_hypervisor_network_security(transaction)
        })
    }

    pub fn mark_hypervisor_network_security_applied(
        &self,
        revision: u64,
        error: Option<&str>,
    ) -> AppResult<HypervisorNetworkSecurity> {
        let stored_revision = checked_i64(revision, "hypervisor network security revision")?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let current = query_hypervisor_network_security(transaction)?;
            if current.revision != revision {
                return Err(AppError::Conflict(
                    "hypervisor network security policy changed before it could be applied".into(),
                ));
            }
            let now = unix_now();
            transaction.execute(
                "UPDATE hypervisor_network_security
                 SET applied_revision = CASE WHEN ?2 IS NULL THEN ?1 ELSE applied_revision END,
                     last_applied_at = CASE WHEN ?2 IS NULL THEN ?3 ELSE last_applied_at END,
                     last_error = ?2, updated_at = ?3 WHERE singleton_id = 1",
                params![stored_revision, error, now],
            )?;
            query_hypervisor_network_security(transaction)
        })
    }

    pub fn prune_metrics(&self, before: Timestamp) -> AppResult<(usize, usize)> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let hosts = transaction.execute("DELETE FROM host_metrics WHERE sampled_at < ?1", [before])?;
            let vms = transaction.execute("DELETE FROM vm_metrics WHERE sampled_at < ?1", [before])?;
            Ok((hosts, vms))
        })
    }

    // --- Customer and VNC bearer credentials ---------------------------------

    pub fn create_customer_token(
        &self,
        vm_id: &str,
        token_hash: &[u8; 32],
        scopes: &[String],
        expires_at: Timestamp,
    ) -> AppResult<CustomerTokenRecord> {
        self.create_customer_link(vm_id, token_hash, scopes, None, expires_at)
    }

    pub fn create_customer_link(
        &self,
        vm_id: &str,
        token_hash: &[u8; 32],
        scopes: &[String],
        bound_ip: Option<&str>,
        expires_at: Timestamp,
    ) -> AppResult<CustomerTokenRecord> {
        let now = unix_now();
        if expires_at <= now {
            return Err(AppError::Validation(
                "customer token expiry must be in the future".into(),
            ));
        }
        let bound_ip = canonical_optional_ip(bound_ip, None)?;
        let id = Uuid::new_v4().to_string();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO customer_tokens(
                    id, vm_id, token_hash, scopes_json, bound_ip, created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    vm_id,
                    token_hash.as_slice(),
                    json_string(scopes)?,
                    bound_ip,
                    now,
                    expires_at,
                ],
            )?;
            query_customer_token(connection, &id)?.ok_or_else(|| AppError::NotFound("customer token".into()))
        })
    }

    /// Exchange the one-time `/status/<token>` URL for a different random
    /// browser cookie. `session_ttl_seconds` is capped at one hour and can never
    /// extend beyond the original link expiry.
    pub fn exchange_customer_link(
        &self,
        link_hash: &[u8; 32],
        session_hash: &[u8; 32],
        source_ip: Option<&str>,
        now: Timestamp,
        session_ttl_seconds: u64,
    ) -> AppResult<Option<CustomerTokenRecord>> {
        if session_ttl_seconds == 0 {
            return Err(AppError::Validation(
                "customer session TTL must be greater than zero".into(),
            ));
        }
        let ttl = i64::try_from(session_ttl_seconds.min(3600)).unwrap_or(3600);
        let source_ip = canonical_optional_ip(source_ip, None)?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let link: Option<(String, Option<String>, Timestamp)> = transaction
                .query_row(
                    "SELECT id, bound_ip, expires_at FROM customer_tokens
                     WHERE token_hash = ?1 AND consumed_at IS NULL AND revoked_at IS NULL
                       AND expires_at > ?2",
                    params![link_hash.as_slice(), now],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((id, bound_ip, link_expires_at)) = link else {
                return Ok(None);
            };
            if bound_ip.is_some() && bound_ip != source_ip {
                return Ok(None);
            }
            let session_expires_at = link_expires_at.min(now.saturating_add(ttl));
            let changed = transaction.execute(
                "UPDATE customer_tokens
                 SET session_hash = ?2, consumed_at = ?3, session_expires_at = ?4,
                     last_used_at = ?3
                 WHERE id = ?1 AND consumed_at IS NULL",
                params![id, session_hash.as_slice(), now, session_expires_at],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            query_customer_token(transaction, &id)
        })
    }

    pub fn authenticate_customer_session(
        &self,
        session_hash: &[u8; 32],
        source_ip: Option<&str>,
        now: Timestamp,
    ) -> AppResult<Option<CustomerTokenRecord>> {
        let source_ip = canonical_optional_ip(source_ip, None)?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let token = transaction
                .query_row(
                    "SELECT id, vm_id, scopes_json, bound_ip, created_at, expires_at,
                            consumed_at, session_expires_at, last_used_at, revoked_at
                     FROM customer_tokens
                     WHERE session_hash = ?1 AND session_expires_at > ?2
                       AND revoked_at IS NULL
                       AND (bound_ip IS NULL OR bound_ip = ?3)",
                    params![session_hash.as_slice(), now, source_ip],
                    row_to_customer_token,
                )
                .optional()?;
            if token.is_some() {
                transaction.execute(
                    "UPDATE customer_tokens SET last_used_at = ?2 WHERE session_hash = ?1",
                    params![session_hash.as_slice(), now],
                )?;
            }
            Ok(token)
        })
    }

    pub fn list_customer_tokens(&self, vm_id: &str) -> AppResult<Vec<CustomerTokenRecord>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, vm_id, scopes_json, bound_ip, created_at, expires_at,
                        consumed_at, session_expires_at, last_used_at, revoked_at
                 FROM customer_tokens
                 WHERE vm_id = ?1 AND revoked_at IS NULL AND expires_at > ?2
                 ORDER BY created_at DESC",
            )?;
            let rows = statement.query_map(params![vm_id, unix_now()], row_to_customer_token)?;
            collect_rows(rows)
        })
    }

    pub fn revoke_customer_token_for_vm(&self, vm_id: &str, id: &str, now: Timestamp) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE customer_tokens
                 SET revoked_at = COALESCE(revoked_at, ?3)
                 WHERE id = ?2 AND vm_id = ?1",
                    params![vm_id, id, now],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "customer token")
    }

    pub fn revoke_customer_session(&self, session_hash: &[u8; 32], now: Timestamp) -> AppResult<usize> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE customer_tokens
                     SET revoked_at = COALESCE(revoked_at, ?2)
                     WHERE session_hash = ?1 AND revoked_at IS NULL",
                    params![session_hash.as_slice(), now],
                )
                .map_err(Into::into)
        })
    }

    pub fn create_vnc_link(
        &self,
        vm_id: &str,
        token_hash: &[u8; 32],
        bound_ip: Option<&str>,
        created_at: Timestamp,
    ) -> AppResult<VncTokenRecord> {
        // The externally visible VNC contract is intentionally fixed at ten minutes.
        let expires_at = created_at + 600;
        let bound_ip = canonical_optional_ip(bound_ip, None)?;
        let id = Uuid::new_v4().to_string();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO vnc_tokens(
                    id, vm_id, token_hash, bound_ip, created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, vm_id, token_hash.as_slice(), bound_ip, created_at, expires_at,],
            )?;
            query_vnc_token(connection, &id)?.ok_or_else(|| AppError::NotFound("VNC token".into()))
        })
    }

    /// Atomically consume a one-time URL token and bind a separately random
    /// browser cookie to the link's remaining absolute ten-minute lifetime.
    pub fn exchange_vnc_link(
        &self,
        link_hash: &[u8; 32],
        session_hash: &[u8; 32],
        source_ip: Option<&str>,
        now: Timestamp,
    ) -> AppResult<Option<VncTokenRecord>> {
        let source_ip = canonical_optional_ip(source_ip, None)?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let id_and_bound: Option<(String, Option<String>, Timestamp)> = transaction
                .query_row(
                    "SELECT id, bound_ip, expires_at FROM vnc_tokens
                     WHERE token_hash = ?1 AND consumed_at IS NULL AND revoked_at IS NULL
                       AND expires_at > ?2",
                    params![link_hash.as_slice(), now],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((id, bound_ip, expires_at)) = id_and_bound else {
                return Ok(None);
            };
            if bound_ip.is_some() && bound_ip != source_ip {
                return Ok(None);
            }
            let changed = transaction.execute(
                "UPDATE vnc_tokens
                 SET session_hash = ?2, consumed_at = ?3, session_expires_at = ?4
                 WHERE id = ?1 AND consumed_at IS NULL",
                params![id, session_hash.as_slice(), now, expires_at],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            query_vnc_token(transaction, &id)
        })
    }

    pub fn authenticate_vnc_session(
        &self,
        session_hash: &[u8; 32],
        source_ip: Option<&str>,
        now: Timestamp,
    ) -> AppResult<Option<VncTokenRecord>> {
        let source_ip = canonical_optional_ip(source_ip, None)?;
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT id, vm_id, created_at, expires_at, consumed_at,
                            session_expires_at, bound_ip, revoked_at
                     FROM vnc_tokens
                     WHERE session_hash = ?1 AND session_expires_at > ?2
                       AND revoked_at IS NULL
                       AND (bound_ip IS NULL OR bound_ip = ?3)",
                    params![session_hash.as_slice(), now, source_ip],
                    row_to_vnc_token,
                )
                .optional()
                .map_err(Into::into)
        })
    }

    pub fn revoke_vm_vnc_tokens(&self, vm_id: &str, now: Timestamp) -> AppResult<usize> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE vnc_tokens SET revoked_at = COALESCE(revoked_at, ?2)
                     WHERE vm_id = ?1",
                    params![vm_id, now],
                )
                .map_err(Into::into)
        })
    }

    pub fn revoke_vnc_session(&self, session_hash: &[u8; 32], now: Timestamp) -> AppResult<usize> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE vnc_tokens
                     SET revoked_at = COALESCE(revoked_at, ?2)
                     WHERE session_hash = ?1 AND revoked_at IS NULL",
                    params![session_hash.as_slice(), now],
                )
                .map_err(Into::into)
        })
    }

    pub fn prune_expired_tokens(&self, now: Timestamp) -> AppResult<(usize, usize)> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let customer = transaction.execute(
                "DELETE FROM customer_tokens
                 WHERE COALESCE(session_expires_at, expires_at) <= ?1 OR revoked_at IS NOT NULL",
                [now],
            )?;
            let vnc = transaction.execute(
                "DELETE FROM vnc_tokens
                 WHERE COALESCE(session_expires_at, expires_at) <= ?1 OR revoked_at IS NOT NULL",
                [now],
            )?;
            Ok((customer, vnc))
        })
    }

    // --- Durable jobs ---------------------------------------------------------

    pub fn enqueue_job(&self, request: &NewJob) -> AppResult<Job> {
        validate_non_empty("job kind", &request.kind)?;
        let now = unix_now();
        let run_after = request.run_after.unwrap_or(now);
        let max_attempts = request.max_attempts.max(1);
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            if let Some(key) = request.idempotency_key.as_deref() {
                if let Some(existing) = query_job_by_idempotency(transaction, key)? {
                    if existing.kind != request.kind
                        || existing.vm_id != request.vm_id
                        || existing.payload != request.payload
                    {
                        return Err(AppError::Conflict(
                            "idempotency key was already used for a different request".into(),
                        ));
                    }
                    return Ok(existing);
                }
            }
            let id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT INTO jobs(
                    id, kind, vm_id, status, payload_json, idempotency_key,
                    max_attempts, run_after, actor_type, actor_id, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'queued', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    id,
                    request.kind,
                    request.vm_id,
                    json_string(&request.payload)?,
                    request.idempotency_key,
                    i64::from(max_attempts),
                    run_after,
                    request.actor_type,
                    request.actor_id,
                    now,
                ],
            )?;
            query_job(transaction, &id)?.ok_or_else(|| AppError::NotFound("job".into()))
        })
    }

    /// Queue at most one active Guest Tools bootstrap for a VM and rotation.
    /// Power reconciliation and a provisioning parent can race; returning the
    /// already queued/running job prevents a later duplicate from reporting a
    /// false failure after the first job promotes the generation.
    pub fn enqueue_guest_tools_bootstrap_job(&self, request: &NewJob) -> AppResult<Job> {
        if request.kind != "vm.guest_tools.bootstrap" {
            return Err(AppError::Validation(
                "Guest Tools bootstrap transaction requires a vm.guest_tools.bootstrap job"
                    .into(),
            ));
        }
        let vm_id = request.vm_id.as_deref().ok_or_else(|| {
            AppError::Validation("Guest Tools bootstrap job requires vm_id".into())
        })?;
        let expected_generation = request
            .payload
            .get("expected_generation")
            .and_then(Value::as_str);
        if let Some(generation) = expected_generation {
            validate_guest_tools_rotation_generation(generation)?;
        }
        let now = unix_now();
        let run_after = request.run_after.unwrap_or(now);
        let max_attempts = request.max_attempts.max(1);
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let active: Option<String> = transaction
                .query_row(
                    "SELECT id FROM jobs
                     WHERE kind = 'vm.guest_tools.bootstrap' AND vm_id = ?1
                       AND status IN ('queued', 'running')
                       AND json_extract(payload_json, '$.expected_generation') IS ?2
                     ORDER BY created_at LIMIT 1",
                    params![vm_id, expected_generation],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = active {
                return query_job(transaction, &id)?
                    .ok_or_else(|| AppError::NotFound("job".into()));
            }
            let id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT INTO jobs(
                    id, kind, vm_id, status, payload_json, idempotency_key,
                    max_attempts, run_after, actor_type, actor_id, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'queued', ?4, NULL, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![
                    id,
                    request.kind,
                    request.vm_id,
                    json_string(&request.payload)?,
                    i64::from(max_attempts),
                    run_after,
                    request.actor_type,
                    request.actor_id,
                    now,
                ],
            )?;
            query_job(transaction, &id)?.ok_or_else(|| AppError::NotFound("job".into()))
        })
    }

    /// Queue one destructive delete per VM. Repeated requests return the
    /// existing active operation so double-clicks cannot create follow-up jobs
    /// that fail after the first job has removed the VM record.
    pub fn enqueue_delete_job(&self, request: &NewJob) -> AppResult<Job> {
        if request.kind != "vm.delete" {
            return Err(AppError::Validation(
                "delete transaction requires a vm.delete job".into(),
            ));
        }
        let vm_id = request
            .vm_id
            .as_deref()
            .ok_or_else(|| AppError::Validation("delete job requires vm_id".into()))?;
        let now = unix_now();
        let run_after = request.run_after.unwrap_or(now);
        let max_attempts = request.max_attempts.max(1);
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            if let Some(key) = request.idempotency_key.as_deref() {
                if let Some(existing) = query_job_by_idempotency(transaction, key)? {
                    if existing.kind != request.kind
                        || existing.vm_id != request.vm_id
                        || existing.payload != request.payload
                    {
                        return Err(AppError::Conflict(
                            "idempotency key was already used for a different request".into(),
                        ));
                    }
                    return Ok(existing);
                }
            }
            let active: Option<String> = transaction
                .query_row(
                    "SELECT id FROM jobs
                     WHERE kind = 'vm.delete' AND vm_id = ?1
                       AND status IN ('queued', 'running')
                     ORDER BY created_at LIMIT 1",
                    [vm_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = active {
                return query_job(transaction, &id)?.ok_or_else(|| AppError::NotFound("job".into()));
            }
            let id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT INTO jobs(
                    id, kind, vm_id, status, payload_json, idempotency_key,
                    max_attempts, run_after, actor_type, actor_id, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'queued', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    id,
                    request.kind,
                    request.vm_id,
                    json_string(&request.payload)?,
                    request.idempotency_key,
                    i64::from(max_attempts),
                    run_after,
                    request.actor_type,
                    request.actor_id,
                    now,
                ],
            )?;
            query_job(transaction, &id)?.ok_or_else(|| AppError::NotFound("job".into()))
        })
    }

    /// Queue a destructive reinstall and optionally stage a new encrypted
    /// credential in the private job payload. The credential is committed (or
    /// cleared for a manual install) only after the hypervisor succeeds. An
    /// idempotent replay returns the original job without mutating state twice.
    pub fn enqueue_reinstall_job(
        &self,
        request: &NewJob,
        password_envelope: Option<&str>,
        desired_state: VmState,
    ) -> AppResult<Job> {
        if request.kind != "vm.reinstall" {
            return Err(AppError::Validation(
                "reinstall transaction requires a vm.reinstall job".into(),
            ));
        }
        let vm_id = request
            .vm_id
            .as_deref()
            .ok_or_else(|| AppError::Validation("reinstall job requires vm_id".into()))?;
        let now = unix_now();
        let run_after = request.run_after.unwrap_or(now);
        let max_attempts = request.max_attempts.max(1);
        if request.payload.get(STAGED_PASSWORD_ENVELOPE_FIELD).is_some() {
            return Err(AppError::Validation(
                "reinstall payload contains a reserved field".into(),
            ));
        }
        if password_envelope.is_some()
            && request
                .payload
                .get("clear_password_after_success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            return Err(AppError::Validation(
                "manual reinstall cannot stage a guest password".into(),
            ));
        }
        let mut job_payload = request.payload.clone();
        if let Some(envelope) = password_envelope {
            validate_non_empty("password envelope", envelope)?;
            let object = job_payload
                .as_object_mut()
                .ok_or_else(|| AppError::Validation("reinstall job payload must be an object".into()))?;
            object.insert(
                STAGED_PASSWORD_ENVELOPE_FIELD.into(),
                Value::String(envelope.to_owned()),
            );
        }
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            if let Some(key) = request.idempotency_key.as_deref() {
                if let Some(existing) = query_job_by_idempotency(transaction, key)? {
                    if existing.kind != request.kind
                        || existing.vm_id != request.vm_id
                        || payload_without_staged_password(&existing.payload) != request.payload
                    {
                        return Err(AppError::Conflict(
                            "idempotency key was already used for a different request".into(),
                        ));
                    }
                    return Ok(existing);
                }
            }
            let active: Option<String> = transaction
                .query_row(
                    "SELECT id FROM jobs
                     WHERE kind = 'vm.reinstall' AND vm_id = ?1
                       AND status IN ('queued', 'running')
                     ORDER BY created_at LIMIT 1",
                    [vm_id],
                    |row| row.get(0),
                )
                .optional()?;
            if active.is_some() {
                return Err(AppError::Conflict(
                    "a reinstall is already queued or running for this VM".into(),
                ));
            }
            let changed = transaction.execute(
                "UPDATE vms
                 SET state = 'reinstalling', desired_state = ?2, updated_at = ?3
                 WHERE id = ?1",
                params![vm_id, desired_state.as_str(), now],
            )?;
            require_changed(changed, "VM")?;
            let id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT INTO jobs(
                    id, kind, vm_id, status, payload_json, idempotency_key,
                    max_attempts, run_after, actor_type, actor_id, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'queued', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    id,
                    request.kind,
                    request.vm_id,
                    json_string(&job_payload)?,
                    request.idempotency_key,
                    i64::from(max_attempts),
                    run_after,
                    request.actor_type,
                    request.actor_id,
                    now,
                ],
            )?;
            query_job(transaction, &id)?.ok_or_else(|| AppError::NotFound("job".into()))
        })
    }

    pub fn get_job(&self, id: &str) -> AppResult<Option<Job>> {
        self.with_connection(|connection| query_job(connection, id))
    }

    pub fn job_by_idempotency_key(&self, key: &str) -> AppResult<Option<Job>> {
        self.with_connection(|connection| query_job_by_idempotency(connection, key))
    }

    pub fn list_jobs(
        &self,
        status: Option<JobStatus>,
        vm_id: Option<&str>,
        limit: usize,
    ) -> AppResult<Vec<Job>> {
        let limit = bounded_limit(limit, 1000);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, kind, vm_id, status, payload_json, result_json, error,
                        progress_percent, idempotency_key, attempts, max_attempts, run_after,
                        locked_by, locked_at, actor_type, actor_id, created_at, updated_at,
                        finished_at
                 FROM jobs
                 WHERE (?1 IS NULL OR status = ?1) AND (?2 IS NULL OR vm_id = ?2)
                 ORDER BY created_at DESC LIMIT ?3",
            )?;
            let rows =
                statement.query_map(params![status.map(JobStatus::as_str), vm_id, limit], row_to_job)?;
            collect_rows(rows)
        })
    }

    pub fn claim_next_job(&self, worker: &str, now: Timestamp) -> AppResult<Option<Job>> {
        validate_non_empty("worker name", worker)?;
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let id: Option<String> = transaction
                .query_row(
                    "SELECT id FROM jobs
                     WHERE status = 'queued' AND run_after <= ?1 AND attempts < max_attempts
                     ORDER BY run_after, created_at LIMIT 1",
                    [now],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(id) = id else {
                return Ok(None);
            };
            let changed = transaction.execute(
                "UPDATE jobs
                 SET status = 'running', attempts = attempts + 1, locked_by = ?2,
                     locked_at = ?3, updated_at = ?3
                 WHERE id = ?1 AND status = 'queued'",
                params![id, worker, now],
            )?;
            if changed == 0 {
                return Ok(None);
            }
            query_job(transaction, &id)
        })
    }

    /// Resolve jobs left locked by a previous process. Safe retries are
    /// re-queued only when their declared attempt budget remains; exhausted
    /// jobs become terminal instead of remaining `running` forever. The sole
    /// exception is a delete whose VM foreign key was cleared by its final DB
    /// commit: its payload receives one cleanup-verification finalizer attempt.
    pub fn recover_interrupted_jobs(&self, now: Timestamp) -> AppResult<(usize, usize)> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let terminal_reinstall_ids = {
                let mut statement = transaction.prepare(
                    "SELECT id FROM jobs
                     WHERE status = 'running' AND attempts >= max_attempts
                       AND kind = 'vm.reinstall'",
                )?;
                let ids = statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                ids
            };
            for id in terminal_reinstall_ids {
                if let Some(job) = query_job(transaction, &id)? {
                    cleanup_unarmed_reinstall_guest_tools(transaction, &job, now)?;
                }
            }
            // Deleting the VM row sets jobs.vm_id to NULL. If the worker dies
            // before `finish_job`, the immutable private target fields still
            // let the worker re-check domain/seed absence. Grant exactly one
            // finalizer attempt even when the ordinary budget was exhausted;
            // a real cleanup error becomes terminal, while another process
            // crash can be recovered the same way on the next startup.
            let delete_finalizers = transaction.execute(
                "UPDATE jobs
                 SET status = 'queued', locked_by = NULL, locked_at = NULL,
                     run_after = ?1, updated_at = ?1,
                     max_attempts = MAX(max_attempts, attempts + 1)
                 WHERE status = 'running' AND kind = 'vm.delete' AND vm_id IS NULL
                   AND json_type(payload_json, '$.target_vm_id') = 'text'
                   AND json_type(payload_json, '$.target_vm_name') = 'text'",
                [now],
            )?;
            let ordinary_requeued = transaction.execute(
                "UPDATE jobs
                 SET status = 'queued', locked_by = NULL, locked_at = NULL,
                     run_after = ?1, updated_at = ?1
                 WHERE status = 'running' AND attempts < max_attempts",
                [now],
            )?;
            let requeued = delete_finalizers.saturating_add(ordinary_requeued);
            // A process can die after staging a rotation but before inserting
            // its reinstall job. Such an unarmed generation cannot have
            // reached published media and is safe to clear. Any generation
            // referenced by a queued/requeued job, and every armed generation,
            // is retained.
            transaction.execute(
                "UPDATE vm_guest_tools
                 SET pending_secret_envelope = NULL,
                     pending_platform = NULL,
                     pending_provisioner = NULL,
                     pending_desired_version = NULL,
                     pending_generation = NULL,
                     pending_installed = 0,
                     updated_at = ?1
                 WHERE pending_installed = 0
                   AND pending_generation IS NOT NULL
                   AND NOT EXISTS (
                    SELECT 1 FROM jobs
                    WHERE kind = 'vm.reinstall'
                      AND status IN ('queued', 'running')
                      AND vm_id = vm_guest_tools.vm_id
                      AND json_extract(
                            payload_json,
                            '$._guest_tools_rotation_generation'
                          ) = vm_guest_tools.pending_generation
                 )",
                [now],
            )?;
            transaction.execute(
                "UPDATE vms
                 SET state = 'error', updated_at = ?1
                 WHERE id IN (
                    SELECT vm_id FROM jobs
                    WHERE status = 'running' AND attempts >= max_attempts
                      AND kind IN ('vm.create', 'vm.reinstall')
                      AND vm_id IS NOT NULL
                 )",
                [now],
            )?;
            transaction.execute(
                "UPDATE snapshots
                 SET state = 'error', updated_at = ?1, completed_at = ?1,
                     metadata_json = json_set(
                        metadata_json,
                        '$.error',
                        'worker interrupted before completion'
                     )
                 WHERE id IN (
                    SELECT json_extract(payload_json, '$.snapshot_id') FROM jobs
                    WHERE status = 'running' AND attempts >= max_attempts
                      AND kind = 'vm.snapshot.create'
                 )",
                [now],
            )?;
            transaction.execute(
                "UPDATE vm_guest_tools
                 SET status = 'error',
                     last_error = 'reinstall worker interrupted after Guest Tools media was armed',
                     updated_at = ?1
                 WHERE pending_installed = 1 AND EXISTS (
                    SELECT 1 FROM jobs
                    WHERE status = 'running' AND attempts >= max_attempts
                      AND kind = 'vm.reinstall'
                      AND vm_id = vm_guest_tools.vm_id
                      AND json_extract(
                            payload_json,
                            '$._guest_tools_rotation_generation'
                          ) = vm_guest_tools.pending_generation
                 )",
                [now],
            )?;
            transaction.execute(
                "UPDATE vm_guest_tools
                 SET status = 'error',
                     last_error = 'VM creation worker interrupted before Guest Tools bootstrap',
                     updated_at = ?1
                 WHERE EXISTS (
                    SELECT 1 FROM jobs
                    WHERE status = 'running' AND attempts >= max_attempts
                      AND kind = 'vm.create'
                      AND vm_id = vm_guest_tools.vm_id
                 )",
                [now],
            )?;
            transaction.execute(
                "UPDATE vm_guest_tools
                 SET status = 'error',
                     last_error = 'Guest Tools bootstrap worker interrupted before completion',
                     updated_at = ?1
                 WHERE EXISTS (
                    SELECT 1 FROM jobs
                    WHERE status = 'running' AND attempts >= max_attempts
                      AND kind = 'vm.guest_tools.bootstrap'
                      AND vm_id = vm_guest_tools.vm_id
                      AND (
                        (vm_guest_tools.pending_installed = 1 AND json_extract(
                            payload_json, '$.expected_generation'
                         ) = vm_guest_tools.pending_generation)
                        OR
                        (vm_guest_tools.pending_installed = 0 AND json_extract(
                            payload_json, '$.expected_generation'
                         ) IS NULL AND NOT (
                            vm_guest_tools.status = 'ready'
                            AND vm_guest_tools.last_seen_at IS NOT NULL
                            AND jobs.locked_at IS NOT NULL
                            AND vm_guest_tools.last_seen_at >= jobs.locked_at
                         ))
                      )
                 )",
                [now],
            )?;
            let failed = transaction.execute(
                "UPDATE jobs
                 SET status = 'failed', error = 'worker interrupted before completion',
                     locked_by = NULL, locked_at = NULL, updated_at = ?1, finished_at = ?1,
                     payload_json = json_remove(payload_json, '$._staged_password_envelope')
                 WHERE status = 'running' AND attempts >= max_attempts",
                [now],
            )?;
            Ok((requeued, failed))
        })
    }

    pub fn update_job_progress(&self, id: &str, progress_percent: f64) -> AppResult<()> {
        if !(0.0..=100.0).contains(&progress_percent) {
            return Err(AppError::Validation(
                "job progress must be between 0 and 100".into(),
            ));
        }
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE jobs SET progress_percent = ?2, updated_at = ?3
                 WHERE id = ?1 AND status = 'running'",
                    params![id, progress_percent, unix_now()],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "running job")
    }

    pub fn finish_job(&self, id: &str, result: &Value, now: Timestamp) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE jobs
                 SET status = 'succeeded', result_json = ?2, error = NULL,
                     progress_percent = 100, locked_by = NULL, locked_at = NULL,
                     updated_at = ?3, finished_at = ?3,
                     payload_json = json_remove(payload_json, '$._staged_password_envelope')
                 WHERE id = ?1 AND status = 'running'",
                    params![id, json_string(result)?, now],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "running job")
    }

    pub fn fail_job(
        &self,
        id: &str,
        error: &str,
        retry_at: Option<Timestamp>,
        now: Timestamp,
    ) -> AppResult<Job> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let job = query_job(transaction, id)?.ok_or_else(|| AppError::NotFound("job".into()))?;
            if job.status != JobStatus::Running {
                return Err(AppError::Conflict("job is not running".into()));
            }
            let retry = retry_at.is_some() && job.attempts < job.max_attempts;
            let status = if retry { "queued" } else { "failed" };
            let finished_at = if retry { None } else { Some(now) };
            if !retry {
                cleanup_unarmed_reinstall_guest_tools(transaction, &job, now)?;
            }
            transaction.execute(
                "UPDATE jobs
                 SET status = ?2, error = ?3, run_after = COALESCE(?4, run_after),
                     locked_by = NULL, locked_at = NULL, updated_at = ?5, finished_at = ?6,
                     payload_json = CASE WHEN ?7 = 1 THEN payload_json
                         ELSE json_remove(payload_json, '$._staged_password_envelope') END
                 WHERE id = ?1",
                params![id, status, error, retry_at, now, finished_at, bool_i64(retry)],
            )?;
            query_job(transaction, id)?.ok_or_else(|| AppError::NotFound("job".into()))
        })
    }

    pub fn cancel_job(&self, id: &str, now: Timestamp) -> AppResult<()> {
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let job = query_job(transaction, id)?.ok_or_else(|| AppError::NotFound("job".into()))?;
            if job.status != JobStatus::Queued {
                return Err(AppError::Conflict("only a queued job can be cancelled".into()));
            }
            let changed = transaction.execute(
                "UPDATE jobs
                 SET status = 'cancelled', locked_by = NULL, locked_at = NULL,
                     updated_at = ?2, finished_at = ?2,
                     payload_json = json_remove(payload_json, '$._staged_password_envelope')
                 WHERE id = ?1 AND status = 'queued'",
                params![id, now],
            )?;
            require_changed(changed, "queued job")?;

            match (job.kind.as_str(), job.vm_id.as_deref()) {
                ("vm.create", Some(vm_id)) => {
                    // A queued create cannot yet have a hypervisor domain. Drop
                    // its provisional database row. Release addresses
                    // explicitly before the delete: databases upgraded from a
                    // release that predates the defensive delete trigger still
                    // have the `used => assigned_vm_id` CHECK, so relying on
                    // `ON DELETE SET NULL` would abort the transaction.
                    transaction.execute(
                        "UPDATE ip_addresses
                         SET status = 'free', assigned_vm_id = NULL, primary_for_vm = 0,
                             updated_at = ?2
                         WHERE assigned_vm_id = ?1",
                        params![vm_id, now],
                    )?;
                    transaction.execute(
                        "DELETE FROM vms
                         WHERE id = ?1 AND state = 'creating' AND libvirt_uuid IS NULL",
                        [vm_id],
                    )?;
                }
                ("vm.reinstall", Some(vm_id)) => {
                    cleanup_unarmed_reinstall_guest_tools(transaction, &job, now)?;
                    // Enqueueing a reinstall is the only operation that changes
                    // VM state before the worker claims it. Inventory sampling
                    // will replace Unknown with the authoritative power state.
                    transaction.execute(
                        "UPDATE vms SET state = 'unknown', updated_at = ?2
                         WHERE id = ?1 AND state = 'reinstalling'",
                        params![vm_id, now],
                    )?;
                }
                ("vm.snapshot.create", _) => {
                    if let Some(snapshot_id) = job.payload.get("snapshot_id").and_then(Value::as_str) {
                        transaction.execute(
                            "UPDATE snapshots
                             SET state = 'error', updated_at = ?2, completed_at = ?2,
                                 metadata_json = json_set(metadata_json, '$.error', 'job cancelled')
                             WHERE id = ?1 AND state = 'creating'",
                            params![snapshot_id, now],
                        )?;
                    }
                }
                _ => {}
            }
            Ok(())
        })
    }

    // --- Snapshots ------------------------------------------------------------

    pub fn create_snapshot(
        &self,
        vm_id: &str,
        name: &str,
        description: &str,
        memory_included: bool,
        metadata: &Value,
    ) -> AppResult<Snapshot> {
        validate_non_empty("snapshot name", name)?;
        let id = Uuid::new_v4().to_string();
        let now = unix_now();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO snapshots(
                    id, vm_id, name, description, state, memory_included,
                    metadata_json, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, 'creating', ?5, ?6, ?7, ?7)",
                params![
                    id,
                    vm_id,
                    name.trim(),
                    description,
                    bool_i64(memory_included),
                    json_string(metadata)?,
                    now,
                ],
            )?;
            query_snapshot(connection, &id)?.ok_or_else(|| AppError::NotFound("snapshot".into()))
        })
    }

    pub fn update_snapshot(
        &self,
        id: &str,
        state: SnapshotState,
        disk_path: Option<&str>,
        size_bytes: Option<u64>,
        metadata: Option<&Value>,
    ) -> AppResult<Snapshot> {
        let now = unix_now();
        let completed_at = matches!(state, SnapshotState::Ready | SnapshotState::Error).then_some(now);
        let changed = self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE snapshots
                 SET state = ?2,
                     disk_path = COALESCE(?3, disk_path),
                     size_bytes = COALESCE(?4, size_bytes),
                     metadata_json = COALESCE(?5, metadata_json),
                     updated_at = ?6,
                     completed_at = COALESCE(?7, completed_at)
                 WHERE id = ?1",
                    params![
                        id,
                        state.as_str(),
                        disk_path,
                        optional_i64(size_bytes, "snapshot size")?,
                        metadata.map(json_string).transpose()?,
                        now,
                        completed_at,
                    ],
                )
                .map_err(Into::into)
        })?;
        require_changed(changed, "snapshot")?;
        self.with_connection(|connection| {
            query_snapshot(connection, id)?.ok_or_else(|| AppError::NotFound("snapshot".into()))
        })
    }

    pub fn list_snapshots(&self, vm_id: &str) -> AppResult<Vec<Snapshot>> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, vm_id, name, description, state, disk_path, size_bytes,
                        memory_included, metadata_json, created_at, updated_at, completed_at
                 FROM snapshots WHERE vm_id = ?1 ORDER BY created_at DESC",
            )?;
            let rows = statement.query_map([vm_id], row_to_snapshot)?;
            collect_rows(rows)
        })
    }

    pub fn delete_snapshot_record(&self, id: &str) -> AppResult<()> {
        let changed = self.with_connection(|connection| {
            connection
                .execute("DELETE FROM snapshots WHERE id = ?1", [id])
                .map_err(Into::into)
        })?;
        require_changed(changed, "snapshot")
    }

    // --- Append-only audit trail ---------------------------------------------

    pub fn append_audit(&self, event: &NewAuditEvent) -> AppResult<AuditEvent> {
        validate_non_empty("audit action", &event.action)?;
        validate_non_empty("audit resource type", &event.resource_type)?;
        let occurred_at = unix_now();
        self.with_connection(|connection| {
            connection.execute(
                "INSERT INTO audit_log(
                    occurred_at, actor_type, actor_id, action, resource_type, resource_id,
                    request_id, source_ip, user_agent, success, details_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    occurred_at,
                    event.actor_type,
                    event.actor_id,
                    event.action,
                    event.resource_type,
                    event.resource_id,
                    event.request_id,
                    event.source_ip,
                    event.user_agent,
                    bool_i64(event.success),
                    json_string(&event.details)?,
                ],
            )?;
            let id = connection.last_insert_rowid();
            connection
                .query_row(
                    "SELECT id, occurred_at, actor_type, actor_id, action, resource_type,
                            resource_id, request_id, source_ip, user_agent, success, details_json
                     FROM audit_log WHERE id = ?1",
                    [id],
                    row_to_audit,
                )
                .map_err(Into::into)
        })
    }

    /// Import one terminal, root-helper update status into the append-only
    /// application audit log. The request UUID ledger and audit insert share a
    /// transaction, so concurrent status readers cannot create duplicates.
    pub fn import_update_status_audit(
        &self,
        request_id: &str,
        outcome: &str,
        event: &NewAuditEvent,
    ) -> AppResult<bool> {
        Uuid::parse_str(request_id)
            .map_err(|_| AppError::Validation("update request ID is invalid".into()))?;
        if !matches!(
            outcome,
            "succeeded" | "failed" | "rolled_back" | "needs_intervention"
        ) {
            return Err(AppError::Validation("update outcome is not terminal".into()));
        }
        validate_non_empty("audit action", &event.action)?;
        validate_non_empty("audit resource type", &event.resource_type)?;
        if event.resource_id.as_deref() != Some(request_id) {
            return Err(AppError::Validation(
                "update audit resource must match its request ID".into(),
            ));
        }
        if event.request_id.as_deref() != Some(request_id) {
            return Err(AppError::Validation(
                "update audit correlation ID must match its request ID".into(),
            ));
        }
        if event.success != (outcome == "succeeded") {
            return Err(AppError::Validation(
                "update audit success flag does not match its terminal outcome".into(),
            ));
        }
        let now = unix_now();
        self.with_transaction(TransactionBehavior::Immediate, |transaction| {
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO update_status_audit_imports(
                    request_id, outcome, imported_at
                 ) VALUES (?1, ?2, ?3)",
                params![request_id, outcome, now],
            )?;
            if inserted == 0 {
                let stored_outcome: String = transaction.query_row(
                    "SELECT outcome FROM update_status_audit_imports WHERE request_id = ?1",
                    [request_id],
                    |row| row.get(0),
                )?;
                if stored_outcome != outcome {
                    return Err(AppError::Conflict(
                        "terminal update status changed after it was audited".into(),
                    ));
                }
                return Ok(false);
            }
            transaction.execute(
                "INSERT INTO audit_log(
                    occurred_at, actor_type, actor_id, action, resource_type, resource_id,
                    request_id, source_ip, user_agent, success, details_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    now,
                    event.actor_type,
                    event.actor_id,
                    event.action,
                    event.resource_type,
                    event.resource_id,
                    event.request_id,
                    event.source_ip,
                    event.user_agent,
                    bool_i64(event.success),
                    json_string(&event.details)?,
                ],
            )?;
            Ok(true)
        })
    }

    pub fn list_audit(
        &self,
        before_id: Option<i64>,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        limit: usize,
    ) -> AppResult<Vec<AuditEvent>> {
        let limit = bounded_limit(limit, 1000);
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, occurred_at, actor_type, actor_id, action, resource_type,
                        resource_id, request_id, source_ip, user_agent, success, details_json
                 FROM audit_log
                 WHERE (?1 IS NULL OR id < ?1)
                   AND (?2 IS NULL OR resource_type = ?2)
                   AND (?3 IS NULL OR resource_id = ?3)
                 ORDER BY id DESC LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![before_id, resource_type, resource_id, limit],
                row_to_audit,
            )?;
            collect_rows(rows)
        })
    }
}

const VM_COLUMNS: &str = "
    id, name, hostname, description, os_family, iso_id, state, desired_state,
    vcpus, memory_mib, disk_gib, disk_format, firmware, machine_type, bridge,
    tap_name, mac_address, network_limit_mbps, traffic_limit_bytes,
    traffic_used_bytes, root_username, guest_agent, autostart, timezone,
    libvirt_uuid, vnc_display, metadata_json, created_at, updated_at
";

pub fn unix_timestamp() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn unix_now() -> Timestamp {
    unix_timestamp()
}

fn query_admin(connection: &Connection, id: &str) -> AppResult<Option<Admin>> {
    connection
        .query_row(
            "SELECT id, username, role, enabled, created_at, updated_at, last_login_at
             FROM admins WHERE id = ?1",
            [id],
            row_to_admin,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_admin(row: &Row<'_>) -> rusqlite::Result<Admin> {
    Ok(Admin {
        id: row.get(0)?,
        username: row.get(1)?,
        role: enum_column(row, 2)?,
        enabled: bool_column(row, 3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        last_login_at: row.get(6)?,
    })
}

fn row_to_admin_session(row: &Row<'_>) -> rusqlite::Result<AdminSession> {
    Ok(AdminSession {
        admin: Admin {
            id: row.get(0)?,
            username: row.get(1)?,
            role: enum_column(row, 2)?,
            enabled: bool_column(row, 3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            last_login_at: row.get(6)?,
        },
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
        last_seen_at: row.get(9)?,
        source_ip: row.get(10)?,
        user_agent: row.get(11)?,
    })
}

fn query_api_key(connection: &Connection, id: &str) -> AppResult<Option<ApiKey>> {
    connection
        .query_row(
            "SELECT id, name, prefix, permissions_json, ip_allowlist_json,
                    created_by, created_at, expires_at, last_used_at, revoked_at
             FROM api_keys WHERE id = ?1",
            [id],
            row_to_api_key,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_api_key(row: &Row<'_>) -> rusqlite::Result<ApiKey> {
    Ok(ApiKey {
        id: row.get(0)?,
        name: row.get(1)?,
        prefix: row.get(2)?,
        permissions: json_column(row, 3)?,
        ip_allowlist: json_column(row, 4)?,
        created_by: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        last_used_at: row.get(8)?,
        revoked_at: row.get(9)?,
    })
}

/// Roll back only the unarmed generation owned by this exact reinstall job.
/// Once `pending_installed` is true, the replacement media or disk may already
/// depend on that key and no terminal/cancellation path is allowed to remove
/// it. Provisional first-time configurations are deleted in the same
/// transaction and only while the exact staged generation is still present.
fn cleanup_unarmed_reinstall_guest_tools(
    transaction: &Transaction<'_>,
    job: &Job,
    now: Timestamp,
) -> AppResult<()> {
    if job.kind != "vm.reinstall" {
        return Ok(());
    }
    let (Some(vm_id), Some(generation)) = (
        job.vm_id.as_deref(),
        job.payload
            .get(STAGED_GUEST_TOOLS_GENERATION_FIELD)
            .and_then(Value::as_str),
    ) else {
        return Ok(());
    };
    if generation.is_empty() || generation.len() > 64 {
        return Ok(());
    }
    let new_configuration = job
        .payload
        .get("guest_tools_new_configuration")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if new_configuration {
        transaction.execute(
            "DELETE FROM vm_guest_tools
             WHERE vm_id = ?1 AND pending_generation = ?2
               AND pending_installed = 0",
            params![vm_id, generation],
        )?;
    } else {
        transaction.execute(
            "UPDATE vm_guest_tools SET
                pending_secret_envelope = NULL,
                pending_platform = NULL,
                pending_provisioner = NULL,
                pending_desired_version = NULL,
                pending_generation = NULL,
                pending_installed = 0,
                updated_at = ?3
             WHERE vm_id = ?1 AND pending_generation = ?2
               AND pending_installed = 0",
            params![vm_id, generation, now],
        )?;
    }
    Ok(())
}

fn query_vm(connection: &Connection, id_or_name: &str) -> AppResult<Option<Vm>> {
    let sql = format!("SELECT {VM_COLUMNS} FROM vms WHERE id = ?1 OR name = ?1 COLLATE NOCASE LIMIT 1");
    connection
        .query_row(&sql, [id_or_name], row_to_vm)
        .optional()
        .map_err(Into::into)
}

fn query_vm_guest_tools(connection: &Connection, vm_id: &str) -> AppResult<Option<VmGuestTools>> {
    connection
        .query_row(
            "SELECT vm_id, enabled, platform, provisioner, desired_version,
                    installed_version, status, last_seen_at, last_error,
                    pending_generation IS NOT NULL, pending_installed,
                    created_at, updated_at
             FROM vm_guest_tools WHERE vm_id = ?1",
            [vm_id],
            |row| {
                Ok(VmGuestTools {
                    vm_id: row.get(0)?,
                    enabled: bool_column(row, 1)?,
                    platform: enum_column(row, 2)?,
                    provisioner: enum_column(row, 3)?,
                    desired_version: row.get(4)?,
                    installed_version: row.get(5)?,
                    status: enum_column(row, 6)?,
                    last_seen_at: row.get(7)?,
                    last_error: row.get(8)?,
                    pending_rotation: bool_column(row, 9)?,
                    pending_installed: bool_column(row, 10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn rotation_generation_conflict(connection: &Connection, vm_id: &str) -> AppError {
    let state = connection
        .query_row(
            "SELECT enabled, pending_generation, pending_installed
             FROM vm_guest_tools WHERE vm_id = ?1",
            [vm_id],
            |row| {
                Ok((
                    bool_column(row, 0)?,
                    row.get::<_, Option<String>>(1)?,
                    bool_column(row, 2)?,
                ))
            },
        )
        .optional();
    match state {
        Err(error) => AppError::Database(error),
        Ok(None) => AppError::NotFound("VM guest-tools configuration".into()),
        Ok(Some((false, _, _))) => AppError::Conflict("Vexa Guest Tools is disabled".into()),
        Ok(Some((true, None, _))) => {
            AppError::Conflict("no Vexa Guest Tools key rotation is pending".into())
        }
        Ok(Some((true, Some(_), false))) => AppError::Conflict(
            "the Vexa Guest Tools key rotation generation does not match or is not installed".into(),
        ),
        Ok(Some((true, Some(_), true))) => {
            AppError::Conflict("the Vexa Guest Tools key rotation generation does not match".into())
        }
    }
}

fn row_to_vm(row: &Row<'_>) -> rusqlite::Result<Vm> {
    Ok(Vm {
        id: row.get(0)?,
        name: row.get(1)?,
        hostname: row.get(2)?,
        description: row.get(3)?,
        os_family: row.get(4)?,
        iso_id: row.get(5)?,
        state: enum_column(row, 6)?,
        desired_state: enum_column(row, 7)?,
        vcpus: checked_u32_column(row, 8)?,
        memory_mib: checked_u64_column(row, 9)?,
        disk_gib: checked_u64_column(row, 10)?,
        disk_format: row.get(11)?,
        firmware: row.get(12)?,
        machine_type: row.get(13)?,
        bridge: row.get(14)?,
        tap_name: row.get(15)?,
        mac_address: row.get(16)?,
        network_limit_mbps: optional_u64_column(row, 17)?,
        traffic_limit_bytes: optional_u64_column(row, 18)?,
        traffic_used_bytes: checked_u64_column(row, 19)?,
        root_username: row.get(20)?,
        guest_agent: bool_column(row, 21)?,
        autostart: bool_column(row, 22)?,
        timezone: row.get(23)?,
        libvirt_uuid: row.get(24)?,
        vnc_display: row.get(25)?,
        metadata: json_column(row, 26)?,
        created_at: row.get(27)?,
        updated_at: row.get(28)?,
    })
}

fn save_vm(connection: &Connection, vm: &Vm) -> AppResult<()> {
    connection.execute(
        "UPDATE vms SET
            hostname = ?2, description = ?3, state = ?4, desired_state = ?5,
            vcpus = ?6, memory_mib = ?7, disk_gib = ?8,
            tap_name = ?9, network_limit_mbps = ?10, traffic_limit_bytes = ?11,
            traffic_used_bytes = ?12, guest_agent = ?13, autostart = ?14,
            timezone = ?15, libvirt_uuid = ?16, vnc_display = ?17,
            metadata_json = ?18, updated_at = ?19
         WHERE id = ?1",
        params![
            vm.id,
            vm.hostname,
            vm.description,
            vm.state.as_str(),
            vm.desired_state.as_str(),
            i64::from(vm.vcpus),
            checked_i64(vm.memory_mib, "memory_mib")?,
            checked_i64(vm.disk_gib, "disk_gib")?,
            vm.tap_name,
            optional_i64(vm.network_limit_mbps, "network_limit_mbps")?,
            optional_i64(vm.traffic_limit_bytes, "traffic_limit_bytes")?,
            checked_i64(vm.traffic_used_bytes, "traffic_used_bytes")?,
            bool_i64(vm.guest_agent),
            bool_i64(vm.autostart),
            vm.timezone,
            vm.libvirt_uuid,
            vm.vnc_display,
            json_string(&vm.metadata)?,
            vm.updated_at,
        ],
    )?;
    Ok(())
}

fn query_ip_pool(connection: &Connection, id: &str) -> AppResult<Option<IpPool>> {
    connection
        .query_row(
            "SELECT id, name, cidr, family, scope, gateway, bridge, vlan_id, mtu,
                    enabled, created_at, updated_at
             FROM ip_pools WHERE id = ?1",
            [id],
            row_to_ip_pool,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_ip_pool(row: &Row<'_>) -> rusqlite::Result<IpPool> {
    Ok(IpPool {
        id: row.get(0)?,
        name: row.get(1)?,
        cidr: row.get(2)?,
        family: family_column(row, 3)?,
        scope: enum_column(row, 4)?,
        gateway: row.get(5)?,
        bridge: row.get(6)?,
        vlan_id: optional_u16_column(row, 7)?,
        mtu: checked_u32_column(row, 8)?,
        enabled: bool_column(row, 9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn query_ip_address(connection: &Connection, address_or_id: &str) -> AppResult<Option<IpAddressRecord>> {
    connection
        .query_row(
            "SELECT id, pool_id, address, family, prefix_length, scope, status, gateway,
                    assigned_vm_id, primary_for_vm, reverse_dns, metadata_json,
                    created_at, updated_at
             FROM ip_addresses WHERE address = ?1 OR id = ?1 LIMIT 1",
            [address_or_id],
            row_to_ip_address,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_ip_address(row: &Row<'_>) -> rusqlite::Result<IpAddressRecord> {
    let prefix = checked_u64_column(row, 4)?;
    Ok(IpAddressRecord {
        id: row.get(0)?,
        pool_id: row.get(1)?,
        address: row.get(2)?,
        family: family_column(row, 3)?,
        prefix_length: u8::try_from(prefix)
            .map_err(|_| conversion_error(4, Type::Integer, "prefix length is out of range"))?,
        scope: enum_column(row, 5)?,
        status: enum_column(row, 6)?,
        gateway: row.get(7)?,
        assigned_vm_id: row.get(8)?,
        primary_for_vm: bool_column(row, 9)?,
        reverse_dns: row.get(10)?,
        metadata: json_column(row, 11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn query_dns_servers(
    connection: &Connection,
    pool_id: Option<&str>,
    vm_id: Option<&str>,
) -> AppResult<Vec<DnsServer>> {
    let mut statement = connection.prepare(
        "SELECT id, address, family, priority, pool_id, vm_id
         FROM dns_servers
         WHERE ((?1 IS NULL AND pool_id IS NULL) OR pool_id = ?1)
           AND ((?2 IS NULL AND vm_id IS NULL) OR vm_id = ?2)
         ORDER BY priority, id",
    )?;
    let rows = statement.query_map(params![pool_id, vm_id], |row| {
        Ok(DnsServer {
            id: row.get(0)?,
            address: row.get(1)?,
            family: family_column(row, 2)?,
            priority: row.get(3)?,
            pool_id: row.get(4)?,
            vm_id: row.get(5)?,
        })
    })?;
    collect_rows(rows)
}

fn query_vm_network_security(
    connection: &Connection,
    vm_id: &str,
) -> AppResult<Option<VmNetworkSecurity>> {
    connection
        .query_row(
            "SELECT vm_id, firewall_enabled, ddos_enabled, default_ingress_action,
                    default_egress_action, syn_rate_limit_pps, udp_rate_limit_pps,
                    icmp_rate_limit_pps, new_connection_limit_pps,
                    concurrent_connection_limit, port_scan_protection,
                    drop_invalid_packets, revision, applied_revision, last_applied_at,
                    last_error, created_at, updated_at
             FROM vm_network_security WHERE vm_id = ?1",
            [vm_id],
            row_to_vm_network_security,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_vm_network_security(row: &Row<'_>) -> rusqlite::Result<VmNetworkSecurity> {
    Ok(VmNetworkSecurity {
        vm_id: row.get(0)?,
        firewall_enabled: bool_column(row, 1)?,
        ddos_enabled: bool_column(row, 2)?,
        default_ingress_action: enum_column(row, 3)?,
        default_egress_action: enum_column(row, 4)?,
        syn_rate_limit_pps: optional_u32_column(row, 5)?,
        udp_rate_limit_pps: optional_u32_column(row, 6)?,
        icmp_rate_limit_pps: optional_u32_column(row, 7)?,
        new_connection_limit_pps: optional_u32_column(row, 8)?,
        concurrent_connection_limit: optional_u32_column(row, 9)?,
        port_scan_protection: bool_column(row, 10)?,
        drop_invalid_packets: bool_column(row, 11)?,
        revision: checked_u64_column(row, 12)?,
        applied_revision: optional_u64_column(row, 13)?,
        last_applied_at: row.get(14)?,
        last_error: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

fn bump_vm_network_security_revision(
    connection: &Connection,
    vm_id: &str,
    now: Timestamp,
) -> AppResult<()> {
    let changed = connection.execute(
        "UPDATE vm_network_security
         SET revision = revision + 1, last_error = NULL, updated_at = ?2
         WHERE vm_id = ?1",
        params![vm_id, now],
    )?;
    require_changed(changed, "VM network security profile")
}

fn query_vm_firewall_rule(
    connection: &Connection,
    vm_id: &str,
    rule_id: &str,
) -> AppResult<Option<VmFirewallRule>> {
    connection
        .query_row(
            "SELECT id, vm_id, priority, direction, action, protocol, source_cidr,
                    destination_cidr, source_ports_json, destination_ports_json,
                    log, enabled, description, owner_type, owner_id, created_at, updated_at
             FROM vm_firewall_rules WHERE vm_id = ?1 AND id = ?2",
            params![vm_id, rule_id],
            row_to_vm_firewall_rule,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_vm_firewall_rule(row: &Row<'_>) -> rusqlite::Result<VmFirewallRule> {
    Ok(VmFirewallRule {
        id: row.get(0)?,
        vm_id: row.get(1)?,
        priority: checked_u16_column(row, 2)?,
        direction: enum_column(row, 3)?,
        action: enum_column(row, 4)?,
        protocol: enum_column(row, 5)?,
        source_cidr: row.get(6)?,
        destination_cidr: row.get(7)?,
        source_ports: json_column(row, 8)?,
        destination_ports: json_column(row, 9)?,
        log: bool_column(row, 10)?,
        enabled: bool_column(row, 11)?,
        description: row.get(12)?,
        owner_type: row.get(13)?,
        owner_id: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

fn query_hypervisor_network_security(connection: &Connection) -> AppResult<HypervisorNetworkSecurity> {
    connection
        .query_row(
            "SELECT ip_ownership_guard_enabled, bcp38_enabled, revision,
                    applied_revision, last_applied_at,
                    last_error, updated_by, created_at, updated_at
             FROM hypervisor_network_security WHERE singleton_id = 1",
            [],
            |row| {
                Ok(HypervisorNetworkSecurity {
                    ip_ownership_guard_enabled: bool_column(row, 0)?,
                    bcp38_enabled: bool_column(row, 1)?,
                    revision: checked_u64_column(row, 2)?,
                    applied_revision: optional_u64_column(row, 3)?,
                    last_applied_at: row.get(4)?,
                    last_error: row.get(5)?,
                    updated_by: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map_err(Into::into)
}

fn query_ip_blacklist_entry(
    connection: &Connection,
    id_or_cidr: &str,
) -> AppResult<Option<IpBlacklistEntry>> {
    connection
        .query_row(
            "SELECT id, cidr, family, reason, source, enabled, expires_at, created_by,
                    metadata_json, created_at, updated_at
             FROM ip_blacklist WHERE id = ?1 OR cidr = ?1 LIMIT 1",
            [id_or_cidr],
            row_to_ip_blacklist_entry,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_ip_blacklist_entry(row: &Row<'_>) -> rusqlite::Result<IpBlacklistEntry> {
    Ok(IpBlacklistEntry {
        id: row.get(0)?,
        cidr: row.get(1)?,
        family: family_column(row, 2)?,
        reason: row.get(3)?,
        source: row.get(4)?,
        enabled: bool_column(row, 5)?,
        expires_at: row.get(6)?,
        created_by: row.get(7)?,
        metadata: json_column(row, 8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn ip_is_blacklisted(connection: &Connection, address: IpAddr, at: Timestamp) -> AppResult<bool> {
    let family = family_for_ip(address);
    let mut statement = connection.prepare(
        "SELECT cidr FROM ip_blacklist
         WHERE enabled = 1 AND family = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
    )?;
    let rows = statement.query_map(params![family.as_i64(), at], |row| row.get::<_, String>(0))?;
    for stored in rows {
        let stored = stored?;
        let network = stored.parse::<IpNet>().map_err(|_| {
            AppError::Internal(format!("stored blacklist CIDR is invalid: {stored}"))
        })?;
        if network.contains(&address) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn query_ip_abuse_record(connection: &Connection, id: &str) -> AppResult<Option<IpAbuseRecord>> {
    connection
        .query_row(
            "SELECT id, address, family, vm_id, category, severity, summary, reporter,
                    provider_reference, observed_at, reported_at, resolved_at,
                    resolved_by, resolution, metadata_json
             FROM ip_abuse_records WHERE id = ?1",
            [id],
            row_to_ip_abuse_record,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_ip_abuse_record(row: &Row<'_>) -> rusqlite::Result<IpAbuseRecord> {
    let severity = checked_u64_column(row, 5)?;
    Ok(IpAbuseRecord {
        id: row.get(0)?,
        address: row.get(1)?,
        family: family_column(row, 2)?,
        vm_id: row.get(3)?,
        category: row.get(4)?,
        severity: u8::try_from(severity)
            .map_err(|_| conversion_error(5, Type::Integer, "abuse severity is out of range"))?,
        summary: row.get(6)?,
        reporter: row.get(7)?,
        provider_reference: row.get(8)?,
        observed_at: row.get(9)?,
        reported_at: row.get(10)?,
        resolved_at: row.get(11)?,
        resolved_by: row.get(12)?,
        resolution: row.get(13)?,
        metadata: json_column(row, 14)?,
    })
}

fn query_setting(connection: &Connection, key: &str) -> AppResult<Option<SettingRecord>> {
    connection
        .query_row(
            "SELECT key, value_json, encrypted, updated_by, updated_at
             FROM settings WHERE key = ?1",
            [key],
            row_to_setting,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_setting(row: &Row<'_>) -> rusqlite::Result<SettingRecord> {
    Ok(SettingRecord {
        key: row.get(0)?,
        value: json_column(row, 1)?,
        encrypted: bool_column(row, 2)?,
        updated_by: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn query_iso(connection: &Connection, id_or_slug: &str) -> AppResult<Option<IsoImage>> {
    connection
        .query_row(
            "SELECT id, slug, name, version, os_family, architecture, install_mode,
                    source_url, local_path, checksum_sha256, size_bytes,
                    supports_guest_agent, supports_cloud_init, uefi, enabled,
                    metadata_json, created_at, updated_at
             FROM iso_images WHERE id = ?1 OR slug = ?1 COLLATE NOCASE LIMIT 1",
            [id_or_slug],
            row_to_iso,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_iso(row: &Row<'_>) -> rusqlite::Result<IsoImage> {
    Ok(IsoImage {
        id: row.get(0)?,
        slug: row.get(1)?,
        name: row.get(2)?,
        version: row.get(3)?,
        os_family: row.get(4)?,
        architecture: row.get(5)?,
        install_mode: enum_column(row, 6)?,
        source_url: row.get(7)?,
        local_path: row.get(8)?,
        checksum_sha256: row.get(9)?,
        size_bytes: optional_u64_column(row, 10)?,
        supports_guest_agent: bool_column(row, 11)?,
        supports_cloud_init: bool_column(row, 12)?,
        uefi: bool_column(row, 13)?,
        enabled: bool_column(row, 14)?,
        metadata: json_column(row, 15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

fn row_to_host_inventory(row: &Row<'_>) -> rusqlite::Result<HostInventory> {
    Ok(HostInventory {
        hostname: row.get(0)?,
        architecture: row.get(1)?,
        kernel: row.get(2)?,
        cpu_model: row.get(3)?,
        cpu_cores: checked_u32_column(row, 4)?,
        memory_total_bytes: checked_u64_column(row, 5)?,
        root_disk_total_bytes: checked_u64_column(row, 6)?,
        listen_port: checked_u16_column(row, 7)?,
        public_interface: row.get(8)?,
        detected_addresses: json_column(row, 9)?,
        metadata: json_column(row, 10)?,
        updated_at: row.get(11)?,
    })
}

fn row_to_host_metric(row: &Row<'_>) -> rusqlite::Result<HostMetric> {
    Ok(HostMetric {
        sampled_at: row.get(0)?,
        cpu_percent: row.get(1)?,
        load_one: row.get(2)?,
        load_five: row.get(3)?,
        load_fifteen: row.get(4)?,
        memory_total_bytes: checked_u64_column(row, 5)?,
        memory_used_bytes: checked_u64_column(row, 6)?,
        swap_total_bytes: checked_u64_column(row, 7)?,
        swap_used_bytes: checked_u64_column(row, 8)?,
        disk_total_bytes: checked_u64_column(row, 9)?,
        disk_used_bytes: checked_u64_column(row, 10)?,
        disk_read_bps: row.get(11)?,
        disk_write_bps: row.get(12)?,
        network_rx_bytes: checked_u64_column(row, 13)?,
        network_tx_bytes: checked_u64_column(row, 14)?,
        network_rx_bps: row.get(15)?,
        network_tx_bps: row.get(16)?,
        uptime_seconds: checked_u64_column(row, 17)?,
        metadata: json_column(row, 18)?,
    })
}

fn row_to_vm_metric(row: &Row<'_>) -> rusqlite::Result<VmMetric> {
    Ok(VmMetric {
        vm_id: row.get(0)?,
        sampled_at: row.get(1)?,
        cpu_percent: row.get(2)?,
        memory_used_bytes: checked_u64_column(row, 3)?,
        memory_total_bytes: checked_u64_column(row, 4)?,
        disk_read_bytes: checked_u64_column(row, 5)?,
        disk_write_bytes: checked_u64_column(row, 6)?,
        disk_read_bps: row.get(7)?,
        disk_write_bps: row.get(8)?,
        network_rx_bytes: checked_u64_column(row, 9)?,
        network_tx_bytes: checked_u64_column(row, 10)?,
        network_rx_bps: row.get(11)?,
        network_tx_bps: row.get(12)?,
        traffic_used_bytes: checked_u64_column(row, 13)?,
        traffic_limit_bytes: optional_u64_column(row, 14)?,
        metadata: json_column(row, 15)?,
    })
}

fn query_customer_token(connection: &Connection, id: &str) -> AppResult<Option<CustomerTokenRecord>> {
    connection
        .query_row(
            "SELECT id, vm_id, scopes_json, bound_ip, created_at, expires_at,
                    consumed_at, session_expires_at, last_used_at, revoked_at
             FROM customer_tokens WHERE id = ?1",
            [id],
            row_to_customer_token,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_customer_token(row: &Row<'_>) -> rusqlite::Result<CustomerTokenRecord> {
    Ok(CustomerTokenRecord {
        id: row.get(0)?,
        vm_id: row.get(1)?,
        scopes: json_column(row, 2)?,
        bound_ip: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        consumed_at: row.get(6)?,
        session_expires_at: row.get(7)?,
        last_used_at: row.get(8)?,
        revoked_at: row.get(9)?,
    })
}

fn query_vnc_token(connection: &Connection, id: &str) -> AppResult<Option<VncTokenRecord>> {
    connection
        .query_row(
            "SELECT id, vm_id, created_at, expires_at, consumed_at,
                    session_expires_at, bound_ip, revoked_at
             FROM vnc_tokens WHERE id = ?1",
            [id],
            row_to_vnc_token,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_vnc_token(row: &Row<'_>) -> rusqlite::Result<VncTokenRecord> {
    Ok(VncTokenRecord {
        id: row.get(0)?,
        vm_id: row.get(1)?,
        created_at: row.get(2)?,
        expires_at: row.get(3)?,
        consumed_at: row.get(4)?,
        session_expires_at: row.get(5)?,
        bound_ip: row.get(6)?,
        revoked_at: row.get(7)?,
    })
}

const JOB_COLUMNS: &str = "
    id, kind, vm_id, status, payload_json, result_json, error, progress_percent,
    idempotency_key, attempts, max_attempts, run_after, locked_by, locked_at,
    actor_type, actor_id, created_at, updated_at, finished_at
";

fn query_job(connection: &Connection, id: &str) -> AppResult<Option<Job>> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1");
    connection
        .query_row(&sql, [id], row_to_job)
        .optional()
        .map_err(Into::into)
}

fn query_job_by_idempotency(connection: &Connection, key: &str) -> AppResult<Option<Job>> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM jobs WHERE idempotency_key = ?1");
    connection
        .query_row(&sql, [key], row_to_job)
        .optional()
        .map_err(Into::into)
}

fn row_to_job(row: &Row<'_>) -> rusqlite::Result<Job> {
    Ok(Job {
        id: row.get(0)?,
        kind: row.get(1)?,
        vm_id: row.get(2)?,
        status: enum_column(row, 3)?,
        payload: json_column(row, 4)?,
        result: optional_json_column(row, 5)?,
        error: row.get(6)?,
        progress_percent: row.get(7)?,
        idempotency_key: row.get(8)?,
        attempts: checked_u32_column(row, 9)?,
        max_attempts: checked_u32_column(row, 10)?,
        run_after: row.get(11)?,
        locked_by: row.get(12)?,
        locked_at: row.get(13)?,
        actor_type: row.get(14)?,
        actor_id: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
        finished_at: row.get(18)?,
    })
}

fn query_snapshot(connection: &Connection, id: &str) -> AppResult<Option<Snapshot>> {
    connection
        .query_row(
            "SELECT id, vm_id, name, description, state, disk_path, size_bytes,
                    memory_included, metadata_json, created_at, updated_at, completed_at
             FROM snapshots WHERE id = ?1",
            [id],
            row_to_snapshot,
        )
        .optional()
        .map_err(Into::into)
}

fn row_to_snapshot(row: &Row<'_>) -> rusqlite::Result<Snapshot> {
    Ok(Snapshot {
        id: row.get(0)?,
        vm_id: row.get(1)?,
        name: row.get(2)?,
        description: row.get(3)?,
        state: enum_column(row, 4)?,
        disk_path: row.get(5)?,
        size_bytes: optional_u64_column(row, 6)?,
        memory_included: bool_column(row, 7)?,
        metadata: json_column(row, 8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        completed_at: row.get(11)?,
    })
}

fn row_to_audit(row: &Row<'_>) -> rusqlite::Result<AuditEvent> {
    Ok(AuditEvent {
        id: row.get(0)?,
        occurred_at: row.get(1)?,
        actor_type: row.get(2)?,
        actor_id: row.get(3)?,
        action: row.get(4)?,
        resource_type: row.get(5)?,
        resource_id: row.get(6)?,
        request_id: row.get(7)?,
        source_ip: row.get(8)?,
        user_agent: row.get(9)?,
        success: bool_column(row, 10)?,
        details: json_column(row, 11)?,
    })
}

fn validate_vm_spec(spec: &NewVm) -> AppResult<()> {
    validate_non_empty("VM name", &spec.name)?;
    validate_non_empty("hostname", &spec.hostname)?;
    validate_non_empty("disk format", &spec.disk_format)?;
    validate_non_empty("root username", &spec.root_username)?;
    if spec.root_username.len() > 64
        || spec.root_username.starts_with('-')
        || !spec
            .root_username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AppError::Validation(
            "root username must be a local account name containing only letters, numbers, periods, underscores, or hyphens"
                .into(),
        ));
    }
    if spec.vcpus == 0 {
        return Err(AppError::Validation("vcpus must be greater than zero".into()));
    }
    if spec.memory_mib < 256 {
        return Err(AppError::Validation("memory_mib must be at least 256".into()));
    }
    if spec.disk_gib == 0 {
        return Err(AppError::Validation("disk_gib must be greater than zero".into()));
    }
    if !matches!(spec.firmware.as_str(), "bios" | "uefi") {
        return Err(AppError::Validation("firmware must be bios or uefi".into()));
    }
    if spec
        .machine_type
        .as_deref()
        .is_some_and(|value| !matches!(value, "q35" | "i440fx"))
    {
        return Err(AppError::Validation("machine_type must be q35 or i440fx".into()));
    }
    if spec.network_limit_mbps == Some(0) {
        return Err(AppError::Validation(
            "network_limit_mbps must be greater than zero".into(),
        ));
    }
    Ok(())
}

fn validate_non_empty(label: &str, value: &str) -> AppResult<()> {
    if value.trim().is_empty() {
        Err(AppError::Validation(format!("{label} cannot be empty")))
    } else {
        Ok(())
    }
}

fn validate_guest_tools_version(label: &str, value: &str) -> AppResult<()> {
    validate_non_empty(label, value)?;
    if value.len() > 64 || value.chars().any(char::is_control) {
        return Err(AppError::Validation(format!(
            "{label} must contain at most 64 bytes and no control characters"
        )));
    }
    Ok(())
}

fn validate_guest_tools_rotation_generation(generation: &str) -> AppResult<()> {
    let parsed = Uuid::parse_str(generation).map_err(|_| {
        AppError::Validation("guest-tools rotation generation is invalid".into())
    })?;
    if parsed.to_string() != generation {
        return Err(AppError::Validation(
            "guest-tools rotation generation is not canonical".into(),
        ));
    }
    Ok(())
}

fn canonical_ip(value: &str) -> AppResult<String> {
    value
        .trim()
        .parse::<IpAddr>()
        .map(|address| address.to_string())
        .map_err(|_| AppError::Validation(format!("invalid IP address: {value}")))
}

fn normalize_dns_addresses(addresses: &[String]) -> AppResult<Vec<String>> {
    if addresses.len() > 32 {
        return Err(AppError::Validation("at most 32 DNS servers are allowed".into()));
    }
    let mut normalized = Vec::new();
    for address in addresses {
        let address = canonical_ip(address)?;
        if !normalized.contains(&address) {
            normalized.push(address);
        }
    }
    Ok(normalized)
}

fn networks_overlap(left: &IpNet, right: &IpNet) -> bool {
    family_for_ip(left.addr()) == family_for_ip(right.addr())
        && (left.contains(&right.addr()) || right.contains(&left.addr()))
}

fn canonical_optional_ip(
    value: Option<&str>,
    expected_family: Option<AddressFamily>,
) -> AppResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let address: IpAddr = value
        .parse()
        .map_err(|_| AppError::Validation(format!("invalid IP address: {value}")))?;
    if expected_family.is_some_and(|expected| expected != family_for_ip(address)) {
        return Err(AppError::Validation(
            "IP address family does not match its pool".into(),
        ));
    }
    Ok(Some(address.to_string()))
}

fn family_for_ip(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::V4,
        IpAddr::V6(_) => AddressFamily::V6,
    }
}

fn validate_prefix(family: AddressFamily, prefix: u8) -> AppResult<()> {
    let maximum = match family {
        AddressFamily::V4 => 32,
        AddressFamily::V6 => 128,
    };
    if prefix > maximum {
        Err(AppError::Validation(format!(
            "prefix length {prefix} is invalid for {family:?}"
        )))
    } else {
        Ok(())
    }
}

fn json_string<T: Serialize + ?Sized>(value: &T) -> AppResult<String> {
    serde_json::to_string(value)
        .map_err(|error| AppError::Internal(format!("could not encode JSON: {error}")))
}

fn payload_without_staged_password(payload: &Value) -> Value {
    let mut payload = payload.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove(STAGED_PASSWORD_ENVELOPE_FIELD);
    }
    payload
}

fn json_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> rusqlite::Result<T> {
    let raw: String = row.get(index)?;
    serde_json::from_str(&raw)
        .map_err(|error| rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(error)))
}

fn optional_json_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<T>> {
    let raw: Option<String> = row.get(index)?;
    raw.map(|value| {
        serde_json::from_str(&value)
            .map_err(|error| rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(error)))
    })
    .transpose()
}

fn enum_column<T>(row: &Row<'_>, index: usize) -> rusqlite::Result<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let value: String = row.get(index)?;
    value
        .parse::<T>()
        .map_err(|error| conversion_error(index, Type::Text, &error.to_string()))
}

fn family_column(row: &Row<'_>, index: usize) -> rusqlite::Result<AddressFamily> {
    let value: i64 = row.get(index)?;
    AddressFamily::from_i64(value).map_err(|error| conversion_error(index, Type::Integer, &error))
}

fn bool_column(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
    let value: i64 = row.get(index)?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(conversion_error(
            index,
            Type::Integer,
            "boolean column is not zero or one",
        )),
    }
}

fn checked_u64_column(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| conversion_error(index, Type::Integer, "negative unsigned value"))
}

fn optional_u64_column(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    let value: Option<i64> = row.get(index)?;
    value
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| conversion_error(index, Type::Integer, "negative unsigned value"))
        })
        .transpose()
}

fn checked_u32_column(row: &Row<'_>, index: usize) -> rusqlite::Result<u32> {
    let value = checked_u64_column(row, index)?;
    u32::try_from(value).map_err(|_| conversion_error(index, Type::Integer, "value exceeds u32"))
}

fn optional_u32_column(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u32>> {
    optional_u64_column(row, index)?
        .map(|value| {
            u32::try_from(value).map_err(|_| conversion_error(index, Type::Integer, "value exceeds u32"))
        })
        .transpose()
}

fn checked_u16_column(row: &Row<'_>, index: usize) -> rusqlite::Result<u16> {
    let value = checked_u64_column(row, index)?;
    u16::try_from(value).map_err(|_| conversion_error(index, Type::Integer, "value exceeds u16"))
}

fn optional_u16_column(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u16>> {
    optional_u64_column(row, index)?
        .map(|value| {
            u16::try_from(value).map_err(|_| conversion_error(index, Type::Integer, "value exceeds u16"))
        })
        .transpose()
}

fn conversion_error(index: usize, data_type: Type, message: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        data_type,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message.to_owned(),
        )),
    )
}

fn checked_i64(value: u64, label: &str) -> AppResult<i64> {
    i64::try_from(value).map_err(|_| AppError::Validation(format!("{label} exceeds SQLite integer range")))
}

fn optional_i64(value: Option<u64>, label: &str) -> AppResult<Option<i64>> {
    value.map(|value| checked_i64(value, label)).transpose()
}

const fn bool_i64(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn bounded_limit(requested: usize, maximum: usize) -> i64 {
    let selected = if requested == 0 {
        maximum.min(100)
    } else {
        requested.min(maximum)
    };
    i64::try_from(selected).unwrap_or(i64::MAX)
}

/// Select at most `limit` representative points while preserving the complete
/// requested time window. The old newest-N query made a 24-hour or seven-day
/// chart show only the last few hours at the default 15-second sample rate.
fn metric_bucket_seconds(since: Timestamp, latest: Option<Timestamp>, limit: i64) -> i64 {
    let limit = limit.max(1);
    let inclusive_span = latest
        .unwrap_or(since)
        .saturating_sub(since)
        .saturating_add(1)
        .max(1);
    inclusive_span
        .saturating_add(limit - 1)
        .saturating_div(limit)
        .max(1)
}

fn collect_rows<T>(rows: impl Iterator<Item = rusqlite::Result<T>>) -> AppResult<Vec<T>> {
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

fn sort_ip_addresses_numerically(records: &mut [IpAddressRecord], primary_first: bool) {
    records.sort_by(|left, right| {
        let primary_order = primary_first
            .then(|| right.primary_for_vm.cmp(&left.primary_for_vm))
            .unwrap_or(std::cmp::Ordering::Equal);
        primary_order.then_with(|| {
            match (left.address.parse::<IpAddr>(), right.address.parse::<IpAddr>()) {
                (Ok(left), Ok(right)) => left.cmp(&right),
                _ => left.address.cmp(&right.address),
            }
        })
    });
}

fn require_changed(changed: usize, resource: &str) -> AppResult<()> {
    if changed == 0 {
        Err(AppError::NotFound(resource.into()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::json;

    fn host_metric(sampled_at: Timestamp) -> HostMetric {
        HostMetric {
            sampled_at,
            cpu_percent: (sampled_at % 100) as f64,
            load_one: 0.1,
            load_five: 0.2,
            load_fifteen: 0.3,
            memory_total_bytes: 1024,
            memory_used_bytes: 512,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            disk_total_bytes: 4096,
            disk_used_bytes: 1024,
            disk_read_bps: 10.0,
            disk_write_bps: 20.0,
            network_rx_bytes: sampled_at.max(0) as u64,
            network_tx_bytes: sampled_at.max(0) as u64,
            network_rx_bps: 30.0,
            network_tx_bps: 40.0,
            uptime_seconds: sampled_at.max(0) as u64,
            metadata: json!({}),
        }
    }

    fn vm_metric(vm_id: &str, sampled_at: Timestamp) -> VmMetric {
        VmMetric {
            vm_id: vm_id.into(),
            sampled_at,
            cpu_percent: (sampled_at % 100) as f64,
            memory_used_bytes: 512,
            memory_total_bytes: 1024,
            disk_read_bytes: sampled_at.max(0) as u64,
            disk_write_bytes: sampled_at.max(0) as u64,
            disk_read_bps: 10.0,
            disk_write_bps: 20.0,
            network_rx_bytes: sampled_at.max(0) as u64,
            network_tx_bytes: sampled_at.max(0) as u64,
            network_rx_bps: 30.0,
            network_tx_bps: 40.0,
            traffic_used_bytes: sampled_at.max(0) as u64,
            traffic_limit_bytes: None,
            metadata: json!({}),
        }
    }

    fn test_vm() -> NewVm {
        NewVm {
            name: "vm-one".into(),
            hostname: "vm-one.example.test".into(),
            description: "test VM".into(),
            os_family: "linux".into(),
            iso_id: None,
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 20,
            disk_format: "qcow2".into(),
            firmware: "bios".into(),
            machine_type: None,
            bridge: Some("vexa0".into()),
            tap_name: Some("tap-vm-one".into()),
            mac_address: Some("52:54:00:00:00:01".into()),
            network_limit_mbps: Some(100),
            traffic_limit_bytes: Some(1_000_000),
            root_username: "root".into(),
            guest_agent: true,
            autostart: false,
            timezone: Some("UTC".into()),
            metadata: json!({"purpose": "test"}),
        }
    }

    fn test_vm_named(name: &str, suffix: u8) -> NewVm {
        let mut vm = test_vm();
        vm.name = name.into();
        vm.hostname = format!("{name}.example.test");
        vm.tap_name = Some(format!("tap-{name}"));
        vm.mac_address = Some(format!("52:54:00:00:00:{suffix:02x}"));
        vm
    }

    #[test]
    fn migration_and_vm_crud_work() {
        let database = Database::open_in_memory().unwrap();
        assert_eq!(database.schema_version().unwrap(), 10);
        let vm = database.create_vm(&test_vm()).unwrap();
        assert_eq!(database.get_vm("vm-one").unwrap().unwrap().id, vm.id);
        database
            .patch_vm(
                &vm.id,
                &VmPatch {
                    state: Some(VmState::Running),
                    memory_mib: Some(4096),
                    tap_name: Some(Some("vexa-persisted".into())),
                    ..VmPatch::default()
                },
            )
            .unwrap();
        assert_eq!(database.get_vm(&vm.id).unwrap().unwrap().memory_mib, 4096);
        assert_eq!(
            database.get_vm(&vm.id).unwrap().unwrap().tap_name.as_deref(),
            Some("vexa-persisted")
        );
    }

    #[test]
    fn ip_inventory_is_sorted_by_numeric_address_value() {
        let database = Database::open_in_memory().unwrap();
        for address in [
            "203.0.113.126",
            "203.0.113.66",
            "203.0.113.100",
            "203.0.113.99",
        ] {
            database
                .upsert_ip_address(&NewIpAddress {
                    pool_id: None,
                    address: address.into(),
                    prefix_length: 32,
                    scope: IpScope::Public,
                    status: IpStatus::Free,
                    gateway: None,
                    reverse_dns: None,
                    metadata: json!({}),
                })
                .unwrap();
        }

        let addresses = database
            .list_ip_addresses(Some(AddressFamily::V4), Some(IpScope::Public), None)
            .unwrap()
            .into_iter()
            .map(|record| record.address)
            .collect::<Vec<_>>();
        assert_eq!(
            addresses,
            [
                "203.0.113.66",
                "203.0.113.99",
                "203.0.113.100",
                "203.0.113.126",
            ]
        );
    }

    #[test]
    fn guest_tools_secret_is_vm_bound_and_never_stored_in_plaintext() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let security = Security::new([0x42; 32]);
        let secret = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0x11_u8; 32]);
        let record = database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                &secret,
                "0.1.0",
                &security,
            )
            .unwrap();
        assert!(record.enabled);
        assert_eq!(
            database
                .decrypt_vm_guest_tools_secret(&vm.id, &security)
                .unwrap()
                .as_deref(),
            Some(secret.as_str())
        );
        let envelope: String = database
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT secret_envelope FROM vm_guest_tools WHERE vm_id = ?1",
                        [&vm.id],
                        |row| row.get(0),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert_ne!(envelope, secret);
        assert!(!envelope.contains(&secret));
    }

    #[test]
    fn guest_tools_rotation_is_generation_bound_and_two_phase() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let security = Security::new([0x43; 32]);
        let active_secret = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0x21_u8; 32]);
        let pending_secret = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0x22_u8; 32]);
        database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                &active_secret,
                "0.1.0",
                &security,
            )
            .unwrap();

        let generation = database
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Windows,
                GuestToolsProvisioner::CloudbaseNoCloud,
                &pending_secret,
                "0.2.0",
                &security,
            )
            .unwrap();
        let staged = database.vm_guest_tools(&vm.id).unwrap().unwrap();
        assert!(staged.pending_rotation);
        assert!(!staged.pending_installed);
        assert_eq!(staged.platform, GuestToolsPlatform::Linux);
        assert_eq!(staged.desired_version, "0.1.0");
        let public_record = serde_json::to_value(&staged).unwrap();
        assert!(public_record.get("pending_rotation").is_some());
        assert!(public_record.get("pending_installed").is_some());
        assert!(public_record.get("pending_generation").is_none());
        assert!(public_record.get("secret").is_none());
        assert!(public_record.get("secret_envelope").is_none());

        let seed = database
            .pending_vm_guest_tools_seed(&vm.id, &security)
            .unwrap()
            .unwrap();
        assert_eq!(seed.generation, generation);
        assert_eq!(seed.platform, GuestToolsPlatform::Windows);
        assert_eq!(seed.provisioner, GuestToolsProvisioner::CloudbaseNoCloud);
        assert_eq!(seed.desired_version, "0.2.0");
        assert_eq!(seed.secret, pending_secret);
        assert!(!seed.installed);
        assert!(!format!("{seed:?}").contains(&pending_secret));

        let before_install = database
            .vm_guest_tools_client_secret(&vm.id, &security)
            .unwrap()
            .unwrap();
        assert_eq!(before_install.secret, active_secret);
        assert_eq!(before_install.desired_version, "0.1.0");
        assert!(before_install.pending_generation.is_none());
        assert_eq!(
            database
                .decrypt_vm_guest_tools_secret(&vm.id, &security)
                .unwrap()
                .as_deref(),
            Some(active_secret.as_str())
        );

        let wrong_generation = Uuid::new_v4().to_string();
        assert!(database
            .mark_vm_guest_tools_rotation_installed(&vm.id, &wrong_generation)
            .is_err());
        let installed = database
            .mark_vm_guest_tools_rotation_installed(&vm.id, &generation)
            .unwrap();
        assert!(installed.pending_rotation);
        assert!(installed.pending_installed);
        assert!(database
            .discard_vm_guest_tools_rotation(&vm.id, &generation)
            .is_err());
        assert!(database.delete_vm_guest_tools_configuration(&vm.id).is_err());
        let guarded = database
            .update_vm_guest_tools_status(
                &vm.id,
                GuestToolsStatus::Ready,
                Some("0.2.0"),
                None,
                true,
            )
            .unwrap();
        assert_eq!(guarded.status, GuestToolsStatus::Pending);
        assert!(guarded.installed_version.is_none());
        assert_eq!(
            database
                .installed_vm_guest_tools_rotation_generation(&vm.id)
                .unwrap()
                .as_deref(),
            Some(generation.as_str())
        );

        let after_install = database
            .vm_guest_tools_client_secret(&vm.id, &security)
            .unwrap()
            .unwrap();
        assert_eq!(after_install.secret, pending_secret);
        assert_eq!(after_install.desired_version, "0.2.0");
        assert_eq!(after_install.pending_generation.as_deref(), Some(generation.as_str()));
        assert!(!format!("{after_install:?}").contains(&pending_secret));
        // The durable active envelope is still the old one until promotion.
        assert_eq!(
            database
                .decrypt_vm_guest_tools_secret(&vm.id, &security)
                .unwrap()
                .as_deref(),
            Some(active_secret.as_str())
        );

        assert!(database
            .promote_vm_guest_tools_rotation(&vm.id, &generation, "wrong-version", &security)
            .is_err());
        assert!(database.vm_guest_tools(&vm.id).unwrap().unwrap().pending_installed);
        let promoted = database
            .promote_vm_guest_tools_rotation(&vm.id, &generation, "0.2.0", &security)
            .unwrap();
        assert!(!promoted.pending_rotation);
        assert!(!promoted.pending_installed);
        assert!(database
            .installed_vm_guest_tools_rotation_generation(&vm.id)
            .unwrap()
            .is_none());
        assert_eq!(promoted.platform, GuestToolsPlatform::Windows);
        assert_eq!(promoted.provisioner, GuestToolsProvisioner::CloudbaseNoCloud);
        assert_eq!(promoted.desired_version, "0.2.0");
        assert_eq!(promoted.installed_version.as_deref(), Some("0.2.0"));
        assert_eq!(promoted.status, GuestToolsStatus::Ready);
        assert!(promoted.last_seen_at.is_some());
        assert!(database.pending_vm_guest_tools_seed(&vm.id, &security).unwrap().is_none());
        assert_eq!(
            database
                .decrypt_vm_guest_tools_secret(&vm.id, &security)
                .unwrap()
                .as_deref(),
            Some(pending_secret.as_str())
        );
    }

    #[test]
    fn pending_guest_tools_envelope_is_private_context_bound_and_discardable() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let security = Security::new([0x44; 32]);
        let active_secret = "active-channel-secret";
        let pending_secret = "fresh-reinstall-channel-secret";
        database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                active_secret,
                "0.1.0",
                &security,
            )
            .unwrap();
        let generation = database
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                pending_secret,
                "0.2.0",
                &security,
            )
            .unwrap();
        assert!(database
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "another-secret",
                "0.3.0",
                &security,
            )
            .is_err());

        let envelope: String = database
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT pending_secret_envelope FROM vm_guest_tools WHERE vm_id = ?1",
                        [&vm.id],
                        |row| row.get(0),
                    )
                    .map_err(Into::into)
            })
            .unwrap();
        assert!(!envelope.contains(pending_secret));
        assert!(security
            .decrypt_secret(&envelope, &vm_guest_tools_secret_context(&vm.id))
            .is_err());
        assert!(security
            .decrypt_secret(
                &envelope,
                &vm_guest_tools_pending_secret_context(&vm.id, "wrong-generation"),
            )
            .is_err());
        let wrong_generation = Uuid::new_v4().to_string();
        assert!(database
            .discard_vm_guest_tools_rotation(&vm.id, &wrong_generation)
            .is_err());
        let record = database
            .discard_vm_guest_tools_rotation(&vm.id, &generation)
            .unwrap();
        assert!(!record.pending_rotation);
        assert!(!record.pending_installed);
        assert_eq!(
            database
                .vm_guest_tools_client_secret(&vm.id, &security)
                .unwrap()
                .unwrap()
                .secret,
            active_secret
        );
    }

    #[test]
    fn configuring_guest_tools_clears_stale_pending_rotation() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let security = Security::new([0x45; 32]);
        database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "first-active-secret",
                "0.1.0",
                &security,
            )
            .unwrap();
        let generation = database
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "pending-secret",
                "0.2.0",
                &security,
            )
            .unwrap();
        let configured = database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Windows,
                GuestToolsProvisioner::CloudbaseNoCloud,
                "replacement-active-secret",
                "0.3.0",
                &security,
            )
            .unwrap();
        assert!(!configured.pending_rotation);
        assert!(!configured.pending_installed);
        assert!(database
            .discard_vm_guest_tools_rotation(&vm.id, &generation)
            .is_err());
        database.delete_vm_guest_tools_configuration(&vm.id).unwrap();
        assert!(database.vm_guest_tools(&vm.id).unwrap().is_none());
    }

    #[test]
    fn armed_guest_tools_rotation_cannot_be_reconfigured_or_deleted() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let security = Security::new([0x47; 32]);
        let active_secret = "active-secret-before-reinstall";
        let pending_secret = "pending-secret-on-replacement-media";
        database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                active_secret,
                "0.1.0",
                &security,
            )
            .unwrap();
        let generation = database
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                pending_secret,
                "0.2.0",
                &security,
            )
            .unwrap();
        database
            .mark_vm_guest_tools_rotation_installed(&vm.id, &generation)
            .unwrap();

        assert!(database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Windows,
                GuestToolsProvisioner::CloudbaseNoCloud,
                "replacement-secret",
                "0.3.0",
                &security,
            )
            .is_err());
        assert!(database.delete_vm_guest_tools_configuration(&vm.id).is_err());
        let retained = database
            .vm_guest_tools_client_secret(&vm.id, &security)
            .unwrap()
            .unwrap();
        assert_eq!(retained.secret, pending_secret);
        assert_eq!(retained.pending_generation.as_deref(), Some(generation.as_str()));
        assert_eq!(
            database
                .decrypt_vm_guest_tools_secret(&vm.id, &security)
                .unwrap()
                .as_deref(),
            Some(active_secret)
        );
    }

    #[test]
    fn terminal_reinstall_cleanup_is_generation_exact_and_armed_safe() {
        let database = Database::open_in_memory().unwrap();
        let security = Security::new([0x48; 32]);
        let fingerprint = "a".repeat(64);

        let vm = database.create_vm(&test_vm()).unwrap();
        database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "active-one",
                "0.1.0",
                &security,
            )
            .unwrap();
        let generation = database
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "pending-one",
                "0.2.0",
                &security,
            )
            .unwrap();
        let job = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(vm.id.clone()),
                    payload: json!({
                        "_guest_tools_rotation_generation": generation.clone(),
                        "guest_tools_new_configuration": false,
                        "request_fingerprint": fingerprint.clone(),
                    }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        database
            .claim_next_job("test-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        database
            .fail_job(&job.id, "failed before media publish", None, unix_timestamp())
            .unwrap();
        let cleaned = database.vm_guest_tools(&vm.id).unwrap().unwrap();
        assert!(!cleaned.pending_rotation);
        assert_eq!(
            database
                .decrypt_vm_guest_tools_secret(&vm.id, &security)
                .unwrap()
                .as_deref(),
            Some("active-one")
        );

        let provisional_vm = database
            .create_vm(&test_vm_named("vm-provisional", 4))
            .unwrap();
        database
            .configure_vm_guest_tools(
                &provisional_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "placeholder-never-seeded",
                "0.1.0",
                &security,
            )
            .unwrap();
        let provisional_generation = database
            .stage_vm_guest_tools_rotation(
                &provisional_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "fresh-provisional-key",
                "0.1.0",
                &security,
            )
            .unwrap();
        let provisional_job = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(provisional_vm.id.clone()),
                    payload: json!({
                        "_guest_tools_rotation_generation": provisional_generation,
                        "guest_tools_new_configuration": true,
                        "request_fingerprint": "d".repeat(64),
                    }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        database
            .claim_next_job("test-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        database
            .fail_job(
                &provisional_job.id,
                "failed before provisional media publish",
                None,
                unix_timestamp(),
            )
            .unwrap();
        assert!(database
            .vm_guest_tools(&provisional_vm.id)
            .unwrap()
            .is_none());

        let armed_vm = database
            .create_vm(&test_vm_named("vm-armed", 2))
            .unwrap();
        database
            .configure_vm_guest_tools(
                &armed_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "active-two",
                "0.1.0",
                &security,
            )
            .unwrap();
        let armed_generation = database
            .stage_vm_guest_tools_rotation(
                &armed_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "pending-two",
                "0.2.0",
                &security,
            )
            .unwrap();
        let armed_job = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(armed_vm.id.clone()),
                    payload: json!({
                        "_guest_tools_rotation_generation": armed_generation.clone(),
                        "guest_tools_new_configuration": false,
                        "request_fingerprint": fingerprint.clone(),
                    }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        database
            .claim_next_job("test-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        database
            .mark_vm_guest_tools_rotation_installed(&armed_vm.id, &armed_generation)
            .unwrap();
        database
            .fail_job(
                &armed_job.id,
                "failed after media publish",
                None,
                unix_timestamp(),
            )
            .unwrap();
        let armed = database.vm_guest_tools(&armed_vm.id).unwrap().unwrap();
        assert!(armed.pending_rotation);
        assert!(armed.pending_installed);
        assert!(database
            .reusable_vm_guest_tools_rotation(&armed_vm.id, &"b".repeat(64))
            .unwrap()
            .is_none());
        let reusable = database
            .reusable_vm_guest_tools_rotation(&armed_vm.id, &fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(reusable.generation, armed_generation);
        assert_eq!(reusable.origin_job_id, armed_job.id);
        assert_eq!(
            database
                .vm_guest_tools_client_secret(&armed_vm.id, &security)
                .unwrap()
                .unwrap()
                .secret,
            "pending-two"
        );

        let mismatched_vm = database
            .create_vm(&test_vm_named("vm-mismatch", 3))
            .unwrap();
        database
            .configure_vm_guest_tools(
                &mismatched_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "active-three",
                "0.1.0",
                &security,
            )
            .unwrap();
        let retained_generation = database
            .stage_vm_guest_tools_rotation(
                &mismatched_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "pending-three",
                "0.2.0",
                &security,
            )
            .unwrap();
        let wrong_generation = Uuid::new_v4().to_string();
        let mismatched_job = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(mismatched_vm.id.clone()),
                    payload: json!({
                        "_guest_tools_rotation_generation": wrong_generation,
                        "guest_tools_new_configuration": true,
                        "request_fingerprint": "c".repeat(64),
                    }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        database
            .claim_next_job("test-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        database
            .fail_job(
                &mismatched_job.id,
                "mismatched generation",
                None,
                unix_timestamp(),
            )
            .unwrap();
        let retained = database.vm_guest_tools(&mismatched_vm.id).unwrap().unwrap();
        assert!(retained.pending_rotation);
        assert!(!retained.pending_installed);
        assert_eq!(
            database
                .pending_vm_guest_tools_seed(&mismatched_vm.id, &security)
                .unwrap()
                .unwrap()
                .generation,
            retained_generation
        );
    }

    #[test]
    fn interrupted_reinstall_recovery_cleans_only_unarmed_exact_generation() {
        let security = Security::new([0x49; 32]);

        let unarmed = Database::open_in_memory().unwrap();
        let vm = unarmed.create_vm(&test_vm()).unwrap();
        unarmed
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "active-before-crash",
                "0.1.0",
                &security,
            )
            .unwrap();
        let generation = unarmed
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "unpublished-key",
                "0.2.0",
                &security,
            )
            .unwrap();
        unarmed
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(vm.id.clone()),
                    payload: json!({
                        "_guest_tools_rotation_generation": generation,
                        "guest_tools_new_configuration": false,
                        "request_fingerprint": "e".repeat(64),
                    }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        unarmed
            .claim_next_job("worker-before-crash", unix_timestamp())
            .unwrap()
            .unwrap();
        let orphan_vm = unarmed
            .create_vm(&test_vm_named("vm-orphan-unarmed", 5))
            .unwrap();
        unarmed
            .configure_vm_guest_tools(
                &orphan_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "orphan-active",
                "0.1.0",
                &security,
            )
            .unwrap();
        unarmed
            .stage_vm_guest_tools_rotation(
                &orphan_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "orphan-never-published",
                "0.2.0",
                &security,
            )
            .unwrap();
        let queued_vm = unarmed
            .create_vm(&test_vm_named("vm-queued-rotation", 7))
            .unwrap();
        unarmed
            .configure_vm_guest_tools(
                &queued_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "queued-active",
                "0.1.0",
                &security,
            )
            .unwrap();
        let queued_generation = unarmed
            .stage_vm_guest_tools_rotation(
                &queued_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "queued-pending",
                "0.2.0",
                &security,
            )
            .unwrap();
        unarmed
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(queued_vm.id.clone()),
                    payload: json!({
                        "_guest_tools_rotation_generation": queued_generation,
                        "guest_tools_new_configuration": false,
                        "request_fingerprint": "0".repeat(64),
                    }),
                    idempotency_key: None,
                    run_after: Some(unix_timestamp() + 60),
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        let (_, failed) = unarmed
            .recover_interrupted_jobs(unix_timestamp() + 1)
            .unwrap();
        assert_eq!(failed, 1);
        assert!(!unarmed
            .vm_guest_tools(&vm.id)
            .unwrap()
            .unwrap()
            .pending_rotation);
        assert!(unarmed
            .vm_guest_tools(&queued_vm.id)
            .unwrap()
            .unwrap()
            .pending_rotation);
        assert!(!unarmed
            .vm_guest_tools(&orphan_vm.id)
            .unwrap()
            .unwrap()
            .pending_rotation);

        let armed = Database::open_in_memory().unwrap();
        let vm = armed.create_vm(&test_vm()).unwrap();
        armed
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "active-before-armed-crash",
                "0.1.0",
                &security,
            )
            .unwrap();
        let generation = armed
            .stage_vm_guest_tools_rotation(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "published-key",
                "0.2.0",
                &security,
            )
            .unwrap();
        armed
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(vm.id.clone()),
                    payload: json!({
                        "_guest_tools_rotation_generation": generation.clone(),
                        "guest_tools_new_configuration": true,
                        "request_fingerprint": "f".repeat(64),
                    }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        armed
            .claim_next_job("worker-before-crash", unix_timestamp())
            .unwrap()
            .unwrap();
        armed
            .mark_vm_guest_tools_rotation_installed(&vm.id, &generation)
            .unwrap();
        let orphan_vm = armed
            .create_vm(&test_vm_named("vm-orphan-armed", 6))
            .unwrap();
        armed
            .configure_vm_guest_tools(
                &orphan_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "orphan-armed-active",
                "0.1.0",
                &security,
            )
            .unwrap();
        let orphan_generation = armed
            .stage_vm_guest_tools_rotation(
                &orphan_vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "orphan-already-published",
                "0.2.0",
                &security,
            )
            .unwrap();
        armed
            .mark_vm_guest_tools_rotation_installed(&orphan_vm.id, &orphan_generation)
            .unwrap();
        armed
            .recover_interrupted_jobs(unix_timestamp() + 1)
            .unwrap();
        let retained = armed.vm_guest_tools(&vm.id).unwrap().unwrap();
        assert!(retained.pending_rotation);
        assert!(retained.pending_installed);
        assert_eq!(retained.status, GuestToolsStatus::Error);
        assert_eq!(
            armed
                .vm_guest_tools_client_secret(&vm.id, &security)
                .unwrap()
                .unwrap()
                .secret,
            "published-key"
        );
        let orphan_retained = armed.vm_guest_tools(&orphan_vm.id).unwrap().unwrap();
        assert!(orphan_retained.pending_rotation);
        assert!(orphan_retained.pending_installed);
    }

    #[test]
    fn cancelling_reinstall_discards_unarmed_but_never_armed_rotation() {
        let security = Security::new([0x4a; 32]);
        for armed in [false, true] {
            let database = Database::open_in_memory().unwrap();
            let vm = database.create_vm(&test_vm()).unwrap();
            database
                .configure_vm_guest_tools(
                    &vm.id,
                    GuestToolsPlatform::Linux,
                    GuestToolsProvisioner::CloudInit,
                    "active-cancel-key",
                    "0.1.0",
                    &security,
                )
                .unwrap();
            let generation = database
                .stage_vm_guest_tools_rotation(
                    &vm.id,
                    GuestToolsPlatform::Linux,
                    GuestToolsProvisioner::CloudInit,
                    "pending-cancel-key",
                    "0.2.0",
                    &security,
                )
                .unwrap();
            let job = database
                .enqueue_reinstall_job(
                    &NewJob {
                        kind: "vm.reinstall".into(),
                        vm_id: Some(vm.id.clone()),
                        payload: json!({
                            "_guest_tools_rotation_generation": generation.clone(),
                            "guest_tools_new_configuration": false,
                            "request_fingerprint": "1".repeat(64),
                        }),
                        idempotency_key: None,
                        run_after: None,
                        max_attempts: 1,
                        actor_type: None,
                        actor_id: None,
                    },
                    None,
                    VmState::Running,
                )
                .unwrap();
            if armed {
                database
                    .mark_vm_guest_tools_rotation_installed(&vm.id, &generation)
                    .unwrap();
            }
            database.cancel_job(&job.id, unix_timestamp()).unwrap();
            let retained = database.vm_guest_tools(&vm.id).unwrap().unwrap();
            assert_eq!(retained.pending_rotation, armed);
            assert_eq!(retained.pending_installed, armed);
            assert_eq!(
                database
                    .vm_guest_tools_client_secret(&vm.id, &security)
                    .unwrap()
                    .unwrap()
                    .secret,
                if armed {
                    "pending-cancel-key"
                } else {
                    "active-cancel-key"
                }
            );
        }
    }

    #[test]
    fn guest_tools_bootstrap_jobs_are_deduplicated_per_generation() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let first = database
            .enqueue_guest_tools_bootstrap_job(&NewJob {
                kind: "vm.guest_tools.bootstrap".into(),
                vm_id: Some(vm.id.clone()),
                payload: json!({
                    "expected_generation": null,
                    "deadline": unix_timestamp() + 600,
                    "parent_job_id": "parent-one",
                }),
                idempotency_key: None,
                run_after: None,
                max_attempts: 2,
                actor_type: None,
                actor_id: None,
            })
            .unwrap();
        let duplicate = database
            .enqueue_guest_tools_bootstrap_job(&NewJob {
                kind: "vm.guest_tools.bootstrap".into(),
                vm_id: Some(vm.id.clone()),
                payload: json!({
                    "expected_generation": null,
                    "deadline": unix_timestamp() + 1200,
                    "parent_job_id": "parent-two",
                }),
                idempotency_key: None,
                run_after: None,
                max_attempts: 3,
                actor_type: Some("admin".into()),
                actor_id: Some("another-actor".into()),
            })
            .unwrap();
        assert_eq!(duplicate.id, first.id);

        let generation = Uuid::new_v4().to_string();
        let rotation = database
            .enqueue_guest_tools_bootstrap_job(&NewJob {
                kind: "vm.guest_tools.bootstrap".into(),
                vm_id: Some(vm.id),
                payload: json!({
                    "expected_generation": generation.clone(),
                    "deadline": unix_timestamp() + 600,
                }),
                idempotency_key: None,
                run_after: None,
                max_attempts: 2,
                actor_type: None,
                actor_id: None,
            })
            .unwrap();
        assert_ne!(rotation.id, first.id);
    }

    #[test]
    fn interrupted_bootstrap_does_not_overwrite_persisted_authenticated_health() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let security = Security::new([0x4b; 32]);
        database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "active-bootstrap-key",
                "0.1.0",
                &security,
            )
            .unwrap();
        let job = database
            .enqueue_guest_tools_bootstrap_job(&NewJob {
                kind: "vm.guest_tools.bootstrap".into(),
                vm_id: Some(vm.id.clone()),
                payload: json!({
                    "expected_generation": null,
                    "deadline": unix_timestamp() + 600,
                }),
                idempotency_key: None,
                run_after: None,
                max_attempts: 1,
                actor_type: None,
                actor_id: None,
            })
            .unwrap();
        let claimed_at = unix_timestamp();
        database
            .claim_next_job("bootstrap-worker", claimed_at)
            .unwrap()
            .unwrap();
        database
            .update_vm_guest_tools_status(
                &vm.id,
                GuestToolsStatus::Ready,
                Some("0.1.0"),
                None,
                true,
            )
            .unwrap();
        database
            .recover_interrupted_jobs(claimed_at + 1)
            .unwrap();
        assert_eq!(
            database.vm_guest_tools(&vm.id).unwrap().unwrap().status,
            GuestToolsStatus::Ready
        );
        assert_eq!(
            database.get_job(&job.id).unwrap().unwrap().status,
            JobStatus::Failed
        );
    }

    #[test]
    fn migrations_seven_through_ten_upgrade_an_existing_schema_sequentially() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(INITIAL_MIGRATION).unwrap();
        connection.execute_batch(API_KEY_ALLOWLIST_MIGRATION).unwrap();
        connection.execute_batch(TRAFFIC_ENFORCEMENT_MIGRATION).unwrap();
        connection.execute_batch(NETWORK_SECURITY_MIGRATION).unwrap();
        connection.execute_batch(GUEST_TOOLS_MIGRATION).unwrap();
        connection
            .execute_batch(FIREWALL_RULE_OWNERSHIP_MIGRATION)
            .unwrap();
        let database = Database::from_connection(connection).unwrap();
        assert_eq!(database.schema_version().unwrap(), 10);
        let columns: Vec<String> = database
            .with_connection(|connection| {
                let mut statement = connection.prepare("PRAGMA table_info(vm_guest_tools)")?;
                let rows = statement.query_map([], |row| row.get(1))?;
                collect_rows(rows)
            })
            .unwrap();
        assert!(columns.contains(&"pending_secret_envelope".into()));
        assert!(columns.contains(&"pending_generation".into()));
        assert!(columns.contains(&"pending_installed".into()));
        let host_policy = database.hypervisor_network_security().unwrap();
        assert!(host_policy.ip_ownership_guard_enabled);
        assert!(!host_policy.bcp38_enabled);
        assert_eq!(host_policy.revision, 1);
        assert_eq!(host_policy.applied_revision, None);

        let vm = database.create_vm(&test_vm()).unwrap();
        let security = Security::new([0x46; 32]);
        database
            .configure_vm_guest_tools(
                &vm.id,
                GuestToolsPlatform::Linux,
                GuestToolsProvisioner::CloudInit,
                "active-secret",
                "0.1.0",
                &security,
            )
            .unwrap();
        let malformed = database.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE vm_guest_tools SET pending_generation = ?2 WHERE vm_id = ?1",
                    params![vm.id, Uuid::new_v4().to_string()],
                )
                .map(|_| ())
                .map_err(Into::into)
        });
        assert!(malformed.is_err());
    }

    #[test]
    fn safe_default_migration_only_clears_untouched_invalid_packet_presets() {
        let database = Database::open_in_memory().unwrap();
        let untouched = database.create_vm(&test_vm_named("vm-untouched", 31)).unwrap();
        let edited = database.create_vm(&test_vm_named("vm-edited", 32)).unwrap();
        database
            .with_connection(|connection| {
                connection.execute(
                    "UPDATE vm_network_security SET drop_invalid_packets = 1 WHERE vm_id = ?1",
                    [&untouched.id],
                )?;
                connection.execute(
                    "UPDATE vm_network_security SET drop_invalid_packets = 1, revision = 1 WHERE vm_id = ?1",
                    [&edited.id],
                )?;
                connection.execute_batch(NETWORK_SECURITY_SAFE_DEFAULTS_MIGRATION)?;
                Ok(())
            })
            .unwrap();

        assert!(!database
            .vm_network_security(&untouched.id)
            .unwrap()
            .unwrap()
            .drop_invalid_packets);
        assert!(database
            .vm_network_security(&edited.id)
            .unwrap()
            .unwrap()
            .drop_invalid_packets);
        let new_vm = database.create_vm(&test_vm_named("vm-new-default", 33)).unwrap();
        assert!(!database
            .vm_network_security(&new_vm.id)
            .unwrap()
            .unwrap()
            .drop_invalid_packets);
    }

    #[test]
    fn terminal_update_status_audit_is_imported_exactly_once() {
        let database = Database::open_in_memory().unwrap();
        let request_id = Uuid::new_v4().to_string();
        let event = NewAuditEvent {
            actor_type: "system".into(),
            actor_id: Some("vexa-update-helper".into()),
            action: "update.activate".into(),
            resource_type: "update_request".into(),
            resource_id: Some(request_id.clone()),
            request_id: Some(request_id.clone()),
            source_ip: None,
            user_agent: None,
            success: true,
            details: json!({ "outcome": "succeeded" }),
        };

        assert!(database
            .import_update_status_audit(&request_id, "succeeded", &event)
            .unwrap());
        assert!(!database
            .import_update_status_audit(&request_id, "succeeded", &event)
            .unwrap());
        assert!(database
            .import_update_status_audit(&request_id, "failed", &event)
            .is_err());
        let events = database
            .list_audit(None, Some("update_request"), Some(&request_id), 10)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "update.activate");

        let mutation = database.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE update_status_audit_imports SET outcome = 'failed' WHERE request_id = ?1",
                    [&request_id],
                )
                .map(|_| ())
                .map_err(Into::into)
        });
        assert!(mutation.is_err());
    }

    #[test]
    fn host_metric_sampling_preserves_the_complete_requested_range() {
        let database = Database::open_in_memory().unwrap();
        let since = 1_700_000_000;
        for hour in 0..=168 {
            database
                .insert_host_metric(&host_metric(since + hour * 60 * 60))
                .unwrap();
        }

        let samples = database.host_metrics(since, 12).unwrap();
        assert!(samples.len() <= 12);
        assert_eq!(samples.first().unwrap().sampled_at, since + 7 * 24 * 60 * 60);
        assert!(samples.last().unwrap().sampled_at <= since + 14 * 60 * 60);
    }

    #[test]
    fn vm_metric_sampling_preserves_range_and_vm_identity() {
        let database = Database::open_in_memory().unwrap();
        let first = database.create_vm(&test_vm()).unwrap();
        let mut second_spec = test_vm();
        second_spec.name = "vm-two".into();
        second_spec.hostname = "vm-two.example.test".into();
        second_spec.tap_name = Some("tap-vm-two".into());
        second_spec.mac_address = Some("52:54:00:00:00:02".into());
        let second = database.create_vm(&second_spec).unwrap();
        let since = 1_700_000_000;
        for hour in 0..=168 {
            let sampled_at = since + hour * 60 * 60;
            database
                .insert_vm_metric(&vm_metric(&first.id, sampled_at))
                .unwrap();
            database
                .insert_vm_metric(&vm_metric(&second.id, sampled_at))
                .unwrap();
        }

        let samples = database.vm_metrics(&first.id, since, 12).unwrap();
        assert!(samples.len() <= 12);
        assert!(samples.iter().all(|sample| sample.vm_id == first.id));
        assert_eq!(samples.first().unwrap().sampled_at, since + 7 * 24 * 60 * 60);
        assert!(samples.last().unwrap().sampled_at <= since + 14 * 60 * 60);
    }

    #[test]
    fn csrf_and_one_time_customer_exchange_are_bound() {
        let database = Database::open_in_memory().unwrap();
        let admin = database
            .bootstrap_admin("admin", "$argon2id$placeholder")
            .unwrap();
        let session = [1_u8; 32];
        let csrf = [2_u8; 32];
        let now = unix_timestamp();
        database
            .create_admin_session(&admin.id, &session, &csrf, now + 600, None, None)
            .unwrap();
        assert!(database.verify_admin_session_csrf(&session, &csrf, now).unwrap());
        assert!(!database
            .verify_admin_session_csrf(&session, &[3_u8; 32], now)
            .unwrap());

        let vm = database.create_vm(&test_vm()).unwrap();
        let link = [4_u8; 32];
        let cookie = [5_u8; 32];
        database
            .create_customer_token(&vm.id, &link, &["status:read".into()], now + 3600)
            .unwrap();
        assert!(database
            .exchange_customer_link(&link, &cookie, None, now, 900)
            .unwrap()
            .is_some());
        assert!(database
            .exchange_customer_link(&link, &[6_u8; 32], None, now, 900)
            .unwrap()
            .is_none());
        assert!(database
            .authenticate_customer_session(&cookie, None, now)
            .unwrap()
            .is_some());
    }

    #[test]
    fn customer_token_revocation_is_scoped_to_its_vm() {
        let database = Database::open_in_memory().unwrap();
        let first_vm = database.create_vm(&test_vm()).unwrap();
        let mut second_spec = test_vm();
        second_spec.name = "vm-two".into();
        second_spec.hostname = "vm-two.example.test".into();
        second_spec.tap_name = Some("tap-vm-two".into());
        second_spec.mac_address = Some("52:54:00:00:00:02".into());
        let second_vm = database.create_vm(&second_spec).unwrap();
        let token = database
            .create_customer_link(
                &first_vm.id,
                &[9_u8; 32],
                &["read".into()],
                None,
                unix_timestamp() + 3600,
            )
            .unwrap();

        assert!(database
            .revoke_customer_token_for_vm(&second_vm.id, &token.id, unix_timestamp())
            .is_err());
        assert_eq!(database.list_customer_tokens(&first_vm.id).unwrap().len(), 1);
        database
            .revoke_customer_token_for_vm(&first_vm.id, &token.id, unix_timestamp())
            .unwrap();
        assert!(database.list_customer_tokens(&first_vm.id).unwrap().is_empty());
    }

    #[test]
    fn interrupted_terminal_jobs_repair_dependent_resource_states() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let reinstall = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(vm.id.clone()),
                    payload: json!({}),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Running,
            )
            .unwrap();
        database
            .claim_next_job("test-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        let (_, failed) = database.recover_interrupted_jobs(unix_timestamp() + 1).unwrap();
        assert_eq!(failed, 1);
        assert_eq!(
            database.get_job(&reinstall.id).unwrap().unwrap().status,
            JobStatus::Failed
        );
        assert_eq!(database.get_vm(&vm.id).unwrap().unwrap().state, VmState::Error);

        let snapshot = database
            .create_snapshot(&vm.id, "before-upgrade", "", false, &json!({}))
            .unwrap();
        database
            .enqueue_job(&NewJob {
                kind: "vm.snapshot.create".into(),
                vm_id: Some(vm.id.clone()),
                payload: json!({ "snapshot_id": snapshot.id.clone() }),
                idempotency_key: None,
                run_after: None,
                max_attempts: 1,
                actor_type: None,
                actor_id: None,
            })
            .unwrap();
        database
            .claim_next_job("test-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        database.recover_interrupted_jobs(unix_timestamp() + 1).unwrap();
        let snapshot = database
            .list_snapshots(&vm.id)
            .unwrap()
            .into_iter()
            .find(|item| item.id == snapshot.id)
            .unwrap();
        assert_eq!(snapshot.state, SnapshotState::Error);
        assert_eq!(
            snapshot.metadata.get("error").and_then(Value::as_str),
            Some("worker interrupted before completion")
        );
    }

    #[test]
    fn interrupted_delete_after_vm_commit_gets_a_tracked_finalizer_attempt() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let job = database
            .enqueue_delete_job(&NewJob {
                kind: "vm.delete".into(),
                vm_id: Some(vm.id.clone()),
                payload: json!({
                    "delete_storage": true,
                    "target_vm_id": vm.id.clone(),
                    "target_vm_name": vm.name.clone(),
                }),
                idempotency_key: None,
                run_after: None,
                max_attempts: 1,
                actor_type: None,
                actor_id: None,
            })
            .unwrap();
        database
            .claim_next_job("delete-worker", unix_timestamp())
            .unwrap()
            .unwrap();

        // The production worker reaches this transaction only after the
        // domain and durable seed cleanup. ON DELETE SET NULL creates the
        // small crash window between this commit and finish_job.
        database.delete_vm(&vm.id).unwrap();
        let interrupted = database.get_job(&job.id).unwrap().unwrap();
        assert_eq!(interrupted.status, JobStatus::Running);
        assert!(interrupted.vm_id.is_none());

        let (requeued, failed) = database
            .recover_interrupted_jobs(unix_timestamp() + 1)
            .unwrap();
        assert_eq!((requeued, failed), (1, 0));
        let recovered = database.get_job(&job.id).unwrap().unwrap();
        assert_eq!(recovered.status, JobStatus::Queued);
        assert_eq!(recovered.max_attempts, 2);
        assert_eq!(
            recovered
                .payload
                .get("target_vm_id")
                .and_then(Value::as_str),
            Some(vm.id.as_str())
        );
    }

    #[test]
    fn network_setting_and_default_dns_are_canonical_and_atomic() {
        let database = Database::open_in_memory().unwrap();
        let network = json!({
            "default_bridge": "vexa0",
            "dns_servers": [],
        });
        let (_, dns) = database
            .set_network_setting_and_default_dns(
                &network,
                &["2001:0db8::1".into(), "2001:db8::1".into()],
                None,
            )
            .unwrap();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].address, "2001:db8::1");
        assert_eq!(
            database
                .get_setting("network")
                .unwrap()
                .unwrap()
                .value
                .get("dns_servers"),
            Some(&json!(["2001:db8::1"]))
        );

        assert!(
            database
                .set_network_setting_and_default_dns(
                    &network,
                    &["9.9.9.9".into()],
                    Some("missing-administrator"),
                )
                .is_err()
        );
        assert_eq!(
            database.dns_servers(None, None).unwrap()[0].address,
            "2001:db8::1"
        );
        assert_eq!(
            database
                .get_setting("network")
                .unwrap()
                .unwrap()
                .value
                .get("dns_servers"),
            Some(&json!(["2001:db8::1"]))
        );
    }

    #[test]
    fn reinstall_password_is_private_and_staged_until_success() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        database.set_vm_password_envelope(&vm.id, "old-envelope").unwrap();
        let request = NewJob {
            kind: "vm.reinstall".into(),
            vm_id: Some(vm.id.clone()),
            payload: json!({ "request": { "image": "test" } }),
            idempotency_key: Some("reinstall-once".into()),
            run_after: None,
            max_attempts: 1,
            actor_type: None,
            actor_id: None,
        };
        let mut contradictory = request.clone();
        contradictory.idempotency_key = None;
        contradictory.payload = json!({ "clear_password_after_success": true });
        assert!(database
            .enqueue_reinstall_job(&contradictory, Some("must-not-be-staged"), VmState::Running,)
            .is_err());
        assert_eq!(database.get_vm(&vm.id).unwrap().unwrap().state, VmState::Creating);
        let job = database
            .enqueue_reinstall_job(&request, Some("new-envelope"), VmState::Running)
            .unwrap();
        assert_eq!(
            database.vm_password_envelope(&vm.id).unwrap().as_deref(),
            Some("old-envelope")
        );
        assert_eq!(
            job.payload
                .get(STAGED_PASSWORD_ENVELOPE_FIELD)
                .and_then(Value::as_str),
            Some("new-envelope")
        );
        assert!(serde_json::to_value(&job).unwrap().get("payload").is_none());
        assert_eq!(
            database
                .enqueue_reinstall_job(&request, Some("different-retry-envelope"), VmState::Running,)
                .unwrap()
                .id,
            job.id
        );

        database
            .claim_next_job("test-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        let failed = database
            .fail_job(&job.id, "provisioning failed", None, unix_timestamp())
            .unwrap();
        assert!(failed.payload.get(STAGED_PASSWORD_ENVELOPE_FIELD).is_none());
        assert_eq!(
            database.vm_password_envelope(&vm.id).unwrap().as_deref(),
            Some("old-envelope")
        );

        database.clear_vm_password(&vm.id).unwrap();
        assert!(database.vm_password_envelope(&vm.id).unwrap().is_none());
    }

    #[test]
    fn reinstall_credential_commit_survives_a_later_job_failure() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        database.set_vm_password_envelope(&vm.id, "old-envelope").unwrap();
        let job = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(vm.id.clone()),
                    payload: json!({ "request": { "image": "test" } }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                Some("replacement-envelope"),
                VmState::Running,
            )
            .unwrap();
        database
            .claim_next_job("reinstall-worker", unix_timestamp())
            .unwrap()
            .unwrap();

        // This is the point immediately after the destructive hypervisor call.
        // Repeating it is harmless if worker bookkeeping is retried.
        database
            .commit_reinstall_password_after_hypervisor(&job.id)
            .unwrap();
        database
            .commit_reinstall_password_after_hypervisor(&job.id)
            .unwrap();
        assert_eq!(
            database.vm_password_envelope(&vm.id).unwrap().as_deref(),
            Some("replacement-envelope")
        );

        // Simulate a firewall/start/traffic post-step failure. Terminal job
        // cleanup removes its private staged field, not the now-authoritative
        // VM credential.
        let failed = database
            .fail_job(
                &job.id,
                "post-provisioning policy failed",
                None,
                unix_timestamp(),
            )
            .unwrap();
        assert!(failed.payload.get(STAGED_PASSWORD_ENVELOPE_FIELD).is_none());
        assert_eq!(
            database.vm_password_envelope(&vm.id).unwrap().as_deref(),
            Some("replacement-envelope")
        );
    }

    #[test]
    fn manual_reinstall_credential_clear_survives_a_later_job_failure() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        database.set_vm_password_envelope(&vm.id, "old-envelope").unwrap();
        let job = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(vm.id.clone()),
                    payload: json!({
                        "request": { "image": "manual-installer" },
                        "clear_password_after_success": true,
                    }),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                None,
                VmState::Stopped,
            )
            .unwrap();
        database
            .claim_next_job("manual-reinstall-worker", unix_timestamp())
            .unwrap()
            .unwrap();
        database
            .commit_reinstall_password_after_hypervisor(&job.id)
            .unwrap();
        database
            .fail_job(
                &job.id,
                "post-provisioning inventory failed",
                None,
                unix_timestamp(),
            )
            .unwrap();
        assert!(database.vm_password_envelope(&vm.id).unwrap().is_none());
    }

    #[test]
    fn cancelling_queued_jobs_repairs_provisional_resource_state() {
        let database = Database::open_in_memory().unwrap();
        let provisional = database.create_vm(&test_vm()).unwrap();
        for (address, prefix_length) in [("203.0.113.45", 24), ("2001:db8::45", 64)] {
            database
                .upsert_ip_address(&NewIpAddress {
                    pool_id: None,
                    address: address.into(),
                    prefix_length,
                    scope: IpScope::Public,
                    status: IpStatus::Free,
                    gateway: None,
                    reverse_dns: None,
                    metadata: json!({}),
                })
                .unwrap();
            database.assign_ip(address, &provisional.id, true).unwrap();
        }
        // Simulate an existing database installed before the trigger was
        // shipped. The cancellation path must remain self-contained.
        database
            .with_connection(|connection| {
                connection.execute_batch("DROP TRIGGER release_ip_addresses_before_vm_delete")?;
                Ok(())
            })
            .unwrap();
        let create = database
            .enqueue_job(&NewJob {
                kind: "vm.create".into(),
                vm_id: Some(provisional.id.clone()),
                payload: json!({}),
                idempotency_key: None,
                run_after: None,
                max_attempts: 1,
                actor_type: None,
                actor_id: None,
            })
            .unwrap();
        database.cancel_job(&create.id, unix_timestamp()).unwrap();
        assert_eq!(
            database.get_job(&create.id).unwrap().unwrap().status,
            JobStatus::Cancelled
        );
        assert!(database.get_vm(&provisional.id).unwrap().is_none());
        for address in ["203.0.113.45", "2001:db8::45"] {
            let record = database.get_ip_address(address).unwrap().unwrap();
            assert_eq!(record.status, IpStatus::Free);
            assert!(record.assigned_vm_id.is_none());
            assert!(!record.primary_for_vm);
        }

        let mut spec = test_vm();
        spec.name = "vm-two".into();
        spec.hostname = "vm-two.example.test".into();
        spec.tap_name = Some("tap-vm-two".into());
        spec.mac_address = Some("52:54:00:00:00:02".into());
        let vm = database.create_vm(&spec).unwrap();
        database.set_vm_password_envelope(&vm.id, "old-envelope").unwrap();
        let reinstall = database
            .enqueue_reinstall_job(
                &NewJob {
                    kind: "vm.reinstall".into(),
                    vm_id: Some(vm.id.clone()),
                    payload: json!({}),
                    idempotency_key: None,
                    run_after: None,
                    max_attempts: 1,
                    actor_type: None,
                    actor_id: None,
                },
                Some("new-envelope"),
                VmState::Running,
            )
            .unwrap();
        database.cancel_job(&reinstall.id, unix_timestamp()).unwrap();
        assert_eq!(database.get_vm(&vm.id).unwrap().unwrap().state, VmState::Unknown);
        assert_eq!(
            database.vm_password_envelope(&vm.id).unwrap().as_deref(),
            Some("old-envelope")
        );
        assert!(database
            .get_job(&reinstall.id)
            .unwrap()
            .unwrap()
            .payload
            .get(STAGED_PASSWORD_ENVELOPE_FIELD)
            .is_none());

        let snapshot = database
            .create_snapshot(&vm.id, "cancel-me", "", false, &json!({}))
            .unwrap();
        let snapshot_job = database
            .enqueue_job(&NewJob {
                kind: "vm.snapshot.create".into(),
                vm_id: Some(vm.id.clone()),
                payload: json!({ "snapshot_id": snapshot.id.clone() }),
                idempotency_key: None,
                run_after: None,
                max_attempts: 1,
                actor_type: None,
                actor_id: None,
            })
            .unwrap();
        database.cancel_job(&snapshot_job.id, unix_timestamp()).unwrap();
        let snapshot = database
            .list_snapshots(&vm.id)
            .unwrap()
            .into_iter()
            .find(|item| item.id == snapshot.id)
            .unwrap();
        assert_eq!(snapshot.state, SnapshotState::Error);
        assert_eq!(
            snapshot.metadata.get("error").and_then(Value::as_str),
            Some("job cancelled")
        );
    }

    #[test]
    fn optional_network_controls_are_inert_while_ownership_guard_defaults_on() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let profile = database.vm_network_security(&vm.id).unwrap().unwrap();
        assert!(!profile.firewall_enabled);
        assert!(!profile.ddos_enabled);
        assert_eq!(profile.syn_rate_limit_pps, Some(5_000));
        assert_eq!(profile.udp_rate_limit_pps, Some(25_000));
        assert_eq!(profile.icmp_rate_limit_pps, Some(1_000));
        assert_eq!(profile.new_connection_limit_pps, Some(10_000));
        assert!(!profile.drop_invalid_packets);
        assert_eq!(profile.revision, 0);
        let host_defaults = database.hypervisor_network_security().unwrap();
        assert!(host_defaults.ip_ownership_guard_enabled);
        assert!(!host_defaults.bcp38_enabled);

        let rule = database
            .create_vm_firewall_rule(
                &vm.id,
                &NewVmFirewallRule {
                    priority: 100,
                    direction: FirewallDirection::Ingress,
                    action: FirewallAction::Drop,
                    protocol: FirewallProtocol::Tcp,
                    source_cidr: Some("192.0.2.9/24".into()),
                    destination_cidr: None,
                    source_ports: vec![],
                    destination_ports: vec![PortRange::single(22)],
                    log: true,
                    enabled: false,
                    description: "SSH guard".into(),
                },
            )
            .unwrap();
        assert!(!rule.enabled);
        assert_eq!(rule.owner_type, "admin");
        assert_eq!(rule.owner_id, None);
        assert_eq!(rule.source_cidr.as_deref(), Some("192.0.2.0/24"));
        let customer_rule = database
            .create_vm_firewall_rule_owned(
                &vm.id,
                &NewVmFirewallRule {
                    priority: 200,
                    direction: FirewallDirection::Ingress,
                    action: FirewallAction::Drop,
                    protocol: FirewallProtocol::Udp,
                    source_cidr: None,
                    destination_cidr: None,
                    source_ports: vec![],
                    destination_ports: vec![PortRange::single(53)],
                    log: false,
                    enabled: false,
                    description: "Customer DNS block".into(),
                },
                "customer_token",
                Some("status-token-id"),
            )
            .unwrap();
        assert_eq!(customer_rule.owner_type, "customer_token");
        assert_eq!(customer_rule.owner_id.as_deref(), Some("status-token-id"));
        let profile = database.vm_network_security(&vm.id).unwrap().unwrap();
        let compiled = crate::services::network_security::compile_vm_network_policy(
            &profile,
            &database.list_vm_firewall_rules(&vm.id).unwrap(),
        )
        .unwrap();
        assert!(compiled.rules.is_empty());
        assert!(compiled.ddos.is_none());

        database
            .patch_vm_firewall_rule(
                &vm.id,
                &rule.id,
                &VmFirewallRulePatch {
                    enabled: Some(true),
                    ..VmFirewallRulePatch::default()
                },
            )
            .unwrap();
        let profile = database
            .patch_vm_network_security(
                &vm.id,
                &VmNetworkSecurityPatch {
                    firewall_enabled: Some(true),
                    ddos_enabled: Some(true),
                    syn_rate_limit_pps: Some(Some(2_000)),
                    drop_invalid_packets: Some(true),
                    ..VmNetworkSecurityPatch::default()
                },
            )
            .unwrap();
        let compiled = crate::services::network_security::compile_vm_network_policy(
            &profile,
            &database.list_vm_firewall_rules(&vm.id).unwrap(),
        )
        .unwrap();
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.ddos.unwrap().syn_rate_limit_pps, Some(2_000));
        assert!(database
            .mark_vm_network_security_applied(&vm.id, profile.revision, None)
            .unwrap()
            .last_error
            .is_none());

        let host = database
            .patch_hypervisor_network_security(
                &HypervisorNetworkSecurityPatch {
                    ip_ownership_guard_enabled: None,
                    bcp38_enabled: Some(true),
                },
                Some("admin-id"),
            )
            .unwrap();
        assert!(host.bcp38_enabled);
        assert!(host.ip_ownership_guard_enabled);
        assert_eq!(host.revision, 2);

        let host = database
            .patch_hypervisor_network_security(
                &HypervisorNetworkSecurityPatch {
                    ip_ownership_guard_enabled: Some(false),
                    bcp38_enabled: None,
                },
                Some("admin-id"),
            )
            .unwrap();
        assert!(!host.ip_ownership_guard_enabled);
        assert!(host.bcp38_enabled);
        assert_eq!(host.revision, 3);
    }

    #[test]
    fn firewall_rule_ownership_and_vm_scope_survive_mutation() {
        let database = Database::open_in_memory().unwrap();
        let first = database.create_vm(&test_vm()).unwrap();
        let mut second_spec = test_vm();
        second_spec.name = "vm-two".into();
        second_spec.hostname = "vm-two.example.test".into();
        second_spec.tap_name = Some("tap-vm-two".into());
        second_spec.mac_address = Some("52:54:00:00:00:02".into());
        let second = database.create_vm(&second_spec).unwrap();
        let rule_spec = NewVmFirewallRule {
            priority: 100,
            direction: FirewallDirection::Ingress,
            action: FirewallAction::Drop,
            protocol: FirewallProtocol::Tcp,
            source_cidr: None,
            destination_cidr: None,
            source_ports: vec![],
            destination_ports: vec![PortRange::single(22)],
            log: false,
            enabled: false,
            description: "Customer SSH block".into(),
        };

        assert!(database
            .create_vm_firewall_rule_owned(
                &first.id,
                &rule_spec,
                "customer_token",
                None,
            )
            .is_err());
        assert!(database
            .create_vm_firewall_rule_owned(&first.id, &rule_spec, "untrusted", Some("actor"))
            .is_err());

        let rule = database
            .create_vm_firewall_rule_owned(
                &first.id,
                &rule_spec,
                "customer_token",
                Some("status-token-id"),
            )
            .unwrap();
        assert!(database
            .get_vm_firewall_rule(&second.id, &rule.id)
            .unwrap()
            .is_none());
        assert!(matches!(
            database.patch_vm_firewall_rule(
                &second.id,
                &rule.id,
                &VmFirewallRulePatch {
                    enabled: Some(true),
                    ..VmFirewallRulePatch::default()
                },
            ),
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            database.delete_vm_firewall_rule(&second.id, &rule.id),
            Err(AppError::NotFound(_))
        ));

        let patched = database
            .patch_vm_firewall_rule(
                &first.id,
                &rule.id,
                &VmFirewallRulePatch {
                    enabled: Some(true),
                    description: Some("Updated customer SSH block".into()),
                    ..VmFirewallRulePatch::default()
                },
            )
            .unwrap();
        assert!(patched.enabled);
        assert_eq!(patched.owner_type, "customer_token");
        assert_eq!(patched.owner_id.as_deref(), Some("status-token-id"));
    }

    #[test]
    fn deleting_a_vm_releases_assigned_dual_stack_addresses_and_preserves_history() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        for (address, prefix_length) in [("203.0.113.25", 24), ("2001:db8::25", 64)] {
            database
                .upsert_ip_address(&NewIpAddress {
                    pool_id: None,
                    address: address.into(),
                    prefix_length,
                    scope: IpScope::Public,
                    status: IpStatus::Free,
                    gateway: None,
                    reverse_dns: None,
                    metadata: json!({}),
                })
                .unwrap();
            database.assign_ip(address, &vm.id, true).unwrap();
        }
        let abuse = database
            .record_ip_abuse(&NewIpAbuseRecord {
                address: "203.0.113.25".into(),
                vm_id: Some(vm.id.clone()),
                category: "spam".into(),
                severity: 4,
                summary: "provider complaint".into(),
                reporter: Some("example-datacenter".into()),
                provider_reference: Some("CASE-25".into()),
                observed_at: None,
                metadata: json!({}),
            })
            .unwrap();
        database
            .append_audit(&NewAuditEvent {
                actor_type: "admin".into(),
                actor_id: Some("admin-1".into()),
                action: "vm.delete.request".into(),
                resource_type: "vm".into(),
                resource_id: Some(vm.id.clone()),
                request_id: None,
                source_ip: None,
                user_agent: None,
                success: true,
                details: json!({}),
            })
            .unwrap();

        // Existing installations may predate the defensive trigger in the
        // initial schema; the explicit transaction must be sufficient.
        database
            .with_connection(|connection| {
                connection.execute_batch("DROP TRIGGER release_ip_addresses_before_vm_delete")?;
                Ok(())
            })
            .unwrap();

        database.delete_vm(&vm.id).unwrap();

        assert!(database.get_vm(&vm.id).unwrap().is_none());
        for address in ["203.0.113.25", "2001:db8::25"] {
            let record = database.get_ip_address(address).unwrap().unwrap();
            assert_eq!(record.status, IpStatus::Free);
            assert!(record.assigned_vm_id.is_none());
            assert!(!record.primary_for_vm);
        }
        let abuse = database.get_ip_abuse_record(&abuse.id).unwrap().unwrap();
        assert!(abuse.vm_id.is_none());
        assert_eq!(abuse.address, "203.0.113.25");
        let events = database
            .list_audit(None, Some("vm"), Some(&vm.id), 10)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "vm.delete.request");
    }

    #[test]
    fn blacklisted_addresses_cannot_be_newly_assigned() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        database
            .upsert_ip_address(&NewIpAddress {
                pool_id: None,
                address: "203.0.113.25".into(),
                prefix_length: 24,
                scope: IpScope::Public,
                status: IpStatus::Free,
                gateway: Some("203.0.113.1".into()),
                reverse_dns: None,
                metadata: json!({}),
            })
            .unwrap();
        let entry = database
            .create_ip_blacklist_entry(&NewIpBlacklistEntry {
                cidr: "203.0.113.16/28".into(),
                reason: "datacenter abuse hold".into(),
                source: "provider".into(),
                enabled: true,
                expires_at: None,
                created_by: Some("admin-id".into()),
                metadata: json!({"ticket": "DC-1"}),
            })
            .unwrap();
        assert!(database
            .ip_is_blacklisted("203.0.113.25", unix_timestamp())
            .unwrap());
        assert!(matches!(
            database.assign_ip("203.0.113.25", &vm.id, true),
            Err(AppError::Conflict(_))
        ));

        database
            .patch_ip_blacklist_entry(
                &entry.id,
                &IpBlacklistPatch {
                    enabled: Some(false),
                    ..IpBlacklistPatch::default()
                },
            )
            .unwrap();
        assert!(!database
            .ip_is_blacklisted("203.0.113.25", unix_timestamp())
            .unwrap());
        assert_eq!(
            database
                .assign_ip("203.0.113.25", &vm.id, true)
                .unwrap()
                .assigned_vm_id
                .as_deref(),
            Some(vm.id.as_str())
        );
    }

    #[test]
    fn disabled_ip_pools_block_new_allocations_but_preserve_existing_ownership() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let pool = database
            .create_ip_pool(&NewIpPool {
                name: "Imported routed range".into(),
                cidr: "203.0.113.0/29".into(),
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
                address: "203.0.113.2".into(),
                prefix_length: 32,
                scope: IpScope::Public,
                status: IpStatus::Free,
                gateway: None,
                reverse_dns: None,
                metadata: json!({"topology": "legacy-routed"}),
            })
            .unwrap();

        assert!(matches!(
            database.assign_ip("203.0.113.2", &vm.id, true),
            Err(AppError::Conflict(message)) if message.contains("disabled pool")
        ));

        database
            .patch_ip_pool(
                &pool.id,
                &IpPoolPatch {
                    enabled: Some(true),
                    ..IpPoolPatch::default()
                },
            )
            .unwrap();
        database.assign_ip("203.0.113.2", &vm.id, true).unwrap();
        database
            .patch_ip_pool(
                &pool.id,
                &IpPoolPatch {
                    enabled: Some(false),
                    ..IpPoolPatch::default()
                },
            )
            .unwrap();

        let existing = database.assign_ip("203.0.113.2", &vm.id, false).unwrap();
        assert_eq!(existing.assigned_vm_id.as_deref(), Some(vm.id.as_str()));
        assert!(!existing.primary_for_vm);
    }

    #[test]
    fn detected_host_refresh_preserves_imported_main_address_details() {
        let database = Database::open_in_memory().unwrap();
        let pool = database
            .create_ip_pool(&NewIpPool {
                name: "Imported routed range".into(),
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
                        "preserved_status": "main"
                    },
                    "operator_note": "keep"
                }),
            })
            .unwrap();

        let refreshed = database
            .upsert_detected_host_address(&NewIpAddress {
                pool_id: None,
                address: "203.0.113.10".into(),
                prefix_length: 24,
                scope: IpScope::Public,
                status: IpStatus::Main,
                gateway: None,
                reverse_dns: None,
                metadata: json!({
                    "detected_host_address": true,
                    "interface": "eno49"
                }),
            })
            .unwrap();

        assert_eq!(refreshed.status, IpStatus::Main);
        assert_eq!(refreshed.pool_id.as_deref(), Some(pool.id.as_str()));
        assert_eq!(refreshed.gateway.as_deref(), Some("203.0.113.1"));
        assert_eq!(refreshed.reverse_dns.as_deref(), Some("node.example.test"));
        assert_eq!(
            refreshed.metadata.pointer("/legacy_import/source"),
            Some(&json!("legacy-controller"))
        );
        assert_eq!(refreshed.metadata["operator_note"], "keep");
        assert_eq!(refreshed.metadata["detected_host_address"], true);
        assert_eq!(refreshed.metadata["interface"], "eno49");
        assert!(!database.get_ip_pool(&pool.id).unwrap().unwrap().enabled);
    }

    #[test]
    fn ip_abuse_records_retain_provider_evidence_and_resolution() {
        let database = Database::open_in_memory().unwrap();
        let vm = database.create_vm(&test_vm()).unwrap();
        let record = database
            .record_ip_abuse(&NewIpAbuseRecord {
                address: "2001:0db8::44".into(),
                vm_id: Some(vm.id.clone()),
                category: "port_scan".into(),
                severity: 7,
                summary: "outbound scan complaint".into(),
                reporter: Some("example-datacenter".into()),
                provider_reference: Some("ABUSE-42".into()),
                observed_at: None,
                metadata: json!({"evidence_sha256": "abc"}),
            })
            .unwrap();
        assert_eq!(record.address, "2001:db8::44");
        assert_eq!(
            database
                .list_ip_abuse_records(Some("2001:db8::44"), None, true, 50)
                .unwrap()
                .len(),
            1
        );
        let resolved = database
            .resolve_ip_abuse_record(&record.id, Some("admin-id"), "customer remediated")
            .unwrap();
        assert!(resolved.resolved_at.is_some());
        assert!(database
            .list_ip_abuse_records(None, Some(&vm.id), true, 50)
            .unwrap()
            .is_empty());
    }
}
