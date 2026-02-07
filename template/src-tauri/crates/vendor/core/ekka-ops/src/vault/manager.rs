//! Vault Manager
//!
//! Internal vault manager that handles encryption/decryption with tenant scoping.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};
use ekka_crypto::KeyDerivationConfig;
use ekka_path_guard::PathGuard;
use ekka_vault::{Vault, VaultConfig};
use serde::{Deserialize, Serialize};

use super::types::{AuditAction, AuditEvent, AuditLog};

/// Vault manager that handles encryption/decryption
///
/// This is exposed publicly for caching purposes. External code should
/// not construct this directly but instead use `get_or_init_vault_manager`.
pub struct VaultManager {
    pub(crate) vault: Vault,
    tenant_id: String,
    actor_id: Option<String>,
}

impl VaultManager {
    /// Create a new VaultManager with tenant scoping
    pub fn new(ctx: &RuntimeContext) -> EkkaResult<Self> {
        let home_path = ctx.home_path.clone();
        let vault_path = home_path.join("vault");

        // Get auth context for key derivation and tenant scoping
        let auth = ctx.auth.as_ref().ok_or_else(|| {
            EkkaError::new(
                codes::NOT_AUTHENTICATED,
                "Must be authenticated to access vault",
            )
        })?;

        // Create path guard for vault
        let path_guard = PathGuard::home_only(home_path.clone());

        // Get device secret from context
        // TODO: Get actual device secret from secure storage
        let device_secret = ctx.node_id.to_string();

        let config = VaultConfig {
            vault_path,
            user_id: auth.sub.clone(),
            device_secret,
            security_epoch: 1,
            key_config: KeyDerivationConfig::default(),
        };

        let vault = Vault::new(config, path_guard)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to initialize vault", e))?;

        Ok(Self {
            vault,
            tenant_id: auth.tenant_id.clone(),
            actor_id: Some(auth.sub.clone()),
        })
    }

    /// Get the tenant ID
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Get the actor ID for audit
    pub fn actor_id(&self) -> Option<&str> {
        self.actor_id.as_deref()
    }

    /// Read JSON from a tenant-scoped path
    pub fn read_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> EkkaResult<T> {
        let full_path = format!("t_{}/{}", self.tenant_id, path);

        if !self.vault.exists(&full_path) {
            return Err(EkkaError::new(
                codes::VAULT_ERROR,
                format!("File not found: {}", path),
            ));
        }

        let content = self
            .vault
            .read_string(&full_path)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to read vault file", e))?;

        serde_json::from_str(&content)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to parse vault file", e))
    }

    /// Read JSON or return default if file doesn't exist
    pub fn read_json_or_default<T: for<'de> Deserialize<'de> + Default>(
        &self,
        path: &str,
    ) -> EkkaResult<T> {
        let full_path = format!("t_{}/{}", self.tenant_id, path);

        if !self.vault.exists(&full_path) {
            return Ok(T::default());
        }

        let content = self
            .vault
            .read_string(&full_path)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to read vault file", e))?;

        serde_json::from_str(&content)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to parse vault file", e))
    }

    /// Write JSON to a tenant-scoped path
    pub fn write_json<T: Serialize>(&self, path: &str, data: &T) -> EkkaResult<()> {
        let full_path = format!("t_{}/{}", self.tenant_id, path);

        let content = serde_json::to_string_pretty(data)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to serialize data", e))?;

        self.vault
            .write_string(&full_path, &content)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to write vault file", e))?;

        Ok(())
    }

    /// Write a secret value (encrypted)
    pub fn write_secret_value(&self, secret_id: &str, value: &str) -> EkkaResult<()> {
        let path = format!("t_{}/values/{}.enc", self.tenant_id, secret_id);
        self.vault
            .write_string(&path, value)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to write secret value", e))
    }

    /// Read a secret value (decrypted)
    #[allow(dead_code)]
    pub fn read_secret_value(&self, secret_id: &str) -> EkkaResult<String> {
        let path = format!("t_{}/values/{}.enc", self.tenant_id, secret_id);
        self.vault
            .read_string(&path)
            .map_err(|e| EkkaError::from_source(codes::SECRET_NOT_FOUND, "Failed to read secret value", e))
    }

    /// Delete a secret value
    pub fn delete_secret_value(&self, secret_id: &str) -> EkkaResult<()> {
        let path = format!("t_{}/values/{}.enc", self.tenant_id, secret_id);
        self.vault
            .delete(&path)
            .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to delete secret value", e))
    }

    /// Record an audit event
    pub fn record_audit_event(&self, event: AuditEvent) -> EkkaResult<()> {
        let month = &event.timestamp[..7]; // "2026-01"
        let path = format!("audit/{}.json", month);

        let mut log: AuditLog = self.read_json_or_default(&path)?;
        log.events.push(event);
        self.write_json(&path, &log)
    }
}

/// Generate a unique ID with prefix
pub fn generate_id(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        uuid::Uuid::new_v4().to_string().replace("-", "")[..12].to_string()
    )
}

/// Get current timestamp in ISO format
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Create a new audit event
pub fn new_audit_event(action: AuditAction, actor_id: Option<&str>) -> AuditEvent {
    AuditEvent {
        event_id: generate_id("evt"),
        action,
        timestamp: now_iso(),
        secret_id: None,
        secret_name: None,
        bundle_id: None,
        path: None,
        actor_id: actor_id.map(String::from),
    }
}
