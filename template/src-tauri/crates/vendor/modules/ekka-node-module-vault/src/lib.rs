//! EKKA Node Vault Module - RAPTOR-2 Local Data Visibility
//!
//! Provides read-only status information about the secure local data home.
//! Never exposes absolute filesystem paths or internal implementation details.
//!
//! ## Security Properties
//!
//! - No absolute paths in responses (uses hints like "default" or "custom")
//! - Read-only status only (no modifications)
//! - Structured logging with node.vault.* prefix
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - A VaultModuleContext with vault state
//!
//! When disabled via EKKA_ENABLE_VAULT=0, routes are NOT mounted -> 404.

use axum::{
    extract::State,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

pub use ekka_node_modules::{error_codes, ModuleConfig, ModuleError};

// =============================================================================
// Module Configuration
// =============================================================================

/// Vault module configuration
pub const VAULT_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Vault",
    env_var: "EKKA_ENABLE_VAULT",
    default_enabled: true, // Vault is read-only and safe, enabled by default
};

// =============================================================================
// Vault Status Types
// =============================================================================

/// Vault initialization status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Ready,
    NotInitialized,
    #[allow(dead_code)] // Part of API contract, used for future error states
    Error,
}

impl std::fmt::Display for VaultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultStatus::Ready => write!(f, "ready"),
            VaultStatus::NotInitialized => write!(f, "not_initialized"),
            VaultStatus::Error => write!(f, "error"),
        }
    }
}

/// Vault status response - safe for external consumption
#[derive(Debug, Serialize)]
pub struct VaultStatusResponse {
    /// Overall status of the vault
    pub status: VaultStatus,
    /// Whether data home is configured (true if using env var or default)
    pub data_home_configured: bool,
    /// Hint about local data path (never absolute path)
    pub local_data_path_hint: String,
    /// Whether vault subdirectory exists
    pub has_vault_dir: bool,
    /// Whether db subdirectory exists
    pub has_db_dir: bool,
    /// Whether tmp subdirectory exists
    pub has_tmp_dir: bool,
    /// Security epoch seen (as string for JSON compatibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_epoch_seen: Option<String>,
}

/// Vault error response
#[derive(Debug, Serialize)]
pub struct VaultError {
    pub error: String,
    pub code: String,
}

/// Bundle list response
#[derive(Debug, Serialize)]
pub struct VaultBundlesResponse {
    pub bundles: Vec<BundleInfo>,
}

/// Information about a stored bundle (placeholder for future)
#[derive(Debug, Serialize)]
pub struct BundleInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

// =============================================================================
// Vault State (provided by host)
// =============================================================================

/// Runtime vault state for API access
#[derive(Debug, Clone)]
pub struct VaultState {
    /// Whether the bootstrap completed successfully
    pub initialized: bool,
    /// Whether data home was configured via env var
    pub data_home_from_env: bool,
    /// Whether vault subdir exists
    pub has_vault_dir: bool,
    /// Whether db subdir exists
    pub has_db_dir: bool,
    /// Whether tmp subdir exists
    pub has_tmp_dir: bool,
    /// Security epoch seen during initialization
    pub epoch_seen: u32,
}

impl VaultState {
    /// Create vault state from bootstrap results
    pub fn from_bootstrap(
        initialized: bool,
        data_home_from_env: bool,
        has_vault_dir: bool,
        has_db_dir: bool,
        has_tmp_dir: bool,
        epoch_seen: u32,
    ) -> Self {
        Self {
            initialized,
            data_home_from_env,
            has_vault_dir,
            has_db_dir,
            has_tmp_dir,
            epoch_seen,
        }
    }

    /// Convert to status response (safe for external API)
    pub fn to_status_response(&self) -> VaultStatusResponse {
        let status = if self.initialized {
            VaultStatus::Ready
        } else {
            VaultStatus::NotInitialized
        };

        let path_hint = if self.data_home_from_env {
            "custom (environment variable)".to_string()
        } else {
            "default (~/.ekka-node)".to_string()
        };

        VaultStatusResponse {
            status,
            data_home_configured: true,
            local_data_path_hint: path_hint,
            has_vault_dir: self.has_vault_dir,
            has_db_dir: self.has_db_dir,
            has_tmp_dir: self.has_tmp_dir,
            security_epoch_seen: Some(self.epoch_seen.to_string()),
        }
    }
}

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Context for the Vault module
/// Provided by the host application when mounting
#[derive(Clone)]
pub struct VaultModuleContext {
    /// Vault state (immutable snapshot from bootstrap)
    pub vault_state: VaultState,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
}

impl VaultModuleContext {
    pub fn new(vault_state: VaultState, log_prefix: impl Into<String>) -> Self {
        Self {
            vault_state,
            log_prefix: log_prefix.into(),
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.vault.{}", self.log_prefix, op)
    }
}

/// Mount the Vault module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: VaultModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !VAULT_MODULE_CONFIG.is_enabled() {
        info!(
            module = "vault",
            enabled = false,
            "Vault module disabled (set EKKA_ENABLE_VAULT=1 to enable)"
        );
        return router;
    }

    info!(
        module = "vault",
        enabled = true,
        "Vault module enabled"
    );

    let state = Arc::new(ctx);

    // Create a sub-router with our state, then merge into main router
    let vault_router: Router<S> = Router::new()
        .route("/v0/vault/status", get(vault_status_handler))
        .route("/v0/vault/bundles", get(vault_bundles_handler))
        .with_state(state);

    router.merge(vault_router)
}

// =============================================================================
// Axum Handlers
// =============================================================================

/// GET /v0/vault/status - Get vault status (read-only, no paths exposed)
async fn vault_status_handler(
    State(ctx): State<Arc<VaultModuleContext>>,
) -> Result<Json<VaultStatusResponse>, (StatusCode, Json<VaultError>)> {
    info!(
        op = %ctx.log_op("status.ok"),
        "Vault status requested"
    );

    Ok(Json(ctx.vault_state.to_status_response()))
}

/// GET /v0/vault/bundles - List vault bundles (stub for now)
async fn vault_bundles_handler(
    State(ctx): State<Arc<VaultModuleContext>>,
) -> Result<Json<VaultBundlesResponse>, (StatusCode, Json<VaultError>)> {
    info!(
        op = %ctx.log_op("bundles.list"),
        "Vault bundles list requested"
    );

    // Stub: return empty list for now
    // Future: discover actual bundles from vault directory
    Ok(Json(VaultBundlesResponse { bundles: vec![] }))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Path Leak Tests (prove we never leak paths)
    // =========================================================================

    fn assert_no_path_leak(json: &str) {
        // Common absolute path patterns that should never appear
        assert!(!json.contains("/Users"), "Leaked /Users path: {}", json);
        assert!(!json.contains("/home"), "Leaked /home path: {}", json);
        assert!(!json.contains("/var"), "Leaked /var path: {}", json);
        assert!(!json.contains("/tmp"), "Leaked /tmp path: {}", json);
        assert!(!json.contains("/private"), "Leaked /private path: {}", json);
        assert!(!json.contains("C:\\"), "Leaked C:\\ path: {}", json);
        assert!(!json.contains("D:\\"), "Leaked D:\\ path: {}", json);
    }

    #[test]
    fn test_vault_status_display() {
        assert_eq!(VaultStatus::Ready.to_string(), "ready");
        assert_eq!(VaultStatus::NotInitialized.to_string(), "not_initialized");
        assert_eq!(VaultStatus::Error.to_string(), "error");
    }

    #[test]
    fn test_vault_state_to_response_initialized() {
        let state = VaultState::from_bootstrap(true, false, true, true, true, 42);
        let response = state.to_status_response();

        assert_eq!(response.status, VaultStatus::Ready);
        assert!(response.data_home_configured);
        assert_eq!(response.local_data_path_hint, "default (~/.ekka-node)");
        assert!(response.has_vault_dir);
        assert!(response.has_db_dir);
        assert!(response.has_tmp_dir);
        assert_eq!(response.security_epoch_seen, Some("42".to_string()));

        // Verify no path leak
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_vault_state_to_response_custom_path() {
        let state = VaultState::from_bootstrap(true, true, true, true, true, 1);
        let response = state.to_status_response();

        assert_eq!(response.local_data_path_hint, "custom (environment variable)");

        // Verify no path leak
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_vault_state_to_response_not_initialized() {
        let state = VaultState::from_bootstrap(false, false, false, false, false, 0);
        let response = state.to_status_response();

        assert_eq!(response.status, VaultStatus::NotInitialized);
        assert!(!response.has_vault_dir);

        // Verify no path leak
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_response_never_contains_paths() {
        let state = VaultState::from_bootstrap(true, true, true, true, true, 1);
        let response = state.to_status_response();
        let json = serde_json::to_string(&response).unwrap();

        // Ensure no absolute paths leak
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_bundles_response_no_paths() {
        let response = VaultBundlesResponse {
            bundles: vec![
                BundleInfo {
                    id: "bundle-1".to_string(),
                    name: "test-bundle".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_vault_error_no_paths() {
        let error = VaultError {
            error: "Vault not initialized".to_string(),
            code: "VAULT_NOT_INITIALIZED".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_module_config_default_enabled() {
        // Vault should be enabled by default (read-only, safe)
        assert!(VAULT_MODULE_CONFIG.default_enabled);
    }
}
