//! EKKA Node Module Registry Interface
//!
//! Defines common types and contracts for node modules.
//! Modules follow a consistent pattern for registration and error handling.
//!
//! ## Module Disabled Policy
//!
//! When a module is disabled, its routes are NOT mounted -> 404.
//! This is the preferred approach for security (no information leakage).
//!
//! ## Capability Gates (RAPTOR-2 Step 17)
//!
//! Even when a module is mounted, access can be gated by capabilities.
//! - Module disabled = 404 (routes not mounted)
//! - Missing capability = 403 CAPABILITY_DENIED
//! - Error messages NEVER contain capability names (security)

use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// =============================================================================
// Common Error Types
// =============================================================================

/// Standard module error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleError {
    pub error: String,
    pub code: String,
}

impl ModuleError {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }

    /// Feature disabled error
    pub fn feature_disabled(feature: &str) -> Self {
        Self {
            error: format!("{} feature is disabled on this node", feature),
            code: "FEATURE_DISABLED".to_string(),
        }
    }

    /// Missing capability error
    pub fn missing_capability(capability: &str) -> Self {
        Self {
            error: format!("Missing required capability: {}", capability),
            code: "MISSING_CAPABILITY".to_string(),
        }
    }

    /// Resource not found
    pub fn not_found(resource: &str) -> Self {
        Self {
            error: format!("{} not found", resource),
            code: format!("{}_NOT_FOUND", resource.to_uppercase().replace(' ', "_")),
        }
    }
}

// =============================================================================
// Module Configuration
// =============================================================================

/// Module enablement configuration
#[derive(Debug, Clone)]
pub struct ModuleConfig {
    /// Human-readable module name
    pub name: &'static str,
    /// Environment variable to check for enablement
    pub env_var: &'static str,
    /// Default enabled state
    pub default_enabled: bool,
}

impl ModuleConfig {
    /// Check if module is enabled via environment variable
    pub fn is_enabled(&self) -> bool {
        std::env::var(self.env_var)
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(self.default_enabled)
    }
}

// =============================================================================
// Common Constants
// =============================================================================

/// Standard error codes used across modules
pub mod error_codes {
    pub const FEATURE_DISABLED: &str = "FEATURE_DISABLED";
    pub const MISSING_CAPABILITY: &str = "MISSING_CAPABILITY";
    pub const CAPABILITY_DENIED: &str = "CAPABILITY_DENIED";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    pub const INVALID_REQUEST: &str = "INVALID_REQUEST";
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
    pub const FORBIDDEN: &str = "FORBIDDEN";
}

// =============================================================================
// Session Types (shared across modules)
// =============================================================================

/// Session information returned by validator
/// Contains only what modules need - no JWT, no secrets
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub tenant_id: String,
    pub user_id: String,
    /// Capabilities granted to this session
    /// e.g., ["actions.use", "vault.read", "workspaces.read", "git.read"]
    pub capabilities: Vec<String>,
}

impl SessionInfo {
    /// Check if session has a specific capability
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    /// Require a capability, returning CAPABILITY_DENIED error if missing
    /// Error message is intentionally vague (no capability names exposed)
    pub fn require_capability(&self, capability: &str) -> Result<(), CapabilityDeniedError> {
        if self.has_capability(capability) {
            Ok(())
        } else {
            Err(CapabilityDeniedError)
        }
    }
}

/// Error from session validation
#[derive(Debug, Clone)]
pub struct SessionValidationError {
    pub error: String,
    pub code: String,
    pub status: StatusCode,
}

/// Session validator function type
/// Takes headers and returns either SessionInfo or an error
pub type SessionValidator = Arc<
    dyn Fn(&HeaderMap) -> Result<SessionInfo, SessionValidationError> + Send + Sync,
>;

// =============================================================================
// Capability Gate Errors
// =============================================================================

/// Capability denied error - intentionally opaque
/// Error message NEVER contains capability name (security)
#[derive(Debug, Clone)]
pub struct CapabilityDeniedError;

impl CapabilityDeniedError {
    /// Convert to safe HTTP error response
    /// IMPORTANT: Message is intentionally vague - no capability names
    pub fn to_module_error(&self) -> ModuleError {
        ModuleError {
            error: "Not permitted".to_string(),
            code: error_codes::CAPABILITY_DENIED.to_string(),
        }
    }

    /// HTTP status code for capability denied
    pub fn status_code(&self) -> StatusCode {
        StatusCode::FORBIDDEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_path_leak(json: &str) {
        assert!(!json.contains("/Users"), "Leaked /Users path: {}", json);
        assert!(!json.contains("/home"), "Leaked /home path: {}", json);
        assert!(!json.contains("/var"), "Leaked /var path: {}", json);
        assert!(!json.contains("/tmp"), "Leaked /tmp path: {}", json);
        assert!(!json.contains("C:\\"), "Leaked C:\\ path: {}", json);
    }

    #[test]
    fn test_module_error_no_paths() {
        let error = ModuleError::feature_disabled("Git");
        let json = serde_json::to_string(&error).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_missing_capability_error() {
        let error = ModuleError::missing_capability("git:read");
        assert_eq!(error.code, "MISSING_CAPABILITY");
        assert!(error.error.contains("git:read"));
    }

    #[test]
    fn test_module_config_default_disabled() {
        let config = ModuleConfig {
            name: "test",
            env_var: "EKKA_TEST_MODULE_NONEXISTENT",
            default_enabled: false,
        };
        assert!(!config.is_enabled());
    }

    // =========================================================================
    // Session and Capability Tests
    // =========================================================================

    #[test]
    fn test_session_info_has_capability() {
        let session = SessionInfo {
            session_id: "sess-123".to_string(),
            tenant_id: "tenant-abc".to_string(),
            user_id: "user-xyz".to_string(),
            capabilities: vec![
                "actions.use".to_string(),
                "vault.read".to_string(),
                "workspaces.read".to_string(),
            ],
        };

        assert!(session.has_capability("actions.use"));
        assert!(session.has_capability("vault.read"));
        assert!(session.has_capability("workspaces.read"));
        assert!(!session.has_capability("git.read"));
        assert!(!session.has_capability("unknown"));
    }

    #[test]
    fn test_session_info_require_capability_success() {
        let session = SessionInfo {
            session_id: "sess-123".to_string(),
            tenant_id: "tenant-abc".to_string(),
            user_id: "user-xyz".to_string(),
            capabilities: vec!["git.read".to_string()],
        };

        assert!(session.require_capability("git.read").is_ok());
    }

    #[test]
    fn test_session_info_require_capability_denied() {
        let session = SessionInfo {
            session_id: "sess-123".to_string(),
            tenant_id: "tenant-abc".to_string(),
            user_id: "user-xyz".to_string(),
            capabilities: vec!["actions.use".to_string()],
        };

        assert!(session.require_capability("git.read").is_err());
    }

    #[test]
    fn test_capability_denied_error_no_capability_name() {
        // CRITICAL: Error message must NOT contain capability names
        let err = CapabilityDeniedError;
        let module_error = err.to_module_error();
        let json = serde_json::to_string(&module_error).unwrap();

        // Must NOT contain any capability names
        assert!(!json.contains("git"), "Error leaked capability name: {}", json);
        assert!(!json.contains("workspaces"), "Error leaked capability name: {}", json);
        assert!(!json.contains("vault"), "Error leaked capability name: {}", json);
        assert!(!json.contains("actions"), "Error leaked capability name: {}", json);
        assert!(!json.contains("read"), "Error leaked capability name: {}", json);

        // Must contain generic error message
        assert!(json.contains("Not permitted"), "Missing generic error: {}", json);
        assert!(json.contains("CAPABILITY_DENIED"), "Missing error code: {}", json);
    }

    #[test]
    fn test_capability_denied_status_code() {
        let err = CapabilityDeniedError;
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_capability_denied_response_format() {
        let err = CapabilityDeniedError;
        let module_error = err.to_module_error();

        // Verify exact response format
        assert_eq!(module_error.error, "Not permitted");
        assert_eq!(module_error.code, "CAPABILITY_DENIED");
    }

    #[test]
    fn test_session_info_empty_capabilities() {
        let session = SessionInfo {
            session_id: "sess-123".to_string(),
            tenant_id: "tenant-abc".to_string(),
            user_id: "user-xyz".to_string(),
            capabilities: vec![],
        };

        assert!(!session.has_capability("anything"));
        assert!(session.require_capability("anything").is_err());
    }
}
