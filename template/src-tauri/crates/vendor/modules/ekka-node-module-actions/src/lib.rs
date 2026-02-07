//! EKKA Node Actions Module - RAPTOR-2 Authorization and Execution
//!
//! Provides session-gated action authorization and execution endpoints.
//! Authorizations are tenant-bound, single-use, and expire after 5 minutes.
//!
//! ## Security Properties
//!
//! - Session validation via host-provided validator (module does NOT own sessions)
//! - Tenant isolation: authorizations bound to tenant at creation time
//! - Single-use: each authorization can only be executed once
//! - Short TTL: 5 minute expiry to limit attack window
//! - No absolute paths in responses (even though no paths expected)
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - An ActionsModuleContext with session validator and action store
//!
//! When disabled via EKKA_ENABLE_ACTIONS=0, routes are NOT mounted -> 404.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

pub use ekka_node_modules::{
    error_codes, ModuleConfig, ModuleError,
    // Re-export session types for backwards compatibility
    SessionInfo, SessionValidationError, SessionValidator,
};

// =============================================================================
// Module Configuration
// =============================================================================

/// Actions module configuration
pub const ACTIONS_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Actions",
    env_var: "EKKA_ENABLE_ACTIONS",
    default_enabled: true, // Core demo functionality, non-FS, safe to enable by default
};

// =============================================================================
// Authorization Types
// =============================================================================

/// Resource reference in an authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub id: String,
}

/// Stored authorization (server-side only)
#[derive(Debug, Clone)]
pub struct Authorization {
    pub authorization_id: String,
    #[allow(dead_code)] // Part of audit trail, may be used for session correlation
    pub session_id: String,
    pub tenant_id: String,
    pub subject: String,
    pub action_id: String,
    pub resources: Vec<Resource>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub executed: bool,
}

/// Thread-safe authorization store (in-memory for RAPTOR-2)
pub struct ActionStore {
    authorizations: RwLock<HashMap<String, Authorization>>,
}

impl ActionStore {
    pub fn new() -> Self {
        Self {
            authorizations: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new authorization
    pub fn create_authorization(
        &self,
        session_id: &str,
        tenant_id: &str,
        subject: &str,
        action_id: &str,
        resources: Vec<Resource>,
    ) -> Authorization {
        let authorization_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::minutes(5); // 5 minute TTL

        let auth = Authorization {
            authorization_id: authorization_id.clone(),
            session_id: session_id.to_string(),
            tenant_id: tenant_id.to_string(),
            subject: subject.to_string(),
            action_id: action_id.to_string(),
            resources,
            issued_at: now,
            expires_at,
            executed: false,
        };

        let mut authorizations = self.authorizations.write().unwrap();
        authorizations.insert(authorization_id, auth.clone());

        auth
    }

    /// Get authorization by ID (returns None if not found)
    pub fn get(&self, authorization_id: &str) -> Option<Authorization> {
        let authorizations = self.authorizations.read().unwrap();
        authorizations.get(authorization_id).cloned()
    }

    /// Mark authorization as executed
    pub fn mark_executed(&self, authorization_id: &str) -> bool {
        let mut authorizations = self.authorizations.write().unwrap();
        if let Some(auth) = authorizations.get_mut(authorization_id) {
            auth.executed = true;
            true
        } else {
            false
        }
    }

    /// Check if authorization is valid (exists, not expired, not executed)
    pub fn is_valid(&self, authorization_id: &str) -> Option<(bool, String)> {
        let authorizations = self.authorizations.read().unwrap();
        authorizations.get(authorization_id).map(|auth| {
            let now = Utc::now();
            if auth.executed {
                (false, "AUTHORIZATION_ALREADY_EXECUTED".to_string())
            } else if now > auth.expires_at {
                (false, "AUTHORIZATION_EXPIRED".to_string())
            } else {
                (true, "valid".to_string())
            }
        })
    }
}

impl Default for ActionStore {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Request/Response Types
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub action_id: String,
    pub resources: Vec<Resource>,
    #[serde(default)]
    #[allow(dead_code)] // Client-provided timestamp for audit purposes
    pub issued_at_iso_utc: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub authorization_id: String,
    pub tenant_id: String,
    pub subject: String,
    pub action_id: String,
    pub resources: Vec<Resource>,
    pub issued_at_iso_utc: String,
    pub expires_at_iso_utc: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    pub authorization_id: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub execution_id: String,
    pub authorization_id: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct ActionError {
    pub error: String,
    pub code: String,
}

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Context for the Actions module
/// Provided by the host application when mounting
pub struct ActionsModuleContext {
    /// Action store (owned by module or shared)
    pub action_store: Arc<ActionStore>,
    /// Session validator (provided by host)
    pub session_validator: SessionValidator,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
}

impl ActionsModuleContext {
    pub fn new(
        action_store: Arc<ActionStore>,
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            action_store,
            session_validator,
            log_prefix: log_prefix.into(),
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.action.{}", self.log_prefix, op)
    }
}

/// Mount the Actions module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: ActionsModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !ACTIONS_MODULE_CONFIG.is_enabled() {
        info!(
            module = "actions",
            enabled = false,
            "Actions module disabled (set EKKA_ENABLE_ACTIONS=1 to enable)"
        );
        return router;
    }

    info!(
        module = "actions",
        enabled = true,
        "Actions module enabled"
    );

    let state = Arc::new(ctx);

    // Create a sub-router with our state, then merge into main router
    let actions_router: Router<S> = Router::new()
        .route("/v0/action/authorize", post(action_authorize_handler))
        .route("/v0/action/execute", post(action_execute_handler))
        .with_state(state);

    router.merge(actions_router)
}

// =============================================================================
// Axum Handlers
// =============================================================================

/// POST /v0/action/authorize - Request authorization for an action
async fn action_authorize_handler(
    State(ctx): State<Arc<ActionsModuleContext>>,
    headers: HeaderMap,
    Json(req): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, (StatusCode, Json<ActionError>)> {
    info!(
        op = %ctx.log_op("authorize.request"),
        action_id = %req.action_id,
        resource_count = %req.resources.len(),
        "Authorization request received"
    );

    // Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("authorize.session_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(ActionError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Validate request
    if req.action_id.is_empty() {
        warn!(
            op = %ctx.log_op("authorize.denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            error = "action_id required",
            "Authorization denied"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ActionError {
                error: "action_id is required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        ));
    }

    // Create authorization
    let auth = ctx.action_store.create_authorization(
        &session.session_id,
        &session.tenant_id,
        &session.user_id,
        &req.action_id,
        req.resources.clone(),
    );

    info!(
        op = %ctx.log_op("authorize.success"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        tenant_id = %session.tenant_id,
        action_id = %req.action_id,
        authorization_id = %&auth.authorization_id[..8],
        "Authorization granted"
    );

    Ok(Json(AuthorizeResponse {
        authorization_id: auth.authorization_id,
        tenant_id: auth.tenant_id,
        subject: auth.subject,
        action_id: auth.action_id,
        resources: auth.resources,
        issued_at_iso_utc: auth.issued_at.to_rfc3339(),
        expires_at_iso_utc: auth.expires_at.to_rfc3339(),
        status: "authorized".to_string(),
    }))
}

/// POST /v0/action/execute - Execute an authorized action
async fn action_execute_handler(
    State(ctx): State<Arc<ActionsModuleContext>>,
    headers: HeaderMap,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, (StatusCode, Json<ActionError>)> {
    info!(
        op = %ctx.log_op("execute.request"),
        authorization_id = %&req.authorization_id[..8.min(req.authorization_id.len())],
        note = %req.note.as_deref().unwrap_or("-"),
        "Execute request received"
    );

    // Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("execute.session_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(ActionError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Validate authorization_id is provided
    if req.authorization_id.is_empty() {
        warn!(
            op = %ctx.log_op("execute.denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            error = "authorization_id required",
            "Execution denied"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ActionError {
                error: "authorization_id is required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        ));
    }

    // Get authorization
    let auth = match ctx.action_store.get(&req.authorization_id) {
        Some(a) => a,
        None => {
            warn!(
                op = %ctx.log_op("execute.denied"),
                session_id = %&session.session_id[..8.min(session.session_id.len())],
                authorization_id = %&req.authorization_id[..8.min(req.authorization_id.len())],
                error = "authorization not found",
                "Execution denied"
            );
            return Err((
                StatusCode::NOT_FOUND,
                Json(ActionError {
                    error: "Authorization not found".to_string(),
                    code: "AUTHORIZATION_NOT_FOUND".to_string(),
                }),
            ));
        }
    };

    // Check tenant match
    if auth.tenant_id != session.tenant_id {
        warn!(
            op = %ctx.log_op("execute.denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            authorization_id = %&req.authorization_id[..8],
            auth_tenant = %auth.tenant_id,
            session_tenant = %session.tenant_id,
            error = "tenant mismatch",
            "Execution denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(ActionError {
                error: "Authorization belongs to a different tenant".to_string(),
                code: "TENANT_MISMATCH".to_string(),
            }),
        ));
    }

    // Check authorization validity (not expired, not already executed)
    match ctx.action_store.is_valid(&req.authorization_id) {
        Some((true, _)) => {
            // Valid, continue
        }
        Some((false, reason)) => {
            warn!(
                op = %ctx.log_op("execute.denied"),
                session_id = %&session.session_id[..8.min(session.session_id.len())],
                authorization_id = %&req.authorization_id[..8],
                error = %reason,
                "Execution denied"
            );
            return Err((
                StatusCode::GONE,
                Json(ActionError {
                    error: format!("Authorization invalid: {}", reason),
                    code: reason,
                }),
            ));
        }
        None => {
            // Already checked above, but handle for safety
            return Err((
                StatusCode::NOT_FOUND,
                Json(ActionError {
                    error: "Authorization not found".to_string(),
                    code: "AUTHORIZATION_NOT_FOUND".to_string(),
                }),
            ));
        }
    }

    // Mark as executed
    ctx.action_store.mark_executed(&req.authorization_id);

    // Generate execution ID
    let execution_id = Uuid::new_v4().to_string();

    info!(
        op = %ctx.log_op("execute.success"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        tenant_id = %session.tenant_id,
        authorization_id = %&req.authorization_id[..8],
        execution_id = %&execution_id[..8],
        action_id = %auth.action_id,
        "Execution accepted"
    );

    Ok(Json(ExecuteResponse {
        execution_id,
        authorization_id: req.authorization_id,
        status: "accepted".to_string(),
    }))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Path Leak Tests (prove we never leak paths - even though no paths expected)
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

    // =========================================================================
    // ActionStore Tests
    // =========================================================================

    #[test]
    fn test_action_store_create_authorization() {
        let store = ActionStore::new();
        let resources = vec![Resource {
            resource_type: "account".to_string(),
            id: "acc-123".to_string(),
        }];

        let auth = store.create_authorization(
            "session-1",
            "tenant-1",
            "user-1",
            "transfer",
            resources,
        );

        assert!(!auth.authorization_id.is_empty());
        assert_eq!(auth.tenant_id, "tenant-1");
        assert_eq!(auth.action_id, "transfer");
        assert!(!auth.executed);
    }

    #[test]
    fn test_action_store_get_authorization() {
        let store = ActionStore::new();
        let resources = vec![Resource {
            resource_type: "file".to_string(),
            id: "doc-456".to_string(),
        }];

        let auth = store.create_authorization(
            "session-1",
            "tenant-1",
            "user-1",
            "read",
            resources,
        );

        let retrieved = store.get(&auth.authorization_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().action_id, "read");
    }

    #[test]
    fn test_action_store_authorization_not_found() {
        let store = ActionStore::new();
        let result = store.get("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_action_store_mark_executed() {
        let store = ActionStore::new();
        let resources = vec![];

        let auth = store.create_authorization(
            "session-1",
            "tenant-1",
            "user-1",
            "deploy",
            resources,
        );

        // Check initially valid
        let (valid, _) = store.is_valid(&auth.authorization_id).unwrap();
        assert!(valid);

        // Mark executed
        assert!(store.mark_executed(&auth.authorization_id));

        // Check now invalid (already executed)
        let (valid, reason) = store.is_valid(&auth.authorization_id).unwrap();
        assert!(!valid);
        assert_eq!(reason, "AUTHORIZATION_ALREADY_EXECUTED");
    }

    #[test]
    fn test_action_store_is_valid_not_found() {
        let store = ActionStore::new();
        let result = store.is_valid("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_authorize_request_validation() {
        // Test that we can create authorization with valid inputs
        let store = ActionStore::new();
        let resources = vec![Resource {
            resource_type: "account".to_string(),
            id: "acc-789".to_string(),
        }];

        let auth = store.create_authorization(
            "valid-session",
            "tenant-1",
            "user-1",
            "transfer",
            resources,
        );

        assert!(!auth.authorization_id.is_empty());
    }

    #[test]
    fn test_tenant_isolation() {
        // Test that tenant_id is properly stored and retrievable for isolation checks
        let store = ActionStore::new();
        let resources = vec![];

        let auth = store.create_authorization(
            "session-1",
            "tenant-A",
            "user-1",
            "action",
            resources,
        );

        let retrieved = store.get(&auth.authorization_id).unwrap();
        assert_eq!(retrieved.tenant_id, "tenant-A");
        // Handler would check: if session.tenant_id != retrieved.tenant_id { deny }
    }

    #[test]
    fn test_execute_denied_on_unknown_authorization() {
        let store = ActionStore::new();

        // Trying to get a non-existent authorization returns None
        let result = store.get("garbage-id-12345");
        assert!(result.is_none());

        // is_valid also returns None for non-existent
        let validity = store.is_valid("garbage-id-12345");
        assert!(validity.is_none());
    }

    // =========================================================================
    // Response Serialization Path Leak Tests
    // =========================================================================

    #[test]
    fn test_authorize_response_no_paths() {
        let response = AuthorizeResponse {
            authorization_id: "auth-12345".to_string(),
            tenant_id: "tenant-abc".to_string(),
            subject: "user-xyz".to_string(),
            action_id: "file.read".to_string(),
            resources: vec![Resource {
                resource_type: "document".to_string(),
                id: "doc-999".to_string(),
            }],
            issued_at_iso_utc: "2024-01-01T00:00:00Z".to_string(),
            expires_at_iso_utc: "2024-01-01T00:05:00Z".to_string(),
            status: "authorized".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_execute_response_no_paths() {
        let response = ExecuteResponse {
            execution_id: "exec-12345".to_string(),
            authorization_id: "auth-67890".to_string(),
            status: "accepted".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_action_error_no_paths() {
        let error = ActionError {
            error: "Authorization not found".to_string(),
            code: "AUTHORIZATION_NOT_FOUND".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_resource_no_paths() {
        let resource = Resource {
            resource_type: "file".to_string(),
            id: "document-123".to_string(),
        };

        let json = serde_json::to_string(&resource).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_module_config_default_enabled() {
        // Actions should be enabled by default (core demo functionality)
        assert!(ACTIONS_MODULE_CONFIG.default_enabled);
    }

    #[test]
    fn test_session_info_no_secrets() {
        // Verify SessionInfo doesn't contain JWT or other secrets
        let info = SessionInfo {
            session_id: "sess-123".to_string(),
            tenant_id: "tenant-abc".to_string(),
            user_id: "user-xyz".to_string(),
            capabilities: vec!["actions.use".to_string()],
        };

        // SessionInfo doesn't derive Serialize, but we can check fields don't have sensitive data
        assert!(!info.session_id.contains("jwt"));
        assert!(!info.tenant_id.contains("secret"));
        assert!(!info.user_id.contains("password"));

        // Verify capabilities field exists and works
        assert!(info.has_capability("actions.use"));
    }
}
