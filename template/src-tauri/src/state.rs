//! Application state management
//!
//! Contains the shared state accessible across Tauri commands.

use crate::engine_process::{EngineProcess, EngineStatus};
use crate::node_auth::{NodeIdentity, NodeSessionHolder};
use crate::node_credentials::NodeAuthTokenHolder;
use chrono::{DateTime, Utc};
use ekka_sdk_core::ekka_ops::{
    self as ops, EkkaError, EkkaResult, GrantIssuer, GrantRequest, GrantResponse, RuntimeContext,
    vault::{VaultCacheKey, VaultManager, VaultManagerCache},
};
use ekka_sdk_core::ekka_path_guard::SignedGrant;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

/// Authentication context from login
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthContext {
    pub tenant_id: String,
    pub sub: String,
    pub jwt: String,
    /// Workspace ID (required for node session registration)
    #[serde(default)]
    pub workspace_id: Option<String>,
}

/// Home directory state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HomeState {
    BootstrapPreLogin,
    AuthenticatedNoHomeGrant,
    HomeGranted,
}

// =============================================================================
// Node Auth State (single-flight guard)
// =============================================================================

/// Node authentication state - prevents concurrent/repeated auth attempts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAuthState {
    /// No auth attempted yet
    Unauthenticated,
    /// Auth in progress (single-flight lock)
    Authenticating,
    /// Auth succeeded, token stored
    Authenticated,
    /// Auth failed, do not retry this session
    Failed,
}

impl Default for NodeAuthState {
    fn default() -> Self {
        Self::Unauthenticated
    }
}

/// Thread-safe holder for node auth state
pub struct NodeAuthStateHolder {
    state: RwLock<NodeAuthState>,
    last_error: RwLock<Option<String>>,
}

impl NodeAuthStateHolder {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(NodeAuthState::Unauthenticated),
            last_error: RwLock::new(None),
        }
    }

    /// Get current state
    pub fn get(&self) -> NodeAuthState {
        self.state.read().map(|g| *g).unwrap_or(NodeAuthState::Unauthenticated)
    }

    /// Try to start auth - returns true if allowed, false if already in progress or failed
    pub fn try_start(&self) -> bool {
        if let Ok(mut guard) = self.state.write() {
            match *guard {
                NodeAuthState::Unauthenticated => {
                    *guard = NodeAuthState::Authenticating;
                    true
                }
                _ => false, // Already authenticating, authenticated, or failed
            }
        } else {
            false
        }
    }

    /// Mark auth as successful
    pub fn set_authenticated(&self) {
        if let Ok(mut guard) = self.state.write() {
            *guard = NodeAuthState::Authenticated;
        }
        if let Ok(mut guard) = self.last_error.write() {
            *guard = None;
        }
    }

    /// Mark auth as failed
    pub fn set_failed(&self, error: String) {
        if let Ok(mut guard) = self.state.write() {
            *guard = NodeAuthState::Failed;
        }
        if let Ok(mut guard) = self.last_error.write() {
            *guard = Some(error);
        }
    }

    /// Get last error if failed
    pub fn get_last_error(&self) -> Option<String> {
        self.last_error.read().ok().and_then(|g| g.clone())
    }

    /// Reset to unauthenticated (e.g., on logout or credential change)
    #[allow(dead_code)]
    pub fn reset(&self) {
        if let Ok(mut guard) = self.state.write() {
            *guard = NodeAuthState::Unauthenticated;
        }
        if let Ok(mut guard) = self.last_error.write() {
            *guard = None;
        }
    }
}

impl Default for NodeAuthStateHolder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Runner State
// =============================================================================

/// Runner loop state (running, stopped, error)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunnerLoopState {
    Running,
    Stopped,
    Error,
}

impl Default for RunnerLoopState {
    fn default() -> Self {
        Self::Stopped
    }
}

/// Local runner status - tracks this desktop instance's runner loop
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerStatus {
    pub enabled: bool,
    pub state: RunnerLoopState,
    pub runner_id: Option<String>,
    pub engine_url: Option<String>,
    pub last_poll_at: Option<DateTime<Utc>>,
    pub last_claim_at: Option<DateTime<Utc>>,
    pub last_complete_at: Option<DateTime<Utc>>,
    pub last_task_id: Option<String>,
    pub last_error: Option<String>,
}

impl Default for RunnerStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            state: RunnerLoopState::Stopped,
            runner_id: None,
            engine_url: option_env!("EKKA_ENGINE_URL").map(|s| s.to_string()),
            last_poll_at: None,
            last_claim_at: None,
            last_complete_at: None,
            last_task_id: None,
            last_error: None,
        }
    }
}

/// Thread-safe wrapper for RunnerStatus
#[derive(Clone)]
pub struct RunnerState {
    inner: Arc<RwLock<RunnerStatus>>,
}

impl RunnerState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RunnerStatus::default())),
        }
    }

    /// Get a snapshot of current runner status
    pub fn get(&self) -> RunnerStatus {
        self.inner
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Update runner status
    pub fn update<F>(&self, f: F)
    where
        F: FnOnce(&mut RunnerStatus),
    {
        if let Ok(mut guard) = self.inner.write() {
            f(&mut guard);
        }
    }

    /// Mark a successful poll
    pub fn record_poll(&self) {
        self.update(|s| {
            s.last_poll_at = Some(Utc::now());
            s.state = RunnerLoopState::Running;
        });
    }

    /// Mark a successful claim
    pub fn record_claim(&self, task_id: &str) {
        self.update(|s| {
            s.last_claim_at = Some(Utc::now());
            s.last_task_id = Some(task_id.to_string());
        });
    }

    /// Mark a successful complete
    pub fn record_complete(&self, task_id: &str) {
        self.update(|s| {
            s.last_complete_at = Some(Utc::now());
            s.last_task_id = Some(task_id.to_string());
        });
    }

    /// Mark an error
    pub fn record_error(&self, error: &str) {
        self.update(|s| {
            s.state = RunnerLoopState::Error;
            // Sanitize error - don't include paths or secrets
            s.last_error = Some(sanitize_error(error));
        });
    }

    /// Start the runner
    pub fn start(&self, runner_id: &str) {
        self.update(|s| {
            s.enabled = true;
            s.state = RunnerLoopState::Running;
            s.runner_id = Some(runner_id.to_string());
            // EKKA_ENGINE_URL baked at build time, ENGINE_URL as runtime fallback
            s.engine_url = option_env!("EKKA_ENGINE_URL")
                .map(|s| s.to_string())
                .or_else(|| std::env::var("ENGINE_URL").ok());
            s.last_error = None;
        });
    }

    /// Stop the runner
    pub fn stop(&self) {
        self.update(|s| {
            s.state = RunnerLoopState::Stopped;
        });
    }
}

impl Default for RunnerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Sanitize error messages to avoid leaking paths or secrets
fn sanitize_error(error: &str) -> String {
    // Remove potential file paths
    let sanitized = error
        .lines()
        .map(|line| {
            // Replace anything that looks like a path
            if line.contains('/') && (line.contains("home") || line.contains("Users") || line.contains("tmp")) {
                "[path redacted]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    // Truncate if too long
    if sanitized.len() > 200 {
        format!("{}...", &sanitized[..200])
    } else {
        sanitized
    }
}

/// Global engine state managed by Tauri
pub struct EngineState {
    pub connected: Mutex<bool>,
    pub auth: Mutex<Option<AuthContext>>,
    pub home_path: Mutex<Option<PathBuf>>,
    pub node_id: Mutex<Option<Uuid>>,
    /// Cached VaultManager instances to avoid repeated PBKDF2 key derivation
    vault_cache: VaultCache,
    /// Local runner status for this desktop instance
    pub runner_state: RunnerState,
    /// Node identity metadata (public key, etc.)
    pub node_identity: Mutex<Option<NodeIdentity>>,
    /// Node session holder (in-memory only, never persisted)
    pub node_session: Arc<NodeSessionHolder>,
    /// Node auth token holder (in-memory only, role=node JWT)
    pub node_auth_token: Arc<NodeAuthTokenHolder>,
    /// Node auth state (single-flight guard to prevent retry storms)
    pub node_auth_state: Arc<NodeAuthStateHolder>,
    /// External engine process (Phase 3A)
    pub engine_process: Option<Arc<EngineProcess>>,
    /// Cached grant verification key (fetched from /.well-known/ekka-configuration)
    pub grant_verify_key: RwLock<Option<String>>,
}

impl Default for EngineState {
    fn default() -> Self {
        Self {
            connected: Mutex::new(false),
            auth: Mutex::new(None),
            home_path: Mutex::new(None),
            node_id: Mutex::new(None),
            vault_cache: VaultCache::new(),
            runner_state: RunnerState::new(),
            node_identity: Mutex::new(None),
            node_session: Arc::new(NodeSessionHolder::new()),
            node_auth_token: Arc::new(NodeAuthTokenHolder::new()),
            node_auth_state: Arc::new(NodeAuthStateHolder::new()),
            engine_process: None,
            grant_verify_key: RwLock::new(None),
        }
    }
}

impl EngineState {
    /// Create EngineState with an engine process holder
    pub fn with_engine(engine: Arc<EngineProcess>) -> Self {
        Self {
            connected: Mutex::new(false),
            auth: Mutex::new(None),
            home_path: Mutex::new(None),
            node_id: Mutex::new(None),
            vault_cache: VaultCache::new(),
            runner_state: RunnerState::new(),
            node_identity: Mutex::new(None),
            node_session: Arc::new(NodeSessionHolder::new()),
            node_auth_token: Arc::new(NodeAuthTokenHolder::new()),
            node_auth_state: Arc::new(NodeAuthStateHolder::new()),
            engine_process: Some(engine),
            grant_verify_key: RwLock::new(None),
        }
    }

    /// Get the node auth token if available and valid
    pub fn get_node_auth_token(&self) -> Option<crate::node_credentials::NodeAuthToken> {
        self.node_auth_token.get_valid()
    }

    /// Check if external engine is available
    pub fn is_engine_available(&self) -> bool {
        self.engine_process
            .as_ref()
            .map(|e| e.is_available())
            .unwrap_or(false)
    }

    /// Permanently disable engine routing for this session (one-way switch)
    pub fn disable_engine(&self) {
        if let Some(engine) = &self.engine_process {
            engine.disable();
        }
    }

    /// Get engine status (read-only diagnostics)
    pub fn get_engine_status(&self) -> EngineStatus {
        self.engine_process
            .as_ref()
            .map(|e| e.get_status())
            .unwrap_or(EngineStatus {
                installed: false,
                running: false,
                available: false,
                pid: None,
                version: None,
                build: None,
            })
    }

    /// Create a RuntimeContext from current state
    pub fn to_runtime_context(&self) -> Option<RuntimeContext> {
        let home_path = self.home_path.lock().ok()?.clone()?;
        let node_id = self.node_id.lock().ok()?.clone()?;

        let mut ctx = RuntimeContext::new(home_path, node_id);

        if let Ok(guard) = self.auth.lock() {
            if let Some(auth) = guard.as_ref() {
                ctx.set_auth(ops::AuthContext::new(
                    &auth.tenant_id,
                    &auth.sub,
                    &auth.jwt,
                ));
            }
        }

        Some(ctx)
    }

    /// Get a reference to the vault cache
    ///
    /// Used by vault handlers to pass the cache to ekka_ops functions.
    pub fn vault_cache(&self) -> &dyn VaultManagerCache {
        &self.vault_cache
    }

    /// Clear the vault cache
    ///
    /// Should be called on logout or auth context changes.
    pub fn clear_vault_cache(&self) {
        self.vault_cache.clear();
    }

    /// Get cached grant verification key
    pub fn get_grant_verify_key(&self) -> Option<String> {
        self.grant_verify_key.read().ok()?.clone()
    }

    /// Set grant verification key (fetched from well-known endpoint)
    pub fn set_grant_verify_key(&self, key: String) {
        if let Ok(mut guard) = self.grant_verify_key.write() {
            *guard = Some(key);
        }
    }
}

// =============================================================================
// Vault Cache
// =============================================================================

/// Thread-safe cache for VaultManager instances
///
/// Avoids repeated PBKDF2 key derivation (100k iterations) per vault call.
/// Key derivation happens once per session; subsequent calls reuse cached instance.
pub struct VaultCache {
    inner: RwLock<HashMap<VaultCacheKey, Arc<VaultManager>>>,
}

impl VaultCache {
    /// Create a new empty vault cache
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for VaultCache {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultManagerCache for VaultCache {
    fn get(&self, key: &VaultCacheKey) -> Option<Arc<VaultManager>> {
        self.inner.read().ok()?.get(key).cloned()
    }

    fn insert(&self, key: VaultCacheKey, vm: Arc<VaultManager>) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(key, vm);
        }
    }

    fn remove(&self, key: &VaultCacheKey) -> bool {
        self.inner
            .write()
            .ok()
            .map(|mut guard| guard.remove(key).is_some())
            .unwrap_or(false)
    }

    fn clear(&self) {
        if let Ok(mut guard) = self.inner.write() {
            guard.clear();
        }
    }
}

// =============================================================================
// HTTP Grant Issuer
// =============================================================================

/// HTTP-based grant issuer that calls EKKA Engine
pub struct EngineHttpGrantIssuer;

impl EngineHttpGrantIssuer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EngineHttpGrantIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl GrantIssuer for EngineHttpGrantIssuer {
    fn issue(&self, ctx: &RuntimeContext, req: GrantRequest) -> EkkaResult<GrantResponse> {
        // Must have auth
        let auth = ctx.auth.as_ref().ok_or_else(|| {
            EkkaError::new(ops::codes::NOT_AUTHENTICATED, "Must login before requesting grant")
        })?;

        // Get engine URL (baked at build time)
        let engine_url = option_env!("EKKA_ENGINE_URL").ok_or_else(|| {
            EkkaError::new(
                ops::codes::ENGINE_ERROR,
                "EKKA_ENGINE_URL not baked at build time. Rebuild with EKKA_ENGINE_URL set.",
            )
        })?;

        // Build grant request payload
        let grant_request = serde_json::json!({
            "resource": {
                "kind": "path",
                "path_prefix": req.path_prefix,
                "attrs": {
                    "path_type": req.path_type
                }
            },
            "permissions": {
                "ops": ["read", "write", "delete"],
                "access": req.access
            },
            "purpose": req.purpose,
            "expires_in_seconds": req.expires_in_seconds,
            "node_id": ctx.node_id.to_string(),
            "consent": {
                "mode": "user_click"
            }
        });

        // Make HTTP request
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| EkkaError::from_source(ops::codes::ENGINE_ERROR, "HTTP client error", e))?;

        let request_id = Uuid::new_v4().to_string();
        let response = client
            .post(format!("{}/engine/grants/issue", engine_url))
            .header("Authorization", format!("Bearer {}", auth.jwt))
            .header("Content-Type", "application/json")
            .header("X-EKKA-PROOF-TYPE", "jwt")
            .header("X-REQUEST-ID", &request_id)
            .header("X-EKKA-CORRELATION-ID", &request_id)
            .header("X-EKKA-MODULE", "desktop.paths")
            .header("X-EKKA-ACTION", "grant")
            .header("X-EKKA-CLIENT", "desktop")
            .header("X-EKKA-CLIENT-VERSION", "0.2.0")
            .json(&grant_request)
            .send()
            .map_err(|e| {
                EkkaError::from_source(ops::codes::ENGINE_ERROR, "HTTP request failed", e)
            })?;

        // Check response
        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().unwrap_or_else(|_| "No error body".to_string());
            return Err(EkkaError::new(
                ops::codes::GRANT_DENIED,
                format!("Engine returned {}: {}", status, error_body),
            ));
        }

        // Parse response
        let grant_response: Value = response.json().map_err(|e| {
            EkkaError::from_source(ops::codes::ENGINE_ERROR, "Failed to parse response", e)
        })?;

        // Extract signed grant
        let signed_grant_json = grant_response.get("signed_grant").ok_or_else(|| {
            EkkaError::new(ops::codes::ENGINE_ERROR, "Response missing signed_grant")
        })?;

        let signed_grant: SignedGrant = serde_json::from_value(signed_grant_json.clone())
            .map_err(|e| {
                EkkaError::from_source(ops::codes::ENGINE_ERROR, "Invalid signed_grant format", e)
            })?;

        let expires_at = grant_response
            .get("expires_at")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                signed_grant
                    .grant
                    .expires_at
                    .clone()
                    .unwrap_or_default()
            });

        Ok(GrantResponse {
            signed_grant,
            expires_at,
        })
    }

    fn revoke(&self, ctx: &RuntimeContext, grant_id: &str) -> EkkaResult<()> {
        // Must have auth
        let auth = ctx.auth.as_ref().ok_or_else(|| {
            EkkaError::new(ops::codes::NOT_AUTHENTICATED, "Must login to revoke grant")
        })?;

        // Get engine URL (baked at build time, optional - revoke is best effort)
        let engine_url = match option_env!("EKKA_ENGINE_URL") {
            Some(url) => url,
            None => return Ok(()), // No engine baked, just return success
        };

        // Make revoke request (best effort)
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| EkkaError::from_source(ops::codes::ENGINE_ERROR, "HTTP client error", e))?;

        let request_id = Uuid::new_v4().to_string();
        let _ = client
            .post(format!("{}/engine/grants/revoke", engine_url))
            .header("Authorization", format!("Bearer {}", auth.jwt))
            .header("Content-Type", "application/json")
            .header("X-REQUEST-ID", &request_id)
            .json(&serde_json::json!({ "grant_id": grant_id }))
            .send();

        Ok(())
    }
}
