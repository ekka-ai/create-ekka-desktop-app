//! EKKA Node Workspaces Module - RAPTOR-2 Workspace Inventory
//!
//! Provides read-only workspace status and listing without exposing filesystem paths.
//! Uses product terminology: "Workspaces", "Managed Projects", "Workspace Status".
//!
//! ## Security Properties
//!
//! - No absolute paths in responses (only workspace_id and name)
//! - Read-only access to workspace metadata
//! - Structured logging with node.workspaces.* prefix
//! - Encrypted persistence for inventory data (RAPTOR-2 Step 23)
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - A WorkspacesModuleContext with workspace manager
//!
//! When disabled via EKKA_ENABLE_WORKSPACES=0, routes are NOT mounted -> 404.

pub mod persist;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use ekka_home_bootstrap::{WorkHomeConfig, WorkHomeManager, WorkHomeMode, WorkspaceStatus as BootstrapWorkspaceStatus};

pub use ekka_node_modules::{
    error_codes, ModuleConfig, ModuleError,
    SessionInfo, SessionValidationError, SessionValidator,
};

// =============================================================================
// Module Configuration
// =============================================================================

/// Workspaces module configuration
pub const WORKSPACES_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Workspaces",
    env_var: "EKKA_ENABLE_WORKSPACES",
    default_enabled: false, // Conservative default; enable with EKKA_ENABLE_WORKSPACES=1
};

/// Required capability for workspaces read operations
pub const WORKSPACES_READ_CAPABILITY: &str = "workspaces.read";

/// Required capability for workspaces provisioning (privileged)
pub const WORKSPACES_PROVISION_CAPABILITY: &str = "workspaces.provision";

/// Required capability for binding repo to workspace (privileged)
pub const WORKSPACES_BIND_REPO_CAPABILITY: &str = "workspaces.bind_repo";

// =============================================================================
// Workspace Status Types (API-safe, no paths)
// =============================================================================

/// Workspace feature status response
#[derive(Debug, Serialize)]
pub struct WorkspacesStatusResponse {
    /// Whether workspace feature is enabled
    pub enabled: bool,
    /// Operating mode (disabled, path, interactive)
    pub mode: String,
    /// Whether workspaces are deleted on security epoch change
    pub delete_on_epoch: bool,
    /// Number of managed workspaces
    pub workspace_count: u32,
}

/// Workspace list response
#[derive(Debug, Serialize)]
pub struct WorkspacesListResponse {
    pub workspaces: Vec<WorkspaceInfo>,
}

/// Safe workspace information (no filesystem paths)
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInfo {
    /// Unique workspace identifier
    pub workspace_id: String,
    /// User-provided display name
    pub name: String,
    /// When workspace was created
    pub created_at_iso_utc: String,
    /// Current status
    pub status: String,
}

/// Workspace API error
#[derive(Debug, Serialize)]
pub struct WorkspacesError {
    pub error: String,
    pub code: String,
}

/// Provision request
#[derive(Debug, Deserialize)]
pub struct ProvisionRequest {
    /// User-provided display name
    pub name: String,
    /// Provisioning mode (only "managed" supported for now)
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_mode() -> String {
    "managed".to_string()
}

/// Provision response (no paths exposed)
#[derive(Debug, Serialize)]
pub struct ProvisionResponse {
    /// Unique workspace identifier
    pub workspace_id: String,
    /// User-provided display name
    pub name: String,
    /// Current status
    pub status: String,
}

/// Bind repo request
#[derive(Debug, Deserialize)]
pub struct BindRepoRequest {
    /// Workspace ID to bind repo to
    pub workspace_id: String,
    /// Repository reference in "owner/repo" format (NO URLs, NO .git)
    pub repo_ref: String,
}

/// Bind repo response (minimal, no paths, no repo_ref echo)
#[derive(Debug, Serialize)]
pub struct BindRepoResponse {
    /// Workspace ID
    pub workspace_id: String,
    /// Status of binding
    pub status: String,
}

// =============================================================================
// Workspaces Inventory (with optional persistence - RAPTOR-2 Step 23)
// =============================================================================

/// Workspace inventory entry (server-side only, no paths exposed)
#[derive(Debug, Clone)]
pub struct WorkspaceInventoryEntry {
    /// Unique workspace identifier
    pub workspace_id: Uuid,
    /// User-provided display name
    pub name: String,
    /// Created timestamp
    pub created_at: chrono::DateTime<Utc>,
    /// Current status
    pub status: String,
    /// Optional repo reference (owner/repo format, for Studio)
    /// Set ONLY by trusted server-side flows, NEVER from browser
    pub repo_ref: Option<String>,
}

/// Workspace inventory store with optional encrypted persistence
///
/// ## Persistence Modes
///
/// - In-memory only: `WorkspacesInventory::new()` - data lost on restart
/// - Persistent: `WorkspacesInventory::with_persistence(store)` - survives restart
///
/// When persistence is enabled, changes are auto-saved after mutations.
pub struct WorkspacesInventory {
    workspaces: RwLock<HashMap<Uuid, WorkspaceInventoryEntry>>,
    /// Optional persistent store (None = in-memory only)
    store: Option<persist::InventoryStore>,
}

impl WorkspacesInventory {
    /// Create a new in-memory inventory (no persistence)
    pub fn new() -> Self {
        Self {
            workspaces: RwLock::new(HashMap::new()),
            store: None,
        }
    }

    /// Create inventory with encrypted persistence
    /// Loads existing data from disk if present
    pub fn with_persistence(store: persist::InventoryStore) -> Result<Self, persist::PersistError> {
        // Load existing data from disk
        let data = store.load()?;

        // Convert to in-memory format
        let workspaces = persist::from_persistent_entries(data.workspaces);

        info!(
            op = "workspaces.inventory.load",
            workspace_count = workspaces.len(),
            "Inventory initialized from persistent storage"
        );

        Ok(Self {
            workspaces: RwLock::new(workspaces),
            store: Some(store),
        })
    }

    /// Create a new workspace
    pub fn create(&self, name: String) -> WorkspaceInventoryEntry {
        let workspace_id = Uuid::new_v4();
        let now = Utc::now();

        let entry = WorkspaceInventoryEntry {
            workspace_id,
            name,
            created_at: now,
            status: "provisioned".to_string(),
            repo_ref: None, // Set via set_repo_ref after creation if needed
        };

        {
            let mut workspaces = self.workspaces.write().unwrap();
            workspaces.insert(workspace_id, entry.clone());
        }

        // Auto-save if persistence is enabled
        self.persist();

        entry
    }

    /// Get workspace by ID
    #[allow(dead_code)]
    pub fn get(&self, workspace_id: Uuid) -> Option<WorkspaceInventoryEntry> {
        let workspaces = self.workspaces.read().unwrap();
        workspaces.get(&workspace_id).cloned()
    }

    /// List all workspaces
    pub fn list(&self) -> Vec<WorkspaceInventoryEntry> {
        let workspaces = self.workspaces.read().unwrap();
        workspaces.values().cloned().collect()
    }

    /// Get workspace count
    pub fn count(&self) -> u32 {
        let workspaces = self.workspaces.read().unwrap();
        workspaces.len() as u32
    }

    /// Set repo reference for a workspace (server-side only)
    /// Returns true if workspace found and updated
    #[allow(dead_code)]
    pub fn set_repo_ref(&self, workspace_id: Uuid, repo_ref: String) -> bool {
        // Validate repo_ref format: must be owner/repo, no URLs
        if !is_valid_repo_ref(&repo_ref) {
            return false;
        }

        let updated = {
            let mut workspaces = self.workspaces.write().unwrap();
            if let Some(entry) = workspaces.get_mut(&workspace_id) {
                entry.repo_ref = Some(repo_ref);
                true
            } else {
                false
            }
        };

        // Auto-save if updated and persistence is enabled
        if updated {
            self.persist();
        }

        updated
    }

    /// Get repo reference for a workspace
    #[allow(dead_code)]
    pub fn get_repo_ref(&self, workspace_id: Uuid) -> Option<String> {
        let workspaces = self.workspaces.read().unwrap();
        workspaces.get(&workspace_id).and_then(|e| e.repo_ref.clone())
    }

    /// Check if persistence is enabled
    #[allow(dead_code)]
    pub fn is_persistent(&self) -> bool {
        self.store.is_some()
    }

    /// Persist current state to disk (if persistence is enabled)
    /// Called automatically after mutations
    fn persist(&self) {
        if let Some(ref store) = self.store {
            let workspaces = self.workspaces.read().unwrap();
            let entries = persist::to_persistent_entries(&workspaces);
            let data = persist::InventoryData {
                schema_version: persist::INVENTORY_SCHEMA_VERSION,
                workspaces: entries,
            };

            if let Err(e) = store.save(&data) {
                warn!(
                    op = "workspaces.inventory.persist.error",
                    error = %e,
                    "Failed to persist inventory"
                );
            }
        }
    }
}

impl Default for WorkspacesInventory {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate repo reference format: owner/repo only
/// No URLs, no .git suffix, no scheme
fn is_valid_repo_ref(repo_ref: &str) -> bool {
    let parts: Vec<&str> = repo_ref.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let owner = parts[0];
    let repo = parts[1];

    // No empty parts
    if owner.is_empty() || repo.is_empty() {
        return false;
    }

    // No URLs (must not contain :// or @)
    if repo_ref.contains("://") || repo_ref.contains('@') {
        return false;
    }

    // No .git suffix
    if repo.ends_with(".git") {
        return false;
    }

    // Basic character validation
    owner.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        && repo.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// =============================================================================
// Workspace State (stored in AppState)
// =============================================================================

/// Runtime workspaces state for API access
#[derive(Debug, Clone)]
pub struct WorkspacesState {
    /// Whether workspace feature is enabled
    pub enabled: bool,
    /// Operating mode string
    pub mode: String,
    /// Whether delete on epoch is enabled
    pub delete_on_epoch: bool,
}

impl WorkspacesState {
    /// Create workspaces state from configuration
    pub fn from_config(config: &WorkHomeConfig) -> Self {
        let (enabled, mode) = match &config.mode {
            WorkHomeMode::Disabled => (false, "disabled".to_string()),
            WorkHomeMode::Interactive => (true, "interactive".to_string()),
            WorkHomeMode::Path(_) => (true, "path".to_string()),
        };

        let delete_on_epoch = std::env::var("EKKA_WORK_HOME_DELETE_ON_EPOCH")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            enabled,
            mode,
            delete_on_epoch,
        }
    }

    /// Convert to status response
    pub fn to_status_response(&self, workspace_count: u32) -> WorkspacesStatusResponse {
        WorkspacesStatusResponse {
            enabled: self.enabled,
            mode: self.mode.clone(),
            delete_on_epoch: self.delete_on_epoch,
            workspace_count,
        }
    }
}

/// Convert bootstrap workspace status to API-safe string
fn status_to_string(status: &BootstrapWorkspaceStatus) -> String {
    match status {
        BootstrapWorkspaceStatus::Active => "ready".to_string(),
        BootstrapWorkspaceStatus::Quarantined => "quarantined".to_string(),
        BootstrapWorkspaceStatus::Deleted => "deleted".to_string(),
    }
}

/// Convert WorkHomeManager workspaces to API-safe list (no paths)
pub fn workspaces_to_list(manager: &WorkHomeManager) -> WorkspacesListResponse {
    let workspaces = manager.list_workspaces(None);

    let safe_list: Vec<WorkspaceInfo> = workspaces
        .iter()
        .map(|record| WorkspaceInfo {
            workspace_id: record.workspace_id.to_string(),
            name: if record.display_name.is_empty() {
                "(unnamed)".to_string()
            } else {
                record.display_name.clone()
            },
            created_at_iso_utc: record.created_at.to_rfc3339(),
            status: status_to_string(&record.status),
        })
        .collect();

    WorkspacesListResponse { workspaces: safe_list }
}

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Context for the Workspaces module
/// Provided by the host application when mounting
#[derive(Clone)]
pub struct WorkspacesModuleContext {
    /// Workspaces feature state
    pub workspaces_state: WorkspacesState,
    /// Work home manager (shared with host)
    pub work_home_manager: Arc<RwLock<Option<WorkHomeManager>>>,
    /// Workspaces inventory (in-memory for demo)
    pub inventory: Arc<WorkspacesInventory>,
    /// Session validator (provided by host for request-time auth)
    pub session_validator: SessionValidator,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
    /// Repo allow-list checker (RAPTOR-2 Step 31)
    /// If Some, validates repo_ref at bind time
    pub repo_allowlist: Option<RepoAllowListChecker>,
    /// Whether allow-list is required (RAPTOR-2 Step 31)
    /// If true and repo_allowlist is None, bind-repo fails with REPO_ALLOWLIST_NOT_CONFIGURED
    pub repo_allowlist_required: bool,
}

/// Type alias for repo allow-list checker function
/// Returns true if repo_ref is allowed, false otherwise
pub type RepoAllowListChecker = Arc<dyn Fn(&str) -> bool + Send + Sync>;

impl WorkspacesModuleContext {
    pub fn new(
        workspaces_state: WorkspacesState,
        work_home_manager: Arc<RwLock<Option<WorkHomeManager>>>,
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspaces_state,
            work_home_manager,
            inventory: Arc::new(WorkspacesInventory::new()),
            session_validator,
            log_prefix: log_prefix.into(),
            repo_allowlist: None,
            repo_allowlist_required: false,
        }
    }

    /// Create context with custom inventory (for testing)
    #[allow(dead_code)]
    pub fn with_inventory(
        workspaces_state: WorkspacesState,
        work_home_manager: Arc<RwLock<Option<WorkHomeManager>>>,
        inventory: Arc<WorkspacesInventory>,
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspaces_state,
            work_home_manager,
            inventory,
            session_validator,
            log_prefix: log_prefix.into(),
            repo_allowlist: None,
            repo_allowlist_required: false,
        }
    }

    /// Create context with allow-list support (RAPTOR-2 Step 31)
    pub fn with_allowlist(
        workspaces_state: WorkspacesState,
        work_home_manager: Arc<RwLock<Option<WorkHomeManager>>>,
        inventory: Arc<WorkspacesInventory>,
        session_validator: SessionValidator,
        repo_allowlist: Option<RepoAllowListChecker>,
        repo_allowlist_required: bool,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspaces_state,
            work_home_manager,
            inventory,
            session_validator,
            log_prefix: log_prefix.into(),
            repo_allowlist,
            repo_allowlist_required,
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.workspaces.{}", self.log_prefix, op)
    }
}

/// Mount the Workspaces module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: WorkspacesModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !WORKSPACES_MODULE_CONFIG.is_enabled() {
        info!(
            module = "workspaces",
            enabled = false,
            "Workspaces module disabled (set EKKA_ENABLE_WORKSPACES=1 to enable)"
        );
        return router;
    }

    info!(
        module = "workspaces",
        enabled = true,
        "Workspaces module enabled"
    );

    let state = Arc::new(ctx);

    // Create a sub-router with our state, then merge into main router
    let workspaces_router: Router<S> = Router::new()
        .route("/v0/workspaces/status", get(workspaces_status_handler))
        .route("/v0/workspaces/list", get(workspaces_list_handler))
        .route("/v0/workspaces/provision", post(workspaces_provision_handler))
        .route("/v0/workspaces/bind-repo", post(workspaces_bind_repo_handler))
        .with_state(state);

    router.merge(workspaces_router)
}

// =============================================================================
// Axum Handlers
// =============================================================================

/// GET /v0/workspaces/status - Get workspaces feature status
/// Requires: valid session + "workspaces.read" capability
async fn workspaces_status_handler(
    State(ctx): State<Arc<WorkspacesModuleContext>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<WorkspacesStatusResponse>, (StatusCode, Json<WorkspacesError>)> {
    info!(
        op = %ctx.log_op("status.request"),
        "Workspaces status requested"
    );

    // Step 1: Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("status.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(WorkspacesError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(WORKSPACES_READ_CAPABILITY) {
        warn!(
            op = %ctx.log_op("status.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(WorkspacesError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Get workspace count from manager
    let workspace_count = {
        let manager_guard = ctx.work_home_manager.read().unwrap();
        if let Some(manager) = manager_guard.as_ref() {
            manager.list_workspaces(None).len() as u32
        } else {
            0
        }
    };

    info!(
        op = %ctx.log_op("status.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        enabled = %ctx.workspaces_state.enabled,
        mode = %ctx.workspaces_state.mode,
        workspace_count = %workspace_count,
        "Workspaces status complete"
    );

    Ok(Json(ctx.workspaces_state.to_status_response(workspace_count)))
}

/// GET /v0/workspaces/list - List all managed workspaces (no paths exposed)
/// Requires: valid session + "workspaces.read" capability
async fn workspaces_list_handler(
    State(ctx): State<Arc<WorkspacesModuleContext>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<WorkspacesListResponse>, (StatusCode, Json<WorkspacesError>)> {
    info!(
        op = %ctx.log_op("list.request"),
        "Workspaces list requested"
    );

    // Step 1: Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("list.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(WorkspacesError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(WORKSPACES_READ_CAPABILITY) {
        warn!(
            op = %ctx.log_op("list.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(WorkspacesError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Get workspaces list
    let response = {
        let manager_guard = ctx.work_home_manager.read().unwrap();
        if let Some(manager) = manager_guard.as_ref() {
            workspaces_to_list(manager)
        } else {
            WorkspacesListResponse { workspaces: vec![] }
        }
    };

    info!(
        op = %ctx.log_op("list.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        count = %response.workspaces.len(),
        "Workspaces list complete"
    );

    Ok(Json(response))
}

/// POST /v0/workspaces/provision - Create a new managed workspace
/// Requires: valid session + "workspaces.provision" capability
async fn workspaces_provision_handler(
    State(ctx): State<Arc<WorkspacesModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, (StatusCode, Json<WorkspacesError>)> {
    info!(
        op = %ctx.log_op("provision.request"),
        "Workspace provision requested"
    );

    // Step 1: Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("provision.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(WorkspacesError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(WORKSPACES_PROVISION_CAPABILITY) {
        warn!(
            op = %ctx.log_op("provision.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(WorkspacesError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Validate request
    if request.name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(WorkspacesError {
                error: "Workspace name is required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        ));
    }

    // Sanitize name (max 100 chars, strip control characters)
    let name = request.name
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect::<String>()
        .trim()
        .to_string();

    if name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(WorkspacesError {
                error: "Workspace name is required".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        ));
    }

    // Only "managed" mode is supported
    if request.mode != "managed" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(WorkspacesError {
                error: "Only 'managed' mode is supported".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        ));
    }

    // Step 4: Create workspace in inventory
    let entry = ctx.inventory.create(name.clone());

    info!(
        op = %ctx.log_op("provision.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        workspace_id = %entry.workspace_id,
        name = %name,
        "Workspace provisioned successfully"
    );

    Ok(Json(ProvisionResponse {
        workspace_id: entry.workspace_id.to_string(),
        name: entry.name,
        status: entry.status,
    }))
}

/// POST /v0/workspaces/bind-repo - Bind a repo_ref to a workspace
/// Requires: valid session + "workspaces.bind_repo" capability
/// Request: {"workspace_id": "<uuid>", "repo_ref": "owner/repo"}
/// Response: {"workspace_id": "<uuid>", "status": "bound"}
///
/// SECURITY:
/// - repo_ref must be "owner/repo" format ONLY (no URLs, no .git)
/// - Browser should NOT call this in production; server-side/Studio only
/// - This is capability-gated for demo/admin use
async fn workspaces_bind_repo_handler(
    State(ctx): State<Arc<WorkspacesModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<BindRepoRequest>,
) -> Result<Json<BindRepoResponse>, (StatusCode, Json<WorkspacesError>)> {
    info!(
        op = %ctx.log_op("bind_repo.request"),
        "Workspace bind-repo requested"
    );

    // Step 1: Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("bind_repo.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(WorkspacesError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(WORKSPACES_BIND_REPO_CAPABILITY) {
        warn!(
            op = %ctx.log_op("bind_repo.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(WorkspacesError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Validate workspace_id format
    let workspace_id = request.workspace_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("bind_repo.invalid_workspace_id"),
            "Invalid workspace ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(WorkspacesError {
                error: "Invalid workspace ID".to_string(),
                code: "INVALID_WORKSPACE_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Validate repo_ref format STRICTLY
    // Must be "owner/repo" only - no URLs, no .git, no SSH format
    if !is_valid_repo_ref(&request.repo_ref) {
        warn!(
            op = %ctx.log_op("bind_repo.invalid_repo_ref"),
            "Invalid repo_ref format"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(WorkspacesError {
                error: "Invalid repository reference format".to_string(),
                code: "INVALID_REPO_REF".to_string(),
            }),
        ));
    }

    // Step 4.5: Check repo allow-list (RAPTOR-2 Step 31)
    // If allow-list is required but not configured, fail
    if ctx.repo_allowlist_required && ctx.repo_allowlist.is_none() {
        warn!(
            op = %ctx.log_op("bind_repo.allowlist_not_configured"),
            "Repo allow-list required but not configured"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(WorkspacesError {
                error: "Repository policy not configured".to_string(),
                code: "REPO_ALLOWLIST_NOT_CONFIGURED".to_string(),
            }),
        ));
    }

    // If allow-list is configured, check if repo is allowed
    if let Some(ref checker) = ctx.repo_allowlist {
        if !checker(&request.repo_ref) {
            warn!(
                op = %ctx.log_op("bind_repo.repo_not_allowed"),
                "Repository not in allow-list"
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(WorkspacesError {
                    error: "Repository not permitted".to_string(),
                    code: "REPO_NOT_ALLOWED".to_string(),
                }),
            ));
        }
    }

    // Step 5: Check workspace exists in inventory
    if ctx.inventory.get(workspace_id).is_none() {
        warn!(
            op = %ctx.log_op("bind_repo.workspace_not_found"),
            "Workspace not found in inventory"
        );
        return Err((
            StatusCode::NOT_FOUND,
            Json(WorkspacesError {
                error: "Workspace not found".to_string(),
                code: "WORKSPACE_NOT_FOUND".to_string(),
            }),
        ));
    }

    // Step 6: Bind repo_ref to workspace
    if !ctx.inventory.set_repo_ref(workspace_id, request.repo_ref.clone()) {
        warn!(
            op = %ctx.log_op("bind_repo.bind_failed"),
            "Failed to bind repo_ref"
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(WorkspacesError {
                error: "Failed to bind repository".to_string(),
                code: "BIND_FAILED".to_string(),
            }),
        ));
    }

    info!(
        op = %ctx.log_op("bind_repo.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        workspace_id = %workspace_id,
        "Repo bound to workspace successfully"
    );

    // Return minimal response - do NOT echo repo_ref
    Ok(Json(BindRepoResponse {
        workspace_id: workspace_id.to_string(),
        status: "bound".to_string(),
    }))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
        assert!(!json.contains("secret"), "Leaked sensitive word: {}", json);
    }

    #[test]
    fn test_workspaces_state_disabled() {
        let config = WorkHomeConfig {
            mode: WorkHomeMode::Disabled,
            app_name: "test".to_string(),
            marker_filename: ".test".to_string(),
        };
        let state = WorkspacesState::from_config(&config);

        assert!(!state.enabled);
        assert_eq!(state.mode, "disabled");

        // Verify no path leak
        let response = state.to_status_response(0);
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_workspaces_state_interactive() {
        let config = WorkHomeConfig {
            mode: WorkHomeMode::Interactive,
            app_name: "test".to_string(),
            marker_filename: ".test".to_string(),
        };
        let state = WorkspacesState::from_config(&config);

        assert!(state.enabled);
        assert_eq!(state.mode, "interactive");

        // Verify no path leak
        let response = state.to_status_response(5);
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_workspaces_state_path() {
        let config = WorkHomeConfig {
            mode: WorkHomeMode::Path(PathBuf::from("/Users/secret/path")),
            app_name: "test".to_string(),
            marker_filename: ".test".to_string(),
        };
        let state = WorkspacesState::from_config(&config);

        assert!(state.enabled);
        assert_eq!(state.mode, "path");

        // Verify no path leak - the path should NOT appear in the response
        let response = state.to_status_response(5);
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_status_response_no_paths() {
        let config = WorkHomeConfig {
            mode: WorkHomeMode::Path(PathBuf::from("/Users/secret/path")),
            app_name: "test".to_string(),
            marker_filename: ".test".to_string(),
        };
        let state = WorkspacesState::from_config(&config);
        let response = state.to_status_response(5);

        let json = serde_json::to_string(&response).unwrap();

        // Ensure no absolute paths leak
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_status_to_string() {
        assert_eq!(status_to_string(&BootstrapWorkspaceStatus::Active), "ready");
        assert_eq!(status_to_string(&BootstrapWorkspaceStatus::Quarantined), "quarantined");
        assert_eq!(status_to_string(&BootstrapWorkspaceStatus::Deleted), "deleted");
    }

    #[test]
    fn test_empty_workspaces_list() {
        let config = WorkHomeConfig {
            mode: WorkHomeMode::Disabled,
            app_name: "test".to_string(),
            marker_filename: ".test".to_string(),
        };
        let manager = WorkHomeManager::new(config);
        let response = workspaces_to_list(&manager);

        assert!(response.workspaces.is_empty());

        // Verify no path leak
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_workspace_info_no_paths() {
        let info = WorkspaceInfo {
            workspace_id: "abc-123-def-456".to_string(),
            name: "My Project".to_string(),
            created_at_iso_utc: "2024-01-01T00:00:00Z".to_string(),
            status: "ready".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_workspaces_error_no_paths() {
        let error = WorkspacesError {
            error: "Workspaces feature is disabled".to_string(),
            code: "WORKSPACES_DISABLED".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_workspaces_list_response_no_paths() {
        let response = WorkspacesListResponse {
            workspaces: vec![
                WorkspaceInfo {
                    workspace_id: "ws-1".to_string(),
                    name: "Project One".to_string(),
                    created_at_iso_utc: "2024-01-01T00:00:00Z".to_string(),
                    status: "ready".to_string(),
                },
                WorkspaceInfo {
                    workspace_id: "ws-2".to_string(),
                    name: "(unnamed)".to_string(),
                    created_at_iso_utc: "2024-01-02T00:00:00Z".to_string(),
                    status: "quarantined".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_module_config_default_disabled() {
        // Workspaces should be disabled by default (conservative)
        assert!(!WORKSPACES_MODULE_CONFIG.default_enabled);
    }

    // =========================================================================
    // Workspaces Inventory Tests (RAPTOR-2 Step 21)
    // =========================================================================

    #[test]
    fn test_inventory_create() {
        let inventory = WorkspacesInventory::new();
        let entry = inventory.create("Test Workspace".to_string());

        assert!(!entry.workspace_id.is_nil());
        assert_eq!(entry.name, "Test Workspace");
        assert_eq!(entry.status, "provisioned");
        assert!(entry.repo_ref.is_none());
    }

    #[test]
    fn test_inventory_list() {
        let inventory = WorkspacesInventory::new();
        inventory.create("Workspace 1".to_string());
        inventory.create("Workspace 2".to_string());

        let list = inventory.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_inventory_count() {
        let inventory = WorkspacesInventory::new();
        assert_eq!(inventory.count(), 0);

        inventory.create("Workspace 1".to_string());
        assert_eq!(inventory.count(), 1);

        inventory.create("Workspace 2".to_string());
        assert_eq!(inventory.count(), 2);
    }

    #[test]
    fn test_inventory_get() {
        let inventory = WorkspacesInventory::new();
        let entry = inventory.create("Test Workspace".to_string());

        let retrieved = inventory.get(entry.workspace_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Workspace");
    }

    #[test]
    fn test_inventory_set_repo_ref() {
        let inventory = WorkspacesInventory::new();
        let entry = inventory.create("Test Workspace".to_string());

        // Valid repo ref
        assert!(inventory.set_repo_ref(entry.workspace_id, "owner/repo".to_string()));
        assert_eq!(inventory.get_repo_ref(entry.workspace_id), Some("owner/repo".to_string()));
    }

    #[test]
    fn test_inventory_repo_ref_validation() {
        let inventory = WorkspacesInventory::new();
        let entry = inventory.create("Test Workspace".to_string());

        // Invalid: URL format
        assert!(!inventory.set_repo_ref(entry.workspace_id, "https://github.com/owner/repo".to_string()));

        // Invalid: SSH format
        assert!(!inventory.set_repo_ref(entry.workspace_id, "git@github.com:owner/repo".to_string()));

        // Invalid: .git suffix
        assert!(!inventory.set_repo_ref(entry.workspace_id, "owner/repo.git".to_string()));

        // Invalid: too many slashes
        assert!(!inventory.set_repo_ref(entry.workspace_id, "owner/repo/extra".to_string()));

        // Invalid: empty parts
        assert!(!inventory.set_repo_ref(entry.workspace_id, "/repo".to_string()));
        assert!(!inventory.set_repo_ref(entry.workspace_id, "owner/".to_string()));
    }

    // =========================================================================
    // Provision Response Tests (RAPTOR-2 Step 21)
    // =========================================================================

    #[test]
    fn test_provision_response_no_paths() {
        let response = ProvisionResponse {
            workspace_id: "abc-123-def-456".to_string(),
            name: "My Project".to_string(),
            status: "provisioned".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_provision_request_deserialization() {
        let json = r#"{"name":"Test Workspace","mode":"managed"}"#;
        let request: ProvisionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.name, "Test Workspace");
        assert_eq!(request.mode, "managed");
    }

    #[test]
    fn test_provision_request_default_mode() {
        let json = r#"{"name":"Test Workspace"}"#;
        let request: ProvisionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.name, "Test Workspace");
        assert_eq!(request.mode, "managed"); // Default
    }

    // =========================================================================
    // Repo Ref Validation Tests (RAPTOR-2 Step 21)
    // =========================================================================

    #[test]
    fn test_valid_repo_ref() {
        assert!(is_valid_repo_ref("owner/repo"));
        assert!(is_valid_repo_ref("my-org/my-repo"));
        assert!(is_valid_repo_ref("org_name/repo_name"));
        assert!(is_valid_repo_ref("org/repo.js"));
    }

    #[test]
    fn test_invalid_repo_ref_url() {
        // URLs should be rejected
        assert!(!is_valid_repo_ref("https://github.com/owner/repo"));
        assert!(!is_valid_repo_ref("http://gitlab.com/owner/repo"));
        assert!(!is_valid_repo_ref("git://github.com/owner/repo"));
    }

    #[test]
    fn test_invalid_repo_ref_ssh() {
        // SSH format should be rejected
        assert!(!is_valid_repo_ref("git@github.com:owner/repo"));
    }

    #[test]
    fn test_invalid_repo_ref_git_suffix() {
        // .git suffix should be rejected
        assert!(!is_valid_repo_ref("owner/repo.git"));
    }

    #[test]
    fn test_invalid_repo_ref_format() {
        // Invalid formats
        assert!(!is_valid_repo_ref(""));
        assert!(!is_valid_repo_ref("noslash"));
        assert!(!is_valid_repo_ref("too/many/slashes"));
        assert!(!is_valid_repo_ref("/repo"));
        assert!(!is_valid_repo_ref("owner/"));
        assert!(!is_valid_repo_ref("owner/repo with spaces"));
    }

    // =========================================================================
    // Bind Repo Tests (RAPTOR-2 Step 22)
    // =========================================================================

    #[test]
    fn test_bind_repo_request_deserialization() {
        let json = r#"{"workspace_id":"550e8400-e29b-41d4-a716-446655440000","repo_ref":"owner/repo"}"#;
        let request: BindRepoRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.workspace_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(request.repo_ref, "owner/repo");
    }

    #[test]
    fn test_bind_repo_response_no_paths() {
        let response = BindRepoResponse {
            workspace_id: "abc-123-def-456".to_string(),
            status: "bound".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
        // Must NOT echo repo_ref
        assert!(!json.contains("owner"), "Response should not contain repo_ref owner");
        assert!(!json.contains("repo"), "Response should not contain repo_ref repo");
    }

    #[test]
    fn test_bind_repo_response_no_urls() {
        let response = BindRepoResponse {
            workspace_id: "workspace-123".to_string(),
            status: "bound".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("github.com"), "Response must not contain URLs");
        assert!(!json.contains("https://"), "Response must not contain URL schemes");
        assert!(!json.contains("git@"), "Response must not contain SSH format");
    }

    // =========================================================================
    // Capability Constants Tests
    // =========================================================================

    #[test]
    fn test_capability_constants() {
        assert_eq!(WORKSPACES_READ_CAPABILITY, "workspaces.read");
        assert_eq!(WORKSPACES_PROVISION_CAPABILITY, "workspaces.provision");
        assert_eq!(WORKSPACES_BIND_REPO_CAPABILITY, "workspaces.bind_repo");
    }

    // =========================================================================
    // Persistence Integration Tests (RAPTOR-2 Step 23)
    // =========================================================================

    #[test]
    fn test_inventory_in_memory_mode() {
        let inventory = WorkspacesInventory::new();
        assert!(!inventory.is_persistent());

        let entry = inventory.create("Test".to_string());
        assert_eq!(inventory.count(), 1);
        assert_eq!(inventory.get(entry.workspace_id).unwrap().name, "Test");
    }

    fn create_test_key_config() -> persist::DataKeyConfig {
        // Fixed test key for deterministic testing
        persist::DataKeyConfig::from_key([0x42u8; 32], persist::CURRENT_KEY_VERSION)
    }

    #[test]
    fn test_inventory_persistence_roundtrip() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let node_id = Uuid::new_v4();
        let key_config = create_test_key_config();

        let workspace_id;
        let workspace_name = "Persisted Workspace";
        let repo_ref = "ekka-ai/demo";

        // First "session" - create workspace and bind repo
        {
            let store = persist::InventoryStore::new(persist::InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            });
            let inventory = WorkspacesInventory::with_persistence(store).unwrap();
            assert!(inventory.is_persistent());

            let entry = inventory.create(workspace_name.to_string());
            workspace_id = entry.workspace_id;

            // Bind repo
            assert!(inventory.set_repo_ref(workspace_id, repo_ref.to_string()));
            assert_eq!(inventory.get_repo_ref(workspace_id), Some(repo_ref.to_string()));
        }

        // Second "session" - simulate restart, load from disk
        {
            let store = persist::InventoryStore::new(persist::InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id, // Same node_id (used as salt)
                key_config: key_config.clone(), // Same key for decryption
            });
            let inventory = WorkspacesInventory::with_persistence(store).unwrap();

            // Verify data survived restart
            assert_eq!(inventory.count(), 1);
            let loaded = inventory.get(workspace_id).unwrap();
            assert_eq!(loaded.name, workspace_name);
            assert_eq!(loaded.repo_ref, Some(repo_ref.to_string()));

            // Verify get_repo_ref works
            assert_eq!(inventory.get_repo_ref(workspace_id), Some(repo_ref.to_string()));
        }
    }

    #[test]
    fn test_inventory_persistence_empty_start() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let node_id = Uuid::new_v4();

        let store = persist::InventoryStore::new(persist::InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id,
            key_config: create_test_key_config(),
        });
        let inventory = WorkspacesInventory::with_persistence(store).unwrap();

        // Should start empty
        assert_eq!(inventory.count(), 0);
        assert!(inventory.list().is_empty());
    }

    #[test]
    fn test_inventory_auto_persist_on_create() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let node_id = Uuid::new_v4();
        let key_config = create_test_key_config();

        let workspace_id;

        // Create workspace
        {
            let store = persist::InventoryStore::new(persist::InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            });
            let inventory = WorkspacesInventory::with_persistence(store).unwrap();

            let entry = inventory.create("Auto-Persisted".to_string());
            workspace_id = entry.workspace_id;
            // No explicit save needed - should auto-persist
        }

        // Verify persistence
        {
            let store = persist::InventoryStore::new(persist::InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            });
            let inventory = WorkspacesInventory::with_persistence(store).unwrap();

            assert_eq!(inventory.count(), 1);
            assert_eq!(inventory.get(workspace_id).unwrap().name, "Auto-Persisted");
        }
    }

    #[test]
    fn test_inventory_auto_persist_on_bind_repo() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let node_id = Uuid::new_v4();
        let key_config = create_test_key_config();

        let workspace_id;

        // Create and bind
        {
            let store = persist::InventoryStore::new(persist::InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            });
            let inventory = WorkspacesInventory::with_persistence(store).unwrap();

            let entry = inventory.create("With Repo".to_string());
            workspace_id = entry.workspace_id;

            inventory.set_repo_ref(workspace_id, "owner/repo".to_string());
            // No explicit save needed - should auto-persist
        }

        // Verify repo_ref persisted
        {
            let store = persist::InventoryStore::new(persist::InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            });
            let inventory = WorkspacesInventory::with_persistence(store).unwrap();

            assert_eq!(inventory.get_repo_ref(workspace_id), Some("owner/repo".to_string()));
        }
    }

    #[test]
    fn test_inventory_persistence_no_path_leak_in_errors() {
        // Use invalid path to trigger error
        let _store = persist::InventoryStore::new(persist::InventoryStoreConfig {
            data_dir: PathBuf::from("/nonexistent/deeply/nested/path"),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        });

        // If we had to surface this error, it must not leak the path
        let err = persist::PersistError::Load("/Users/secret/path".to_string());
        let display = format!("{}", err);
        assert_no_path_leak(&display);
        assert_eq!(err.code(), persist::PersistErrorCode::DATA_LOAD_FAILED);
    }
}
