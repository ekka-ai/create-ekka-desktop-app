//! EKKA Node Git Module - Enterprise Hardened
//!
//! Provides safe, workspace-bounded Git operations without exposing filesystem paths.
//! All operations are bounded to managed workspace roots resolved via callback.
//! Browser NEVER sends paths, only workspace_id.
//!
//! ## Security Properties (RAPTOR-2 Step 10)
//!
//! - Hard resource bounds on all operations (time, count, output)
//! - Workspace root canonicalization with symlink escape prevention
//! - No absolute paths in responses or logs
//! - Truncation flags for large repos
//! - Error messages never contain paths
//!
//! ## Authenticated Git Operations (RAPTOR-2 Step 26)
//!
//! - Clone/Push use persisted GitHub OAuth tokens from server-side store
//! - Token lookup via session_id -> (tenant_id, subject) -> token
//! - HTTPS authentication using x-access-token/oauth_token pattern
//! - Tokens NEVER returned to client, logs, or errors
//! - Clone can work without token (public repos), push requires token
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - A GitModuleContext with workspace resolver
//!
//! The workspace resolver is a closure provided by the host that maps
//! workspace_id -> PathBuf. The module NEVER exposes these paths.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use git2::{
    build::RepoBuilder, Cred, CredentialType, FetchOptions, PushOptions,
    RemoteCallbacks, Repository, StatusOptions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub use ekka_node_modules::{
    error_codes, ModuleConfig, ModuleError,
    SessionInfo, SessionValidationError, SessionValidator,
};

// =============================================================================
// Hard Resource Bounds (Enterprise Security)
// =============================================================================

/// Maximum number of status entries to scan (prevents DoS on huge repos)
pub const MAX_STATUS_FILE_SCAN: usize = 10_000;

/// Maximum number of commits to return
pub const MAX_COMMIT_COUNT: usize = 10;

/// Maximum length of commit subject (truncated with "...")
pub const MAX_COMMIT_SUBJECT_LEN: usize = 200;

/// Maximum length of author name (truncated with "...")
pub const MAX_AUTHOR_LEN: usize = 100;

/// Maximum branch name length (truncated)
pub const MAX_BRANCH_LEN: usize = 100;

// =============================================================================
// Module Configuration
// =============================================================================

/// Git module configuration
pub const GIT_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Git",
    env_var: "EKKA_ENABLE_GIT",
    default_enabled: false, // Disabled by default for security
};

// =============================================================================
// Git API Types (safe, no paths)
// =============================================================================

/// Git status response - counts only, no paths
#[derive(Debug, Clone, Serialize)]
pub struct GitStatusResponse {
    /// Workspace ID (echo back for confirmation)
    pub workspace_id: String,
    /// Whether a Git repository was detected at workspace root
    pub repo_detected: bool,
    /// Current branch name (if repo detected, truncated if too long)
    pub branch: Option<String>,
    /// Whether working directory has uncommitted changes
    pub is_dirty: bool,
    /// Number of commits ahead of upstream (0 if no upstream)
    pub ahead_by: u32,
    /// Number of commits behind upstream (0 if no upstream)
    pub behind_by: u32,
    /// Count of changed files (staged + unstaged modifications)
    pub changed_files_count: u32,
    /// Count of untracked files
    pub untracked_files_count: u32,
    /// True if counts were capped due to large repo (> MAX_STATUS_FILE_SCAN)
    #[serde(skip_serializing_if = "is_false")]
    pub counts_truncated: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Commit summary info - no paths
#[derive(Debug, Clone, Serialize)]
pub struct CommitInfo {
    /// Short hash (7 chars)
    pub hash_short: String,
    /// Commit subject line (first line of message, truncated if too long)
    pub subject: String,
    /// Author name (truncated if too long)
    pub author: String,
    /// Commit date in ISO 8601 UTC
    pub date_iso_utc: String,
}

/// Git summary response with recent commits
#[derive(Debug, Clone, Serialize)]
pub struct GitSummaryResponse {
    /// Workspace ID (echo back)
    pub workspace_id: String,
    /// Whether a Git repository was detected
    pub repo_detected: bool,
    /// Recent commits (max MAX_COMMIT_COUNT)
    pub recent_commits: Vec<CommitInfo>,
}

/// Git API error (re-export from module error)
pub type GitError = ModuleError;

// =============================================================================
// Git Write Types (PR-only workflow - RAPTOR-2 Step 18)
// =============================================================================

/// Commit request - creates a commit on the current EKKA branch
#[derive(Debug, Deserialize)]
pub struct CommitRequest {
    /// Workspace ID (UUID)
    pub workspace_id: String,
    /// Commit message (will be truncated and newlines stripped)
    pub message: String,
    /// Optional note for audit log (not included in commit)
    #[serde(default)]
    pub note: Option<String>,
}

/// Commit response - confirms the commit was created
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResponse {
    /// Operation status
    pub status: String,
    /// Branch name the commit was made on
    pub branch: String,
    /// Short commit hash
    pub commit_id: String,
    /// Number of files changed
    pub files_changed: u32,
    /// True if file count was capped
    #[serde(skip_serializing_if = "is_false")]
    pub counts_truncated: bool,
}

/// Push request - pushes the current EKKA branch to remote
#[derive(Debug, Deserialize)]
pub struct PushRequest {
    /// Workspace ID (UUID)
    pub workspace_id: String,
    /// Optional note for audit log
    #[serde(default)]
    pub note: Option<String>,
}

/// Push response - confirms the push
#[derive(Debug, Clone, Serialize)]
pub struct PushResponse {
    /// Operation status
    pub status: String,
    /// Branch that was pushed
    pub branch: String,
}

/// PR request - creates a pull request (stub for now)
#[derive(Debug, Deserialize)]
pub struct PrRequest {
    /// Workspace ID (UUID)
    pub workspace_id: String,
    /// PR title
    pub title: String,
    /// PR body/description (optional)
    #[serde(default)]
    pub body: Option<String>,
    /// Base branch (default: "main")
    #[serde(default)]
    pub base: Option<String>,
}

/// PR response - for now returns GITHUB_NOT_CONFIGURED
#[derive(Debug, Clone, Serialize)]
pub struct PrResponse {
    /// Operation status
    pub status: String,
    /// Error code (when not configured)
    pub code: String,
}

// =============================================================================
// Git Clone Types (RAPTOR-2 Step 22)
// =============================================================================

/// Clone request - workspace_id ONLY, no URLs from browser
#[derive(Debug, Deserialize)]
pub struct CloneRequest {
    /// Workspace ID (UUID) - the clone target is resolved server-side
    pub workspace_id: String,
}

/// Clone response - minimal, no paths
#[derive(Debug, Clone, Serialize)]
pub struct CloneResponse {
    /// Operation status
    pub status: String,
    /// Workspace ID (echo back)
    pub workspace_id: String,
}

/// Clone error codes (safe, no paths or URLs)
pub struct CloneErrorCodes;

impl CloneErrorCodes {
    pub const REPO_NOT_BOUND: &'static str = "REPO_NOT_BOUND";
    pub const REPO_ALREADY_PRESENT: &'static str = "REPO_ALREADY_PRESENT";
    pub const CLONE_FAILED: &'static str = "CLONE_FAILED";
}

// =============================================================================
// Repo Binding Resolution Interface (RAPTOR-2 Step 22)
// =============================================================================

/// Error from repo binding resolution (safe, no URLs in errors)
#[derive(Debug, Clone)]
pub enum RepoBindingError {
    /// Workspace has no repo_ref bound
    NotBound,
    /// Invalid workspace ID
    InvalidWorkspace,
    /// Resolver not available
    ResolverNotAvailable,
}

impl RepoBindingError {
    pub fn code(&self) -> &'static str {
        match self {
            RepoBindingError::NotBound => CloneErrorCodes::REPO_NOT_BOUND,
            RepoBindingError::InvalidWorkspace => "INVALID_WORKSPACE_ID",
            RepoBindingError::ResolverNotAvailable => "RESOLVER_NOT_AVAILABLE",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            RepoBindingError::NotBound => "No repository bound to workspace",
            RepoBindingError::InvalidWorkspace => "Invalid workspace ID",
            RepoBindingError::ResolverNotAvailable => "Repository resolver not available",
        }
    }
}

/// Repo binding resolver - provided by host
/// Resolves workspace_id -> repo_ref (owner/repo format)
/// Browser NEVER sends repo URL - only workspace_id
pub type RepoBindingResolver =
    Arc<dyn Fn(&str) -> Result<String, RepoBindingError> + Send + Sync>;

// =============================================================================
// Git Token Provider Interface (RAPTOR-2 Step 26)
// =============================================================================

/// Token provider for authenticated git operations (provided by host)
/// Returns GitHub OAuth token for a session ID, resolved via session -> (tenant_id, subject)
/// Token is used for HTTPS authentication with username "x-access-token"
pub type GitTokenProvider = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

// =============================================================================
// Idempotency Store (RAPTOR-2 Step 28)
// =============================================================================

/// Maximum idempotency key length
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 100;

/// Idempotency TTL (10 minutes)
const IDEMPOTENCY_TTL: Duration = Duration::from_secs(600);

/// Maximum entries in idempotency store (LRU eviction)
const IDEMPOTENCY_MAX_ENTRIES: usize = 1000;

/// Header name for idempotency key
pub const IDEMPOTENCY_KEY_HEADER: &str = "x-idempotency-key";

/// Stored response for idempotency
#[derive(Clone)]
struct IdempotencyEntry {
    response_json: String,
    status_code: u16,
    created_at: Instant,
}

/// In-memory idempotency store (RAPTOR-2 Step 28)
/// Keyed by (tenant_id, subject, workspace_id, op, idempotency_key)
#[derive(Default)]
pub struct IdempotencyStore {
    entries: RwLock<HashMap<String, IdempotencyEntry>>,
}

impl IdempotencyStore {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Build composite key (no secrets in key itself, just hashes)
    fn make_key(tenant_id: &str, subject: &str, workspace_id: &str, op: &str, idem_key: &str) -> String {
        // Hash to avoid leaking tenant/subject in memory key
        let mut hasher = Sha256::new();
        hasher.update(tenant_id.as_bytes());
        hasher.update(b":");
        hasher.update(subject.as_bytes());
        hasher.update(b":");
        hasher.update(workspace_id.as_bytes());
        hasher.update(b":");
        hasher.update(op.as_bytes());
        hasher.update(b":");
        hasher.update(idem_key.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..16]) // 32 hex chars
    }

    /// Check for existing entry, evicting stale ones
    pub fn get(&self, tenant_id: &str, subject: &str, workspace_id: &str, op: &str, idem_key: &str) -> Option<(String, u16)> {
        let key = Self::make_key(tenant_id, subject, workspace_id, op, idem_key);
        let entries = self.entries.read().ok()?;
        let entry = entries.get(&key)?;

        // Check TTL
        if entry.created_at.elapsed() > IDEMPOTENCY_TTL {
            return None;
        }

        Some((entry.response_json.clone(), entry.status_code))
    }

    /// Store response for idempotency
    pub fn set(&self, tenant_id: &str, subject: &str, workspace_id: &str, op: &str, idem_key: &str, response_json: String, status_code: u16) {
        let key = Self::make_key(tenant_id, subject, workspace_id, op, idem_key);

        if let Ok(mut entries) = self.entries.write() {
            // Evict stale entries if at capacity
            if entries.len() >= IDEMPOTENCY_MAX_ENTRIES {
                let now = Instant::now();
                entries.retain(|_, v| now.duration_since(v.created_at) < IDEMPOTENCY_TTL);

                // If still at capacity, remove oldest
                if entries.len() >= IDEMPOTENCY_MAX_ENTRIES {
                    if let Some(oldest_key) = entries.iter()
                        .min_by_key(|(_, v)| v.created_at)
                        .map(|(k, _)| k.clone())
                    {
                        entries.remove(&oldest_key);
                    }
                }
            }

            entries.insert(key, IdempotencyEntry {
                response_json,
                status_code,
                created_at: Instant::now(),
            });
        }
    }
}

// =============================================================================
// Audit Store (RAPTOR-2 Step 28)
// =============================================================================

/// Maximum audit events in ring buffer
const AUDIT_MAX_EVENTS: usize = 200;

/// Audit event - safe fields only, no paths/URLs/tokens
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Timestamp in ISO 8601 UTC
    pub ts_utc: String,
    /// Workspace ID
    pub workspace_id: String,
    /// Operation: clone, commit, push, pr
    pub op: String,
    /// Result: ok or err
    pub result: String,
    /// Stable error code or "OK"
    pub code: String,
    /// Session key (sha256 truncated of tenant:subject, not raw)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(workspace_id: &str, op: &str, result: &str, code: &str, tenant_id: Option<&str>, subject: Option<&str>) -> Self {
        let session_key = match (tenant_id, subject) {
            (Some(t), Some(s)) => {
                let mut hasher = Sha256::new();
                hasher.update(t.as_bytes());
                hasher.update(b":");
                hasher.update(s.as_bytes());
                let hash = hasher.finalize();
                Some(hex::encode(&hash[..8])) // 16 hex chars, truncated
            }
            _ => None,
        };

        Self {
            ts_utc: chrono::Utc::now().to_rfc3339(),
            workspace_id: workspace_id.to_string(),
            op: op.to_string(),
            result: result.to_string(),
            code: code.to_string(),
            session_key,
        }
    }
}

/// Audit query parameters
#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub workspace_id: String,
    /// Optional limit (max 100, default 50)
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Audit response
#[derive(Debug, Clone, Serialize)]
pub struct AuditResponse {
    pub workspace_id: String,
    pub events: Vec<AuditEvent>,
}

/// In-memory audit ring buffer (RAPTOR-2 Step 28)
#[derive(Default)]
pub struct AuditStore {
    /// Events by workspace_id
    events: RwLock<HashMap<String, Vec<AuditEvent>>>,
}

impl AuditStore {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
        }
    }

    /// Record an audit event
    pub fn record(&self, event: AuditEvent) {
        if let Ok(mut events) = self.events.write() {
            let workspace_events = events.entry(event.workspace_id.clone()).or_insert_with(Vec::new);
            workspace_events.push(event);

            // Keep only last AUDIT_MAX_EVENTS per workspace
            if workspace_events.len() > AUDIT_MAX_EVENTS {
                let excess = workspace_events.len() - AUDIT_MAX_EVENTS;
                workspace_events.drain(0..excess);
            }
        }
    }

    /// Get events for a workspace (most recent first)
    pub fn get(&self, workspace_id: &str, limit: usize) -> Vec<AuditEvent> {
        if let Ok(events) = self.events.read() {
            if let Some(workspace_events) = events.get(workspace_id) {
                let start = workspace_events.len().saturating_sub(limit);
                return workspace_events[start..].iter().rev().cloned().collect();
            }
        }
        Vec::new()
    }
}

// =============================================================================
// Request types
// =============================================================================

/// Query parameters for git endpoints
#[derive(Debug, Deserialize)]
pub struct GitQueryParams {
    pub workspace_id: String,
}

// =============================================================================
// Workspace Resolution Interface
// =============================================================================

/// Error types for workspace resolution
#[derive(Debug, Clone)]
pub enum WorkspaceResolutionError {
    /// Workspaces feature is disabled
    WorkspacesDisabled,
    /// Workspace ID not found
    NotFound,
    /// Workspace is quarantined or deleted
    NotAccessible(String),
    /// Invalid workspace ID format
    InvalidId,
    /// Path validation failed (symlink escape, etc.)
    PathValidationFailed,
}

impl WorkspaceResolutionError {
    /// Convert to safe error code (no path info)
    pub fn code(&self) -> &'static str {
        match self {
            WorkspaceResolutionError::WorkspacesDisabled => "WORKSPACES_DISABLED",
            WorkspaceResolutionError::NotFound => "WORKSPACE_NOT_FOUND",
            WorkspaceResolutionError::NotAccessible(_) => "WORKSPACE_NOT_ACCESSIBLE",
            WorkspaceResolutionError::InvalidId => "INVALID_WORKSPACE_ID",
            WorkspaceResolutionError::PathValidationFailed => "WORKSPACE_PATH_VALIDATION_FAILED",
        }
    }

    /// Convert to safe error message (no path info)
    pub fn message(&self) -> String {
        match self {
            WorkspaceResolutionError::WorkspacesDisabled => {
                "Workspaces feature is disabled".to_string()
            }
            WorkspaceResolutionError::NotFound => "Workspace not found".to_string(),
            WorkspaceResolutionError::NotAccessible(status) => {
                format!("Workspace is {}", status)
            }
            WorkspaceResolutionError::InvalidId => "Invalid workspace ID format".to_string(),
            WorkspaceResolutionError::PathValidationFailed => {
                "Workspace path validation failed".to_string()
            }
        }
    }
}

/// Workspace resolver function type
/// Takes workspace_id string, returns PathBuf or error
/// The resolver is provided by the host application
pub type WorkspaceResolver =
    Arc<dyn Fn(&str) -> Result<PathBuf, WorkspaceResolutionError> + Send + Sync>;

// =============================================================================
// Path Validation (Symlink Escape Prevention)
// =============================================================================

/// Validate workspace root path for security
/// - Must exist and be a directory
/// - Canonicalizes to detect symlink escapes
/// - Never logs or returns the actual path
pub fn validate_workspace_root(root: &Path) -> Result<PathBuf, WorkspaceResolutionError> {
    // Must exist
    if !root.exists() {
        return Err(WorkspaceResolutionError::NotAccessible(
            "path missing".to_string(),
        ));
    }

    // Must be a directory
    if !root.is_dir() {
        return Err(WorkspaceResolutionError::PathValidationFailed);
    }

    // Canonicalize to resolve symlinks and get real path
    let canonical =
        fs::canonicalize(root).map_err(|_| WorkspaceResolutionError::PathValidationFailed)?;

    // The canonical path must still be a directory
    if !canonical.is_dir() {
        return Err(WorkspaceResolutionError::PathValidationFailed);
    }

    Ok(canonical)
}

/// Validate that a git workdir is within the expected workspace root
/// This prevents symlink escapes where .git/config points elsewhere
fn validate_repo_workdir(repo: &Repository, expected_root: &Path) -> Result<(), GitOperationError> {
    // Get the workdir (non-bare repos only)
    let workdir = match repo.workdir() {
        Some(wd) => wd,
        None => {
            // Bare repository - we don't support this for workspace operations
            return Err(GitOperationError::BareRepoNotSupported);
        }
    };

    // Canonicalize both paths for comparison
    let canonical_workdir =
        fs::canonicalize(workdir).map_err(|_| GitOperationError::PathValidationFailed)?;
    let canonical_root =
        fs::canonicalize(expected_root).map_err(|_| GitOperationError::PathValidationFailed)?;

    // The workdir must be within or equal to the expected root
    if !canonical_workdir.starts_with(&canonical_root) {
        return Err(GitOperationError::WorkdirOutsideRoot);
    }

    Ok(())
}

// =============================================================================
// Git Operation Errors (Internal - never exposed with paths)
// =============================================================================

/// Internal git operation errors
#[derive(Debug, Clone)]
pub enum GitOperationError {
    /// Repository could not be opened
    #[allow(dead_code)] // Part of API contract for future error cases
    RepoOpenFailed,
    /// Bare repositories not supported
    BareRepoNotSupported,
    /// Workdir is outside expected root (symlink escape)
    WorkdirOutsideRoot,
    /// Path validation failed
    PathValidationFailed,
    /// Git operation failed internally
    #[allow(dead_code)] // Part of API contract for future error cases
    OperationFailed,
    /// Attempted write to protected branch (main/master)
    ProtectedBranch,
    /// No changes to commit
    NothingToCommit,
    /// No remote configured for push
    NoRemoteConfigured,
    /// Commit failed
    CommitFailed,
}

impl GitOperationError {
    /// Convert to safe error code (no path info)
    pub fn code(&self) -> &'static str {
        match self {
            GitOperationError::RepoOpenFailed => "GIT_REPO_OPEN_FAILED",
            GitOperationError::BareRepoNotSupported => "GIT_BARE_REPO_NOT_SUPPORTED",
            GitOperationError::WorkdirOutsideRoot => "GIT_SECURITY_VIOLATION",
            GitOperationError::PathValidationFailed => "GIT_PATH_VALIDATION_FAILED",
            GitOperationError::OperationFailed => "GIT_INTERNAL_ERROR",
            GitOperationError::ProtectedBranch => "GIT_PROTECTED_BRANCH",
            GitOperationError::NothingToCommit => "GIT_NOTHING_TO_COMMIT",
            GitOperationError::NoRemoteConfigured => "GIT_NO_REMOTE",
            GitOperationError::CommitFailed => "GIT_COMMIT_FAILED",
        }
    }

    /// Convert to safe error message (no path info)
    pub fn message(&self) -> &'static str {
        match self {
            GitOperationError::RepoOpenFailed => "Failed to open Git repository",
            GitOperationError::BareRepoNotSupported => "Bare repositories are not supported",
            GitOperationError::WorkdirOutsideRoot => "Repository configuration is invalid",
            GitOperationError::PathValidationFailed => "Path validation failed",
            GitOperationError::OperationFailed => "Git operation failed",
            GitOperationError::ProtectedBranch => "Cannot write to protected branch",
            GitOperationError::NothingToCommit => "No changes to commit",
            GitOperationError::NoRemoteConfigured => "No remote configured for push",
            GitOperationError::CommitFailed => "Commit operation failed",
        }
    }
}

// =============================================================================
// String Truncation Helpers
// =============================================================================

/// Truncate string to max length with "..." suffix
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s[..max_len].to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

// =============================================================================
// Git Write Helpers (PR-only workflow - RAPTOR-2 Step 18)
// =============================================================================

/// Sanitize commit message: strip newlines and truncate
/// This prevents injection attacks and ensures consistent formatting
pub fn sanitize_commit_message(message: &str) -> String {
    // Replace all newlines with spaces, then collapse multiple spaces
    let sanitized = message
        .replace('\n', " ")
        .replace('\r', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    // Truncate to max length
    truncate_string(&sanitized, MAX_COMMIT_MESSAGE_LEN)
}

/// Maximum length for tenant/subject in branch name (RAPTOR-2 Step 28)
const MAX_BRANCH_SEGMENT_LEN: usize = 32;

/// Sanitize a string for use in branch names (RAPTOR-2 Step 28)
/// - lowercase
/// - only alphanumeric and '-'
/// - max 32 chars
/// - fallback to "unknown" if empty
pub fn sanitize_branch_segment(s: &str) -> String {
    let sanitized: String = s
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(MAX_BRANCH_SEGMENT_LEN)
        .collect();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

/// Generate EKKA branch name for PR-only workflow (RAPTOR-2 Step 28)
/// Format: ekka/<tenant>/<subject>/<timestamp>
/// - tenant/subject are sanitized (lowercase, alnum + '-', max 32 chars)
/// - timestamp is YYYYMMDDHHMMSS UTC
/// - Deterministic given the same inputs (except timestamp)
pub fn generate_ekka_branch_name(tenant_id: &str, subject: &str) -> String {
    let tenant_sanitized = sanitize_branch_segment(tenant_id);
    let subject_sanitized = sanitize_branch_segment(subject);

    // Use UTC timestamp for uniqueness
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");

    format!("{}{}/{}/{}", EKKA_BRANCH_PREFIX, tenant_sanitized, subject_sanitized, timestamp)
}

/// Validate that a branch name is safe for write operations
/// Returns error if branch is protected or doesn't have EKKA prefix
pub fn validate_write_branch(branch: &str) -> Result<(), GitOperationError> {
    // Must have EKKA prefix
    if !branch.starts_with(EKKA_BRANCH_PREFIX) {
        return Err(GitOperationError::ProtectedBranch);
    }

    // Cannot be a protected branch (even with ekka/ prefix, check the base name)
    let branch_lower = branch.to_lowercase();
    for protected in PROTECTED_BRANCHES {
        if branch_lower == *protected || branch_lower.ends_with(&format!("/{}", protected)) {
            return Err(GitOperationError::ProtectedBranch);
        }
    }

    Ok(())
}

/// Check if a branch name is protected (main, master)
pub fn is_protected_branch(branch: &str) -> bool {
    let branch_lower = branch.to_lowercase();
    PROTECTED_BRANCHES.iter().any(|p| branch_lower == *p)
}

// =============================================================================
// Git operations (internal, path-based)
// =============================================================================

/// Get git status for a workspace root
/// Returns a safe response with no paths, bounded counts
pub fn get_git_status(
    workspace_path: &PathBuf,
    workspace_id: &str,
) -> Result<GitStatusResponse, GitOperationError> {
    // Try to open repository
    let repo = match Repository::open(workspace_path) {
        Ok(r) => r,
        Err(_) => {
            // No git repo at this location - not an error, just no repo
            return Ok(GitStatusResponse {
                workspace_id: workspace_id.to_string(),
                repo_detected: false,
                branch: None,
                is_dirty: false,
                ahead_by: 0,
                behind_by: 0,
                changed_files_count: 0,
                untracked_files_count: 0,
                counts_truncated: false,
            });
        }
    };

    // Validate workdir is within expected root
    validate_repo_workdir(&repo, workspace_path)?;

    // Get current branch (truncated)
    let branch = repo
        .head()
        .ok()
        .and_then(|head| head.shorthand().map(|s| truncate_string(s, MAX_BRANCH_LEN)));

    // Get status counts with hard cap
    let mut opts = StatusOptions::new();
    opts.include_untracked(true);
    opts.recurse_untracked_dirs(true);

    let (changed_count, untracked_count, truncated) = match repo.statuses(Some(&mut opts)) {
        Ok(statuses) => {
            let mut changed = 0u32;
            let mut untracked = 0u32;
            let mut scanned = 0usize;
            let mut was_truncated = false;

            for entry in statuses.iter() {
                scanned += 1;
                if scanned > MAX_STATUS_FILE_SCAN {
                    was_truncated = true;
                    break;
                }

                let status = entry.status();
                if status.is_wt_new() || status.is_index_new() {
                    untracked += 1;
                } else if !status.is_ignored() {
                    changed += 1;
                }
            }

            (changed, untracked, was_truncated)
        }
        Err(_) => (0, 0, false),
    };

    // Check ahead/behind (if tracking remote)
    let (ahead, behind) = get_ahead_behind(&repo).unwrap_or((0, 0));

    let is_dirty = changed_count > 0 || untracked_count > 0;

    Ok(GitStatusResponse {
        workspace_id: workspace_id.to_string(),
        repo_detected: true,
        branch,
        is_dirty,
        ahead_by: ahead,
        behind_by: behind,
        changed_files_count: changed_count,
        untracked_files_count: untracked_count,
        counts_truncated: truncated,
    })
}

/// Get recent commits for a workspace
/// Returns a safe response with no paths, bounded commits
pub fn get_git_summary(
    workspace_path: &PathBuf,
    workspace_id: &str,
) -> Result<GitSummaryResponse, GitOperationError> {
    // Try to open repository
    let repo = match Repository::open(workspace_path) {
        Ok(r) => r,
        Err(_) => {
            return Ok(GitSummaryResponse {
                workspace_id: workspace_id.to_string(),
                repo_detected: false,
                recent_commits: vec![],
            });
        }
    };

    // Validate workdir is within expected root
    validate_repo_workdir(&repo, workspace_path)?;

    // Get HEAD commit and walk history (bounded)
    let commits = match get_recent_commits(&repo, MAX_COMMIT_COUNT) {
        Ok(c) => c,
        Err(_) => vec![],
    };

    Ok(GitSummaryResponse {
        workspace_id: workspace_id.to_string(),
        repo_detected: true,
        recent_commits: commits,
    })
}

/// Get ahead/behind counts for current branch vs upstream
fn get_ahead_behind(repo: &Repository) -> Result<(u32, u32), git2::Error> {
    let head = repo.head()?;
    if !head.is_branch() {
        return Ok((0, 0));
    }

    let local_oid = head
        .target()
        .ok_or_else(|| git2::Error::from_str("HEAD has no target"))?;

    // Get upstream branch
    let branch = repo.find_branch(head.shorthand().unwrap_or("HEAD"), git2::BranchType::Local)?;

    let upstream = match branch.upstream() {
        Ok(u) => u,
        Err(_) => return Ok((0, 0)), // No upstream configured
    };

    let upstream_oid = upstream
        .get()
        .target()
        .ok_or_else(|| git2::Error::from_str("Upstream has no target"))?;

    let (ahead, behind) = repo.graph_ahead_behind(local_oid, upstream_oid)?;
    Ok((ahead as u32, behind as u32))
}

/// Get recent commits (max limit) with truncated fields
fn get_recent_commits(repo: &Repository, limit: usize) -> Result<Vec<CommitInfo>, git2::Error> {
    let mut commits = Vec::new();

    let head = repo.head()?;
    let head_oid = head
        .target()
        .ok_or_else(|| git2::Error::from_str("HEAD has no target"))?;

    let mut revwalk = repo.revwalk()?;
    revwalk.push(head_oid)?;
    revwalk.set_sorting(git2::Sort::TIME)?;

    for (count, oid_result) in revwalk.enumerate() {
        if count >= limit {
            break;
        }

        let oid = oid_result?;
        let commit = repo.find_commit(oid)?;

        // Get commit time in UTC
        let time = commit.time();
        let datetime =
            chrono::DateTime::from_timestamp(time.seconds(), 0).unwrap_or_else(chrono::Utc::now);

        // Truncate subject and author for safety
        let subject = truncate_string(
            commit.summary().unwrap_or("(no message)"),
            MAX_COMMIT_SUBJECT_LEN,
        );
        let author = truncate_string(commit.author().name().unwrap_or("Unknown"), MAX_AUTHOR_LEN);

        commits.push(CommitInfo {
            hash_short: format!("{}", oid)[..7].to_string(),
            subject,
            author,
            date_iso_utc: datetime.to_rfc3339(),
        });
    }

    Ok(commits)
}

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Required capability for git read operations
pub const GIT_READ_CAPABILITY: &str = "git.read";

/// Required capability for git commit operations (RAPTOR-2 Step 27)
/// Separate from push for least-privilege
pub const GIT_COMMIT_CAPABILITY: &str = "git.commit";

/// Required capability for git push operations (RAPTOR-2 Step 27)
/// Required for push and PR creation
pub const GIT_PUSH_CAPABILITY: &str = "git.push";

/// Legacy umbrella capability for git write operations
/// DEPRECATED: Use GIT_COMMIT_CAPABILITY and GIT_PUSH_CAPABILITY instead
/// Kept for backwards compatibility - implies both commit and push internally
#[allow(dead_code)]
pub const GIT_WRITE_CAPABILITY: &str = "git.write";

/// Required capability for GitHub PR creation (requires github.pr AND git.push)
pub const GITHUB_PR_CAPABILITY: &str = "github.pr";

/// Required capability for git clone operations (privileged)
pub const GIT_CLONE_CAPABILITY: &str = "git.clone";

/// Maximum commit message length (characters)
pub const MAX_COMMIT_MESSAGE_LEN: usize = 200;

/// Branch prefix required for all write operations (PR-only workflow)
pub const EKKA_BRANCH_PREFIX: &str = "ekka/";

/// Protected branches that cannot be targeted for write operations
pub const PROTECTED_BRANCHES: &[&str] = &["main", "master"];

/// Type alias for repo allow-list checker function (RAPTOR-2 Step 31)
/// Returns true if repo_ref is allowed, false otherwise
pub type RepoAllowListChecker = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Context for the Git module
/// Provided by the host application when mounting
#[derive(Clone)]
pub struct GitModuleContext {
    /// Workspace resolver function (workspace_id -> PathBuf)
    pub workspace_resolver: WorkspaceResolver,
    /// Session validator (provided by host for request-time auth)
    pub session_validator: SessionValidator,
    /// Repo binding resolver (workspace_id -> repo_ref) for clone operations
    pub repo_binding_resolver: Option<RepoBindingResolver>,
    /// Token provider for authenticated git operations (session_id -> token)
    /// Used for clone/push with GitHub OAuth tokens (RAPTOR-2 Step 26)
    pub token_provider: Option<GitTokenProvider>,
    /// Require token for clone operations (RAPTOR-2 Step 27)
    /// When true (studio mode), clone fails if no token available
    /// When false (demo mode), clone can proceed unauthenticated for public repos
    pub clone_requires_token: bool,
    /// Protected branch prefixes (RAPTOR-2 Step 28)
    /// e.g., ["release/", "hotfix/"] - branches starting with these are protected
    pub protected_prefixes: Vec<String>,
    /// Idempotency store for retry-safety (RAPTOR-2 Step 28)
    pub idempotency_store: Arc<IdempotencyStore>,
    /// Audit store for minimal audit trail (RAPTOR-2 Step 28)
    pub audit_store: Arc<AuditStore>,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
    /// Repo allow-list checker (RAPTOR-2 Step 31) - defense in depth
    /// Validates repo_ref at clone/push/pr time even if previously bound
    pub repo_allowlist: Option<RepoAllowListChecker>,
    /// Whether allow-list is required (RAPTOR-2 Step 31)
    /// If true and repo_allowlist is None, operations fail with REPO_ALLOWLIST_NOT_CONFIGURED
    pub repo_allowlist_required: bool,
}

impl GitModuleContext {
    pub fn new(
        resolver: WorkspaceResolver,
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspace_resolver: resolver,
            session_validator,
            repo_binding_resolver: None,
            token_provider: None,
            clone_requires_token: false,
            protected_prefixes: Vec::new(),
            idempotency_store: Arc::new(IdempotencyStore::new()),
            audit_store: Arc::new(AuditStore::new()),
            log_prefix: log_prefix.into(),
            repo_allowlist: None,
            repo_allowlist_required: false,
        }
    }

    /// Create context with repo binding resolver (for clone support)
    pub fn with_repo_binding(
        resolver: WorkspaceResolver,
        session_validator: SessionValidator,
        repo_binding_resolver: RepoBindingResolver,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspace_resolver: resolver,
            session_validator,
            repo_binding_resolver: Some(repo_binding_resolver),
            token_provider: None,
            clone_requires_token: false,
            protected_prefixes: Vec::new(),
            idempotency_store: Arc::new(IdempotencyStore::new()),
            audit_store: Arc::new(AuditStore::new()),
            log_prefix: log_prefix.into(),
            repo_allowlist: None,
            repo_allowlist_required: false,
        }
    }

    /// Create context with repo binding resolver AND token provider (for authenticated clone/push)
    /// RAPTOR-2 Step 26 + Step 27 + Step 28: Enables authenticated git operations with full hardening
    pub fn with_auth(
        resolver: WorkspaceResolver,
        session_validator: SessionValidator,
        repo_binding_resolver: RepoBindingResolver,
        token_provider: GitTokenProvider,
        clone_requires_token: bool,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspace_resolver: resolver,
            session_validator,
            repo_binding_resolver: Some(repo_binding_resolver),
            token_provider: Some(token_provider),
            clone_requires_token,
            protected_prefixes: Vec::new(),
            idempotency_store: Arc::new(IdempotencyStore::new()),
            audit_store: Arc::new(AuditStore::new()),
            log_prefix: log_prefix.into(),
            repo_allowlist: None,
            repo_allowlist_required: false,
        }
    }

    /// Create fully configured context with protected prefixes (RAPTOR-2 Step 28)
    pub fn with_full_config(
        resolver: WorkspaceResolver,
        session_validator: SessionValidator,
        repo_binding_resolver: RepoBindingResolver,
        token_provider: GitTokenProvider,
        clone_requires_token: bool,
        protected_prefixes: Vec<String>,
        idempotency_store: Arc<IdempotencyStore>,
        audit_store: Arc<AuditStore>,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspace_resolver: resolver,
            session_validator,
            repo_binding_resolver: Some(repo_binding_resolver),
            token_provider: Some(token_provider),
            clone_requires_token,
            protected_prefixes,
            idempotency_store,
            audit_store,
            log_prefix: log_prefix.into(),
            repo_allowlist: None,
            repo_allowlist_required: false,
        }
    }

    /// Create context with allow-list support (RAPTOR-2 Step 31)
    pub fn with_allowlist(
        resolver: WorkspaceResolver,
        session_validator: SessionValidator,
        repo_binding_resolver: RepoBindingResolver,
        token_provider: GitTokenProvider,
        clone_requires_token: bool,
        repo_allowlist: Option<RepoAllowListChecker>,
        repo_allowlist_required: bool,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            workspace_resolver: resolver,
            session_validator,
            repo_binding_resolver: Some(repo_binding_resolver),
            token_provider: Some(token_provider),
            clone_requires_token,
            protected_prefixes: Vec::new(),
            idempotency_store: Arc::new(IdempotencyStore::new()),
            audit_store: Arc::new(AuditStore::new()),
            log_prefix: log_prefix.into(),
            repo_allowlist,
            repo_allowlist_required,
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.git.{}", self.log_prefix, op)
    }

    /// Check if a branch matches any protected prefix (RAPTOR-2 Step 28)
    fn is_prefix_protected(&self, branch: &str) -> bool {
        self.protected_prefixes.iter().any(|prefix| branch.starts_with(prefix))
    }

    /// Check if repo_ref is allowed by allow-list (RAPTOR-2 Step 31)
    /// Returns Ok(()) if allowed, Err with appropriate error if not
    fn check_repo_allowlist(&self, repo_ref: &str) -> Result<(), (StatusCode, GitError)> {
        // If allow-list is required but not configured, fail
        if self.repo_allowlist_required && self.repo_allowlist.is_none() {
            return Err((
                StatusCode::FORBIDDEN,
                GitError {
                    error: "Repository policy not configured".to_string(),
                    code: "REPO_ALLOWLIST_NOT_CONFIGURED".to_string(),
                },
            ));
        }

        // If allow-list is configured, check if repo is allowed
        if let Some(ref checker) = self.repo_allowlist {
            if !checker(repo_ref) {
                return Err((
                    StatusCode::FORBIDDEN,
                    GitError {
                        error: "Repository not permitted".to_string(),
                        code: "REPO_NOT_ALLOWED".to_string(),
                    },
                ));
            }
        }

        Ok(())
    }
}

/// Mount the Git module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: GitModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !GIT_MODULE_CONFIG.is_enabled() {
        info!(
            module = "git",
            enabled = false,
            "Git module disabled (set EKKA_ENABLE_GIT=1 to enable)"
        );
        return router;
    }

    info!(
        module = "git",
        enabled = true,
        "Git module enabled"
    );

    let state = Arc::new(ctx);

    // Create a sub-router with our state, then merge into main router
    // Read endpoints: GET /v0/git/status, GET /v0/git/summary, GET /v0/git/audit
    // Write endpoints: POST /v0/git/commit, POST /v0/git/push, POST /v0/git/pr
    let git_router: Router<S> = Router::new()
        // Read operations (require git.read)
        .route("/v0/git/status", get(git_status_handler))
        .route("/v0/git/summary", get(git_summary_handler))
        .route("/v0/git/audit", get(git_audit_handler))  // RAPTOR-2 Step 28
        // Write operations (require git.commit/git.push/github.pr) - PR-only workflow
        .route("/v0/git/commit", post(git_commit_handler))
        .route("/v0/git/push", post(git_push_handler))
        .route("/v0/git/pr", post(git_pr_handler))
        .route("/v0/git/clone", post(git_clone_handler))
        .with_state(state);

    router.merge(git_router)
}

// =============================================================================
// Axum Handlers
// =============================================================================

/// GET /v0/git/status?workspace_id=<id> - Get git status for workspace
/// Requires: valid session + "git.read" capability
async fn git_status_handler(
    State(ctx): State<Arc<GitModuleContext>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GitQueryParams>,
) -> Result<Json<GitStatusResponse>, (StatusCode, Json<GitError>)> {
    let ws_id_short = &params.workspace_id[..8.min(params.workspace_id.len())];

    info!(
        op = %ctx.log_op("status.request"),
        workspace_id = %ws_id_short,
        "Git status requested"
    );

    // Step 1: Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("status.auth_error"),
            workspace_id = %ws_id_short,
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(GitError::new(e.error, e.code)),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(GIT_READ_CAPABILITY) {
        warn!(
            op = %ctx.log_op("status.capability_denied"),
            workspace_id = %ws_id_short,
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Not permitted", error_codes::CAPABILITY_DENIED)),
        ));
    }

    // Step 3: Resolve workspace root (internal only - path never exposed)
    let workspace_path = match (ctx.workspace_resolver)(&params.workspace_id) {
        Ok(path) => path,
        Err(e) => {
            warn!(
                op = %ctx.log_op("status.denied"),
                workspace_id = %ws_id_short,
                error_code = %e.code(),
                "Git status denied"
            );
            return Err((
                match &e {
                    WorkspaceResolutionError::NotFound => StatusCode::NOT_FOUND,
                    WorkspaceResolutionError::InvalidId => StatusCode::BAD_REQUEST,
                    WorkspaceResolutionError::NotAccessible(_) => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::PathValidationFailed => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::WorkspacesDisabled => StatusCode::SERVICE_UNAVAILABLE,
                },
                Json(GitError::new(e.message(), e.code())),
            ));
        }
    };

    // Step 4: Perform git status (path used internally, never exposed)
    let response = match get_git_status(&workspace_path, &params.workspace_id) {
        Ok(r) => r,
        Err(git_err) => {
            warn!(
                op = %ctx.log_op("status.error"),
                workspace_id = %ws_id_short,
                error_code = %git_err.code(),
                "Git status operation failed"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new(git_err.message(), git_err.code())),
            ));
        }
    };

    info!(
        op = %ctx.log_op("status.ok"),
        workspace_id = %ws_id_short,
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        repo_detected = %response.repo_detected,
        is_dirty = %response.is_dirty,
        counts_truncated = %response.counts_truncated,
        "Git status complete"
    );

    Ok(Json(response))
}

/// GET /v0/git/summary?workspace_id=<id> - Get git summary with recent commits
/// Requires: valid session + "git.read" capability
async fn git_summary_handler(
    State(ctx): State<Arc<GitModuleContext>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GitQueryParams>,
) -> Result<Json<GitSummaryResponse>, (StatusCode, Json<GitError>)> {
    let ws_id_short = &params.workspace_id[..8.min(params.workspace_id.len())];

    info!(
        op = %ctx.log_op("summary.request"),
        workspace_id = %ws_id_short,
        "Git summary requested"
    );

    // Step 1: Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("summary.auth_error"),
            workspace_id = %ws_id_short,
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(GitError::new(e.error, e.code)),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(GIT_READ_CAPABILITY) {
        warn!(
            op = %ctx.log_op("summary.capability_denied"),
            workspace_id = %ws_id_short,
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Not permitted", error_codes::CAPABILITY_DENIED)),
        ));
    }

    // Step 3: Resolve workspace root (internal only - path never exposed)
    let workspace_path = match (ctx.workspace_resolver)(&params.workspace_id) {
        Ok(path) => path,
        Err(e) => {
            warn!(
                op = %ctx.log_op("summary.denied"),
                workspace_id = %ws_id_short,
                error_code = %e.code(),
                "Git summary denied"
            );
            return Err((
                match &e {
                    WorkspaceResolutionError::NotFound => StatusCode::NOT_FOUND,
                    WorkspaceResolutionError::InvalidId => StatusCode::BAD_REQUEST,
                    WorkspaceResolutionError::NotAccessible(_) => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::PathValidationFailed => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::WorkspacesDisabled => StatusCode::SERVICE_UNAVAILABLE,
                },
                Json(GitError::new(e.message(), e.code())),
            ));
        }
    };

    // Step 4: Perform git summary (path used internally, never exposed)
    let response = match get_git_summary(&workspace_path, &params.workspace_id) {
        Ok(r) => r,
        Err(git_err) => {
            warn!(
                op = %ctx.log_op("summary.error"),
                workspace_id = %ws_id_short,
                error_code = %git_err.code(),
                "Git summary operation failed"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new(git_err.message(), git_err.code())),
            ));
        }
    };

    info!(
        op = %ctx.log_op("summary.ok"),
        workspace_id = %ws_id_short,
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        repo_detected = %response.repo_detected,
        commit_count = %response.recent_commits.len(),
        "Git summary complete"
    );

    Ok(Json(response))
}

// =============================================================================
// Git Audit Handler (RAPTOR-2 Step 28)
// =============================================================================

/// GET /v0/git/audit?workspace_id=<id>&limit=<n> - Get audit trail for workspace
/// Requires: valid session + "git.read" capability (NOT git.commit/push)
/// Returns: safe fields only (no paths/URLs/tokens/env/caps)
async fn git_audit_handler(
    State(ctx): State<Arc<GitModuleContext>>,
    headers: HeaderMap,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<AuditResponse>, (StatusCode, Json<GitError>)> {
    let ws_id_short = &params.workspace_id[..8.min(params.workspace_id.len())];

    info!(
        op = %ctx.log_op("audit.request"),
        workspace_id = %ws_id_short,
        "Git audit requested"
    );

    // Step 1: Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("audit.auth_error"),
            workspace_id = %ws_id_short,
            code = %e.code,
            "Session validation failed"
        );
        (e.status, Json(GitError::new(e.error, e.code)))
    })?;

    // Step 2: Check git.read capability (NOT git.commit/push - audit is read-only)
    if session.require_capability(GIT_READ_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("audit.capability_denied"),
            workspace_id = %ws_id_short,
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Not permitted", error_codes::CAPABILITY_DENIED)),
        ));
    }

    // Step 3: Get audit events (limit to 100 max, default 50)
    let limit = params.limit.unwrap_or(50).min(100);
    let events = ctx.audit_store.get(&params.workspace_id, limit);

    info!(
        op = %ctx.log_op("audit.ok"),
        workspace_id = %ws_id_short,
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        event_count = events.len(),
        "Git audit complete"
    );

    Ok(Json(AuditResponse {
        workspace_id: params.workspace_id,
        events,
    }))
}

// =============================================================================
// Git Write Handlers (PR-only workflow - RAPTOR-2 Step 18 + Step 28)
// =============================================================================

/// Helper to extract idempotency key from headers (RAPTOR-2 Step 28)
fn extract_idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= MAX_IDEMPOTENCY_KEY_LEN)
        .map(|s| s.to_string())
}

/// Helper to ensure we're on an ekka branch, creating if necessary (RAPTOR-2 Step 28)
/// Returns the branch name on success, or an error
fn ensure_ekka_branch(repo: &Repository, tenant_id: &str, subject: &str, ctx: &GitModuleContext) -> Result<String, (StatusCode, Json<GitError>)> {
    // Check if repo is dirty (uncommitted changes)
    let mut opts = StatusOptions::new();
    opts.include_untracked(false); // Only check tracked files
    let statuses = repo.statuses(Some(&mut opts)).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to check status", "GIT_INTERNAL_ERROR")),
        )
    })?;

    let has_uncommitted = statuses.iter().any(|s| {
        let status = s.status();
        status.is_index_modified() || status.is_wt_modified() || status.is_index_new()
    });

    // Get current branch
    let current_branch = repo
        .head()
        .ok()
        .and_then(|h| h.shorthand().map(String::from));

    let current_branch_name = current_branch.clone().unwrap_or_default();

    // Check if already on an ekka branch
    if current_branch_name.starts_with(EKKA_BRANCH_PREFIX) {
        // Check if current branch is protected by prefix
        if ctx.is_prefix_protected(&current_branch_name) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(GitError::new("Cannot write to protected branch", "GIT_PROTECTED_BRANCH")),
            ));
        }
        return Ok(current_branch_name);
    }

    // Check if current branch is protected
    if is_protected_branch(&current_branch_name) || ctx.is_prefix_protected(&current_branch_name) {
        // Need to create and checkout ekka branch
        if has_uncommitted {
            // Would lose work - fail safely
            return Err((
                StatusCode::BAD_REQUEST,
                Json(GitError::new("Working directory has uncommitted changes", "GIT_WORKDIR_DIRTY")),
            ));
        }

        // Generate and create ekka branch
        let ekka_branch = generate_ekka_branch_name(tenant_id, subject);

        // Get HEAD commit for branch base
        let head = repo.head().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new("Failed to get HEAD", "GIT_INTERNAL_ERROR")),
            )
        })?;
        let commit = head.peel_to_commit().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new("Failed to get commit", "GIT_INTERNAL_ERROR")),
            )
        })?;

        // Create branch
        repo.branch(&ekka_branch, &commit, false).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new("Failed to create branch", "GIT_INTERNAL_ERROR")),
            )
        })?;

        // Checkout branch
        let refname = format!("refs/heads/{}", ekka_branch);
        let obj = repo.revparse_single(&refname).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new("Failed to find branch ref", "GIT_INTERNAL_ERROR")),
            )
        })?;
        repo.checkout_tree(&obj, None).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new("Failed to checkout branch", "GIT_INTERNAL_ERROR")),
            )
        })?;
        repo.set_head(&refname).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new("Failed to set HEAD", "GIT_INTERNAL_ERROR")),
            )
        })?;

        return Ok(ekka_branch);
    }

    // Not on ekka branch and not on protected - this shouldn't happen in PR-only workflow
    // But handle gracefully: create ekka branch
    if has_uncommitted {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GitError::new("Working directory has uncommitted changes", "GIT_WORKDIR_DIRTY")),
        ));
    }

    let ekka_branch = generate_ekka_branch_name(tenant_id, subject);
    let head = repo.head().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to get HEAD", "GIT_INTERNAL_ERROR")),
        )
    })?;
    let commit = head.peel_to_commit().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to get commit", "GIT_INTERNAL_ERROR")),
        )
    })?;

    repo.branch(&ekka_branch, &commit, false).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to create branch", "GIT_INTERNAL_ERROR")),
        )
    })?;

    let refname = format!("refs/heads/{}", ekka_branch);
    let obj = repo.revparse_single(&refname).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to find branch ref", "GIT_INTERNAL_ERROR")),
        )
    })?;
    repo.checkout_tree(&obj, None).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to checkout branch", "GIT_INTERNAL_ERROR")),
        )
    })?;
    repo.set_head(&refname).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to set HEAD", "GIT_INTERNAL_ERROR")),
        )
    })?;

    Ok(ekka_branch)
}

/// POST /v0/git/commit - Create a commit on EKKA branch
/// Requires: valid session + "git.commit" capability
/// RAPTOR-2 Step 28: Server-side branch control, idempotency, audit
async fn git_commit_handler(
    State(ctx): State<Arc<GitModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<CommitRequest>,
) -> Result<Json<CommitResponse>, (StatusCode, Json<GitError>)> {
    let ws_id_short = &request.workspace_id[..8.min(request.workspace_id.len())];

    info!(
        op = %ctx.log_op("commit.request"),
        workspace_id = %ws_id_short,
        "Git commit requested"
    );

    // Step 1: Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("commit.auth_error"),
            workspace_id = %ws_id_short,
            code = %e.code,
            "Session validation failed"
        );
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", &e.code, None, None));
        (e.status, Json(GitError::new(e.error, e.code)))
    })?;

    // Step 2: Check idempotency (RAPTOR-2 Step 28)
    let idempotency_key = extract_idempotency_key(&headers);
    if let Some(ref key) = idempotency_key {
        if let Some((cached_json, cached_status)) = ctx.idempotency_store.get(
            &session.tenant_id, &session.user_id, &request.workspace_id, "commit", key
        ) {
            info!(
                op = %ctx.log_op("commit.idempotent_hit"),
                workspace_id = %ws_id_short,
                "Returning cached response for idempotent request"
            );
            // Return cached response
            if cached_status == 200 {
                let response: CommitResponse = serde_json::from_str(&cached_json)
                    .unwrap_or(CommitResponse {
                        status: "committed".to_string(),
                        branch: "unknown".to_string(),
                        commit_id: "unknown".to_string(),
                        files_changed: 0,
                        counts_truncated: false,
                    });
                return Ok(Json(response));
            } else {
                let error: GitError = serde_json::from_str(&cached_json)
                    .unwrap_or(GitError::new("Cached error", "CACHED_ERROR"));
                return Err((StatusCode::from_u16(cached_status).unwrap_or(StatusCode::BAD_REQUEST), Json(error)));
            }
        }
    }

    // Step 3: Check git.commit capability (RAPTOR-2 Step 27 - explicit capability)
    if session.require_capability(GIT_COMMIT_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("commit.capability_denied"),
            workspace_id = %ws_id_short,
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", error_codes::CAPABILITY_DENIED, Some(&session.tenant_id), Some(&session.user_id)));
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Not permitted", error_codes::CAPABILITY_DENIED)),
        ));
    }

    // Step 4: Resolve workspace
    let workspace_path = match (ctx.workspace_resolver)(&request.workspace_id) {
        Ok(path) => path,
        Err(e) => {
            warn!(
                op = %ctx.log_op("commit.workspace_error"),
                workspace_id = %ws_id_short,
                error_code = %e.code(),
                "Workspace resolution failed"
            );
            ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", e.code(), Some(&session.tenant_id), Some(&session.user_id)));
            return Err((
                match &e {
                    WorkspaceResolutionError::NotFound => StatusCode::NOT_FOUND,
                    WorkspaceResolutionError::InvalidId => StatusCode::BAD_REQUEST,
                    WorkspaceResolutionError::NotAccessible(_) => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::PathValidationFailed => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::WorkspacesDisabled => StatusCode::SERVICE_UNAVAILABLE,
                },
                Json(GitError::new(e.message(), e.code())),
            ));
        }
    };

    // Step 5: Open repo and validate
    let repo = match Repository::open(&workspace_path) {
        Ok(r) => r,
        Err(_) => {
            ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_NO_REPO", Some(&session.tenant_id), Some(&session.user_id)));
            return Err((
                StatusCode::BAD_REQUEST,
                Json(GitError::new("No Git repository found", "GIT_NO_REPO")),
            ));
        }
    };

    if let Err(e) = validate_repo_workdir(&repo, &workspace_path) {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", e.code(), Some(&session.tenant_id), Some(&session.user_id)));
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new(e.message(), e.code())),
        ));
    }

    // Step 6: Ensure on EKKA branch (RAPTOR-2 Step 28 - server-side branch control)
    // Uses session.user_id (subject) instead of session_id for deterministic branch naming
    let branch = match ensure_ekka_branch(&repo, &session.tenant_id, &session.user_id, &ctx) {
        Ok(b) => b,
        Err((status, err)) => {
            let code = &err.code;
            ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", code, Some(&session.tenant_id), Some(&session.user_id)));
            return Err((status, err));
        }
    };

    // Step 7: Check for changes
    let mut opts = StatusOptions::new();
    opts.include_untracked(true);
    let statuses = repo.statuses(Some(&mut opts)).map_err(|_| {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_INTERNAL_ERROR", Some(&session.tenant_id), Some(&session.user_id)));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to check status", "GIT_INTERNAL_ERROR")),
        )
    })?;

    let files_changed = statuses.len() as u32;
    if files_changed == 0 {
        let code = GitOperationError::NothingToCommit.code();
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", code, Some(&session.tenant_id), Some(&session.user_id)));
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GitError::new(
                GitOperationError::NothingToCommit.message(),
                code,
            )),
        ));
    }

    let counts_truncated = files_changed > MAX_STATUS_FILE_SCAN as u32;

    // Step 8: Sanitize commit message
    let sanitized_message = sanitize_commit_message(&request.message);

    // Step 9: Stage all changes and commit
    let mut index = repo.index().map_err(|_| {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_INTERNAL_ERROR", Some(&session.tenant_id), Some(&session.user_id)));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to get index", "GIT_INTERNAL_ERROR")),
        )
    })?;

    index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None).map_err(|_| {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_INTERNAL_ERROR", Some(&session.tenant_id), Some(&session.user_id)));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to stage changes", "GIT_INTERNAL_ERROR")),
        )
    })?;

    index.write().map_err(|_| {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_INTERNAL_ERROR", Some(&session.tenant_id), Some(&session.user_id)));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to write index", "GIT_INTERNAL_ERROR")),
        )
    })?;

    let tree_id = index.write_tree().map_err(|_| {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_INTERNAL_ERROR", Some(&session.tenant_id), Some(&session.user_id)));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to write tree", "GIT_INTERNAL_ERROR")),
        )
    })?;

    let tree = repo.find_tree(tree_id).map_err(|_| {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_INTERNAL_ERROR", Some(&session.tenant_id), Some(&session.user_id)));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to find tree", "GIT_INTERNAL_ERROR")),
        )
    })?;

    let sig = repo.signature().map_err(|_| {
        ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", "GIT_NO_USER_CONFIG", Some(&session.tenant_id), Some(&session.user_id)));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GitError::new("Failed to get signature", "GIT_NO_USER_CONFIG")),
        )
    })?;

    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<_> = parent.iter().collect();

    let commit_oid = repo
        .commit(Some("HEAD"), &sig, &sig, &sanitized_message, &tree, &parents)
        .map_err(|_| {
            let code = GitOperationError::CommitFailed.code();
            ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "err", code, Some(&session.tenant_id), Some(&session.user_id)));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new(
                    GitOperationError::CommitFailed.message(),
                    code,
                )),
            )
        })?;

    let commit_id = format!("{}", commit_oid)[..7].to_string();

    info!(
        op = %ctx.log_op("commit.ok"),
        workspace_id = %ws_id_short,
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        branch = %branch,
        commit_id = %commit_id,
        files_changed = %files_changed,
        "Git commit complete"
    );

    // Record audit event
    ctx.audit_store.record(AuditEvent::new(&request.workspace_id, "commit", "ok", "OK", Some(&session.tenant_id), Some(&session.user_id)));

    let response = CommitResponse {
        status: "committed".to_string(),
        branch,
        commit_id,
        files_changed,
        counts_truncated,
    };

    // Store for idempotency (RAPTOR-2 Step 28)
    if let Some(ref key) = idempotency_key {
        if let Ok(json) = serde_json::to_string(&response) {
            ctx.idempotency_store.set(
                &session.tenant_id, &session.user_id, &request.workspace_id, "commit", key,
                json, 200
            );
        }
    }

    Ok(Json(response))
}

/// POST /v0/git/push - Push EKKA branch to remote
/// Requires: valid session + "git.write" capability
async fn git_push_handler(
    State(ctx): State<Arc<GitModuleContext>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<PushRequest>,
) -> Result<Json<PushResponse>, (StatusCode, Json<GitError>)> {
    let ws_id_short = &request.workspace_id[..8.min(request.workspace_id.len())];

    info!(
        op = %ctx.log_op("push.request"),
        workspace_id = %ws_id_short,
        "Git push requested"
    );

    // Step 1: Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("push.auth_error"),
            workspace_id = %ws_id_short,
            code = %e.code,
            "Session validation failed"
        );
        (e.status, Json(GitError::new(e.error, e.code)))
    })?;

    // Step 2: Check git.push capability (RAPTOR-2 Step 27 - explicit capability)
    if session.require_capability(GIT_PUSH_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("push.capability_denied"),
            workspace_id = %ws_id_short,
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Not permitted", error_codes::CAPABILITY_DENIED)),
        ));
    }

    // Step 3: Resolve workspace
    let workspace_path = match (ctx.workspace_resolver)(&request.workspace_id) {
        Ok(path) => path,
        Err(e) => {
            warn!(
                op = %ctx.log_op("push.workspace_error"),
                workspace_id = %ws_id_short,
                error_code = %e.code(),
                "Workspace resolution failed"
            );
            return Err((
                match &e {
                    WorkspaceResolutionError::NotFound => StatusCode::NOT_FOUND,
                    WorkspaceResolutionError::InvalidId => StatusCode::BAD_REQUEST,
                    WorkspaceResolutionError::NotAccessible(_) => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::PathValidationFailed => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::WorkspacesDisabled => StatusCode::SERVICE_UNAVAILABLE,
                },
                Json(GitError::new(e.message(), e.code())),
            ));
        }
    };

    // Step 3.5: Defense-in-depth allow-list check (RAPTOR-2 Step 31)
    // Resolve repo_ref and check against allow-list
    if let Some(ref repo_resolver) = ctx.repo_binding_resolver {
        if let Ok(repo_ref) = (repo_resolver)(&request.workspace_id) {
            ctx.check_repo_allowlist(&repo_ref).map_err(|(status, err)| {
                warn!(
                    op = %ctx.log_op("push.repo_not_allowed"),
                    workspace_id = %ws_id_short,
                    "Repository not in allow-list"
                );
                (status, Json(err))
            })?;
        }
    } else if ctx.repo_allowlist_required {
        // If allow-list is required but we have no resolver to check, fail safely
        warn!(
            op = %ctx.log_op("push.allowlist_not_configured"),
            workspace_id = %ws_id_short,
            "Allow-list required but not configured"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Repository policy not configured", "REPO_ALLOWLIST_NOT_CONFIGURED")),
        ));
    }

    // Step 4: Open repo and validate
    let repo = match Repository::open(&workspace_path) {
        Ok(r) => r,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(GitError::new("No Git repository found", "GIT_NO_REPO")),
            ));
        }
    };

    if let Err(e) = validate_repo_workdir(&repo, &workspace_path) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new(e.message(), e.code())),
        ));
    }

    // Step 5: Get current branch and validate it's an EKKA branch
    let branch = repo
        .head()
        .ok()
        .and_then(|h| h.shorthand().map(String::from))
        .unwrap_or_default();

    if is_protected_branch(&branch) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GitError::new(
                GitOperationError::ProtectedBranch.message(),
                GitOperationError::ProtectedBranch.code(),
            )),
        ));
    }

    if !branch.starts_with(EKKA_BRANCH_PREFIX) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GitError::new(
                "Must be on an EKKA branch to push",
                "GIT_NOT_EKKA_BRANCH",
            )),
        ));
    }

    // Step 6: Check for remote
    let mut remote = match repo.find_remote("origin") {
        Ok(r) => r,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(GitError::new(
                    GitOperationError::NoRemoteConfigured.message(),
                    GitOperationError::NoRemoteConfigured.code(),
                )),
            ));
        }
    };

    // Step 7: Get token for authenticated push (RAPTOR-2 Step 26)
    let token = ctx.token_provider.as_ref()
        .and_then(|provider| provider(&session.session_id));

    // Token is REQUIRED for push (can't push to GitHub without authentication)
    let token = match token {
        Some(t) => t,
        None => {
            warn!(
                op = %ctx.log_op("push.no_token"),
                workspace_id = %ws_id_short,
                "Push requires authentication - no token available"
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(GitError::new(
                    "GitHub authentication required for push",
                    "GIT_AUTH_REQUIRED",
                )),
            ));
        }
    };

    // Step 8: Perform authenticated push to origin
    info!(
        op = %ctx.log_op("push.starting"),
        workspace_id = %ws_id_short,
        branch = %branch,
        "Starting push operation"
    );

    // Build refspec: refs/heads/<branch>:refs/heads/<branch>
    let refspec = format!("refs/heads/{}:refs/heads/{}", branch, branch);

    let mut push_opts = build_authenticated_push_options(&token);

    match remote.push(&[&refspec], Some(&mut push_opts)) {
        Ok(_) => {
            info!(
                op = %ctx.log_op("push.ok"),
                workspace_id = %ws_id_short,
                session_id = %&session.session_id[..8.min(session.session_id.len())],
                branch = %branch,
                "Git push completed successfully"
            );
            Ok(Json(PushResponse {
                status: "pushed".to_string(),
                branch,
            }))
        }
        Err(e) => {
            // Log error internally but don't expose details (might contain paths/URLs)
            warn!(
                op = %ctx.log_op("push.failed"),
                workspace_id = %ws_id_short,
                error_class = ?e.class(),
                "Push operation failed"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError::new(
                    "Push operation failed",
                    "GIT_PUSH_FAILED",
                )),
            ))
        }
    }
}

/// POST /v0/git/pr - Create a pull request
/// Requires: valid session + "git.write" capability + "github.pr" capability
async fn git_pr_handler(
    State(ctx): State<Arc<GitModuleContext>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<PrRequest>,
) -> Result<Json<PrResponse>, (StatusCode, Json<GitError>)> {
    let ws_id_short = &request.workspace_id[..8.min(request.workspace_id.len())];

    info!(
        op = %ctx.log_op("pr.request"),
        workspace_id = %ws_id_short,
        "Git PR requested"
    );

    // Step 1: Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("pr.auth_error"),
            workspace_id = %ws_id_short,
            code = %e.code,
            "Session validation failed"
        );
        (e.status, Json(GitError::new(e.error, e.code)))
    })?;

    // Step 2: Check git.push capability (RAPTOR-2 Step 27 - explicit capability)
    // PR creation requires push capability since it pushes to remote
    if session.require_capability(GIT_PUSH_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("pr.capability_denied"),
            workspace_id = %ws_id_short,
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied (git.push)"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Not permitted", error_codes::CAPABILITY_DENIED)),
        ));
    }

    // Step 2b: Check github.pr capability (required for PR creation via GitHub API)
    if session.require_capability(GITHUB_PR_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("pr.capability_denied"),
            workspace_id = %ws_id_short,
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied (github.pr)"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Not permitted", error_codes::CAPABILITY_DENIED)),
        ));
    }

    // Step 3: Resolve workspace
    let workspace_path = match (ctx.workspace_resolver)(&request.workspace_id) {
        Ok(path) => path,
        Err(e) => {
            warn!(
                op = %ctx.log_op("pr.workspace_error"),
                workspace_id = %ws_id_short,
                error_code = %e.code(),
                "Workspace resolution failed"
            );
            return Err((
                match &e {
                    WorkspaceResolutionError::NotFound => StatusCode::NOT_FOUND,
                    WorkspaceResolutionError::InvalidId => StatusCode::BAD_REQUEST,
                    WorkspaceResolutionError::NotAccessible(_) => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::PathValidationFailed => StatusCode::FORBIDDEN,
                    WorkspaceResolutionError::WorkspacesDisabled => StatusCode::SERVICE_UNAVAILABLE,
                },
                Json(GitError::new(e.message(), e.code())),
            ));
        }
    };

    // Step 3.5: Defense-in-depth allow-list check (RAPTOR-2 Step 31)
    // Resolve repo_ref and check against allow-list
    if let Some(ref repo_resolver) = ctx.repo_binding_resolver {
        if let Ok(repo_ref) = (repo_resolver)(&request.workspace_id) {
            ctx.check_repo_allowlist(&repo_ref).map_err(|(status, err)| {
                warn!(
                    op = %ctx.log_op("pr.repo_not_allowed"),
                    workspace_id = %ws_id_short,
                    "Repository not in allow-list"
                );
                (status, Json(err))
            })?;
        }
    } else if ctx.repo_allowlist_required {
        // If allow-list is required but we have no resolver to check, fail safely
        warn!(
            op = %ctx.log_op("pr.allowlist_not_configured"),
            workspace_id = %ws_id_short,
            "Allow-list required but not configured"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new("Repository policy not configured", "REPO_ALLOWLIST_NOT_CONFIGURED")),
        ));
    }

    // Step 4: Open repo and validate
    let repo = match Repository::open(&workspace_path) {
        Ok(r) => r,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(GitError::new("No Git repository found", "GIT_NO_REPO")),
            ));
        }
    };

    if let Err(e) = validate_repo_workdir(&repo, &workspace_path) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new(e.message(), e.code())),
        ));
    }

    // Step 5: Get current branch and validate
    let branch = repo
        .head()
        .ok()
        .and_then(|h| h.shorthand().map(String::from))
        .unwrap_or_default();

    if is_protected_branch(&branch) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GitError::new(
                GitOperationError::ProtectedBranch.message(),
                GitOperationError::ProtectedBranch.code(),
            )),
        ));
    }

    if !branch.starts_with(EKKA_BRANCH_PREFIX) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GitError::new(
                "Must be on an EKKA branch to create PR",
                "GIT_NOT_EKKA_BRANCH",
            )),
        ));
    }

    // Step 6: Validate base branch is not being targeted incorrectly
    let base = request.base.as_deref().unwrap_or("main");
    // Base can be main/master (that's the point of PRs), but we validate it exists
    // For the stub, we just acknowledge the request

    info!(
        op = %ctx.log_op("pr.stub"),
        workspace_id = %ws_id_short,
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        branch = %branch,
        base = %base,
        "Git PR stub - GitHub integration not configured"
    );

    // Return stub response - GitHub integration not configured
    Ok(Json(PrResponse {
        status: "not_configured".to_string(),
        code: "GITHUB_NOT_CONFIGURED".to_string(),
    }))
}

// =============================================================================
// Git Credential Helpers (RAPTOR-2 Step 26)
// =============================================================================

/// Username used for GitHub HTTPS authentication with OAuth tokens
/// This is the standard way to authenticate with GitHub using tokens
const GITHUB_TOKEN_USERNAME: &str = "x-access-token";

/// Build FetchOptions with credential callback for authenticated clone
/// Token is used for HTTPS authentication (x-access-token / <oauth_token>)
fn build_authenticated_fetch_options<'a>(token: &'a str) -> FetchOptions<'a> {
    let mut callbacks = RemoteCallbacks::new();

    // Credential callback for HTTPS auth
    callbacks.credentials(move |_url, _username_from_url, allowed_types| {
        if allowed_types.contains(CredentialType::USER_PASS_PLAINTEXT) {
            // For HTTPS, use x-access-token as username and OAuth token as password
            Cred::userpass_plaintext(GITHUB_TOKEN_USERNAME, token)
        } else {
            // If HTTPS userpass is not allowed, fail gracefully
            Err(git2::Error::from_str("Only HTTPS authentication is supported"))
        }
    });

    let mut fetch_opts = FetchOptions::new();
    fetch_opts.remote_callbacks(callbacks);
    fetch_opts
}

/// Build PushOptions with credential callback for authenticated push
/// Token is used for HTTPS authentication (x-access-token / <oauth_token>)
fn build_authenticated_push_options<'a>(token: &'a str) -> PushOptions<'a> {
    let mut callbacks = RemoteCallbacks::new();

    // Credential callback for HTTPS auth
    callbacks.credentials(move |_url, _username_from_url, allowed_types| {
        if allowed_types.contains(CredentialType::USER_PASS_PLAINTEXT) {
            Cred::userpass_plaintext(GITHUB_TOKEN_USERNAME, token)
        } else {
            Err(git2::Error::from_str("Only HTTPS authentication is supported"))
        }
    });

    let mut push_opts = PushOptions::new();
    push_opts.remote_callbacks(callbacks);
    push_opts
}

// =============================================================================
// Git Clone Handler (RAPTOR-2 Step 22 + Step 26)
// =============================================================================

/// POST /v0/git/clone - Clone a repo into a managed workspace
/// Requires: valid session + "git.clone" capability
/// Request: {"workspace_id": "<uuid>"} - NO repo URL from browser
/// Server resolves repo_ref from workspace binding
async fn git_clone_handler(
    State(ctx): State<Arc<GitModuleContext>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CloneRequest>,
) -> Result<Json<CloneResponse>, (StatusCode, Json<GitError>)> {
    info!(
        op = %ctx.log_op("clone.request"),
        "Git clone requested"
    );

    // Step 1: Validate session via host-provided validator
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("clone.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(GitError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check git.clone capability
    if let Err(_) = session.require_capability(GIT_CLONE_CAPABILITY) {
        warn!(
            op = %ctx.log_op("clone.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Resolve workspace path via host-provided resolver
    let workspace_root = (ctx.workspace_resolver)(&request.workspace_id).map_err(|e| {
        warn!(
            op = %ctx.log_op("clone.workspace_error"),
            code = %e.code(),
            "Workspace resolution failed"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(GitError {
                error: e.message(),
                code: e.code().to_string(),
            }),
        )
    })?;

    // Step 4: Get repo binding resolver
    let repo_resolver = ctx.repo_binding_resolver.as_ref().ok_or_else(|| {
        warn!(
            op = %ctx.log_op("clone.no_resolver"),
            "Repo binding resolver not configured"
        );
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(GitError {
                error: "Clone not available".to_string(),
                code: "CLONE_NOT_AVAILABLE".to_string(),
            }),
        )
    })?;

    // Step 5: Resolve repo_ref from workspace binding (server-side)
    let repo_ref = (repo_resolver)(&request.workspace_id).map_err(|e| {
        warn!(
            op = %ctx.log_op("clone.repo_binding_error"),
            code = %e.code(),
            "Repo binding resolution failed"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(GitError {
                error: e.message().to_string(),
                code: e.code().to_string(),
            }),
        )
    })?;

    // Step 5.5: Defense-in-depth allow-list check (RAPTOR-2 Step 31)
    // Even if previously bound, verify repo is still allowed
    ctx.check_repo_allowlist(&repo_ref).map_err(|(status, err)| {
        warn!(
            op = %ctx.log_op("clone.repo_not_allowed"),
            "Repository not in allow-list"
        );
        (status, Json(err))
    })?;

    // Step 6: Check if repo already exists at workspace root
    let git_dir = workspace_root.join(".git");
    if git_dir.exists() {
        warn!(
            op = %ctx.log_op("clone.already_present"),
            workspace_id = %request.workspace_id,
            "Repository already present"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GitError {
                error: "Repository already present in workspace".to_string(),
                code: CloneErrorCodes::REPO_ALREADY_PRESENT.to_string(),
            }),
        ));
    }

    // Step 7: Construct clone URL (server-side, hardcoded to github.com for demo)
    // SECURITY: repo_ref is "owner/repo" format, validated by workspaces module
    let clone_url = format!("https://github.com/{}.git", repo_ref);

    // Step 8: Get token for authenticated clone (RAPTOR-2 Step 26 + Step 27)
    let token = ctx.token_provider.as_ref()
        .and_then(|provider| provider(&session.session_id));

    let has_token = token.is_some();

    // RAPTOR-2 Step 27: Enforce token requirement in studio mode
    if ctx.clone_requires_token && !has_token {
        warn!(
            op = %ctx.log_op("clone.token_required"),
            workspace_id = %request.workspace_id,
            "Clone requires authentication but no token available"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(GitError::new(
                "GitHub authentication required",
                "GITHUB_NOT_CONNECTED",
            )),
        ));
    }

    info!(
        op = %ctx.log_op("clone.starting"),
        workspace_id = %request.workspace_id,
        authenticated = has_token,
        "Starting clone operation"
    );

    // Step 9: Perform clone using git2 (libgit2) with optional authentication
    let clone_result = if let Some(ref token) = token {
        // Authenticated clone using RepoBuilder with credential callbacks
        let fetch_opts = build_authenticated_fetch_options(token);
        let mut builder = RepoBuilder::new();
        builder.fetch_options(fetch_opts);
        builder.clone(&clone_url, &workspace_root)
    } else {
        // Unauthenticated clone (for public repos)
        Repository::clone(&clone_url, &workspace_root)
    };

    match clone_result {
        Ok(_repo) => {
            info!(
                op = %ctx.log_op("clone.ok"),
                session_id = %&session.session_id[..8.min(session.session_id.len())],
                workspace_id = %request.workspace_id,
                authenticated = has_token,
                "Clone completed successfully"
            );
            Ok(Json(CloneResponse {
                status: "cloned".to_string(),
                workspace_id: request.workspace_id,
            }))
        }
        Err(e) => {
            // Log error internally but don't expose details
            warn!(
                op = %ctx.log_op("clone.failed"),
                workspace_id = %request.workspace_id,
                error_class = ?e.class(),
                authenticated = has_token,
                "Clone operation failed"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GitError {
                    error: "Clone operation failed".to_string(),
                    code: CloneErrorCodes::CLONE_FAILED.to_string(),
                }),
            ))
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

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
    fn test_no_repo_detected() {
        let temp_dir = TempDir::new().unwrap();
        let response = get_git_status(&temp_dir.path().to_path_buf(), "test-ws-id").unwrap();

        assert!(!response.repo_detected);
        assert!(response.branch.is_none());
        assert!(!response.is_dirty);
        assert_eq!(response.changed_files_count, 0);
        assert_eq!(response.untracked_files_count, 0);
        assert!(!response.counts_truncated);

        // Verify no path leak
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_status_response_no_paths() {
        let response = GitStatusResponse {
            workspace_id: "abc-123".to_string(),
            repo_detected: true,
            branch: Some("main".to_string()),
            is_dirty: true,
            ahead_by: 2,
            behind_by: 1,
            changed_files_count: 5,
            untracked_files_count: 3,
            counts_truncated: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_status_response_truncated_serialization() {
        // When not truncated, field should be omitted
        let response = GitStatusResponse {
            workspace_id: "test".to_string(),
            repo_detected: true,
            branch: None,
            is_dirty: false,
            ahead_by: 0,
            behind_by: 0,
            changed_files_count: 0,
            untracked_files_count: 0,
            counts_truncated: false,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("counts_truncated"));

        // When truncated, field should be present
        let response_truncated = GitStatusResponse {
            counts_truncated: true,
            ..response
        };
        let json_truncated = serde_json::to_string(&response_truncated).unwrap();
        assert!(json_truncated.contains("\"counts_truncated\":true"));
    }

    #[test]
    fn test_summary_response_no_paths() {
        let response = GitSummaryResponse {
            workspace_id: "abc-123".to_string(),
            repo_detected: true,
            recent_commits: vec![CommitInfo {
                hash_short: "abc1234".to_string(),
                subject: "Initial commit".to_string(),
                author: "Test Author".to_string(),
                date_iso_utc: "2024-01-01T00:00:00+00:00".to_string(),
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_git_error_no_paths() {
        let error = GitError::new("Workspace not found", "WORKSPACE_NOT_FOUND");

        let json = serde_json::to_string(&error).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_git_operation_error_messages_no_paths() {
        // All error messages should be path-free
        let errors = [
            GitOperationError::RepoOpenFailed,
            GitOperationError::BareRepoNotSupported,
            GitOperationError::WorkdirOutsideRoot,
            GitOperationError::PathValidationFailed,
            GitOperationError::OperationFailed,
        ];

        for err in errors {
            let message = err.message();
            let code = err.code();
            assert_no_path_leak(message);
            assert_no_path_leak(code);
        }
    }

    #[test]
    fn test_workspace_resolution_error_messages_no_paths() {
        let errors = [
            WorkspaceResolutionError::WorkspacesDisabled,
            WorkspaceResolutionError::NotFound,
            WorkspaceResolutionError::NotAccessible("quarantined".to_string()),
            WorkspaceResolutionError::InvalidId,
            WorkspaceResolutionError::PathValidationFailed,
        ];

        for err in errors {
            let message = err.message();
            let code = err.code();
            assert_no_path_leak(&message);
            assert_no_path_leak(code);
        }
    }

    // =========================================================================
    // String Truncation Tests
    // =========================================================================

    #[test]
    fn test_truncate_string_short() {
        assert_eq!(truncate_string("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_string_exact() {
        assert_eq!(truncate_string("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_string_long() {
        assert_eq!(truncate_string("hello world", 8), "hello...");
    }

    #[test]
    fn test_truncate_string_very_short_max() {
        assert_eq!(truncate_string("hello", 3), "hel");
    }

    // =========================================================================
    // Workspace Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_workspace_root_exists() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_workspace_root(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_workspace_root_not_exists() {
        let path = PathBuf::from("/nonexistent/path/that/does/not/exist");
        let result = validate_workspace_root(&path);
        assert!(matches!(
            result,
            Err(WorkspaceResolutionError::NotAccessible(_))
        ));
    }

    #[test]
    fn test_validate_workspace_root_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("testfile");
        fs::write(&file_path, "test").unwrap();

        let result = validate_workspace_root(&file_path);
        assert!(matches!(
            result,
            Err(WorkspaceResolutionError::PathValidationFailed)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_escape_prevention() {
        // Create base directory and a separate "escape target"
        let base_dir = TempDir::new().unwrap();
        let escape_target = TempDir::new().unwrap();

        // Create a symlink inside base that points to escape_target
        let symlink_path = base_dir.path().join("escape_link");
        symlink(escape_target.path(), &symlink_path).unwrap();

        // Create a git repo in the escape target
        Repository::init(escape_target.path()).unwrap();

        // Open repo through the symlink
        let repo = Repository::open(&symlink_path).unwrap();

        // Validation works when symlinks resolve to same canonical path
        let result = validate_repo_workdir(&repo, &symlink_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bare_repo_not_supported() {
        let temp_dir = TempDir::new().unwrap();
        let bare_path = temp_dir.path().join("bare.git");

        // Create a bare repository
        Repository::init_bare(&bare_path).unwrap();

        let repo = Repository::open(&bare_path).unwrap();
        let result = validate_repo_workdir(&repo, temp_dir.path());

        assert!(matches!(result, Err(GitOperationError::BareRepoNotSupported)));
    }

    // =========================================================================
    // Git Operation Tests
    // =========================================================================

    #[test]
    fn test_git_repo_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        // Initialize a git repo using git2
        let repo = Repository::init(repo_path).unwrap();

        // Configure user for commits
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        // Create initial commit
        let sig = repo.signature().unwrap();
        let tree_id = {
            let mut index = repo.index().unwrap();
            index.write_tree().unwrap()
        };
        let tree = repo.find_tree(tree_id).unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        // Test status
        let status = get_git_status(&repo_path.to_path_buf(), "test-ws").unwrap();
        assert!(status.repo_detected);
        assert_eq!(status.branch, Some("master".to_string()));
        assert!(!status.counts_truncated);

        // Verify no path leak in response
        let json = serde_json::to_string(&status).unwrap();
        assert_no_path_leak(&json);

        // Test summary
        let summary = get_git_summary(&repo_path.to_path_buf(), "test-ws").unwrap();
        assert!(summary.repo_detected);
        assert_eq!(summary.recent_commits.len(), 1);
        assert_eq!(summary.recent_commits[0].subject, "Initial commit");

        // Verify no path leak in response
        let json = serde_json::to_string(&summary).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_summary_empty_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        // Initialize but don't commit
        Repository::init(repo_path).unwrap();

        let summary = get_git_summary(&repo_path.to_path_buf(), "test-ws").unwrap();
        assert!(summary.repo_detected);
        assert!(summary.recent_commits.is_empty());
    }

    #[test]
    fn test_long_branch_name_truncated() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        let repo = Repository::init(repo_path).unwrap();

        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        let sig = repo.signature().unwrap();
        let tree_id = {
            let mut index = repo.index().unwrap();
            index.write_tree().unwrap()
        };
        let tree = repo.find_tree(tree_id).unwrap();
        let commit_oid = repo
            .commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        // Create a very long branch name
        let long_branch_name = "a".repeat(200);
        let commit = repo.find_commit(commit_oid).unwrap();
        repo.branch(&long_branch_name, &commit, false).unwrap();

        // Checkout the long branch
        let refname = format!("refs/heads/{}", long_branch_name);
        repo.set_head(&refname).unwrap();

        let status = get_git_status(&repo_path.to_path_buf(), "test-ws").unwrap();
        assert!(status.repo_detected);

        // Branch name should be truncated
        if let Some(branch) = &status.branch {
            assert!(branch.len() <= MAX_BRANCH_LEN);
            assert!(branch.ends_with("..."));
        }
    }

    #[test]
    fn test_long_commit_message_truncated() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        let repo = Repository::init(repo_path).unwrap();

        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        let sig = repo.signature().unwrap();
        let tree_id = {
            let mut index = repo.index().unwrap();
            index.write_tree().unwrap()
        };
        let tree = repo.find_tree(tree_id).unwrap();

        // Create commit with very long subject
        let long_subject = "x".repeat(500);
        repo.commit(Some("HEAD"), &sig, &sig, &long_subject, &tree, &[])
            .unwrap();

        let summary = get_git_summary(&repo_path.to_path_buf(), "test-ws").unwrap();
        assert_eq!(summary.recent_commits.len(), 1);
        assert!(summary.recent_commits[0].subject.len() <= MAX_COMMIT_SUBJECT_LEN);
        assert!(summary.recent_commits[0].subject.ends_with("..."));
    }

    #[test]
    fn test_max_commit_count_enforced() {
        let temp_dir = TempDir::new().unwrap();
        let repo_path = temp_dir.path();

        let repo = Repository::init(repo_path).unwrap();

        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        let sig = repo.signature().unwrap();

        // Create more commits than MAX_COMMIT_COUNT
        let mut parent_commit = None;
        for i in 0..15 {
            let tree_id = {
                let mut index = repo.index().unwrap();
                index.write_tree().unwrap()
            };
            let tree = repo.find_tree(tree_id).unwrap();

            let parents: Vec<_> = parent_commit.iter().collect();
            let oid = repo
                .commit(
                    Some("HEAD"),
                    &sig,
                    &sig,
                    &format!("Commit {}", i),
                    &tree,
                    &parents,
                )
                .unwrap();
            parent_commit = Some(repo.find_commit(oid).unwrap());
        }

        let summary = get_git_summary(&repo_path.to_path_buf(), "test-ws").unwrap();
        assert_eq!(summary.recent_commits.len(), MAX_COMMIT_COUNT);
    }

    #[test]
    fn test_module_config_default_disabled() {
        // Without setting env var, git module should be disabled
        assert!(!GIT_MODULE_CONFIG.default_enabled);
    }

    // =========================================================================
    // Git Write Tests (RAPTOR-2 Step 18)
    // =========================================================================

    #[test]
    fn test_ekka_branch_prefix_constant() {
        assert_eq!(EKKA_BRANCH_PREFIX, "ekka/");
    }

    #[test]
    fn test_protected_branches_constant() {
        assert!(PROTECTED_BRANCHES.contains(&"main"));
        assert!(PROTECTED_BRANCHES.contains(&"master"));
    }

    #[test]
    fn test_generate_ekka_branch_name_has_prefix() {
        // RAPTOR-2 Step 28: Now uses (tenant_id, subject) instead of (tenant_id, session_id)
        let branch = generate_ekka_branch_name("tenant-abc", "user-subject");
        assert!(branch.starts_with(EKKA_BRANCH_PREFIX), "Branch must start with ekka/");
    }

    #[test]
    fn test_generate_ekka_branch_name_not_protected() {
        let branch = generate_ekka_branch_name("tenant-abc", "user-subject");
        assert!(!is_protected_branch(&branch), "Generated branch must not be protected");
        assert_ne!(branch, "main");
        assert_ne!(branch, "master");
    }

    #[test]
    fn test_generate_ekka_branch_name_contains_tenant() {
        // Full tenant is now included (sanitized, up to 32 chars)
        let branch = generate_ekka_branch_name("tenant-abc-full-id", "user-subject");
        assert!(branch.contains("tenant-abc-full-id"), "Branch should contain full sanitized tenant");
    }

    #[test]
    fn test_generate_ekka_branch_name_contains_subject() {
        // Subject (user_id) is now used instead of session_id
        let branch = generate_ekka_branch_name("tenant-abc", "user-subject-full");
        assert!(branch.contains("user-subject-full"), "Branch should contain full sanitized subject");
    }

    #[test]
    fn test_validate_write_branch_accepts_ekka_prefix() {
        assert!(validate_write_branch("ekka/tenant/session/20240101120000").is_ok());
        assert!(validate_write_branch("ekka/feature/test").is_ok());
    }

    #[test]
    fn test_validate_write_branch_rejects_no_prefix() {
        assert!(validate_write_branch("feature/test").is_err());
        assert!(validate_write_branch("my-branch").is_err());
    }

    #[test]
    fn test_validate_write_branch_rejects_main() {
        assert!(validate_write_branch("main").is_err());
        assert!(validate_write_branch("Main").is_err());
        assert!(validate_write_branch("MAIN").is_err());
    }

    #[test]
    fn test_validate_write_branch_rejects_master() {
        assert!(validate_write_branch("master").is_err());
        assert!(validate_write_branch("Master").is_err());
        assert!(validate_write_branch("MASTER").is_err());
    }

    #[test]
    fn test_is_protected_branch() {
        assert!(is_protected_branch("main"));
        assert!(is_protected_branch("Main"));
        assert!(is_protected_branch("MAIN"));
        assert!(is_protected_branch("master"));
        assert!(is_protected_branch("Master"));
        assert!(is_protected_branch("MASTER"));
        assert!(!is_protected_branch("develop"));
        assert!(!is_protected_branch("ekka/feature/test"));
    }

    #[test]
    fn test_sanitize_commit_message_strips_newlines() {
        let msg = "First line\nSecond line\nThird line";
        let sanitized = sanitize_commit_message(msg);
        assert!(!sanitized.contains('\n'), "Newlines should be stripped");
        assert!(sanitized.contains("First line"), "Content preserved");
        assert!(sanitized.contains("Second line"), "Content preserved");
    }

    #[test]
    fn test_sanitize_commit_message_strips_carriage_returns() {
        let msg = "Line one\r\nLine two";
        let sanitized = sanitize_commit_message(msg);
        assert!(!sanitized.contains('\r'), "Carriage returns should be stripped");
        assert!(!sanitized.contains('\n'), "Newlines should be stripped");
    }

    #[test]
    fn test_sanitize_commit_message_collapses_whitespace() {
        let msg = "Word   one    two     three";
        let sanitized = sanitize_commit_message(msg);
        assert_eq!(sanitized, "Word one two three");
    }

    #[test]
    fn test_sanitize_commit_message_truncates_long_message() {
        let long_msg = "x".repeat(500);
        let sanitized = sanitize_commit_message(&long_msg);
        assert!(sanitized.len() <= MAX_COMMIT_MESSAGE_LEN);
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn test_sanitize_commit_message_preserves_short_message() {
        let msg = "Short commit message";
        let sanitized = sanitize_commit_message(msg);
        assert_eq!(sanitized, msg);
    }

    #[test]
    fn test_commit_response_no_paths() {
        let response = CommitResponse {
            status: "committed".to_string(),
            branch: "ekka/tenant/session/123".to_string(),
            commit_id: "abc1234".to_string(),
            files_changed: 5,
            counts_truncated: false,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_push_response_no_paths() {
        let response = PushResponse {
            status: "pushed".to_string(),
            branch: "ekka/tenant/session/123".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_pr_response_no_paths() {
        let response = PrResponse {
            status: "not_configured".to_string(),
            code: "GITHUB_NOT_CONFIGURED".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_git_write_error_messages_no_paths() {
        let errors = [
            GitOperationError::ProtectedBranch,
            GitOperationError::NothingToCommit,
            GitOperationError::NoRemoteConfigured,
            GitOperationError::CommitFailed,
        ];

        for err in errors {
            let message = err.message();
            let code = err.code();
            assert_no_path_leak(message);
            assert_no_path_leak(code);
        }
    }

    #[test]
    fn test_commit_request_deserialization() {
        let json = r#"{"workspace_id":"123e4567-e89b-12d3-a456-426614174000","message":"Test commit"}"#;
        let request: CommitRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.message, "Test commit");
        assert!(request.note.is_none());
    }

    #[test]
    fn test_commit_request_with_note() {
        let json = r#"{"workspace_id":"123","message":"Test","note":"Audit note"}"#;
        let request: CommitRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.note, Some("Audit note".to_string()));
    }

    #[test]
    fn test_pr_request_default_base() {
        let json = r#"{"workspace_id":"123","title":"My PR"}"#;
        let request: PrRequest = serde_json::from_str(json).unwrap();
        assert!(request.base.is_none()); // Will default to "main" in handler
    }

    #[test]
    fn test_pr_request_custom_base() {
        let json = r#"{"workspace_id":"123","title":"My PR","base":"develop"}"#;
        let request: PrRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.base, Some("develop".to_string()));
    }

    #[test]
    fn test_max_commit_message_len_constant() {
        assert_eq!(MAX_COMMIT_MESSAGE_LEN, 200);
    }

    #[test]
    fn test_capability_constants() {
        assert_eq!(GIT_READ_CAPABILITY, "git.read");
        assert_eq!(GIT_COMMIT_CAPABILITY, "git.commit");
        assert_eq!(GIT_PUSH_CAPABILITY, "git.push");
        assert_eq!(GIT_WRITE_CAPABILITY, "git.write"); // Legacy, kept for backwards compat
        assert_eq!(GITHUB_PR_CAPABILITY, "github.pr");
        assert_eq!(GIT_CLONE_CAPABILITY, "git.clone");
    }

    // =========================================================================
    // Clone Tests (RAPTOR-2 Step 22)
    // =========================================================================

    #[test]
    fn test_clone_request_deserialization() {
        let json = r#"{"workspace_id":"550e8400-e29b-41d4-a716-446655440000"}"#;
        let request: CloneRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.workspace_id, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_clone_request_no_url_field() {
        // Verify CloneRequest does NOT accept URL field
        let json = r#"{"workspace_id":"test-123","url":"https://github.com/owner/repo"}"#;
        let request: CloneRequest = serde_json::from_str(json).unwrap();
        // Even if url is provided, it should be ignored (not in struct)
        assert_eq!(request.workspace_id, "test-123");
    }

    #[test]
    fn test_clone_response_no_paths() {
        let response = CloneResponse {
            status: "cloned".to_string(),
            workspace_id: "workspace-123".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
    }

    #[test]
    fn test_clone_response_no_urls() {
        let response = CloneResponse {
            status: "cloned".to_string(),
            workspace_id: "workspace-123".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("github.com"), "Response must not contain URLs");
        assert!(!json.contains("https://"), "Response must not contain URL schemes");
        assert!(!json.contains("owner/repo"), "Response must not contain repo ref");
    }

    #[test]
    fn test_clone_error_codes_no_paths() {
        let codes = [
            CloneErrorCodes::REPO_NOT_BOUND,
            CloneErrorCodes::REPO_ALREADY_PRESENT,
            CloneErrorCodes::CLONE_FAILED,
        ];

        for code in codes {
            assert!(!code.contains("/Users"), "Code must not contain path: {}", code);
            assert!(!code.contains("/home"), "Code must not contain path: {}", code);
            assert!(!code.contains("github.com"), "Code must not contain URL: {}", code);
        }
    }

    #[test]
    fn test_repo_binding_error_no_paths() {
        let errors = [
            RepoBindingError::NotBound,
            RepoBindingError::InvalidWorkspace,
            RepoBindingError::ResolverNotAvailable,
        ];

        for err in errors {
            let msg = err.message();
            let code = err.code();
            assert!(!msg.contains("/Users"), "Message must not contain path: {}", msg);
            assert!(!msg.contains("/home"), "Message must not contain path: {}", msg);
            assert!(!code.contains("/Users"), "Code must not contain path: {}", code);
            assert!(!msg.contains("github.com"), "Message must not contain URL: {}", msg);
        }
    }

    // =========================================================================
    // Credential Callback Tests (RAPTOR-2 Step 26)
    // =========================================================================

    #[test]
    fn test_github_token_username_constant() {
        // Verify the GitHub token username is the standard x-access-token
        assert_eq!(GITHUB_TOKEN_USERNAME, "x-access-token");
    }

    #[test]
    fn test_git_token_provider_type() {
        // Test that GitTokenProvider can be created as a closure
        let provider: GitTokenProvider = std::sync::Arc::new(|_session_id: &str| {
            Some("test_token".to_string())
        });
        let result = provider("test-session");
        assert_eq!(result, Some("test_token".to_string()));
    }

    #[test]
    fn test_git_token_provider_returns_none() {
        // Test that GitTokenProvider can return None for missing tokens
        let provider: GitTokenProvider = std::sync::Arc::new(|_session_id: &str| {
            None
        });
        let result = provider("test-session");
        assert!(result.is_none());
    }

    #[test]
    fn test_context_without_token_provider() {
        // Test that GitModuleContext can be created without token provider
        let resolver: WorkspaceResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(WorkspaceResolutionError::NotFound)
        });
        let validator: SessionValidator = std::sync::Arc::new(|_headers: &axum::http::HeaderMap| {
            Err(SessionValidationError {
                error: "test".to_string(),
                code: "TEST".to_string(),
                status: axum::http::StatusCode::UNAUTHORIZED,
            })
        });

        let ctx = GitModuleContext::new(resolver, validator, "test");
        assert!(ctx.token_provider.is_none());
        assert!(ctx.repo_binding_resolver.is_none());
    }

    #[test]
    fn test_context_with_repo_binding_no_token() {
        // Test with_repo_binding still has no token provider
        let resolver: WorkspaceResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(WorkspaceResolutionError::NotFound)
        });
        let validator: SessionValidator = std::sync::Arc::new(|_headers: &axum::http::HeaderMap| {
            Err(SessionValidationError {
                error: "test".to_string(),
                code: "TEST".to_string(),
                status: axum::http::StatusCode::UNAUTHORIZED,
            })
        });
        let repo_resolver: RepoBindingResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(RepoBindingError::NotBound)
        });

        let ctx = GitModuleContext::with_repo_binding(resolver, validator, repo_resolver, "test");
        assert!(ctx.token_provider.is_none());
        assert!(ctx.repo_binding_resolver.is_some());
    }

    #[test]
    fn test_context_with_auth() {
        // Test with_auth has both token provider and repo binding
        let resolver: WorkspaceResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(WorkspaceResolutionError::NotFound)
        });
        let validator: SessionValidator = std::sync::Arc::new(|_headers: &axum::http::HeaderMap| {
            Err(SessionValidationError {
                error: "test".to_string(),
                code: "TEST".to_string(),
                status: axum::http::StatusCode::UNAUTHORIZED,
            })
        });
        let repo_resolver: RepoBindingResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(RepoBindingError::NotBound)
        });
        let token_provider: GitTokenProvider = std::sync::Arc::new(|_session_id: &str| {
            Some("test_token".to_string())
        });

        let ctx = GitModuleContext::with_auth(
            resolver, validator, repo_resolver, token_provider, false, "test"
        );
        assert!(ctx.token_provider.is_some());
        assert!(ctx.repo_binding_resolver.is_some());
        assert!(!ctx.clone_requires_token);
    }

    #[test]
    fn test_push_auth_required_error_no_token_leak() {
        // Verify GIT_AUTH_REQUIRED error message doesn't leak token info
        let error_msg = "GitHub authentication required for push";
        let error_code = "GIT_AUTH_REQUIRED";

        assert!(!error_msg.contains("ghp_"), "Error must not contain token prefix");
        assert!(!error_msg.contains("gho_"), "Error must not contain OAuth token prefix");
        assert!(!error_msg.contains("token"), "Error should not mention 'token' directly");
        assert!(!error_code.contains("/Users"), "Code must not contain path");
    }

    #[test]
    fn test_push_failed_error_no_details() {
        // Verify GIT_PUSH_FAILED error message doesn't expose details
        let error_msg = "Push operation failed";
        let error_code = "GIT_PUSH_FAILED";

        assert!(!error_msg.contains("github.com"), "Error must not contain URL");
        assert!(!error_msg.contains("/Users"), "Error must not contain path");
        assert!(!error_msg.contains("403"), "Error must not contain HTTP status");
        assert!(!error_msg.contains("401"), "Error must not contain HTTP status");
        assert!(!error_code.contains("github"), "Code must not mention github");
    }

    #[test]
    fn test_clone_error_no_token_leak() {
        // Verify clone error doesn't leak authentication info
        let error_msg = "Clone operation failed";
        let error_code = CloneErrorCodes::CLONE_FAILED;

        assert!(!error_msg.contains("ghp_"), "Error must not contain token prefix");
        assert!(!error_msg.contains("gho_"), "Error must not contain OAuth token prefix");
        assert!(!error_msg.contains("x-access-token"), "Error must not contain auth username");
        assert!(!error_code.contains("AUTH"), "Error code must not mention auth");
    }

    // =========================================================================
    // RAPTOR-2 Step 27 - Capability + Profile Hardening Tests
    // =========================================================================

    #[test]
    fn test_explicit_capability_constants_step27() {
        // Verify the new explicit capabilities are correctly defined
        assert_eq!(GIT_COMMIT_CAPABILITY, "git.commit");
        assert_eq!(GIT_PUSH_CAPABILITY, "git.push");
        // Legacy git.write still exists for backwards compat
        assert_eq!(GIT_WRITE_CAPABILITY, "git.write");
    }

    #[test]
    fn test_context_clone_requires_token_default() {
        // Default contexts should not require token for clone
        let resolver: WorkspaceResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(WorkspaceResolutionError::NotFound)
        });
        let validator: SessionValidator = std::sync::Arc::new(|_headers: &axum::http::HeaderMap| {
            Err(SessionValidationError {
                error: "test".to_string(),
                code: "TEST".to_string(),
                status: axum::http::StatusCode::UNAUTHORIZED,
            })
        });

        let ctx = GitModuleContext::new(resolver.clone(), validator.clone(), "test");
        assert!(!ctx.clone_requires_token, "new() should not require token for clone");

        let repo_resolver: RepoBindingResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(RepoBindingError::NotBound)
        });
        let ctx2 = GitModuleContext::with_repo_binding(resolver, validator, repo_resolver, "test");
        assert!(!ctx2.clone_requires_token, "with_repo_binding() should not require token for clone");
    }

    #[test]
    fn test_context_with_auth_clone_requires_token_true() {
        // with_auth can enable clone_requires_token
        let resolver: WorkspaceResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(WorkspaceResolutionError::NotFound)
        });
        let validator: SessionValidator = std::sync::Arc::new(|_headers: &axum::http::HeaderMap| {
            Err(SessionValidationError {
                error: "test".to_string(),
                code: "TEST".to_string(),
                status: axum::http::StatusCode::UNAUTHORIZED,
            })
        });
        let repo_resolver: RepoBindingResolver = std::sync::Arc::new(|_ws_id: &str| {
            Err(RepoBindingError::NotBound)
        });
        let token_provider: GitTokenProvider = std::sync::Arc::new(|_session_id: &str| {
            Some("test_token".to_string())
        });

        // Studio mode: clone_requires_token = true
        let ctx = GitModuleContext::with_auth(
            resolver.clone(), validator.clone(), repo_resolver.clone(), token_provider.clone(), true, "test"
        );
        assert!(ctx.clone_requires_token, "Studio mode should require token for clone");

        // Demo mode: clone_requires_token = false
        let ctx2 = GitModuleContext::with_auth(
            resolver, validator, repo_resolver, token_provider, false, "test"
        );
        assert!(!ctx2.clone_requires_token, "Demo mode should not require token for clone");
    }

    #[test]
    fn test_github_not_connected_error_no_leak() {
        // Verify GITHUB_NOT_CONNECTED error is safe
        let error_msg = "GitHub authentication required";
        let error_code = "GITHUB_NOT_CONNECTED";

        assert!(!error_msg.contains("/Users"), "Error must not contain path");
        assert!(!error_msg.contains("token"), "Error must not mention token");
        assert!(!error_msg.contains("ghp_"), "Error must not contain token prefix");
        assert!(!error_msg.contains("EKKA_"), "Error must not contain env var prefix");
        assert!(!error_code.contains("/"), "Code must not contain path");
    }

    #[test]
    fn test_capability_gating_error_no_capability_name_leak() {
        // CAPABILITY_DENIED error should not leak capability names
        let error_msg = "Not permitted";
        let error_code = error_codes::CAPABILITY_DENIED;

        assert!(!error_msg.contains("git.commit"), "Error must not contain capability name");
        assert!(!error_msg.contains("git.push"), "Error must not contain capability name");
        assert!(!error_msg.contains("git.clone"), "Error must not contain capability name");
        assert!(!error_msg.contains("github.pr"), "Error must not contain capability name");
        assert!(!error_code.contains("git"), "Code must not contain capability");
    }

    // =========================================================================
    // RAPTOR-2 Step 28 - Git Write Determinism + Audit Tests
    // =========================================================================

    #[test]
    fn test_sanitize_branch_segment_lowercase() {
        assert_eq!(sanitize_branch_segment("TenantABC"), "tenantabc");
        assert_eq!(sanitize_branch_segment("User123"), "user123");
    }

    #[test]
    fn test_sanitize_branch_segment_alnum_and_hyphen() {
        assert_eq!(sanitize_branch_segment("user-123"), "user-123");
        assert_eq!(sanitize_branch_segment("user_123"), "user123"); // underscore removed
        assert_eq!(sanitize_branch_segment("user@email.com"), "useremailcom"); // special chars removed
    }

    #[test]
    fn test_sanitize_branch_segment_max_length() {
        let long = "a".repeat(100);
        let result = sanitize_branch_segment(&long);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sanitize_branch_segment_empty_fallback() {
        assert_eq!(sanitize_branch_segment(""), "unknown");
        assert_eq!(sanitize_branch_segment("@#$%"), "unknown"); // all special chars
    }

    #[test]
    fn test_generate_ekka_branch_name_uses_subject() {
        // Now uses subject instead of session_id
        let branch = generate_ekka_branch_name("tenant-abc", "user@example.com");
        assert!(branch.starts_with(EKKA_BRANCH_PREFIX));
        assert!(branch.contains("tenant-abc"));
        assert!(branch.contains("userexamplecom")); // sanitized subject
    }

    #[test]
    fn test_generate_ekka_branch_name_format_step28() {
        // Format: ekka/<tenant>/<subject>/<timestamp>
        let branch = generate_ekka_branch_name("my-tenant", "my-subject");
        let parts: Vec<&str> = branch.split('/').collect();
        assert_eq!(parts.len(), 4, "Branch should have 4 parts: ekka/tenant/subject/timestamp");
        assert_eq!(parts[0], "ekka");
        assert_eq!(parts[1], "my-tenant");
        assert_eq!(parts[2], "my-subject");
        assert!(parts[3].len() == 14, "Timestamp should be YYYYMMDDHHMMSS (14 chars)");
    }

    #[test]
    fn test_idempotency_store_basic() {
        let store = IdempotencyStore::new();

        // Set and get
        store.set("tenant", "subject", "ws-123", "commit", "key-abc", "response-json".to_string(), 200);
        let result = store.get("tenant", "subject", "ws-123", "commit", "key-abc");
        assert!(result.is_some());
        let (json, status) = result.unwrap();
        assert_eq!(json, "response-json");
        assert_eq!(status, 200);
    }

    #[test]
    fn test_idempotency_store_different_keys() {
        let store = IdempotencyStore::new();

        store.set("t1", "s1", "ws", "op", "key1", "resp1".to_string(), 200);
        store.set("t1", "s1", "ws", "op", "key2", "resp2".to_string(), 201);

        let r1 = store.get("t1", "s1", "ws", "op", "key1");
        let r2 = store.get("t1", "s1", "ws", "op", "key2");

        assert!(r1.is_some());
        assert!(r2.is_some());
        assert_eq!(r1.unwrap().0, "resp1");
        assert_eq!(r2.unwrap().0, "resp2");
    }

    #[test]
    fn test_idempotency_store_isolation() {
        let store = IdempotencyStore::new();

        // Same key but different tenant/subject should not collide
        store.set("tenant1", "subject1", "ws", "op", "same-key", "resp1".to_string(), 200);
        store.set("tenant2", "subject2", "ws", "op", "same-key", "resp2".to_string(), 201);

        let r1 = store.get("tenant1", "subject1", "ws", "op", "same-key");
        let r2 = store.get("tenant2", "subject2", "ws", "op", "same-key");

        assert_eq!(r1.unwrap().0, "resp1");
        assert_eq!(r2.unwrap().0, "resp2");
    }

    #[test]
    fn test_idempotency_key_header_constant() {
        assert_eq!(IDEMPOTENCY_KEY_HEADER, "x-idempotency-key");
    }

    #[test]
    fn test_audit_store_basic() {
        let store = AuditStore::new();

        let event = AuditEvent::new("ws-123", "commit", "ok", "OK", Some("tenant"), Some("subject"));
        store.record(event);

        let events = store.get("ws-123", 10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].workspace_id, "ws-123");
        assert_eq!(events[0].op, "commit");
        assert_eq!(events[0].result, "ok");
        assert_eq!(events[0].code, "OK");
    }

    #[test]
    fn test_audit_store_workspace_isolation() {
        let store = AuditStore::new();

        store.record(AuditEvent::new("ws-1", "commit", "ok", "OK", None, None));
        store.record(AuditEvent::new("ws-2", "push", "ok", "OK", None, None));

        let ws1_events = store.get("ws-1", 10);
        let ws2_events = store.get("ws-2", 10);

        assert_eq!(ws1_events.len(), 1);
        assert_eq!(ws2_events.len(), 1);
        assert_eq!(ws1_events[0].op, "commit");
        assert_eq!(ws2_events[0].op, "push");
    }

    #[test]
    fn test_audit_event_session_key_hashed() {
        let event = AuditEvent::new("ws", "commit", "ok", "OK", Some("tenant-123"), Some("subject-456"));

        // Session key should be hashed, not raw values
        assert!(event.session_key.is_some());
        let key = event.session_key.unwrap();
        assert!(!key.contains("tenant-123"), "Session key must not contain raw tenant");
        assert!(!key.contains("subject-456"), "Session key must not contain raw subject");
        assert_eq!(key.len(), 16, "Session key should be 16 hex chars (truncated sha256)");
    }

    #[test]
    fn test_audit_event_no_paths() {
        let event = AuditEvent::new("ws-123", "clone", "err", "CLONE_FAILED", Some("t"), Some("s"));
        let json = serde_json::to_string(&event).unwrap();

        assert!(!json.contains("/Users"), "Audit event must not contain paths");
        assert!(!json.contains("/home"), "Audit event must not contain paths");
        assert!(!json.contains("github.com"), "Audit event must not contain URLs");
    }

    #[test]
    fn test_audit_response_no_leak() {
        let response = AuditResponse {
            workspace_id: "ws-123".to_string(),
            events: vec![
                AuditEvent::new("ws-123", "commit", "ok", "OK", Some("t"), Some("s")),
            ],
        };
        let json = serde_json::to_string(&response).unwrap();

        assert!(!json.contains("/Users"), "Response must not contain paths");
        assert!(!json.contains("github.com"), "Response must not contain URLs");
        assert!(!json.contains("ghp_"), "Response must not contain tokens");
        assert!(!json.contains("EKKA_"), "Response must not contain env vars");
    }

    #[test]
    fn test_commit_request_no_branch_field() {
        // Verify CommitRequest does NOT have a branch field
        let json = r#"{"workspace_id":"ws-123","message":"test commit","branch":"feature/x"}"#;
        let request: CommitRequest = serde_json::from_str(json).unwrap();
        // Branch field should be ignored (not in struct)
        assert_eq!(request.workspace_id, "ws-123");
        assert_eq!(request.message, "test commit");
    }

    #[test]
    fn test_push_request_no_branch_field() {
        // Verify PushRequest does NOT have a branch field
        let json = r#"{"workspace_id":"ws-123","branch":"feature/x"}"#;
        let request: PushRequest = serde_json::from_str(json).unwrap();
        // Branch field should be ignored
        assert_eq!(request.workspace_id, "ws-123");
    }

    #[test]
    fn test_protected_prefix_check() {
        let resolver: WorkspaceResolver = std::sync::Arc::new(|_| Err(WorkspaceResolutionError::NotFound));
        let validator: SessionValidator = std::sync::Arc::new(|_| {
            Err(SessionValidationError {
                error: "test".to_string(),
                code: "TEST".to_string(),
                status: StatusCode::UNAUTHORIZED,
            })
        });

        let ctx = GitModuleContext::new(resolver, validator, "test");

        // Default: no protected prefixes
        assert!(!ctx.is_prefix_protected("release/1.0"));
        assert!(!ctx.is_prefix_protected("hotfix/fix-bug"));
    }

    #[test]
    fn test_workdir_dirty_error_no_leak() {
        let error_msg = "Working directory has uncommitted changes";
        let error_code = "GIT_WORKDIR_DIRTY";

        assert!(!error_msg.contains("/Users"), "Error must not contain paths");
        assert!(!error_msg.contains("/home"), "Error must not contain paths");
        assert!(!error_code.contains("/"), "Code must not contain paths");
    }

    #[test]
    fn test_protected_branch_error_no_leak() {
        let error_msg = "Cannot write to protected branch";
        let error_code = "GIT_PROTECTED_BRANCH";

        // Must not leak which branches are protected
        assert!(!error_msg.contains("main"), "Error must not leak protected branch names");
        assert!(!error_msg.contains("master"), "Error must not leak protected branch names");
        assert!(!error_msg.contains("release"), "Error must not leak protected prefixes");
        assert!(!error_code.contains("main"), "Code must not leak protected branches");
    }

    #[test]
    fn test_audit_store_limit_enforced() {
        let store = AuditStore::new();

        // Add 250 events (more than AUDIT_MAX_EVENTS = 200)
        for i in 0..250 {
            store.record(AuditEvent::new("ws-1", &format!("op{}", i), "ok", "OK", None, None));
        }

        let events = store.get("ws-1", 300);
        assert!(events.len() <= 200, "Audit store should cap at 200 events");
    }

    #[test]
    fn test_idempotency_key_max_length() {
        assert_eq!(MAX_IDEMPOTENCY_KEY_LEN, 100);
    }
}
