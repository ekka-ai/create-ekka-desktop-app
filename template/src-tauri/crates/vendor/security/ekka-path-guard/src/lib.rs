//! Path Security Guardrails
//!
//! ALL file operations in the app MUST go through this module.
//! Provides grant-based path validation with engine-signed authorization.
//!
//! ## Security Model
//!
//! - **HOME path**: Auto-allowed READ_WRITE, explicit bootstrap entry, immutable
//! - **Non-HOME paths**: Require engine-signed grants (local config is NOT authority)
//! - **Operation enforcement**: READ_ONLY blocks write/delete/mkdir/rmdir/wipe
//! - **Matching**: Most-specific path prefix wins
//!
//! ## Grant Flow
//!
//! 1. User consents via TS frontend
//! 2. Engine signs grant with Ed25519
//! 3. Node stores grant in `<EKKA_HOME>/grants.json`
//! 4. PathGuard verifies signature on each access

mod grant_store;

pub use grant_store::GrantStore;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

// =============================================================================
// Constants
// =============================================================================

const MAX_AUDIT_LOG_SIZE: usize = 1000;

// =============================================================================
// Types
// =============================================================================

/// Path type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathType {
    General,
    Workspace,
    Data,
    Temp,
    Cache,
    Home,
}

impl Default for PathType {
    fn default() -> Self {
        PathType::General
    }
}

/// Access level for a path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathAccess {
    ReadOnly,
    ReadWrite,
}

impl Default for PathAccess {
    fn default() -> Self {
        PathAccess::ReadOnly
    }
}

/// Operation category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOperation {
    Read,
    Write,
    Delete,
}

impl PathOperation {
    pub fn from_str(op: &str) -> Self {
        match op {
            "read" | "vault_read" | "list" | "list_dir" | "vault_list" | "exists" | "exists_check" => {
                PathOperation::Read
            }
            "write" | "vault_write" | "mkdir" | "create_dir" | "vault_mkdir" | "vault_init" => {
                PathOperation::Write
            }
            "delete" | "vault_delete" | "delete_dir" | "rmdir" | "wipe" | "vault_wipe"
            | "vault_wipe_standalone" => PathOperation::Delete,
            _ => PathOperation::Write,
        }
    }

    pub fn is_allowed_by(&self, access: PathAccess) -> bool {
        match access {
            PathAccess::ReadWrite => true,
            PathAccess::ReadOnly => matches!(self, PathOperation::Read),
        }
    }
}

// =============================================================================
// Unified Grant Types (ONLY unified schema supported - no legacy compatibility)
// =============================================================================

/// Resource kind discriminator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Connector,
    Path,
}

/// Unified resource structure (discriminated union)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantResource {
    Connector {
        id: String,
    },
    Path {
        path_prefix: String,
        #[serde(default)]
        attrs: Option<PathResourceAttrs>,
    },
}

/// Path resource attributes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathResourceAttrs {
    #[serde(default)]
    pub path_type: Option<PathType>,
}

/// Unified permissions structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantPermissions {
    pub ops: Vec<String>,
    #[serde(default)]
    pub access: Option<PathAccess>,
}

/// Consent information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantConsent {
    pub mode: String,
    pub approved_at: String,
    pub approved_by: String,
}

/// Grant payload - UNIFIED SCHEMA ONLY
///
/// Required format:
/// ```json
/// {
///   "grant_id": "uuid",
///   "issuer": "ekka-engine",
///   "issued_at": "RFC3339",
///   "expires_at": "RFC3339",
///   "tenant_id": "...",
///   "sub": "...",
///   "node_id": "uuid",
///   "resource": { "kind": "path"|"connector", ... },
///   "permissions": { "ops": [...], "access": "READ_WRITE"|"READ_ONLY" },
///   "purpose": "...",
///   "consent": { "mode": "...", "approved_at": "...", "approved_by": "..." }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    // Required identity fields
    pub sub: String,
    pub tenant_id: String,
    pub node_id: Uuid,

    // Required unified schema fields
    pub grant_id: String,
    pub issuer: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub resource: GrantResource,
    pub permissions: GrantPermissions,
    pub purpose: String,
    pub consent: GrantConsent,
}

impl Grant {
    /// Get path prefix from grant
    pub fn path_prefix(&self) -> &str {
        match &self.resource {
            GrantResource::Path { path_prefix, .. } => path_prefix.as_str(),
            GrantResource::Connector { id } => id.as_str(),
        }
    }

    /// Get expiration timestamp (RFC3339 to unix timestamp)
    pub fn expiration_timestamp(&self) -> Option<i64> {
        self.expires_at.as_ref().and_then(|expires_at| {
            chrono::DateTime::parse_from_rfc3339(expires_at)
                .ok()
                .map(|dt| dt.timestamp())
        })
    }

    /// Get access level from permissions
    pub fn access_level(&self) -> Option<PathAccess> {
        self.permissions.access
    }

    /// Check if this is a path grant
    pub fn is_path_grant(&self) -> bool {
        matches!(self.resource, GrantResource::Path { .. })
    }
}

/// Signed grant envelope - UNIFIED SCHEMA ONLY
///
/// Required envelope fields:
/// - schema: "GRANT"
/// - canon_alg: "SECURITY.CANONICALIZE.V1"
/// - signing_alg: "ed25519"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    /// Must be "GRANT"
    pub schema: String,
    /// Must be "SECURITY.CANONICALIZE.V1"
    pub canon_alg: String,
    /// Must be "ed25519"
    pub signing_alg: String,

    pub grant: Grant,
    pub grant_canonical_b64: String,
    pub signature_b64: String,
}

impl SignedGrant {
    /// Validate that this is a proper unified grant schema
    pub fn validate_schema(&self) -> Result<(), PathGuardError> {
        if self.schema != "GRANT" {
            return Err(PathGuardError::InvalidGrantSchema {
                reason: format!("Expected schema='GRANT', got '{}'", self.schema),
            });
        }
        if self.canon_alg != "SECURITY.CANONICALIZE.V1" {
            return Err(PathGuardError::InvalidGrantSchema {
                reason: format!(
                    "Expected canon_alg='SECURITY.CANONICALIZE.V1', got '{}'",
                    self.canon_alg
                ),
            });
        }
        if self.signing_alg != "ed25519" {
            return Err(PathGuardError::InvalidGrantSchema {
                reason: format!("Expected signing_alg='ed25519', got '{}'", self.signing_alg),
            });
        }
        Ok(())
    }
}

/// Path grant with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathGrant {
    #[serde(flatten)]
    pub signed_grant: SignedGrant,
    #[serde(default)]
    pub path_type: PathType,
    #[serde(default)]
    pub path_access: PathAccess,
}

impl PathGrant {
    /// Get path prefix from grant
    pub fn path_prefix(&self) -> &str {
        self.signed_grant.grant.path_prefix()
    }

    pub fn tenant_id(&self) -> &str {
        &self.signed_grant.grant.tenant_id
    }

    pub fn subject(&self) -> &str {
        &self.signed_grant.grant.sub
    }

    pub fn node_id(&self) -> Uuid {
        self.signed_grant.grant.node_id
    }

    pub fn grant_id(&self) -> &str {
        &self.signed_grant.grant.grant_id
    }

    /// Get expiration timestamp (RFC3339 to unix timestamp)
    pub fn expires_at(&self) -> i64 {
        self.signed_grant.grant.expiration_timestamp().unwrap_or(0)
    }

    /// Get access level from grant permissions (with fallback to PathGrant metadata)
    pub fn access(&self) -> PathAccess {
        self.signed_grant.grant.access_level().unwrap_or(self.path_access)
    }

    pub fn covers_path(&self, path: &Path) -> bool {
        let prefix = self.path_prefix();
        if prefix.is_empty() {
            return false;
        }
        path.starts_with(prefix)
    }

    pub fn specificity(&self) -> usize {
        self.path_prefix().len()
    }

    /// Validate the signed grant schema
    pub fn validate_schema(&self) -> Result<(), PathGuardError> {
        self.signed_grant.validate_schema()
    }
}

/// Grant decision
#[derive(Debug, Clone)]
pub struct GrantDecision {
    pub allowed: bool,
    pub grant_id: Option<String>,
    pub reason: String,
    pub path_type: PathType,
    pub path_access: PathAccess,
    /// The path prefix that granted access (for revoke)
    pub path_prefix: Option<String>,
}

impl GrantDecision {
    pub fn allow(grant_id: Option<String>, reason: &str, path_type: PathType, access: PathAccess, path_prefix: Option<String>) -> Self {
        Self {
            allowed: true,
            grant_id,
            reason: reason.to_string(),
            path_type,
            path_access: access,
            path_prefix,
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            grant_id: None,
            reason: reason.to_string(),
            path_type: PathType::General,
            path_access: PathAccess::ReadOnly,
            path_prefix: None,
        }
    }

    pub fn home(home_path: &str) -> Self {
        Self {
            allowed: true,
            grant_id: Some("BOOTSTRAP_HOME".to_string()),
            reason: "HOME path - bootstrap entry".to_string(),
            path_type: PathType::Home,
            path_access: PathAccess::ReadWrite,
            path_prefix: Some(home_path.to_string()),
        }
    }
}

/// Grants file format
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrantsFile {
    pub schema_version: String,
    pub grants: Vec<PathGrant>,
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Error, Debug)]
pub enum PathGuardError {
    #[error("Access denied: '{path}' requires grant")]
    AccessDenied { path: String },

    #[error("Operation denied: '{operation}' blocked on '{path}' (access: {access:?})")]
    OperationDenied {
        path: String,
        operation: String,
        access: PathAccess,
    },

    #[error("Invalid grant: {reason}")]
    InvalidGrant { reason: String },

    #[error("Invalid grant schema: {reason}")]
    InvalidGrantSchema { reason: String },

    #[error("Expired grant: expired at {expired_at}, now {current_time}")]
    ExpiredGrant { expired_at: i64, current_time: i64 },

    #[error("Tenant mismatch: expected '{expected}', got '{actual}'")]
    TenantMismatch { expected: String, actual: String },

    #[error("Subject mismatch: expected '{expected}', got '{actual}'")]
    SubjectMismatch { expected: String, actual: String },

    #[error("Path resolution failed: {msg}")]
    PathResolution { msg: String },

    #[error("Symlink escape: '{path}'")]
    SymlinkEscape { path: String },

    #[error("No home directory")]
    NoHomeDirectory,

    #[error("Missing ENGINE_GRANT_VERIFY_KEY_B64")]
    MissingVerificationKey,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// =============================================================================
// Audit Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathValidationResult {
    pub allowed: bool,
    pub path: String,
    pub reason: String,
    pub grant_id: Option<String>,
    pub path_type: PathType,
    pub path_access: PathAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAccessLog {
    pub timestamp: u64,
    pub operation: String,
    pub path: String,
    pub allowed: bool,
    pub caller: String,
    pub grant_id: Option<String>,
    pub path_type: PathType,
    pub path_access: PathAccess,
    pub decision_reason: String,
}

// =============================================================================
// Global Audit Log
// =============================================================================

static AUDIT_LOG: std::sync::OnceLock<Mutex<Vec<PathAccessLog>>> = std::sync::OnceLock::new();

fn audit_log() -> &'static Mutex<Vec<PathAccessLog>> {
    AUDIT_LOG.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn get_audit_log_entries(limit: usize) -> Vec<PathAccessLog> {
    if let Ok(log) = audit_log().lock() {
        let start = log.len().saturating_sub(limit);
        log[start..].to_vec()
    } else {
        vec![]
    }
}

pub fn get_denied_attempts(limit: usize) -> Vec<PathAccessLog> {
    if let Ok(log) = audit_log().lock() {
        log.iter().filter(|e| !e.allowed).rev().take(limit).cloned().collect()
    } else {
        vec![]
    }
}

pub fn clear_audit_log() {
    if let Ok(mut log) = audit_log().lock() {
        log.clear();
    }
}

// =============================================================================
// AuthContext
// =============================================================================

/// Authentication context for grant validation
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Tenant identifier (from JWT)
    pub tenant_id: String,
    /// Subject identifier / user ID (from JWT)
    pub sub: String,
}

impl AuthContext {
    pub fn new(tenant_id: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            sub: sub.into(),
        }
    }
}

// =============================================================================
// PathGuard
// =============================================================================

/// Path guard with grant-based authorization
pub struct PathGuard {
    /// HOME path (bootstrap entry, always RW)
    home_path: PathBuf,
    /// Grant store for signature verification
    grant_store: Option<GrantStore>,
    /// Auth context for grant validation (None for home_only mode)
    auth: Option<AuthContext>,
}

impl PathGuard {
    /// Primary production constructor.
    ///
    /// Loads ENGINE_GRANT_VERIFY_KEY_B64 from env (hard fail if missing).
    /// Uses grants file at `<home_path>/grants.json`.
    /// Binds tenant_id + sub from AuthContext for grant validation.
    ///
    /// NOTE: home_path is canonicalized if it exists (resolves symlinks).
    pub fn from_env(home_path: PathBuf, auth: AuthContext) -> Result<Self, PathGuardError> {
        // Canonicalize home_path to resolve symlinks
        let canonical_home = home_path.canonicalize().unwrap_or(home_path);
        let key_b64 = GrantStore::key_from_env()?;
        let grants_path = canonical_home.join("grants.json");
        let grant_store = GrantStore::new(grants_path, &key_b64)?;

        Ok(Self {
            home_path: canonical_home,
            grant_store: Some(grant_store),
            auth: Some(auth),
        })
    }

    /// HOME_ONLY: Internal EKKA home sandbox only.
    ///
    /// ONLY allows paths under home_path. DENIES everything outside.
    /// No external grants, no tenant/sub binding.
    /// Use ONLY for internal EKKA_HOME operations.
    ///
    /// NOTE: home_path is canonicalized if it exists (resolves symlinks).
    pub fn home_only(home_path: PathBuf) -> Self {
        // Canonicalize home_path to resolve symlinks (e.g., /tmp -> /private/tmp on macOS)
        let canonical_home = home_path.canonicalize().unwrap_or(home_path);
        Self {
            home_path: canonical_home,
            grant_store: None,
            auth: None,
        }
    }

    /// Test-only constructor with explicit grant store and auth context.
    /// NOT for production use.
    #[cfg(test)]
    pub(crate) fn with_grants(home_path: PathBuf, grant_store: GrantStore, auth: AuthContext) -> Self {
        Self {
            home_path,
            grant_store: Some(grant_store),
            auth: Some(auth),
        }
    }

    /// Get HOME path
    pub fn home_path(&self) -> &Path {
        &self.home_path
    }

    /// Normalize path (resolve symlinks, .., etc)
    fn normalize(&self, path: &Path) -> Result<PathBuf, PathGuardError> {
        // Try canonicalize first (handles existing paths with symlinks)
        if let Ok(canonical) = path.canonicalize() {
            return Ok(canonical);
        }

        // For non-existent paths, first resolve .. and . components
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| PathGuardError::PathResolution {
                    msg: "Cannot get current directory".to_string(),
                })?
                .join(path)
        };

        // Resolve .. and . components FIRST (before finding existing ancestor)
        let mut components = Vec::new();
        for comp in absolute.components() {
            match comp {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    components.pop();
                }
                c => components.push(c),
            }
        }

        let mut logical_normalized = PathBuf::new();
        for c in &components {
            logical_normalized.push(c);
        }

        // Now try to canonicalize the existing portion to resolve symlinks
        // Find the longest existing ancestor
        let mut existing_ancestor = logical_normalized.clone();
        let mut non_existent_parts = Vec::new();

        while !existing_ancestor.as_os_str().is_empty() && !existing_ancestor.exists() {
            if let Some(file_name) = existing_ancestor.file_name() {
                non_existent_parts.push(file_name.to_os_string());
            }
            if !existing_ancestor.pop() {
                break;
            }
        }

        // Canonicalize the existing portion (resolves symlinks like /tmp -> /private/tmp)
        let canonical_ancestor = if existing_ancestor.exists() {
            existing_ancestor.canonicalize().unwrap_or(existing_ancestor)
        } else {
            existing_ancestor
        };

        // Rebuild with non-existent parts (in reverse order)
        let mut result = canonical_ancestor;
        for part in non_existent_parts.into_iter().rev() {
            result.push(part);
        }

        Ok(result)
    }

    /// Check if path is under HOME
    fn is_home_path(&self, normalized: &Path) -> bool {
        normalized.starts_with(&self.home_path)
    }

    /// Evaluate access for a path and operation
    pub fn evaluate(&self, path: &Path, operation: &str) -> GrantDecision {
        let normalized = match self.normalize(path) {
            Ok(p) => p,
            Err(e) => return GrantDecision::deny(&e.to_string()),
        };

        let op = PathOperation::from_str(operation);

        // HOME always allowed with RW
        if self.is_home_path(&normalized) {
            return GrantDecision::home(&self.home_path.to_string_lossy());
        }

        // Non-HOME requires grant + auth context
        let grant_store = match &self.grant_store {
            Some(gs) => gs,
            None => return GrantDecision::deny("Path outside HOME, no grants configured"),
        };

        let auth = match &self.auth {
            Some(a) => a,
            None => return GrantDecision::deny("Path outside HOME, no auth context"),
        };

        // Find matching grants (sorted by specificity)
        let matching = grant_store.find_grants_for_path(&normalized);
        if matching.is_empty() {
            return GrantDecision::deny("No grant covers this path");
        }

        // Use most specific grant
        let grant = matching[0];

        // Validate tenant_id and sub match auth context
        if grant.tenant_id() != auth.tenant_id {
            return GrantDecision::deny(&format!(
                "Grant tenant mismatch: expected '{}', grant has '{}'",
                auth.tenant_id,
                grant.tenant_id()
            ));
        }
        if grant.subject() != auth.sub {
            return GrantDecision::deny(&format!(
                "Grant subject mismatch: expected '{}', grant has '{}'",
                auth.sub,
                grant.subject()
            ));
        }

        // Check operation allowed by access level (unified format uses grant.access())
        let access = grant.access();
        if !op.is_allowed_by(access) {
            return GrantDecision {
                allowed: false,
                grant_id: Some(grant.grant_id().to_string()),
                reason: format!(
                    "Operation '{}' denied by {:?} access",
                    operation, access
                ),
                path_type: grant.path_type,
                path_access: access,
                path_prefix: Some(grant.path_prefix().to_string()),
            };
        }

        GrantDecision::allow(
            Some(grant.grant_id().to_string()),
            &format!("Granted by {}", grant.path_prefix()),
            grant.path_type,
            access,
            Some(grant.path_prefix().to_string()),
        )
    }

    /// Validate path with audit logging
    pub fn validate_path_audited(
        &self,
        path: &Path,
        operation: &str,
        caller: &str,
    ) -> Result<PathBuf, PathGuardError> {
        let decision = self.evaluate(path, operation);
        self.log_access(path, operation, caller, &decision);

        if decision.allowed {
            self.normalize(path)
        } else if decision.grant_id.is_some() {
            // Had a grant but operation not allowed
            Err(PathGuardError::OperationDenied {
                path: path.display().to_string(),
                operation: operation.to_string(),
                access: decision.path_access,
            })
        } else {
            Err(PathGuardError::AccessDenied {
                path: path.display().to_string(),
            })
        }
    }

    /// Check if path is allowed (no audit)
    pub fn is_allowed(&self, path: &Path, operation: &str) -> bool {
        self.evaluate(path, operation).allowed
    }

    /// Get validation details
    pub fn get_validation_details(&self, path: &Path, operation: &str) -> PathValidationResult {
        let decision = self.evaluate(path, operation);
        PathValidationResult {
            allowed: decision.allowed,
            path: path.display().to_string(),
            reason: decision.reason,
            grant_id: decision.grant_id,
            path_type: decision.path_type,
            path_access: decision.path_access,
        }
    }

    fn log_access(&self, path: &Path, operation: &str, caller: &str, decision: &GrantDecision) {
        let entry = PathAccessLog {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            operation: operation.to_string(),
            path: path.display().to_string(),
            allowed: decision.allowed,
            caller: caller.to_string(),
            grant_id: decision.grant_id.clone(),
            path_type: decision.path_type,
            path_access: decision.path_access,
            decision_reason: decision.reason.clone(),
        };

        if let Ok(mut log) = audit_log().lock() {
            log.push(entry);
            let len = log.len();
            if len > MAX_AUDIT_LOG_SIZE {
                log.drain(0..len - MAX_AUDIT_LOG_SIZE);
            }
        }
    }

    // =========================================================================
    // Guarded Operations (with TOCTOU hardening)
    // =========================================================================

    /// TOCTOU: Re-canonicalize and verify path is still allowed before mutation
    fn verify_before_mutation(&self, path: &Path, operation: &str) -> Result<PathBuf, PathGuardError> {
        // Re-canonicalize immediately before fs operation
        let canonical = if path.exists() {
            path.canonicalize().map_err(|_| PathGuardError::SymlinkEscape {
                path: path.display().to_string(),
            })?
        } else {
            // For non-existent paths, verify parent is canonical and allowed
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let canonical_parent = parent.canonicalize().map_err(|_| {
                        PathGuardError::SymlinkEscape {
                            path: parent.display().to_string(),
                        }
                    })?;
                    // Verify parent is still under allowed paths
                    let decision = self.evaluate(&canonical_parent, operation);
                    if !decision.allowed {
                        return Err(PathGuardError::SymlinkEscape {
                            path: format!(
                                "Parent directory resolved outside allowed path: {}",
                                canonical_parent.display()
                            ),
                        });
                    }
                    canonical_parent.join(path.file_name().unwrap_or_default())
                } else {
                    self.normalize(path)?
                }
            } else {
                self.normalize(path)?
            }
        };

        // Final check: is canonical path still allowed?
        let decision = self.evaluate(&canonical, operation);
        if !decision.allowed {
            return Err(PathGuardError::SymlinkEscape {
                path: format!(
                    "Path resolved outside allowed boundary: {} ({})",
                    canonical.display(),
                    decision.reason
                ),
            });
        }

        Ok(canonical)
    }

    pub fn read_file(&self, path: &Path, caller: &str) -> Result<String, PathGuardError> {
        let validated = self.validate_path_audited(path, "read", caller)?;
        // Read: re-canonicalize existing file
        let canonical = if validated.exists() {
            validated.canonicalize().map_err(|_| PathGuardError::SymlinkEscape {
                path: validated.display().to_string(),
            })?
        } else {
            validated
        };
        fs::read_to_string(&canonical).map_err(PathGuardError::Io)
    }

    pub fn write_file(&self, path: &Path, content: &str, caller: &str) -> Result<(), PathGuardError> {
        let validated = self.validate_path_audited(path, "write", caller)?;
        // TOCTOU: verify before mutation
        let canonical = self.verify_before_mutation(&validated, "write")?;
        if let Some(parent) = canonical.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&canonical, content).map_err(PathGuardError::Io)
    }

    pub fn delete_file(&self, path: &Path, caller: &str) -> Result<(), PathGuardError> {
        let validated = self.validate_path_audited(path, "delete", caller)?;
        if validated.exists() {
            // TOCTOU: verify before mutation
            let canonical = self.verify_before_mutation(&validated, "delete")?;
            fs::remove_file(&canonical)?;
        }
        Ok(())
    }

    pub fn create_dir(&self, path: &Path, caller: &str) -> Result<(), PathGuardError> {
        let validated = self.validate_path_audited(path, "create_dir", caller)?;
        // TOCTOU: verify before mutation
        let canonical = self.verify_before_mutation(&validated, "create_dir")?;
        fs::create_dir_all(&canonical).map_err(PathGuardError::Io)
    }

    pub fn delete_dir(&self, path: &Path, caller: &str) -> Result<(), PathGuardError> {
        let validated = self.validate_path_audited(path, "delete_dir", caller)?;
        if validated.exists() {
            // TOCTOU: verify before mutation
            let canonical = self.verify_before_mutation(&validated, "delete_dir")?;
            fs::remove_dir_all(&canonical)?;
        }
        Ok(())
    }

    pub fn exists(&self, path: &Path, caller: &str) -> Result<bool, PathGuardError> {
        let validated = self.validate_path_audited(path, "exists", caller)?;
        Ok(validated.exists())
    }

    pub fn list_dir(&self, path: &Path, caller: &str) -> Result<Vec<PathBuf>, PathGuardError> {
        let validated = self.validate_path_audited(path, "list_dir", caller)?;
        // Re-canonicalize for list
        let canonical = if validated.exists() {
            validated.canonicalize().map_err(|_| PathGuardError::SymlinkEscape {
                path: validated.display().to_string(),
            })?
        } else {
            validated
        };
        Ok(fs::read_dir(&canonical)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_guard() -> (PathGuard, TempDir) {
        let temp = TempDir::new().unwrap();
        let home = temp.path().to_path_buf();
        let guard = PathGuard::home_only(home);
        (guard, temp)
    }

    #[test]
    fn test_home_path_allowed_rw() {
        let (guard, temp) = test_guard();
        let path = temp.path().join("test.txt");

        // Read allowed
        assert!(guard.is_allowed(&path, "read"));
        // Write allowed
        assert!(guard.is_allowed(&path, "write"));
        // Delete allowed
        assert!(guard.is_allowed(&path, "delete"));

        let decision = guard.evaluate(&path, "write");
        assert!(decision.allowed);
        assert_eq!(decision.path_type, PathType::Home);
        assert_eq!(decision.path_access, PathAccess::ReadWrite);
    }

    #[test]
    fn test_non_home_denied_without_grant() {
        let (guard, _temp) = test_guard();
        let outside_path = Path::new("/etc/passwd");

        assert!(!guard.is_allowed(outside_path, "read"));

        let decision = guard.evaluate(outside_path, "read");
        assert!(!decision.allowed);
        assert!(decision.reason.contains("outside HOME"));
    }

    #[test]
    fn test_traversal_blocked() {
        let (guard, temp) = test_guard();
        // Try to escape via ..
        let attack = temp.path().join("subdir").join("..").join("..").join("etc").join("passwd");

        // This normalizes to /etc/passwd which is outside HOME
        assert!(!guard.is_allowed(&attack, "read"));
    }

    #[test]
    fn test_audit_log_populated() {
        clear_audit_log();
        let (guard, temp) = test_guard();
        let path = temp.path().join("audit-test.txt");

        let _ = guard.validate_path_audited(&path, "read", "test-caller");

        let logs = get_audit_log_entries(10);
        assert!(!logs.is_empty());
        assert_eq!(logs[0].caller, "test-caller");
        assert_eq!(logs[0].operation, "read");
        assert!(logs[0].allowed);
        assert_eq!(logs[0].path_type, PathType::Home);
    }

    #[test]
    fn test_validation_details() {
        let (guard, temp) = test_guard();
        let path = temp.path().join("details.txt");

        let details = guard.get_validation_details(&path, "write");
        assert!(details.allowed);
        assert_eq!(details.path_type, PathType::Home);
        assert_eq!(details.path_access, PathAccess::ReadWrite);
        assert!(details.grant_id.as_ref().unwrap().contains("BOOTSTRAP"));
    }

    /// Helper function to create a unified grant for testing
    fn make_unified_grant(
        signing_key: &ed25519_dalek::SigningKey,
        path: &str,
        access: PathAccess,
        tenant_id: &str,
        sub: &str,
    ) -> PathGrant {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use ed25519_dalek::Signer;

        let grant = Grant {
            sub: sub.to_string(),
            tenant_id: tenant_id.to_string(),
            node_id: uuid::Uuid::new_v4(),
            grant_id: uuid::Uuid::new_v4().to_string(),
            issuer: "ekka-engine".to_string(),
            issued_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            resource: GrantResource::Path {
                path_prefix: path.to_string(),
                attrs: Some(PathResourceAttrs {
                    path_type: Some(PathType::Workspace),
                }),
            },
            permissions: GrantPermissions {
                ops: vec!["read".to_string(), "write".to_string(), "delete".to_string()],
                access: Some(access),
            },
            purpose: "workspace_access".to_string(),
            consent: GrantConsent {
                mode: "user_click".to_string(),
                approved_at: "2024-01-01T00:00:00Z".to_string(),
                approved_by: sub.to_string(),
            },
        };
        let canonical = serde_json::to_string(&grant).unwrap();
        let signature = signing_key.sign(canonical.as_bytes());

        PathGrant {
            signed_grant: SignedGrant {
                schema: "GRANT".to_string(),
                canon_alg: "SECURITY.CANONICALIZE.V1".to_string(),
                signing_alg: "ed25519".to_string(),
                grant,
                grant_canonical_b64: BASE64.encode(canonical.as_bytes()),
                signature_b64: BASE64.encode(signature.to_bytes()),
            },
            path_type: PathType::Workspace,
            path_access: access,
        }
    }

    #[test]
    fn test_read_only_blocks_write() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use ed25519_dalek::SigningKey;

        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();

        let external = temp.path().join("external");
        std::fs::create_dir_all(&external).unwrap();

        // Canonicalize paths (resolves /tmp -> /private/tmp on macOS)
        let external_canonical = external.canonicalize().unwrap();

        // Create keypair
        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let signing_key = SigningKey::from_bytes(&secret);
        let verify_key_b64 = BASE64.encode(signing_key.verifying_key().as_bytes());

        // Create unified grant with READ_ONLY
        let path_grant = make_unified_grant(
            &signing_key,
            &external_canonical.to_string_lossy(),
            PathAccess::ReadOnly,
            "tenant",
            "user",
        );

        // Save grant
        let grants_path = home.join("grants.json");
        let grants_file = GrantsFile {
            schema_version: "1.0".to_string(),
            grants: vec![path_grant],
        };
        std::fs::write(&grants_path, serde_json::to_string(&grants_file).unwrap()).unwrap();

        // Create guard with auth context matching grant's tenant/sub
        let store = GrantStore::new(grants_path, &verify_key_b64).unwrap();
        let auth = AuthContext::new("tenant", "user");
        let guard = PathGuard::with_grants(home, store, auth);

        let file_path = external.join("test.txt");

        // READ allowed
        assert!(guard.is_allowed(&file_path, "read"));
        assert!(guard.is_allowed(&file_path, "list_dir"));
        assert!(guard.is_allowed(&file_path, "exists"));

        // WRITE blocked
        assert!(!guard.is_allowed(&file_path, "write"));
        assert!(!guard.is_allowed(&file_path, "create_dir"));

        // DELETE blocked
        assert!(!guard.is_allowed(&file_path, "delete"));
        assert!(!guard.is_allowed(&file_path, "wipe"));

        // Verify error type
        let result = guard.validate_path_audited(&file_path, "write", "test");
        assert!(matches!(result, Err(PathGuardError::OperationDenied { .. })));
    }

    #[test]
    fn test_most_specific_grant_wins() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use ed25519_dalek::SigningKey;

        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();

        let projects = temp.path().join("projects");
        let readonly_repo = projects.join("readonly-repo");
        std::fs::create_dir_all(&readonly_repo).unwrap();

        // Canonicalize paths (resolves /tmp -> /private/tmp on macOS)
        let projects_canonical = projects.canonicalize().unwrap();
        let readonly_repo_canonical = readonly_repo.canonicalize().unwrap();

        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let signing_key = SigningKey::from_bytes(&secret);
        let verify_key_b64 = BASE64.encode(signing_key.verifying_key().as_bytes());

        // Parent grant: RW, Child grant: RO - use canonical paths
        let grants = vec![
            make_unified_grant(
                &signing_key,
                &projects_canonical.to_string_lossy(),
                PathAccess::ReadWrite,
                "tenant",
                "user",
            ),
            make_unified_grant(
                &signing_key,
                &readonly_repo_canonical.to_string_lossy(),
                PathAccess::ReadOnly,
                "tenant",
                "user",
            ),
        ];

        let grants_path = home.join("grants.json");
        let grants_file = GrantsFile {
            schema_version: "1.0".to_string(),
            grants,
        };
        std::fs::write(&grants_path, serde_json::to_string(&grants_file).unwrap()).unwrap();

        let store = GrantStore::new(grants_path, &verify_key_b64).unwrap();
        let auth = AuthContext::new("tenant", "user");
        let guard = PathGuard::with_grants(home, store, auth);

        // File in readonly-repo: RO wins (more specific)
        let ro_file = readonly_repo.join("file.txt");
        assert!(guard.is_allowed(&ro_file, "read"));
        assert!(!guard.is_allowed(&ro_file, "write"), "More specific RO should block write");

        // File in projects (not readonly-repo): RW applies
        let rw_file = projects.join("other-repo").join("file.txt");
        assert!(guard.is_allowed(&rw_file, "write"));
    }

    #[test]
    fn test_legacy_grant_rejected() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use ed25519_dalek::SigningKey;

        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();

        let external = temp.path().join("external");
        std::fs::create_dir_all(&external).unwrap();

        let external_canonical = external.canonicalize().unwrap();

        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let signing_key = SigningKey::from_bytes(&secret);
        let verify_key_b64 = BASE64.encode(signing_key.verifying_key().as_bytes());

        // Create a legacy-style grant JSON (missing schema, canon_alg, signing_alg)
        let legacy_grant_json = serde_json::json!({
            "grant": {
                "sub": "user",
                "tenant_id": "tenant",
                "node_id": uuid::Uuid::new_v4().to_string(),
                "scope": {
                    "action": "path_access",
                    "resource_id": external_canonical.to_string_lossy()
                },
                "exp": 9999999999i64
            },
            "grant_canonical_b64": BASE64.encode(b"fake"),
            "signature_b64": BASE64.encode([0u8; 64]),
            "path_type": "WORKSPACE",
            "path_access": "READ_ONLY"
        });

        // Save legacy grant
        let grants_path = home.join("grants.json");
        let grants_file_json = serde_json::json!({
            "schema_version": "1.0",
            "grants": [legacy_grant_json]
        });
        std::fs::write(&grants_path, serde_json::to_string(&grants_file_json).unwrap()).unwrap();

        // GrantStore should fail to load the legacy grant due to schema validation
        let store = GrantStore::new(grants_path, &verify_key_b64);

        // The store should either fail to load or have 0 valid grants
        // (depending on whether it rejects at parse or validation time)
        match store {
            Ok(s) => {
                // If it parsed, it should have rejected during validation
                assert_eq!(s.grants().len(), 0, "Legacy grants should be rejected");
            }
            Err(_) => {
                // Parse failure is also acceptable
            }
        }
    }
}
