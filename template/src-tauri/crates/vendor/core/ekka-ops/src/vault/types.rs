//! Vault Types
//!
//! All shared types for vault operations.

use serde::{Deserialize, Serialize};

// =============================================================================
// Secret Types
// =============================================================================

/// Secret type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretType {
    Password,
    ApiKey,
    Token,
    Certificate,
    SshKey,
    GenericText,
}

impl Default for SecretType {
    fn default() -> Self {
        SecretType::GenericText
    }
}

/// Secret metadata - NEVER contains the actual value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub id: String,
    pub name: String,
    pub secret_type: SecretType,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Direct bundle reference (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Input for creating a secret (value accepted here only)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretCreateInput {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub secret_type: SecretType,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub bundle_id: Option<String>,
}

/// Input for updating a secret (value accepted here only)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretUpdateInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<SecretType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
}

/// Options for listing secrets
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretListOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<SecretType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
}

// =============================================================================
// Bundle Types
// =============================================================================

/// Bundle metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleMeta {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub secret_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Input for creating a bundle
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleCreateInput {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Options for listing bundles
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleListOptions {
    // Reserved for future filtering
}

// =============================================================================
// File Types (NEW)
// =============================================================================

/// File entry kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileKind {
    File,
    Dir,
}

/// File entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    /// Relative path from workspace root
    pub path: String,
    /// Filename only
    pub name: String,
    /// File or Dir
    pub kind: FileKind,
    /// Size in bytes (for files only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Last modified timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
}

/// Options for file operations
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileOptions {
    /// Workspace ID (defaults to context workspace or "default")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
}

/// Options for listing files
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileListOptions {
    /// Workspace ID (defaults to context workspace or "default")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Whether to list recursively
    #[serde(default)]
    pub recursive: bool,
}

/// Options for deleting files/directories
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDeleteOptions {
    /// Workspace ID (defaults to context workspace or "default")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Whether to delete recursively (for directories)
    #[serde(default)]
    pub recursive: bool,
}

// =============================================================================
// SecretRef Types (Non-Revealing Usage)
// =============================================================================

/// How to inject a secret value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretInjection {
    /// Inject as environment variable
    EnvVar { name: String },
    /// Write to temporary file
    File { path: String },
    /// Inject as HTTP header
    Header { name: String },
}

/// Reference to a secret for non-revealing usage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    /// Secret ID (preferred) or name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    /// Secret name (for lookup if id not provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// How to inject the secret
    pub inject_as: SecretInjection,
}

// =============================================================================
// Audit Types
// =============================================================================

/// Audit event action (dot-notation format)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Secret events
    #[serde(rename = "secret.created")]
    SecretCreated,
    #[serde(rename = "secret.updated")]
    SecretUpdated,
    #[serde(rename = "secret.deleted")]
    SecretDeleted,
    #[serde(rename = "secret.accessed")]
    SecretAccessed,
    // Bundle events
    #[serde(rename = "bundle.created")]
    BundleCreated,
    #[serde(rename = "bundle.updated")]
    BundleUpdated,
    #[serde(rename = "bundle.deleted")]
    BundleDeleted,
    #[serde(rename = "bundle.secret_added")]
    BundleSecretAdded,
    #[serde(rename = "bundle.secret_removed")]
    BundleSecretRemoved,
    // File events
    #[serde(rename = "file.written")]
    FileWritten,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.deleted")]
    FileDeleted,
    #[serde(rename = "file.mkdir")]
    FileMkdir,
    #[serde(rename = "file.moved")]
    FileMoved,
    // Legacy (for backward compatibility during migration)
    #[serde(rename = "secrets_injected")]
    SecretsInjected,
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub event_id: String,
    pub action: AuditAction,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
}

/// Options for listing audit events (cursor-based pagination)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListOptions {
    /// Maximum number of events to return (default 50, max 100)
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque cursor for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Filter by action (e.g., "secret.created", "file.written")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Text search across event data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Filter by secret ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    /// Filter by bundle ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    /// Filter by path prefix
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
}

/// Audit list result with cursor-based pagination
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListResult {
    pub events: Vec<AuditEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

// =============================================================================
// Status Types
// =============================================================================

/// Vault status
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// Whether the vault is initialized
    pub initialized: bool,
    /// Current tenant ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Available workspace IDs
    pub workspaces: Vec<String>,
}

/// Vault capabilities
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultCapabilities {
    /// Supported features
    pub features: Vec<String>,
    /// Maximum secret value size in bytes
    pub max_secret_size: u64,
    /// Maximum file size in bytes
    pub max_file_size: u64,
    /// Maximum path depth
    pub max_path_depth: u32,
}

// =============================================================================
// Internal Storage Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct SecretsIndex {
    pub secrets: Vec<SecretMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct BundlesIndex {
    pub bundles: Vec<BundleMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AuditLog {
    pub events: Vec<AuditEvent>,
}
