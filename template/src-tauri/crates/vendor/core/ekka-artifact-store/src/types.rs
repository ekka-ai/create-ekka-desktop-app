//! Artifact store types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Reference to a stored artifact (returned from put_bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Stable URI: ekka://artifacts/<tenant>/<prefix>/<sha256>/<filename>
    pub uri: String,
    /// SHA256 hash of raw content
    pub sha256: String,
    /// Raw content size in bytes
    pub bytes_raw: usize,
    /// Stored size in bytes (after compression)
    pub bytes_stored: usize,
    /// Expiration time (if set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Artifact metadata (stored as sidecar JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// SHA256 hash of raw content
    pub sha256: String,
    /// Raw content size
    pub bytes_raw: usize,
    /// Stored size (after compression)
    pub bytes_stored: usize,
    /// MIME content type
    pub content_type: String,
    /// Whether content is gzip compressed
    pub compressed: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Tenant ID
    pub tenant_id: String,
    /// Original filename
    pub filename: String,
}
