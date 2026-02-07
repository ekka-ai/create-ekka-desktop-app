//! EKKA Artifact Store - Content-addressed filesystem storage
//!
//! Provides a stable interface for storing and retrieving artifacts.

mod compression;
mod error;
mod fs_store;
mod hash;
mod retrieve;
mod types;

pub use compression::{gzip_compress, gzip_decompress};
pub use error::{ArtifactError, Result};
pub use fs_store::FilesystemArtifactStore;
pub use hash::sha256_hex;
pub use retrieve::{get_artifact, RetrievalResult};
pub use types::{ArtifactMetadata, ArtifactRef};

/// Artifact store trait - stable interface for artifact storage backends.
pub trait ArtifactStore {
    /// Store content and return artifact reference.
    fn put_bytes(
        &self,
        tenant_id: &str,
        filename: &str,
        content_type: &str,
        content: &[u8],
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ArtifactRef>;

    /// Retrieve content by artifact URI.
    fn get_bytes(&self, artifact_uri: &str) -> Result<Vec<u8>>;

    /// Get metadata without retrieving content.
    fn head(&self, artifact_uri: &str) -> Result<ArtifactMetadata>;

    /// Delete artifact by URI.
    fn delete(&self, artifact_uri: &str) -> Result<()>;

    /// Remove expired artifacts. Returns count of deleted artifacts.
    fn garbage_collect_expired(&self, now: chrono::DateTime<chrono::Utc>) -> Result<usize>;
}
