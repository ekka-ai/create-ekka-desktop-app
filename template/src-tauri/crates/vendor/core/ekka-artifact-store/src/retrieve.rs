//! Artifact retrieval with deterministic logging

use crate::error::Result;
use crate::types::ArtifactMetadata;
use crate::ArtifactStore;
use tracing::{error, info};

/// Retrieval result containing both metadata and content.
pub struct RetrievalResult {
    pub metadata: ArtifactMetadata,
    pub content: Vec<u8>,
}

/// Retrieve artifact with deterministic logging.
///
/// Logs:
/// - `artifact.get.started` when retrieval begins
/// - `artifact.get.success` on success with sha256, bytes
/// - `artifact.get.failed` on failure with error
pub fn get_artifact<S: ArtifactStore>(store: &S, uri: &str) -> Result<RetrievalResult> {
    info!(op = "artifact.get.started", uri = %uri, "Retrieving artifact");

    // Get metadata first
    let metadata = match store.head(uri) {
        Ok(m) => m,
        Err(e) => {
            error!(op = "artifact.get.failed", uri = %uri, error = %e, "Head failed");
            return Err(e);
        }
    };

    // Get content (auto-decompresses)
    let content = match store.get_bytes(uri) {
        Ok(c) => c,
        Err(e) => {
            error!(op = "artifact.get.failed", uri = %uri, error = %e, "Get failed");
            return Err(e);
        }
    };

    info!(
        op = "artifact.get.success",
        uri = %uri,
        sha256 = %metadata.sha256,
        bytes_raw = metadata.bytes_raw,
        bytes_stored = metadata.bytes_stored,
        compressed = metadata.compressed,
        "Artifact retrieved"
    );

    Ok(RetrievalResult { metadata, content })
}
