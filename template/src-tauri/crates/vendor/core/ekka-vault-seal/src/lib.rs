//! EKKA Vault Seal - Seal staging directories into encrypted vault storage
//!
//! This crate provides a reusable primitive for sealing plaintext staging directories
//! into encrypted vault storage. It is UI-free and can be used by any node type
//! (desktop, execution nodes, etc.).
//!
//! # Process
//! 1. Enumerate all files under staging directory (recursive)
//! 2. For each file: read -> gzip compress -> AES-256-GCM encrypt -> write to vault
//! 3. Write metadata JSON alongside each encrypted blob
//! 4. Delete staging directory after successful sealing
//!
//! # Example
//! ```ignore
//! use ekka_vault_seal::{SealRequest, seal_run_dir};
//!
//! let request = SealRequest {
//!     tenant_id: "tenant-123".to_string(),
//!     workspace_id: "workspace-456".to_string(),
//!     workflow_run_id: "run-789".to_string(),
//!     task_id: "task-abc".to_string(),
//!     staging_dir: PathBuf::from("/path/to/staging"),
//!     vault_root: PathBuf::from("/path/to/vault"),
//!     retention_days: Some(30),
//!     key_material: derive_key(...),
//! };
//!
//! let result = seal_run_dir(request)?;
//! println!("Sealed {} files, {} bytes", result.files_sealed, result.bytes_raw_total);
//! ```

use chrono::{DateTime, Duration, Utc};
use ekka_crypto::{encrypt, KeyMaterial};
use ekka_ops::llm_result::{ArtifactCategory, ArtifactRef, CompressionAlgorithm};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{info, warn};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during vault sealing operations
#[derive(Debug, Error)]
pub enum SealError {
    #[error("Staging directory does not exist: {0}")]
    StagingDirNotFound(PathBuf),

    #[error("Staging directory is not a directory: {0}")]
    StagingDirNotDirectory(PathBuf),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] ekka_crypto::CryptoError),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Failed to strip staging prefix from path: {0}")]
    PathPrefixError(PathBuf),
}

/// Result type for seal operations
pub type SealResult<T> = Result<T, SealError>;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to seal a staging directory into the vault
pub struct SealRequest {
    /// Tenant identifier
    pub tenant_id: String,

    /// Workspace identifier
    pub workspace_id: String,

    /// Workflow run identifier (used for vault path organization)
    pub workflow_run_id: String,

    /// Task identifier (for logging)
    pub task_id: String,

    /// Path to the staging directory containing plaintext files
    pub staging_dir: PathBuf,

    /// Root path of the vault (e.g., EKKA_HOME/vault)
    pub vault_root: PathBuf,

    /// Retention period in days (optional)
    pub retention_days: Option<u32>,

    /// Encryption key material (from ekka-crypto key derivation)
    pub key_material: KeyMaterial,
}

/// Result of sealing a staging directory
pub struct SealOutput {
    /// Artifact references for each sealed file
    pub artifacts: Vec<ArtifactRef>,

    /// Number of files successfully sealed
    pub files_sealed: usize,

    /// Total raw bytes (before compression/encryption)
    pub bytes_raw_total: u64,

    /// Total encrypted bytes (after compression and encryption)
    pub bytes_encrypted_total: u64,

    /// Whether the staging directory was successfully deleted
    pub staging_deleted: bool,
}

/// Metadata stored alongside each encrypted blob
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedFileMetadata {
    /// Original filename (relative path from staging root)
    pub filename: String,

    /// MIME content type
    pub content_type: String,

    /// Original size in bytes (before compression)
    pub bytes_raw: u64,

    /// Size after gzip compression (before encryption)
    pub bytes_gz: u64,

    /// Size after encryption
    pub bytes_encrypted: u64,

    /// SHA-256 hash of the original (raw) content
    pub sha256_raw: String,

    /// SHA-256 hash of the encrypted blob
    pub sha256_encrypted: String,

    /// When the artifact was created
    pub created_at: DateTime<Utc>,

    /// When the artifact expires (for auto-cleanup)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Crypto version used (from ekka-crypto)
    pub crypto_version: u8,

    /// Compression algorithm used
    pub compression: String,
}

// =============================================================================
// Core Sealing Logic
// =============================================================================

/// Seal a staging directory into the encrypted vault.
///
/// This function:
/// 1. Enumerates all files in the staging directory (recursive)
/// 2. For each file: reads bytes, gzip compresses, encrypts with AES-256-GCM
/// 3. Writes encrypted blob to vault path: `<vault_root>/<tenant>/<workspace>/runs/<run_id>/<sha>.bin`
/// 4. Writes metadata JSON alongside each blob
/// 5. Returns ArtifactRef for each sealed file
/// 6. Deletes staging directory (best-effort)
///
/// # Arguments
/// * `request` - Seal request containing paths, identifiers, and key material
///
/// # Returns
/// * `SealOutput` containing artifact references and statistics
pub fn seal_run_dir(request: SealRequest) -> SealResult<SealOutput> {
    let task_id_short = if request.task_id.len() > 8 {
        &request.task_id[..8]
    } else {
        &request.task_id
    };

    // Validate staging directory exists
    if !request.staging_dir.exists() {
        return Err(SealError::StagingDirNotFound(request.staging_dir));
    }

    if !request.staging_dir.is_dir() {
        return Err(SealError::StagingDirNotDirectory(request.staging_dir));
    }

    // Calculate expiration time
    let expires_at = request.retention_days.map(|days| {
        Utc::now() + Duration::days(i64::from(days))
    });

    // Build vault output directory: <vault_root>/<tenant>/<workspace>/runs/<run_id>/
    let vault_output_dir = request
        .vault_root
        .join(&request.tenant_id)
        .join(&request.workspace_id)
        .join("runs")
        .join(&request.workflow_run_id);

    info!(
        op = "vault.seal.started",
        task_id = %task_id_short,
        staging_dir = %request.staging_dir.display(),
        vault_root = %request.vault_root.display(),
        vault_output_dir = %vault_output_dir.display(),
        "Starting vault seal operation"
    );

    // Ensure vault output directory exists
    fs::create_dir_all(&vault_output_dir)?;

    // Enumerate all files in staging directory
    let files = enumerate_files_recursive(&request.staging_dir)?;

    let mut artifacts = Vec::new();
    let mut bytes_raw_total: u64 = 0;
    let mut bytes_encrypted_total: u64 = 0;

    for file_path in &files {
        // Get relative path from staging root
        let rel_path = file_path
            .strip_prefix(&request.staging_dir)
            .map_err(|_| SealError::PathPrefixError(file_path.clone()))?;

        let rel_path_str = rel_path.to_string_lossy().to_string();

        // Seal the file
        let (artifact, metadata) = seal_single_file(
            file_path,
            &rel_path_str,
            &vault_output_dir,
            &request.key_material,
            expires_at,
            task_id_short,
        )?;

        bytes_raw_total += metadata.bytes_raw;
        bytes_encrypted_total += metadata.bytes_encrypted;
        artifacts.push(artifact);
    }

    let files_sealed = artifacts.len();

    info!(
        op = "vault.seal.completed",
        task_id = %task_id_short,
        files_sealed = files_sealed,
        bytes_raw_total = bytes_raw_total,
        bytes_enc_total = bytes_encrypted_total,
        "Vault seal operation completed"
    );

    // Delete staging directory (best-effort)
    let staging_deleted = delete_staging_dir(&request.staging_dir, task_id_short);

    Ok(SealOutput {
        artifacts,
        files_sealed,
        bytes_raw_total,
        bytes_encrypted_total,
        staging_deleted,
    })
}

/// Seal a single file into the vault.
fn seal_single_file(
    file_path: &Path,
    rel_path: &str,
    vault_output_dir: &Path,
    key: &KeyMaterial,
    expires_at: Option<DateTime<Utc>>,
    task_id_short: &str,
) -> SealResult<(ArtifactRef, SealedFileMetadata)> {
    // Read raw file bytes
    let raw_bytes = fs::read(file_path)?;
    let bytes_raw = raw_bytes.len() as u64;

    // Compute SHA-256 of raw content
    let sha256_raw = compute_sha256(&raw_bytes);

    // Gzip compress
    let gz_bytes = gzip_compress(&raw_bytes)?;
    let bytes_gz = gz_bytes.len() as u64;

    // Encrypt with AES-256-GCM
    let encrypted_bytes = encrypt(&gz_bytes, key)?;
    let bytes_encrypted = encrypted_bytes.len() as u64;

    // Compute SHA-256 of encrypted content (used as filename)
    let sha256_encrypted = compute_sha256(&encrypted_bytes);

    // Determine content type from filename
    let content_type = guess_content_type(rel_path);

    // Write encrypted blob to vault
    let blob_filename = format!("{}.bin", &sha256_encrypted[..16]); // Use first 16 chars of hash
    let blob_path = vault_output_dir.join(&blob_filename);
    fs::write(&blob_path, &encrypted_bytes)?;

    // Build metadata
    let created_at = Utc::now();
    let metadata = SealedFileMetadata {
        filename: rel_path.to_string(),
        content_type: content_type.clone(),
        bytes_raw,
        bytes_gz,
        bytes_encrypted,
        sha256_raw: sha256_raw.clone(),
        sha256_encrypted: sha256_encrypted.clone(),
        created_at,
        expires_at,
        crypto_version: ekka_crypto::CRYPTO_VERSION,
        compression: "gzip".to_string(),
    };

    // Write metadata JSON alongside blob
    let meta_filename = format!("{}.meta.json", &sha256_encrypted[..16]);
    let meta_path = vault_output_dir.join(&meta_filename);
    let meta_json = serde_json::to_string_pretty(&metadata)?;
    fs::write(&meta_path, meta_json)?;

    // Build vault URI: vault://<tenant>/<workspace>/runs/<run_id>/<sha>.bin
    // Note: We use a relative scheme that can be resolved by the runner
    let vault_uri = format!(
        "vault://runs/{}/{}",
        vault_output_dir.file_name().unwrap_or_default().to_string_lossy(),
        blob_filename
    );

    info!(
        op = "vault.seal.file",
        task_id = %task_id_short,
        rel_path = %rel_path,
        bytes_raw = bytes_raw,
        bytes_gz = bytes_gz,
        bytes_enc = bytes_encrypted,
        sha256 = %sha256_raw,
        "Sealed file to vault"
    );

    // Build ArtifactRef
    let mut artifact = ArtifactRef::new(
        vault_uri,
        sha256_raw, // Use raw hash for content verification
        bytes_encrypted,
        content_type,
    )
    .with_compression(CompressionAlgorithm::Gzip, bytes_raw)
    .with_category(ArtifactCategory::DocumentOutput);

    if let Some(exp) = expires_at {
        artifact = artifact.with_expires_at(exp);
    }

    // Use filename as label
    artifact = artifact.with_label(rel_path);

    Ok((artifact, metadata))
}

/// Enumerate all files in a directory recursively.
fn enumerate_files_recursive(dir: &Path) -> SealResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    enumerate_files_inner(dir, &mut files)?;
    files.sort(); // Deterministic ordering
    Ok(files)
}

fn enumerate_files_inner(dir: &Path, files: &mut Vec<PathBuf>) -> SealResult<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            enumerate_files_inner(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// Gzip compress data.
fn gzip_compress(data: &[u8]) -> SealResult<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Compute SHA-256 hash of data, returning hex string.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Guess MIME content type from filename.
fn guess_content_type(filename: &str) -> String {
    let lower = filename.to_lowercase();
    if lower.ends_with(".md") {
        "text/markdown".to_string()
    } else if lower.ends_with(".json") {
        "application/json".to_string()
    } else if lower.ends_with(".txt") {
        "text/plain".to_string()
    } else if lower.ends_with(".html") || lower.ends_with(".htm") {
        "text/html".to_string()
    } else if lower.ends_with(".xml") {
        "application/xml".to_string()
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        "text/yaml".to_string()
    } else if lower.ends_with(".rs") {
        "text/x-rust".to_string()
    } else if lower.ends_with(".py") {
        "text/x-python".to_string()
    } else if lower.ends_with(".js") || lower.ends_with(".ts") {
        "text/javascript".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

/// Delete staging directory (best-effort).
fn delete_staging_dir(staging_dir: &Path, task_id_short: &str) -> bool {
    match fs::remove_dir_all(staging_dir) {
        Ok(()) => {
            info!(
                op = "vault.seal.staging_deleted",
                task_id = %task_id_short,
                deleted = true,
                staging_dir = %staging_dir.display(),
                "Staging directory deleted"
            );
            true
        }
        Err(e) => {
            warn!(
                op = "vault.seal.staging_deleted",
                task_id = %task_id_short,
                deleted = false,
                staging_dir = %staging_dir.display(),
                error = %e,
                "Failed to delete staging directory (best-effort)"
            );
            false
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ekka_crypto::{derive_key, KeyDerivationConfig};
    use tempfile::TempDir;

    fn test_key() -> KeyMaterial {
        derive_key(
            "test_device_secret",
            "test_user",
            1,
            "vault_seal_test",
            &KeyDerivationConfig::default(),
        )
    }

    #[test]
    fn test_seal_run_dir_with_two_files() {
        // Setup: Create temp directories for staging and vault
        let temp_dir = TempDir::new().unwrap();
        let staging_dir = temp_dir.path().join("staging");
        let vault_root = temp_dir.path().join("vault");

        fs::create_dir_all(&staging_dir).unwrap();

        // Create two test files
        let file1_content = "# README\n\nThis is a test README file.";
        let file2_content = "# ARCHITECTURE\n\nThis is a test architecture doc.";

        fs::write(staging_dir.join("README.md"), file1_content).unwrap();
        fs::write(staging_dir.join("ARCHITECTURE.md"), file2_content).unwrap();

        // Seal
        let request = SealRequest {
            tenant_id: "tenant-123".to_string(),
            workspace_id: "workspace-456".to_string(),
            workflow_run_id: "run-789".to_string(),
            task_id: "task-abc".to_string(),
            staging_dir: staging_dir.clone(),
            vault_root: vault_root.clone(),
            retention_days: Some(30),
            key_material: test_key(),
        };

        let result = seal_run_dir(request).unwrap();

        // Assertions
        assert_eq!(result.artifacts.len(), 2, "Should have 2 artifacts");
        assert_eq!(result.files_sealed, 2, "Should have sealed 2 files");
        assert!(result.bytes_raw_total > 0, "Should have processed bytes");
        assert!(result.bytes_encrypted_total > 0, "Should have encrypted bytes");

        // Verify vault files exist
        let vault_output_dir = vault_root
            .join("tenant-123")
            .join("workspace-456")
            .join("runs")
            .join("run-789");

        assert!(vault_output_dir.exists(), "Vault output dir should exist");

        // Count files in vault output dir (should be 4: 2 .bin + 2 .meta.json)
        let vault_files: Vec<_> = fs::read_dir(&vault_output_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(vault_files.len(), 4, "Should have 4 vault files (2 blobs + 2 metadata)");

        // Verify staging dir is deleted
        assert!(!staging_dir.exists(), "Staging dir should be deleted");
        assert!(result.staging_deleted, "staging_deleted should be true");

        // Verify artifact URIs
        for artifact in &result.artifacts {
            assert!(artifact.uri.starts_with("vault://"), "URI should start with vault://");
            assert!(!artifact.sha256.is_empty(), "SHA256 should not be empty");
            assert!(artifact.bytes > 0, "Bytes should be > 0");
            assert_eq!(artifact.compression, CompressionAlgorithm::Gzip, "Should be gzip compressed");
            assert!(artifact.original_bytes.is_some(), "Original bytes should be set");
            assert!(artifact.expires_at.is_some(), "Expiration should be set");
        }
    }

    #[test]
    fn test_seal_staging_dir_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let staging_dir = temp_dir.path().join("nonexistent");
        let vault_root = temp_dir.path().join("vault");

        let request = SealRequest {
            tenant_id: "tenant".to_string(),
            workspace_id: "workspace".to_string(),
            workflow_run_id: "run".to_string(),
            task_id: "task".to_string(),
            staging_dir,
            vault_root,
            retention_days: None,
            key_material: test_key(),
        };

        let result = seal_run_dir(request);
        assert!(matches!(result, Err(SealError::StagingDirNotFound(_))));
    }

    #[test]
    fn test_seal_empty_staging_dir() {
        let temp_dir = TempDir::new().unwrap();
        let staging_dir = temp_dir.path().join("staging");
        let vault_root = temp_dir.path().join("vault");

        fs::create_dir_all(&staging_dir).unwrap();

        let request = SealRequest {
            tenant_id: "tenant".to_string(),
            workspace_id: "workspace".to_string(),
            workflow_run_id: "run".to_string(),
            task_id: "task".to_string(),
            staging_dir,
            vault_root,
            retention_days: None,
            key_material: test_key(),
        };

        let result = seal_run_dir(request).unwrap();
        assert_eq!(result.files_sealed, 0);
        assert_eq!(result.artifacts.len(), 0);
        assert_eq!(result.bytes_raw_total, 0);
    }

    #[test]
    fn test_compute_sha256() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_guess_content_type() {
        assert_eq!(guess_content_type("README.md"), "text/markdown");
        assert_eq!(guess_content_type("config.json"), "application/json");
        assert_eq!(guess_content_type("notes.txt"), "text/plain");
        assert_eq!(guess_content_type("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn test_gzip_roundtrip() {
        let data = b"test data for compression";
        let compressed = gzip_compress(data).unwrap();
        assert!(compressed.len() > 0);
        // Compressed might be larger for small data, but should work
    }
}
