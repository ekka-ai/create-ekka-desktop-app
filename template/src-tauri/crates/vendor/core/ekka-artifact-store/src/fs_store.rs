//! Filesystem artifact store implementation

use crate::compression::{gzip_compress, gzip_decompress, should_compress};
use crate::error::{ArtifactError, Result};
use crate::hash::sha256_hex;
use crate::types::{ArtifactMetadata, ArtifactRef};
use crate::ArtifactStore;
use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

const URI_SCHEME: &str = "ekka://artifacts";
const METADATA_SUFFIX: &str = ".meta.json";

/// Filesystem-backed artifact store.
pub struct FilesystemArtifactStore {
    root: PathBuf,
}

impl FilesystemArtifactStore {
    /// Create store with given root directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Build artifact directory path: <root>/<tenant>/<prefix>/<sha256>/
    fn artifact_dir(&self, tenant_id: &str, sha256: &str) -> PathBuf {
        let prefix = &sha256[..4]; // First 2 bytes = 4 hex chars
        self.root.join(tenant_id).join(prefix).join(sha256)
    }

    /// Build artifact URI.
    fn build_uri(tenant_id: &str, sha256: &str, filename: &str) -> String {
        let prefix = &sha256[..4];
        format!("{URI_SCHEME}/{tenant_id}/{prefix}/{sha256}/{filename}")
    }

    /// Parse artifact URI into (tenant_id, sha256, filename).
    fn parse_uri(uri: &str) -> Result<(String, String, String)> {
        let stripped = uri
            .strip_prefix(&format!("{URI_SCHEME}/"))
            .ok_or_else(|| ArtifactError::InvalidUri(uri.to_string()))?;

        let parts: Vec<&str> = stripped.splitn(4, '/').collect();
        if parts.len() != 4 {
            return Err(ArtifactError::InvalidUri(uri.to_string()));
        }

        Ok((
            parts[0].to_string(), // tenant_id
            parts[2].to_string(), // sha256 (skip prefix)
            parts[3].to_string(), // filename
        ))
    }

    fn blob_path(&self, tenant_id: &str, sha256: &str) -> PathBuf {
        self.artifact_dir(tenant_id, sha256).join("blob")
    }

    fn meta_path(&self, tenant_id: &str, sha256: &str) -> PathBuf {
        self.artifact_dir(tenant_id, sha256).join(format!("blob{METADATA_SUFFIX}"))
    }
}

impl ArtifactStore for FilesystemArtifactStore {
    fn put_bytes(
        &self,
        tenant_id: &str,
        filename: &str,
        content_type: &str,
        content: &[u8],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ArtifactRef> {
        let sha256 = sha256_hex(content);
        let dir = self.artifact_dir(tenant_id, &sha256);

        // Check if already exists (dedup)
        if dir.exists() {
            let meta = self.head(&Self::build_uri(tenant_id, &sha256, filename))?;
            info!(op = "artifact.put.dedup", sha256 = %sha256, "Artifact already exists");
            return Ok(ArtifactRef {
                uri: Self::build_uri(tenant_id, &sha256, filename),
                sha256,
                bytes_raw: meta.bytes_raw,
                bytes_stored: meta.bytes_stored,
                expires_at: meta.expires_at,
            });
        }

        // Compress if applicable
        let compress = should_compress(content_type);
        let stored_content = if compress {
            gzip_compress(content)?
        } else {
            content.to_vec()
        };

        // Create directory and write files
        fs::create_dir_all(&dir)?;
        fs::write(self.blob_path(tenant_id, &sha256), &stored_content)?;

        let metadata = ArtifactMetadata {
            sha256: sha256.clone(),
            bytes_raw: content.len(),
            bytes_stored: stored_content.len(),
            content_type: content_type.to_string(),
            compressed: compress,
            created_at: Utc::now(),
            expires_at,
            tenant_id: tenant_id.to_string(),
            filename: filename.to_string(),
        };
        fs::write(self.meta_path(tenant_id, &sha256), serde_json::to_string_pretty(&metadata)?)?;

        info!(op = "artifact.put.ok", sha256 = %sha256, bytes_raw = content.len(), compressed = compress);

        Ok(ArtifactRef {
            uri: Self::build_uri(tenant_id, &sha256, filename),
            sha256,
            bytes_raw: content.len(),
            bytes_stored: stored_content.len(),
            expires_at,
        })
    }

    fn get_bytes(&self, artifact_uri: &str) -> Result<Vec<u8>> {
        let (tenant_id, sha256, _) = Self::parse_uri(artifact_uri)?;
        let blob_path = self.blob_path(&tenant_id, &sha256);

        if !blob_path.exists() {
            return Err(ArtifactError::NotFound(artifact_uri.to_string()));
        }

        let meta = self.head(artifact_uri)?;
        let stored = fs::read(&blob_path)?;

        if meta.compressed {
            gzip_decompress(&stored)
        } else {
            Ok(stored)
        }
    }

    fn head(&self, artifact_uri: &str) -> Result<ArtifactMetadata> {
        let (tenant_id, sha256, _) = Self::parse_uri(artifact_uri)?;
        let meta_path = self.meta_path(&tenant_id, &sha256);

        if !meta_path.exists() {
            return Err(ArtifactError::NotFound(artifact_uri.to_string()));
        }

        let meta_json = fs::read_to_string(&meta_path)?;
        Ok(serde_json::from_str(&meta_json)?)
    }

    fn delete(&self, artifact_uri: &str) -> Result<()> {
        let (tenant_id, sha256, _) = Self::parse_uri(artifact_uri)?;
        let dir = self.artifact_dir(&tenant_id, &sha256);

        if dir.exists() {
            fs::remove_dir_all(&dir)?;
            info!(op = "artifact.delete.ok", sha256 = %sha256);
        }
        Ok(())
    }

    fn garbage_collect_expired(&self, now: DateTime<Utc>) -> Result<usize> {
        let mut deleted = 0;
        collect_expired_recursive(&self.root, now, &mut deleted)?;
        if deleted > 0 {
            info!(op = "artifact.gc.ok", deleted = deleted);
        }
        Ok(deleted)
    }
}

/// Recursively find and delete expired artifacts.
fn collect_expired_recursive(dir: &Path, now: DateTime<Utc>, deleted: &mut usize) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            collect_expired_recursive(&path, now, deleted)?;
            // Try to remove empty dirs
            let _ = fs::remove_dir(&path);
        } else if path.extension().is_some_and(|e| e == "json") {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(meta) = serde_json::from_str::<ArtifactMetadata>(&content) {
                    if let Some(expires) = meta.expires_at {
                        if expires < now {
                            if let Some(parent) = path.parent() {
                                let _ = fs::remove_dir_all(parent);
                                *deleted += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_put_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = FilesystemArtifactStore::new(tmp.path());

        // Use larger content so compression is effective
        let content = br#"{"key": "value", "data": "some longer content that compresses well when repeated multiple times in a row"}"#;
        let artifact = store
            .put_bytes("tenant-1", "data.json", "application/json", content, None)
            .unwrap();

        assert!(artifact.uri.starts_with("ekka://artifacts/tenant-1/"));
        assert_eq!(artifact.bytes_raw, content.len());

        let retrieved = store.get_bytes(&artifact.uri).unwrap();
        assert_eq!(content.to_vec(), retrieved);
    }

    #[test]
    fn test_dedup() {
        let tmp = TempDir::new().unwrap();
        let store = FilesystemArtifactStore::new(tmp.path());

        let content = b"duplicate content";
        let a1 = store.put_bytes("t1", "f1.txt", "text/plain", content, None).unwrap();
        let a2 = store.put_bytes("t1", "f2.txt", "text/plain", content, None).unwrap();

        assert_eq!(a1.sha256, a2.sha256);
    }

    #[test]
    fn test_parse_uri() {
        let (t, s, f) = FilesystemArtifactStore::parse_uri(
            "ekka://artifacts/tenant-1/abcd/abcdef1234567890/file.json",
        )
        .unwrap();
        assert_eq!(t, "tenant-1");
        assert_eq!(s, "abcdef1234567890");
        assert_eq!(f, "file.json");
    }
}
