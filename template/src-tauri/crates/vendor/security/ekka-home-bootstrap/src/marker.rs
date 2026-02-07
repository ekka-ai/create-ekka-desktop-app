//! Marker File Management
//!
//! Handles the JSON marker file that tracks home directory ownership,
//! security epochs, and device fingerprints. The marker file contains
//! NO secrets - only metadata for validation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{info, debug};
use uuid::Uuid;

use crate::{BootstrapConfig, BootstrapError, compute_device_fingerprint};

// =============================================================================
// Marker Data Structure
// =============================================================================

/// Marker file data structure - stored as JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkerData {
    /// Schema version for future migrations
    pub schema_version: String,
    /// Application name (e.g., "ekka-node-desktop")
    pub app_name: String,
    /// Unique instance identifier (UUID v4) - auto-generated for this installation
    pub instance_id: Uuid,
    /// Device hardware fingerprint (no secrets)
    pub device_id_fingerprint: String,
    /// When marker was first created
    pub created_at: DateTime<Utc>,
    /// Last time marker was updated
    pub last_seen_at: DateTime<Utc>,
    /// Last security epoch seen (for remote wipe)
    pub epoch_seen: u32,
    /// Storage layout version (for migrations)
    pub storage_layout_version: String,
}

impl MarkerData {
    /// Create new marker with current timestamp
    pub fn new(config: &BootstrapConfig) -> Self {
        let now = Utc::now();
        Self {
            schema_version: "1.0".to_string(),
            app_name: config.app_name.clone(),
            instance_id: Uuid::new_v4(),
            device_id_fingerprint: compute_device_fingerprint(),
            created_at: now,
            last_seen_at: now,
            epoch_seen: 1, // Default epoch
            storage_layout_version: config.storage_layout_version.clone(),
        }
    }

    /// Update last_seen_at to current time
    pub fn update_last_seen(&mut self) {
        self.last_seen_at = Utc::now();
    }

    /// Validate marker integrity
    pub fn validate(&self) -> Result<(), BootstrapError> {
        if self.schema_version.is_empty() {
            return Err(BootstrapError::Security("Invalid schema_version".to_string()));
        }

        if self.app_name.is_empty() {
            return Err(BootstrapError::Security("Invalid app_name".to_string()));
        }

        if self.instance_id.is_nil() {
            return Err(BootstrapError::Security("Invalid instance_id".to_string()));
        }

        if !self.device_id_fingerprint.starts_with("sha256:") {
            return Err(BootstrapError::Security("Invalid device fingerprint format".to_string()));
        }

        if self.epoch_seen == 0 {
            return Err(BootstrapError::Security("Invalid epoch_seen (must be >= 1)".to_string()));
        }

        Ok(())
    }

    /// Check if marker is stale (last_seen > threshold)
    pub fn is_stale(&self, threshold_days: u32) -> bool {
        let threshold = chrono::Duration::days(threshold_days as i64);
        let now = Utc::now();
        now.signed_duration_since(self.last_seen_at) > threshold
    }
}

// =============================================================================
// MarkerFile - File Operations
// =============================================================================

/// Marker file operations
pub struct MarkerFile;

impl MarkerFile {
    /// Load marker from file, or create new if not exists
    pub fn load_or_create(path: &Path, config: &BootstrapConfig) -> Result<MarkerData, BootstrapError> {
        if path.exists() {
            Self::load(path)
        } else {
            let marker = MarkerData::new(config);
            Self::save(&marker, path)?;
            Ok(marker)
        }
    }

    /// Load marker from existing file
    pub fn load(path: &Path) -> Result<MarkerData, BootstrapError> {
        debug!(
            op = "marker.load",
            path = %path.display(),
            "Loading marker file"
        );

        let content = fs::read_to_string(path)
            .map_err(|e| BootstrapError::Io(e))?;

        let marker: MarkerData = serde_json::from_str(&content)?;
        marker.validate()?;

        info!(
            op = "marker.loaded",
            instance_id = %marker.instance_id,
            epoch_seen = marker.epoch_seen,
            fingerprint = %marker.device_id_fingerprint[..16], // First 16 chars
            "Marker file loaded successfully"
        );

        Ok(marker)
    }

    /// Save marker to file
    pub fn save(marker: &MarkerData, path: &Path) -> Result<(), BootstrapError> {
        marker.validate()?;

        let content = serde_json::to_string_pretty(marker)?;
        fs::write(path, content)?;

        // Set secure permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        debug!(
            op = "marker.saved",
            path = %path.display(),
            instance_id = %marker.instance_id,
            epoch = marker.epoch_seen,
            "Marker file saved"
        );

        Ok(())
    }
}

impl MarkerData {
    /// Convenience method to save to path
    pub fn save(&self, path: &Path) -> Result<(), BootstrapError> {
        MarkerFile::save(self, path)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootstrapConfig, HomeStrategy, EpochSource};
    use tempfile::NamedTempFile;

    #[test]
    fn test_marker_creation() {
        let config = BootstrapConfig {
            app_name: "test-app".to_string(),
            default_folder_name: ".test-app".to_string(),
            home_strategy: HomeStrategy::Fixed(std::path::PathBuf::from("/tmp")),
            marker_filename: ".test-marker.json".to_string(),
            keychain_service: "test.service".to_string(),
            subdirs: vec!["vault".to_string()],
            epoch_source: EpochSource::Fixed(1),
            storage_layout_version: "v1".to_string(),
        };
        let marker = MarkerData::new(&config);

        assert_eq!(marker.schema_version, "1.0");
        assert_eq!(marker.app_name, "test-app");
        assert!(!marker.instance_id.is_nil());
        assert!(marker.device_id_fingerprint.starts_with("sha256:"));
        assert_eq!(marker.epoch_seen, 1);
        assert!(marker.validate().is_ok());
    }

    #[test]
    fn test_marker_roundtrip() {
        let config = BootstrapConfig {
            app_name: "test-app".to_string(),
            default_folder_name: ".test-app".to_string(),
            home_strategy: HomeStrategy::Fixed(std::path::PathBuf::from("/tmp")),
            marker_filename: ".test-marker.json".to_string(),
            keychain_service: "test.service".to_string(),
            subdirs: vec!["vault".to_string()],
            epoch_source: EpochSource::Fixed(1),
            storage_layout_version: "v1".to_string(),
        };
        let original = MarkerData::new(&config);

        let temp_file = NamedTempFile::new().unwrap();
        original.save(temp_file.path()).unwrap();

        let loaded = MarkerFile::load(temp_file.path()).unwrap();

        assert_eq!(original.instance_id, loaded.instance_id);
        assert_eq!(original.device_id_fingerprint, loaded.device_id_fingerprint);
        assert_eq!(original.epoch_seen, loaded.epoch_seen);
        assert_eq!(original.app_name, loaded.app_name);
    }

    #[test]
    fn test_marker_validation() {
        let config = BootstrapConfig {
            app_name: "test-app".to_string(),
            default_folder_name: ".test-app".to_string(),
            home_strategy: HomeStrategy::Fixed(std::path::PathBuf::from("/tmp")),
            marker_filename: ".test-marker.json".to_string(),
            keychain_service: "test.service".to_string(),
            subdirs: vec!["vault".to_string()],
            epoch_source: EpochSource::Fixed(1),
            storage_layout_version: "v1".to_string(),
        };
        let mut marker = MarkerData::new(&config);

        // Valid marker should pass
        assert!(marker.validate().is_ok());

        // Invalid schema version
        marker.schema_version = "".to_string();
        assert!(marker.validate().is_err());

        // Invalid epoch
        marker = MarkerData::new(&config);
        marker.epoch_seen = 0;
        assert!(marker.validate().is_err());
    }

    #[test]
    fn test_staleness_check() {
        let config = BootstrapConfig {
            app_name: "test-app".to_string(),
            default_folder_name: ".test-app".to_string(),
            home_strategy: HomeStrategy::Fixed(std::path::PathBuf::from("/tmp")),
            marker_filename: ".test-marker.json".to_string(),
            keychain_service: "test.service".to_string(),
            subdirs: vec!["vault".to_string()],
            epoch_source: EpochSource::Fixed(1),
            storage_layout_version: "v1".to_string(),
        };
        let mut marker = MarkerData::new(&config);

        // Fresh marker should not be stale
        assert!(!marker.is_stale(30));

        // Old marker should be stale
        marker.last_seen_at = Utc::now() - chrono::Duration::days(31);
        assert!(marker.is_stale(30));
    }
}