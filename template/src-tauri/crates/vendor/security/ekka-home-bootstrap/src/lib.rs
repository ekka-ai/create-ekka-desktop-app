//! EKKA Home Bootstrap - RAPTOR-1 Foundation
//!
//! Manages device-bound home directory initialization with marker files and security epoch
//! remote wipe capabilities. Everything is configurable for enterprise deployments.
//!
//! ## Core Components
//!
//! - **HomeBootstrap**: Resolves EKKA_HOME, creates folder tree, ensures permissions
//! - **MarkerFile**: JSON file with schema_version, instance_id, device fingerprint, epoch tracking
//! - **SecurityEpochManager**: Fetches current epoch, performs local wipe on mismatch
//!
//! ## Security Properties
//!
//! - Marker file contains NO secrets, only metadata for validation
//! - Epoch change invalidates all encrypted data through key derivation
//! - Local wipe is deterministic: deletes encrypted DB + vault + caches
//! - Directory permissions are set to 0700 (owner-only) on Unix
//!
//! ## Configuration
//!
//! All paths, filenames, service names, and sources are configurable via `BootstrapConfig`.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub mod marker;
pub mod epoch;
pub mod wipe;
pub mod work_home;

// Re-export key types for convenience
pub use marker::{MarkerFile, MarkerData};
pub use epoch::SecurityEpochManager;
pub use work_home::{WorkHomeManager, WorkHomeConfig, WorkHomeMode, WorkspaceRecord, WorkspaceStatus};

// =============================================================================
// Core Bootstrap Types
// =============================================================================

/// Bootstrap configuration with full configurability
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Application name (used in paths and services)
    pub app_name: String,
    /// Default folder name when using OS home strategy
    pub default_folder_name: String,
    /// Home directory resolution strategy
    pub home_strategy: HomeStrategy,
    /// Marker filename (e.g., ".ekka-marker.json")
    pub marker_filename: String,
    /// Service name for keychain (e.g., "com.ekka.node-desktop")
    pub keychain_service: String,
    /// Subdirectories to create in home
    pub subdirs: Vec<String>,
    /// Source for security epoch
    pub epoch_source: EpochSource,
    /// Storage layout version (for future migrations)
    pub storage_layout_version: String,
}

/// Home directory resolution strategy
#[derive(Debug, Clone)]
pub enum HomeStrategy {
    /// Use environment variable, fallback to OS home + default folder
    DataHome { env_var: String },
    /// Use fixed path
    Fixed(PathBuf),
}

/// Epoch source configuration
#[derive(Debug, Clone)]
pub enum EpochSource {
    /// Environment variable (for dev/demo)
    EnvVar(String),
    /// HTTP endpoint (for production)
    #[cfg(feature = "http-epoch")]
    Http { url: String, timeout_secs: u64 },
    /// Fixed value (for testing)
    Fixed(u32),
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            app_name: "ekka-node-desktop".to_string(),
            default_folder_name: ".ekka-node".to_string(),
            home_strategy: HomeStrategy::DataHome {
                env_var: "EKKA_DATA_HOME".to_string(),
            },
            marker_filename: ".ekka-marker.json".to_string(),
            keychain_service: "com.ekka.node-desktop".to_string(),
            subdirs: vec!["vault".to_string(), "db".to_string(), "tmp".to_string()],
            epoch_source: EpochSource::EnvVar("EKKA_SECURITY_EPOCH".to_string()),
            storage_layout_version: "v1".to_string(),
        }
    }
}

// =============================================================================
// Bootstrap Errors
// =============================================================================

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Home directory not found: {0}")]
    HomeNotFound(String),
    #[error("Epoch fetch failed: {0}")]
    EpochFetch(String),
    #[error("Security validation failed: {0}")]
    Security(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

// =============================================================================
// HomeBootstrap - Main Entry Point
// =============================================================================

/// Main bootstrap manager - handles home initialization and validation
pub struct HomeBootstrap {
    config: BootstrapConfig,
    home_path: PathBuf,
    work_home_manager: Option<WorkHomeManager>,
}

impl HomeBootstrap {
    /// Create new bootstrap manager with configuration
    pub fn new(config: BootstrapConfig) -> Result<Self, BootstrapError> {
        let home_path = Self::resolve_home_path(&config.home_strategy, &config)?;

        // Initialize work home manager if enabled
        let work_home_config = WorkHomeConfig::default();
        let work_home_manager = if work_home_config.mode != WorkHomeMode::Disabled {
            Some(WorkHomeManager::new(work_home_config))
        } else {
            None
        };

        Ok(Self { config, home_path, work_home_manager })
    }

    /// Initialize or validate existing home directory
    pub fn initialize(&self) -> Result<MarkerData, BootstrapError> {
        info!(
            op = "home.bootstrap.init",
            home = %self.home_path.display(),
            "Initializing EKKA home directory"
        );

        // Create home directory with secure permissions
        self.ensure_home_exists()?;

        // Load or create marker file
        let marker_path = self.home_path.join(&self.config.marker_filename);
        let mut marker = MarkerFile::load_or_create(&marker_path, &self.config)?;

        // Ensure subdirectories exist
        self.create_subdirectories()?;

        // Update last_seen_at
        marker.update_last_seen();
        marker.save(&marker_path)?;

        info!(
            op = "home.bootstrap.complete",
            instance_id = %marker.instance_id,
            epoch_seen = marker.epoch_seen,
            "Home directory bootstrap complete"
        );

        Ok(marker)
    }

    /// Perform security epoch check and wipe if needed
    pub fn check_security_epoch(&mut self, marker: &mut MarkerData) -> Result<bool, BootstrapError> {
        let epoch_manager = SecurityEpochManager::new(&self.config.epoch_source);
        let current_epoch = epoch_manager.fetch_current_epoch()?;

        if marker.epoch_seen != current_epoch {
            warn!(
                op = "security.epoch_mismatch",
                epoch_seen = marker.epoch_seen,
                epoch_current = current_epoch,
                "Security epoch mismatch detected - performing local wipe"
            );

            // ALWAYS WIPE DATA HOME
            wipe::perform_local_wipe(&self.home_path, &self.config)?;

            // Handle WORK HOME based on policy
            if let Some(work_manager) = &mut self.work_home_manager {
                // Check if delete policy is enabled (default: quarantine only)
                let delete_policy = std::env::var("EKKA_WORK_HOME_DELETE_ON_EPOCH")
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false);

                let affected_workspaces = work_manager.handle_epoch_mismatch(current_epoch, delete_policy)?;
                if !affected_workspaces.is_empty() {
                    warn!(
                        op = "security.work_homes_affected",
                        count = affected_workspaces.len(),
                        delete_policy = delete_policy,
                        "Work homes affected by epoch mismatch"
                    );
                }
            }

            // Update marker with new epoch
            marker.epoch_seen = current_epoch;
            marker.update_last_seen();

            let marker_path = self.home_path.join(&self.config.marker_filename);
            marker.save(&marker_path)?;

            info!(
                op = "security.wipe_complete",
                epoch_new = current_epoch,
                "Local wipe completed, epoch updated"
            );

            return Ok(true); // Wipe occurred
        }

        Ok(false) // No wipe needed
    }

    /// Get work home manager (if enabled)
    pub fn work_home_manager(&self) -> Option<&WorkHomeManager> {
        self.work_home_manager.as_ref()
    }

    /// Get mutable work home manager (if enabled)
    pub fn work_home_manager_mut(&mut self) -> Option<&mut WorkHomeManager> {
        self.work_home_manager.as_mut()
    }

    /// Get home directory path
    pub fn home_path(&self) -> &Path {
        &self.home_path
    }

    /// Get configuration
    pub fn config(&self) -> &BootstrapConfig {
        &self.config
    }

    // =============================================================================
    // Private Implementation
    // =============================================================================

    fn resolve_home_path(strategy: &HomeStrategy, config: &BootstrapConfig) -> Result<PathBuf, BootstrapError> {
        match strategy {
            HomeStrategy::DataHome { env_var } => {
                if let Ok(env_path) = std::env::var(env_var) {
                    if !env_path.is_empty() {
                        return Ok(PathBuf::from(env_path));
                    }
                }
                // Fallback to OS home + default folder name
                dirs::home_dir()
                    .map(|h| h.join(&config.default_folder_name))
                    .ok_or_else(|| BootstrapError::HomeNotFound("OS home directory not found".to_string()))
            }
            HomeStrategy::Fixed(path) => Ok(path.clone()),
        }
    }

    fn ensure_home_exists(&self) -> Result<(), BootstrapError> {
        if !self.home_path.exists() {
            info!(
                op = "home.create",
                path = %self.home_path.display(),
                "Creating home directory"
            );

            fs::create_dir_all(&self.home_path)?;
            self.set_secure_permissions(&self.home_path)?;
        }

        Ok(())
    }

    fn create_subdirectories(&self) -> Result<(), BootstrapError> {
        for subdir in &self.config.subdirs {
            let subdir_path = self.home_path.join(subdir);
            if !subdir_path.exists() {
                fs::create_dir_all(&subdir_path)?;
                self.set_secure_permissions(&subdir_path)?;
            }
        }
        Ok(())
    }

    fn set_secure_permissions(&self, path: &Path) -> Result<(), BootstrapError> {
        #[cfg(unix)]
        {
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
}

/// Compute device fingerprint from hardware/OS characteristics
pub fn compute_device_fingerprint() -> String {
    let mut hasher = Sha256::new();

    // Include hostname if available
    if let Ok(hostname) = hostname::get() {
        hasher.update(hostname.as_encoded_bytes());
    }

    // Include OS info
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(std::env::consts::ARCH.as_bytes());

    // Include username if available
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        hasher.update(user.as_bytes());
    }

    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(&result[..8])) // First 8 bytes = 16 hex chars
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_bootstrap_creates_home_and_marker() {
        let temp_dir = TempDir::new().unwrap();
        let config = BootstrapConfig {
            app_name: "test-app".to_string(),
            default_folder_name: ".test-app".to_string(),
            home_strategy: HomeStrategy::Fixed(temp_dir.path().to_path_buf()),
            marker_filename: ".ekka-marker.json".to_string(),
            keychain_service: "test.service".to_string(),
            subdirs: vec!["vault".to_string(), "db".to_string(), "tmp".to_string()],
            epoch_source: EpochSource::Fixed(1),
            storage_layout_version: "v1".to_string(),
        };

        let bootstrap = HomeBootstrap::new(config).unwrap();
        let marker = bootstrap.initialize().unwrap();

        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().join(".ekka-marker.json").exists());
        assert!(!marker.instance_id.is_nil());
        assert_eq!(marker.app_name, "test-app");
    }

    #[test]
    fn test_device_fingerprint_consistent() {
        let fp1 = compute_device_fingerprint();
        let fp2 = compute_device_fingerprint();
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("sha256:"));
    }
}