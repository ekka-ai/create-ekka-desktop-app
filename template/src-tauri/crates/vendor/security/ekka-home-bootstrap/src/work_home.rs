//! Work Home Management
//!
//! Manages user workspace directories outside the DATA_HOME for project files.
//! Provides secure, capability-gated access to user-chosen directories with
//! proper validation and quarantine capabilities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn, debug};
use uuid::Uuid;

use crate::BootstrapError;

// =============================================================================
// Work Home Configuration
// =============================================================================

/// Work home operating modes
#[derive(Debug, Clone, PartialEq)]
pub enum WorkHomeMode {
    /// Work home functionality disabled
    Disabled,
    /// Interactive mode - use native folder picker
    Interactive,
    /// Path mode - use specified path
    Path(PathBuf),
}

/// Work home configuration
#[derive(Debug, Clone)]
pub struct WorkHomeConfig {
    /// Operating mode
    pub mode: WorkHomeMode,
    /// Application name for subdirectory creation
    pub app_name: String,
    /// Marker filename for managed directories
    pub marker_filename: String,
}

impl Default for WorkHomeConfig {
    fn default() -> Self {
        let mode = match std::env::var("EKKA_WORK_HOME_MODE").as_deref() {
            Ok("disabled") => WorkHomeMode::Disabled,
            Ok("interactive") => WorkHomeMode::Interactive,
            Ok("path") => {
                if let Ok(path_str) = std::env::var("EKKA_WORK_HOME_PATH") {
                    WorkHomeMode::Path(PathBuf::from(path_str))
                } else {
                    WorkHomeMode::Disabled
                }
            }
            _ => WorkHomeMode::Disabled,
        };

        Self {
            mode,
            app_name: "EKKA".to_string(),
            marker_filename: ".ekka-managed.json".to_string(),
        }
    }
}

// =============================================================================
// Workspace Data Structures
// =============================================================================

/// Workspace metadata stored in encrypted database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    /// Unique workspace identifier
    pub workspace_id: Uuid,
    /// User-provided display name
    pub display_name: String,
    /// Absolute path to workspace directory
    pub path: PathBuf,
    /// Current status (active, quarantined, deleted)
    pub status: WorkspaceStatus,
    /// When workspace was created
    pub created_at: DateTime<Utc>,
    /// Last accessed time
    pub last_accessed_at: DateTime<Utc>,
    /// Security epoch when last validated
    pub epoch_validated: u32,
}

/// Workspace status for quarantine/access control
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WorkspaceStatus {
    /// Active and accessible
    Active,
    /// Quarantined due to epoch mismatch
    Quarantined,
    /// Marked for deletion
    Deleted,
}

/// Marker file written to managed directories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMarker {
    /// Schema version
    pub schema_version: String,
    /// Application that manages this directory
    pub managed_by: String,
    /// Workspace ID
    pub workspace_id: Uuid,
    /// When management started
    pub managed_since: DateTime<Utc>,
    /// Warning for users
    pub warning: String,
}

impl WorkspaceMarker {
    fn new(workspace_id: Uuid, app_name: &str) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            managed_by: app_name.to_string(),
            workspace_id,
            managed_since: Utc::now(),
            warning: format!(
                "This directory is managed by {}. Manual changes may be overwritten.",
                app_name
            ),
        }
    }
}

// =============================================================================
// Work Home Manager
// =============================================================================

/// Manages user workspace directories
pub struct WorkHomeManager {
    config: WorkHomeConfig,
    workspaces: HashMap<Uuid, WorkspaceRecord>,
}

impl WorkHomeManager {
    /// Create new work home manager
    pub fn new(config: WorkHomeConfig) -> Self {
        Self {
            config,
            workspaces: HashMap::new(),
        }
    }

    /// Provision workspace interactively (opens native folder picker)
    pub fn provision_interactive(&mut self, display_name: String) -> Result<Uuid, BootstrapError> {
        match &self.config.mode {
            WorkHomeMode::Disabled => {
                return Err(BootstrapError::Config("Work home is disabled".to_string()));
            }
            WorkHomeMode::Interactive => {
                // STUB: In real implementation, this would open native folder picker
                // For RAPTOR-1, we'll return an error with instructions
                warn!(
                    op = "work_home.interactive_stub",
                    "Interactive folder picker not implemented in RAPTOR-1"
                );
                return Err(BootstrapError::Config(
                    "Interactive mode not implemented. Use EKKA_WORK_HOME_MODE=path with EKKA_WORK_HOME_PATH".to_string()
                ));
            }
            WorkHomeMode::Path(base_path) => {
                self.provision_path(base_path.clone(), display_name)
            }
        }
    }

    /// Provision workspace at specified path
    pub fn provision_path(&mut self, user_path: PathBuf, display_name: String) -> Result<Uuid, BootstrapError> {
        if self.config.mode == WorkHomeMode::Disabled {
            return Err(BootstrapError::Config("Work home is disabled".to_string()));
        }

        info!(
            op = "work_home.provision_start",
            path = %user_path.display(),
            display_name = %display_name,
            "Starting workspace provisioning"
        );

        // TODO: Validate path via PathGuard (integrate with ekka-path-guard crate)
        self.validate_user_path(&user_path)?;

        // Generate workspace ID
        let workspace_id = Uuid::new_v4();

        // Create managed subdirectory: <chosen>/EKKA/<app>/<workspace_id>/
        let managed_dir = user_path
            .join(&self.config.app_name)
            .join(&self.config.app_name.to_lowercase())
            .join(workspace_id.to_string());

        // Ensure managed directory exists
        fs::create_dir_all(&managed_dir)
            .map_err(|e| BootstrapError::Io(e))?;

        // Set secure permissions
        self.set_secure_permissions(&managed_dir)?;

        // Write marker file
        let marker_path = managed_dir.join(&self.config.marker_filename);
        let marker = WorkspaceMarker::new(workspace_id, &self.config.app_name);
        let marker_content = serde_json::to_string_pretty(&marker)?;
        fs::write(&marker_path, marker_content)?;

        // Create workspace record
        let now = Utc::now();
        let record = WorkspaceRecord {
            workspace_id,
            display_name: display_name.clone(),
            path: managed_dir.clone(),
            status: WorkspaceStatus::Active,
            created_at: now,
            last_accessed_at: now,
            epoch_validated: 1, // TODO: Get current epoch
        };

        // Store in memory (TODO: persist to encrypted DB)
        self.workspaces.insert(workspace_id, record);

        info!(
            op = "work_home.provision_complete",
            workspace_id = %workspace_id,
            path = %managed_dir.display(),
            "Workspace provisioned successfully"
        );

        Ok(workspace_id)
    }

    /// Get workspace by ID
    pub fn get_workspace(&self, workspace_id: Uuid) -> Option<&WorkspaceRecord> {
        self.workspaces.get(&workspace_id)
    }

    /// List all workspaces with optional status filter
    pub fn list_workspaces(&self, status_filter: Option<WorkspaceStatus>) -> Vec<&WorkspaceRecord> {
        self.workspaces
            .values()
            .filter(|record| {
                status_filter.as_ref().map_or(true, |status| record.status == *status)
            })
            .collect()
    }

    /// Quarantine workspace (due to epoch mismatch)
    pub fn quarantine_workspace(&mut self, workspace_id: Uuid) -> Result<(), BootstrapError> {
        if let Some(record) = self.workspaces.get_mut(&workspace_id) {
            if record.status == WorkspaceStatus::Active {
                record.status = WorkspaceStatus::Quarantined;
                warn!(
                    op = "work_home.quarantined",
                    workspace_id = %workspace_id,
                    path = %record.path.display(),
                    "Workspace quarantined due to security epoch mismatch"
                );
            }
            Ok(())
        } else {
            Err(BootstrapError::Config(format!("Workspace {} not found", workspace_id)))
        }
    }

    /// Delete workspace directory (DANGEROUS - requires explicit policy)
    pub fn delete_workspace(&mut self, workspace_id: Uuid, force_delete: bool) -> Result<(), BootstrapError> {
        let record = self.workspaces.get(&workspace_id)
            .ok_or_else(|| BootstrapError::Config(format!("Workspace {} not found", workspace_id)))?
            .clone(); // Clone to avoid borrowing issues

        // Check if marker exists (safety check)
        let marker_path = record.path.join(&self.config.marker_filename);
        let has_marker = marker_path.exists();

        if !has_marker && !force_delete {
            return Err(BootstrapError::Security(
                "Workspace deletion denied: no marker file found (safety check)".to_string()
            ));
        }

        if !force_delete {
            warn!(
                op = "work_home.delete_denied",
                workspace_id = %workspace_id,
                "Workspace deletion requires explicit policy flag"
            );
            return Err(BootstrapError::Config(
                "Workspace deletion requires explicit policy authorization".to_string()
            ));
        }

        // Perform deletion
        if record.path.exists() {
            fs::remove_dir_all(&record.path)
                .map_err(|e| BootstrapError::Io(e))?;
        }

        // Remove from tracking
        self.workspaces.remove(&workspace_id);

        warn!(
            op = "work_home.deleted",
            workspace_id = %workspace_id,
            path = %record.path.display(),
            "Workspace directory deleted"
        );

        Ok(())
    }

    /// Process epoch mismatch for all workspaces
    pub fn handle_epoch_mismatch(&mut self, new_epoch: u32, delete_policy: bool) -> Result<Vec<Uuid>, BootstrapError> {
        let mut affected_workspaces = Vec::new();

        for (workspace_id, record) in &mut self.workspaces {
            if record.epoch_validated != new_epoch {
                affected_workspaces.push(*workspace_id);

                // Default behavior: quarantine
                if record.status == WorkspaceStatus::Active {
                    record.status = WorkspaceStatus::Quarantined;
                    warn!(
                        op = "work_home.epoch_quarantine",
                        workspace_id = %workspace_id,
                        old_epoch = record.epoch_validated,
                        new_epoch = new_epoch,
                        "Workspace quarantined due to epoch mismatch"
                    );
                }
            }
        }

        // If delete policy is enabled, delete quarantined workspaces with markers
        if delete_policy {
            let quarantined: Vec<_> = affected_workspaces.iter().cloned().collect();
            for workspace_id in quarantined {
                if let Err(e) = self.delete_workspace(workspace_id, true) {
                    warn!(
                        op = "work_home.epoch_delete_failed",
                        workspace_id = %workspace_id,
                        error = %e,
                        "Failed to delete workspace during epoch cleanup"
                    );
                }
            }
        }

        Ok(affected_workspaces)
    }

    // =============================================================================
    // Private Implementation
    // =============================================================================

    fn validate_user_path(&self, path: &Path) -> Result<(), BootstrapError> {
        // Basic validation - in real implementation, use ekka-path-guard
        if !path.exists() {
            return Err(BootstrapError::Config(
                format!("Path does not exist: {}", path.display())
            ));
        }

        if !path.is_dir() {
            return Err(BootstrapError::Config(
                format!("Path is not a directory: {}", path.display())
            ));
        }

        // Check for dangerous paths
        let path_str = path.to_string_lossy();
        if path_str == "/" || path_str == "C:\\" || path_str.contains("System32") {
            return Err(BootstrapError::Security(
                "Dangerous path rejected for workspace provisioning".to_string()
            ));
        }

        debug!(
            op = "work_home.path_validated",
            path = %path.display(),
            "User path validated successfully"
        );

        Ok(())
    }

    fn set_secure_permissions(&self, path: &Path) -> Result<(), BootstrapError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_work_home_config_from_env() {
        std::env::set_var("EKKA_WORK_HOME_MODE", "disabled");
        let config = WorkHomeConfig::default();
        assert_eq!(config.mode, WorkHomeMode::Disabled);

        std::env::set_var("EKKA_WORK_HOME_MODE", "path");
        std::env::set_var("EKKA_WORK_HOME_PATH", "/tmp/test");
        let config = WorkHomeConfig::default();
        match config.mode {
            WorkHomeMode::Path(ref path) => assert_eq!(path, &PathBuf::from("/tmp/test")),
            _ => panic!("Expected Path mode"),
        }

        std::env::remove_var("EKKA_WORK_HOME_MODE");
        std::env::remove_var("EKKA_WORK_HOME_PATH");
    }

    #[test]
    fn test_workspace_marker_creation() {
        let workspace_id = Uuid::new_v4();
        let marker = WorkspaceMarker::new(workspace_id, "test-app");

        assert_eq!(marker.schema_version, "1.0");
        assert_eq!(marker.managed_by, "test-app");
        assert_eq!(marker.workspace_id, workspace_id);
        assert!(marker.warning.contains("test-app"));
    }

    #[test]
    fn test_workspace_provisioning() {
        let temp_dir = TempDir::new().unwrap();

        let config = WorkHomeConfig {
            mode: WorkHomeMode::Path(temp_dir.path().to_path_buf()),
            app_name: "test-app".to_string(),
            marker_filename: ".test-marker.json".to_string(),
        };

        let mut manager = WorkHomeManager::new(config);
        let workspace_id = manager.provision_path(
            temp_dir.path().to_path_buf(),
            "Test Workspace".to_string()
        ).unwrap();

        // Verify workspace was created
        let record = manager.get_workspace(workspace_id).unwrap();
        assert_eq!(record.display_name, "Test Workspace");
        assert_eq!(record.status, WorkspaceStatus::Active);

        // Verify managed directory exists
        let managed_dir = temp_dir.path()
            .join("test-app")
            .join("test-app")
            .join(workspace_id.to_string());
        assert!(managed_dir.exists());

        // Verify marker file exists
        let marker_path = managed_dir.join(".test-marker.json");
        assert!(marker_path.exists());
    }

    #[test]
    fn test_workspace_quarantine() {
        let temp_dir = TempDir::new().unwrap();

        let config = WorkHomeConfig {
            mode: WorkHomeMode::Path(temp_dir.path().to_path_buf()),
            app_name: "test-app".to_string(),
            marker_filename: ".test-marker.json".to_string(),
        };

        let mut manager = WorkHomeManager::new(config);
        let workspace_id = manager.provision_path(
            temp_dir.path().to_path_buf(),
            "Test Workspace".to_string()
        ).unwrap();

        // Quarantine the workspace
        manager.quarantine_workspace(workspace_id).unwrap();

        let record = manager.get_workspace(workspace_id).unwrap();
        assert_eq!(record.status, WorkspaceStatus::Quarantined);
    }

    #[test]
    fn test_epoch_mismatch_handling() {
        let temp_dir = TempDir::new().unwrap();

        let config = WorkHomeConfig {
            mode: WorkHomeMode::Path(temp_dir.path().to_path_buf()),
            app_name: "test-app".to_string(),
            marker_filename: ".test-marker.json".to_string(),
        };

        let mut manager = WorkHomeManager::new(config);
        let workspace_id = manager.provision_path(
            temp_dir.path().to_path_buf(),
            "Test Workspace".to_string()
        ).unwrap();

        // Simulate epoch mismatch
        let affected = manager.handle_epoch_mismatch(2, false).unwrap();
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0], workspace_id);

        let record = manager.get_workspace(workspace_id).unwrap();
        assert_eq!(record.status, WorkspaceStatus::Quarantined);
    }
}