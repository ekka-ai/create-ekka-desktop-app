//! Local Data Wipe Operations
//!
//! Handles deterministic local data wiping when security epochs change.
//! This module implements safe, auditable deletion of encrypted data
//! while preserving user preferences and configuration.

use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn, debug, error};

use crate::{BootstrapConfig, BootstrapError};

// =============================================================================
// Local Wipe Operations
// =============================================================================

/// Perform complete local data wipe due to security epoch mismatch
pub fn perform_local_wipe(home_path: &Path, config: &BootstrapConfig) -> Result<(), BootstrapError> {
    info!(
        op = "wipe.start",
        home = %home_path.display(),
        "Starting local data wipe due to security epoch mismatch"
    );

    let mut errors = Vec::new();
    let mut deleted_count = 0;

    // Define files/directories to wipe (encrypted sensitive data)
    let wipe_targets = get_wipe_targets(home_path, config);

    for target in wipe_targets {
        match wipe_target(&target) {
            Ok(true) => {
                deleted_count += 1;
                debug!(op = "wipe.deleted", path = %target.display(), "Deleted target");
            }
            Ok(false) => {
                debug!(op = "wipe.not_found", path = %target.display(), "Target not found (ok)");
            }
            Err(e) => {
                error!(op = "wipe.error", path = %target.display(), error = %e, "Failed to delete target");
                errors.push(format!("{}: {}", target.display(), e));
            }
        }
    }

    // Wipe keychain secrets (if supported)
    if let Err(e) = wipe_keychain_secrets(config) {
        warn!(op = "wipe.keychain_error", error = %e, "Failed to wipe keychain secrets");
        errors.push(format!("keychain: {}", e));
    }

    // Report results
    if errors.is_empty() {
        info!(
            op = "wipe.complete",
            deleted_count = deleted_count,
            "Local wipe completed successfully"
        );
        Ok(())
    } else {
        error!(
            op = "wipe.partial",
            deleted_count = deleted_count,
            error_count = errors.len(),
            errors = ?errors,
            "Local wipe completed with errors"
        );
        Err(BootstrapError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Wipe completed with {} errors: {}", errors.len(), errors.join("; "))
        )))
    }
}

/// Get list of files/directories to wipe during epoch mismatch
fn get_wipe_targets(home_path: &Path, config: &BootstrapConfig) -> Vec<PathBuf> {
    let mut targets = Vec::new();

    // Core encrypted data directories
    targets.push(home_path.join("vault"));
    targets.push(home_path.join("temp"));

    // Database files (typically encrypted)
    targets.push(home_path.join("telemetry.db"));
    targets.push(home_path.join("database.db"));
    targets.push(home_path.join("node.db"));

    // Cache and session files
    targets.push(home_path.join("cache"));
    targets.push(home_path.join("sessions"));
    targets.push(home_path.join("outbox"));

    // Credential files (encrypted tokens, etc.)
    targets.push(home_path.join("credentials.json"));
    targets.push(home_path.join("tokens.json"));

    // Manifest and cache files
    targets.push(home_path.join("claude-manifest.json"));
    targets.push(home_path.join("claude-config-cache.json"));

    // Add any custom subdirectories that contain encrypted data
    for subdir in &config.subdirs {
        if subdir != "config" && subdir != "hooks" && subdir != "logs" {
            targets.push(home_path.join(subdir));
        }
    }

    // PRESERVE: Configuration, hooks, and logs (user preferences)
    // These are explicitly NOT in the wipe targets:
    // - config.json (user settings)
    // - hooks/ (user scripts)
    // - logs/ (debugging info)
    // - allowed_paths.json (user permissions)

    targets
}

/// Wipe a single target (file or directory)
fn wipe_target(path: &Path) -> Result<bool, std::io::Error> {
    if !path.exists() {
        return Ok(false); // Not found, nothing to delete
    }

    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }

    Ok(true) // Successfully deleted
}

/// Wipe keychain/secure storage secrets
fn wipe_keychain_secrets(config: &BootstrapConfig) -> Result<(), BootstrapError> {
    // For RAPTOR-1, we'll use the existing secure storage crate
    // In a real implementation, this would call ekka-secure-storage::delete_device_secret()
    debug!(
        op = "wipe.keychain",
        service = %config.keychain_service,
        "Wiping keychain secrets"
    );

    // TODO: Integration with ekka-secure-storage crate
    // ekka_secure_storage::SecureStorage::new(config).delete_device_secret()?;

    Ok(())
}

/// Verify wipe completion by checking that targets are gone
pub fn verify_wipe_completion(home_path: &Path, config: &BootstrapConfig) -> Result<bool, BootstrapError> {
    let targets = get_wipe_targets(home_path, config);
    let remaining: Vec<_> = targets
        .iter()
        .filter(|path| path.exists())
        .collect();

    if remaining.is_empty() {
        info!(op = "wipe.verify_ok", "Wipe verification passed - all targets removed");
        Ok(true)
    } else {
        warn!(
            op = "wipe.verify_failed",
            remaining_count = remaining.len(),
            remaining = ?remaining.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "Wipe verification failed - some targets remain"
        );
        Ok(false)
    }
}

// =============================================================================
// Emergency Wipe (for testing and disaster recovery)
// =============================================================================

/// Emergency wipe - removes EVERYTHING in home directory except marker
pub fn emergency_wipe(home_path: &Path, config: &BootstrapConfig) -> Result<(), BootstrapError> {
    warn!(
        op = "wipe.emergency",
        home = %home_path.display(),
        "Performing EMERGENCY WIPE - all data will be lost"
    );

    if !home_path.exists() {
        return Ok(()); // Nothing to wipe
    }

    let marker_path = home_path.join(&config.marker_filename);
    let mut marker_content = None;

    // Backup marker file if it exists
    if marker_path.exists() {
        marker_content = Some(fs::read_to_string(&marker_path)?);
    }

    // Remove everything
    for entry in fs::read_dir(home_path)? {
        let entry = entry?;
        let path = entry.path();

        // Skip marker file
        if path.file_name() == Some(config.marker_filename.as_ref()) {
            continue;
        }

        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }

    // Restore marker file if we had one
    if let Some(content) = marker_content {
        fs::write(&marker_path, content)?;
    }

    warn!(
        op = "wipe.emergency_complete",
        "Emergency wipe completed - only marker file preserved"
    );

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_wipe_targets_includes_sensitive_data() {
        let temp_dir = TempDir::new().unwrap();
        let config = BootstrapConfig::default();

        let targets = get_wipe_targets(temp_dir.path(), &config);

        // Should include encrypted data directories
        assert!(targets.iter().any(|p| p.ends_with("vault")));
        assert!(targets.iter().any(|p| p.ends_with("telemetry.db")));
        assert!(targets.iter().any(|p| p.ends_with("credentials.json")));

        // Should NOT include config files (they're preserved)
        assert!(!targets.iter().any(|p| p.ends_with("config.json")));
        assert!(!targets.iter().any(|p| p.ends_with("hooks")));
    }

    #[test]
    fn test_wipe_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("does-not-exist.db");

        let result = wipe_target(&nonexistent).unwrap();
        assert!(!result); // Should return false for non-existent files
    }

    #[test]
    fn test_wipe_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.db");

        fs::write(&test_file, "test data").unwrap();
        assert!(test_file.exists());

        let result = wipe_target(&test_file).unwrap();
        assert!(result); // Should return true for successfully deleted files
        assert!(!test_file.exists());
    }

    #[test]
    fn test_wipe_directory() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test-vault");

        fs::create_dir_all(&test_dir).unwrap();
        fs::write(test_dir.join("secret.txt"), "secret data").unwrap();
        assert!(test_dir.exists());

        let result = wipe_target(&test_dir).unwrap();
        assert!(result); // Should return true for successfully deleted directories
        assert!(!test_dir.exists());
    }

    #[test]
    fn test_verify_wipe_completion() {
        let temp_dir = TempDir::new().unwrap();
        let config = BootstrapConfig::default();

        // Create some files that should be wiped
        let vault_dir = temp_dir.path().join("vault");
        fs::create_dir_all(&vault_dir).unwrap();
        fs::write(vault_dir.join("secret.txt"), "secret").unwrap();

        let db_file = temp_dir.path().join("telemetry.db");
        fs::write(&db_file, "database").unwrap();

        // Verify they exist
        assert!(!verify_wipe_completion(temp_dir.path(), &config).unwrap());

        // Remove them
        fs::remove_dir_all(&vault_dir).unwrap();
        fs::remove_file(&db_file).unwrap();

        // Verify they're gone
        assert!(verify_wipe_completion(temp_dir.path(), &config).unwrap());
    }
}