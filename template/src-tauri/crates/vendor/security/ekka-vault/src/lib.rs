//! Encrypted Vault Module
//!
//! Provides encrypted file storage for sensitive data using AES-256-GCM.
//! All files in the vault directory are encrypted at rest.
//!
//! Key derivation uses configurable approach:
//! - user_id: Ties data to specific user
//! - device_secret: Ties data to specific device (from secure storage)
//! - security_epoch: Allows remote invalidation when incremented

use ekka_crypto::{derive_key, decrypt, encrypt, KeyDerivationConfig, KeyMaterial};
use ekka_path_guard::{PathGuard, PathGuardError};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

/// Error types for vault operations
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Path guard error: {0}")]
    PathGuard(#[from] PathGuardError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] ekka_crypto::CryptoError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Vault file not found: {0}")]
    FileNotFound(String),
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

/// Configuration for vault initialization
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Base path for vault storage
    pub vault_path: PathBuf,
    /// User identifier for key derivation
    pub user_id: String,
    /// Device-specific secret for key derivation
    pub device_secret: String,
    /// Security epoch for key rotation
    pub security_epoch: u32,
    /// Key derivation configuration
    pub key_config: KeyDerivationConfig,
}

/// Encrypted vault for sensitive file storage
pub struct Vault {
    key: KeyMaterial,
    base_path: PathBuf,
    path_guard: PathGuard,
}

impl Vault {
    /// Initialize vault with derived encryption key and path validation.
    ///
    /// # Arguments
    /// * `config` - Vault configuration
    /// * `path_guard` - Path guard for validation
    ///
    /// # Returns
    /// A new Vault instance with derived key
    pub fn new(config: VaultConfig, path_guard: PathGuard) -> Result<Self, VaultError> {
        let key = derive_key(
            &config.device_secret,
            &config.user_id,
            config.security_epoch,
            "vault",
            &config.key_config,
        );

        let base_path = config.vault_path;

        // Ensure vault directory exists
        if !base_path.exists() {
            // Validate path before creating
            path_guard.validate_path_audited(&base_path, "vault_init", "vault::new")?;
            fs::create_dir_all(&base_path)?;
        }

        Ok(Vault {
            key,
            base_path,
            path_guard,
        })
    }

    /// Get the full path for a vault file.
    fn get_full_path(&self, relative_path: &str) -> PathBuf {
        self.base_path.join(relative_path)
    }

    /// Write encrypted data to vault.
    ///
    /// # Arguments
    /// * `relative_path` - Path relative to vault directory (e.g., "prompts/my-prompt.md")
    /// * `data` - Raw data to encrypt and store
    pub fn write(&self, relative_path: &str, data: &[u8]) -> Result<(), VaultError> {
        let full_path = self.get_full_path(relative_path);

        // Validate path is within vault
        self.path_guard
            .validate_path_audited(&full_path, "vault_write", "vault::write")?;

        // Ensure parent directory exists
        if let Some(parent) = full_path.parent() {
            if !parent.exists() {
                self.path_guard
                    .validate_path_audited(parent, "vault_mkdir", "vault::write")?;
                fs::create_dir_all(parent)?;
            }
        }

        // Encrypt data
        let encrypted = encrypt(data, &self.key)?;

        // Write encrypted data
        fs::write(&full_path, encrypted)?;
        Ok(())
    }

    /// Read and decrypt data from vault.
    ///
    /// # Arguments
    /// * `relative_path` - Path relative to vault directory
    ///
    /// # Returns
    /// Decrypted data
    pub fn read(&self, relative_path: &str) -> Result<Vec<u8>, VaultError> {
        let full_path = self.get_full_path(relative_path);

        // Validate path is within vault
        self.path_guard
            .validate_path_audited(&full_path, "vault_read", "vault::read")?;

        // Check file exists
        if !full_path.exists() {
            return Err(VaultError::FileNotFound(relative_path.to_string()));
        }

        // Read encrypted data
        let encrypted = fs::read(&full_path)?;

        // Decrypt and return
        let decrypted = decrypt(&encrypted, &self.key)?;
        Ok(decrypted)
    }

    /// Read and decrypt a text file from vault.
    ///
    /// # Arguments
    /// * `relative_path` - Path relative to vault directory
    ///
    /// # Returns
    /// Decrypted string
    pub fn read_string(&self, relative_path: &str) -> Result<String, VaultError> {
        let data = self.read(relative_path)?;
        Ok(String::from_utf8(data)?)
    }

    /// Write a string to vault (encrypted).
    ///
    /// # Arguments
    /// * `relative_path` - Path relative to vault directory
    /// * `content` - String to encrypt and store
    pub fn write_string(&self, relative_path: &str, content: &str) -> Result<(), VaultError> {
        self.write(relative_path, content.as_bytes())
    }

    /// Delete a file from vault.
    ///
    /// # Arguments
    /// * `relative_path` - Path relative to vault directory
    pub fn delete(&self, relative_path: &str) -> Result<(), VaultError> {
        let full_path = self.get_full_path(relative_path);

        // Validate path is within vault
        self.path_guard
            .validate_path_audited(&full_path, "vault_delete", "vault::delete")?;

        if full_path.exists() {
            fs::remove_file(&full_path)?;
        }

        Ok(())
    }

    /// Check if a file exists in the vault.
    ///
    /// # Arguments
    /// * `relative_path` - Path relative to vault directory
    pub fn exists(&self, relative_path: &str) -> bool {
        let full_path = self.get_full_path(relative_path);
        full_path.exists()
    }

    /// List files in a vault subdirectory.
    ///
    /// # Arguments
    /// * `subdir` - Subdirectory to list (e.g., "prompts")
    ///
    /// # Returns
    /// Vector of relative paths within the subdirectory
    pub fn list(&self, subdir: &str) -> Result<Vec<String>, VaultError> {
        let full_path = self.get_full_path(subdir);

        // Validate path is within vault
        self.path_guard
            .validate_path_audited(&full_path, "vault_list", "vault::list")?;

        if !full_path.exists() {
            return Ok(vec![]);
        }

        if !full_path.is_dir() {
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} is not a directory", subdir),
            )));
        }

        let entries = fs::read_dir(&full_path)?;

        let mut files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name() {
                    files.push(name.to_string_lossy().to_string());
                }
            }
        }

        Ok(files)
    }

    /// Wipe entire vault - security recovery function.
    ///
    /// Called when security epoch changes (credential rotation, compromise response).
    /// Deletes the entire vault directory and all encrypted contents.
    ///
    /// # Usage
    /// Public API for admin/recovery tools - not called in normal app flow.
    pub fn wipe(&self) -> Result<(), VaultError> {
        if self.base_path.exists() {
            // Validate we can access this path
            self.path_guard
                .validate_path_audited(&self.base_path, "vault_wipe", "vault::wipe")?;

            fs::remove_dir_all(&self.base_path)?;
        }

        Ok(())
    }

    /// Get the vault base path
    pub fn get_base_path(&self) -> &PathBuf {
        &self.base_path
    }
}

/// Wipe vault without needing a vault instance - security recovery function.
///
/// Used during surgical wipe when we don't have valid credentials to construct
/// a proper Vault instance (e.g., after logout, credential rotation, or compromise response).
///
/// # Arguments
/// * `vault_path` - Path to the vault directory
/// * `path_guard` - Path guard for validation
///
/// # Usage
/// Public API for admin/recovery tools - not called in normal app flow.
pub fn wipe_vault(vault_path: &PathBuf, path_guard: &PathGuard) -> Result<(), VaultError> {
    if vault_path.exists() {
        path_guard.validate_path_audited(vault_path, "vault_wipe_standalone", "vault::wipe_vault")?;
        fs::remove_dir_all(vault_path)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(vault_path: PathBuf) -> VaultConfig {
        VaultConfig {
            vault_path,
            user_id: "test_user".to_string(),
            device_secret: "test_device_secret".to_string(),
            security_epoch: 1,
            key_config: KeyDerivationConfig::default(),
        }
    }

    #[test]
    fn test_vault_write_read_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let config = test_config(vault_path.clone());

        // HOME_ONLY: internal EKKA home sandbox only
        let path_guard = PathGuard::home_only(temp_dir.path().to_path_buf());

        let vault = Vault::new(config, path_guard).unwrap();

        let test_data = b"Hello, encrypted world!";
        let test_path = "test/roundtrip.txt";

        // Write
        vault.write(test_path, test_data).unwrap();

        // Read
        let read_data = vault.read(test_path).unwrap();
        assert_eq!(read_data, test_data);

        // Cleanup
        vault.delete(test_path).unwrap();
    }

    #[test]
    fn test_vault_string_operations() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let config = test_config(vault_path.clone());

        // HOME_ONLY: internal EKKA home sandbox only
        let path_guard = PathGuard::home_only(temp_dir.path().to_path_buf());

        let vault = Vault::new(config, path_guard).unwrap();

        let test_content = "Test string with unicode: 你好世界";
        let test_path = "test/string_test.txt";

        // Write string
        vault.write_string(test_path, test_content).unwrap();

        // Read string
        let read_content = vault.read_string(test_path).unwrap();
        assert_eq!(read_content, test_content);

        // Cleanup
        vault.delete(test_path).unwrap();
    }

    #[test]
    fn test_vault_different_epoch_fails() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // HOME_ONLY: internal EKKA home sandbox only
        let path_guard1 = PathGuard::home_only(temp_dir.path().to_path_buf());
        let path_guard2 = PathGuard::home_only(temp_dir.path().to_path_buf());

        let mut config1 = test_config(vault_path.clone());
        config1.security_epoch = 1;
        let vault1 = Vault::new(config1, path_guard1).unwrap();

        let mut config2 = test_config(vault_path);
        config2.security_epoch = 2;
        let vault2 = Vault::new(config2, path_guard2).unwrap();

        let test_data = b"Secret data";
        let test_path = "test/epoch_test.txt";

        // Write with epoch 1
        vault1.write(test_path, test_data).unwrap();

        // Try to read with epoch 2 - should fail
        let result = vault2.read(test_path);
        assert!(result.is_err());

        // Cleanup with correct key
        vault1.delete(test_path).unwrap();
    }

    #[test]
    fn test_vault_list() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let config = test_config(vault_path.clone());

        // HOME_ONLY: internal EKKA home sandbox only
        let path_guard = PathGuard::home_only(temp_dir.path().to_path_buf());

        let vault = Vault::new(config, path_guard).unwrap();

        // Create test files
        vault.write_string("test_list/file1.txt", "content1").unwrap();
        vault.write_string("test_list/file2.txt", "content2").unwrap();

        // List
        let files = vault.list("test_list").unwrap();
        assert!(files.contains(&"file1.txt".to_string()));
        assert!(files.contains(&"file2.txt".to_string()));

        // Cleanup
        vault.delete("test_list/file1.txt").unwrap();
        vault.delete("test_list/file2.txt").unwrap();
    }

    #[test]
    fn test_vault_exists() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let config = test_config(vault_path.clone());

        // HOME_ONLY: internal EKKA home sandbox only
        let path_guard = PathGuard::home_only(temp_dir.path().to_path_buf());

        let vault = Vault::new(config, path_guard).unwrap();
        let test_path = "test/exists_test.txt";

        assert!(!vault.exists(test_path));

        vault.write_string(test_path, "content").unwrap();
        assert!(vault.exists(test_path));

        vault.delete(test_path).unwrap();
        assert!(!vault.exists(test_path));
    }
}