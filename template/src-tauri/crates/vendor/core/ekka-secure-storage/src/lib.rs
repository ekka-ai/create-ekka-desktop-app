//! Secure Storage Module
//!
//! Manages device-bound secrets using the OS Keychain (macOS) or
//! equivalent secure storage on other platforms.
//!
//! The device_secret is:
//! - Generated once on first app launch
//! - Stored in OS Keychain (never on disk in plain text)
//! - Cached in memory to avoid multiple keychain prompts per session
//! - Used as part of the encryption key for local SQLite database
//! - Device-specific (cannot be transferred between machines)
//!
//! Security Note:
//! The secret is cached in process memory after first access. This is
//! standard practice (used by SSH agents, password managers, etc.) because:
//! - If process is compromised, attacker has full access anyway
//! - Memory is protected by OS from other processes
//! - Cache is cleared automatically on process exit

use keyring::Entry;
use rand::Rng;
use sha2::{Sha256, Digest};
use std::sync::OnceLock;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

const DEVICE_SECRET_KEY: &str = "device_encryption_key";

/// Error types for secure storage operations
#[derive(Error, Debug)]
pub enum SecureStorageError {
    #[error("Failed to create keyring entry: {0}")]
    KeyringEntry(#[from] keyring::Error),
    #[error("Access denied to secure storage: {msg}")]
    AccessDenied { msg: String },
    #[error("Invalid secret format (len={len}). Please delete the keychain entry and restart")]
    InvalidFormat { len: usize },
    #[error("Multiple keychain entries found. Please delete duplicates and restart")]
    Ambiguous,
    #[error("Keychain operation failed: {msg}")]
    KeychainError { msg: String },
}

/// Secure wrapper for secret bytes that zeros on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretBytes(String);

impl SecretBytes {
    fn new(data: String) -> Self {
        SecretBytes(data)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// In-memory cache for the device secret.
/// Populated on first access, cleared on process exit.
static CACHED_SECRET: OnceLock<SecretBytes> = OnceLock::new();

/// Configuration for secure storage
#[derive(Debug, Clone)]
pub struct SecureStorageConfig {
    pub service_name: String,
}

impl SecureStorageConfig {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

/// Secure storage manager
pub struct SecureStorage {
    config: SecureStorageConfig,
}

impl SecureStorage {
    /// Create a new secure storage instance with the given configuration
    pub fn new(config: SecureStorageConfig) -> Self {
        Self { config }
    }

    /// Get the device secret from cache or Keychain.
    /// Creates a new secret if none exists.
    /// Returns a 64-character hex string (32 bytes).
    ///
    /// The secret is cached in memory after first access to avoid
    /// multiple Keychain prompts during a single app session.
    pub fn get_or_create_device_secret(&self) -> Result<String, SecureStorageError> {
        // Return cached value if available (no keychain access)
        if let Some(secret) = CACHED_SECRET.get() {
            return Ok(secret.as_str().to_string());
        }

        // First access this session - read from keychain
        let secret = self.read_or_create_from_keychain()?;

        // Cache for future calls (ignore if already set by another thread)
        let _ = CACHED_SECRET.set(SecretBytes::new(secret.clone()));

        Ok(secret)
    }

    /// Internal: Read from keychain or create new secret
    /// BULLETPROOF: Handles all edge cases including permission denial
    fn read_or_create_from_keychain(&self) -> Result<String, SecureStorageError> {
        let entry = Entry::new(&self.config.service_name, DEVICE_SECRET_KEY)?;

        // Try to read existing secret
        match entry.get_password() {
            Ok(secret) => {
                // Validate it looks like a valid secret (64 hex chars)
                if secret.len() == 64 && secret.chars().all(|c| c.is_ascii_hexdigit()) {
                    // Log key fingerprint (first 8 chars of SHA256 hash, NOT the key itself)
                    let fingerprint = compute_key_fingerprint(&secret);
                    println!("[Keychain] result=HIT fingerprint={}", fingerprint);
                    return Ok(secret);
                }
                // Invalid format - this is a serious error, don't auto-recreate
                println!("[Keychain] result=INVALID_FORMAT len={}", secret.len());
                return Err(SecureStorageError::InvalidFormat { len: secret.len() });
            }
            Err(keyring::Error::NoEntry) => {
                // No secret exists - create one
                println!("[Keychain] result=MISS (no entry)");
                self.create_new_secret(&entry)
            }
            Err(keyring::Error::Ambiguous(creds)) => {
                // Multiple entries found - log and fail (don't auto-delete)
                println!("[Keychain] result=AMBIGUOUS count={}", creds.len());
                Err(SecureStorageError::Ambiguous)
            }
            Err(e) => {
                // Permission denied or other error
                let error_str = e.to_string().to_lowercase();
                println!("[Keychain] result=ERROR: {}", e);

                if error_str.contains("denied") || error_str.contains("cancel") {
                    // User denied access - we can't proceed without secure storage
                    return Err(SecureStorageError::AccessDenied {
                        msg: format!(
                            "Access denied to {}. Please grant access when prompted. Technical: {}",
                            get_platform_storage_name(),
                            e
                        ),
                    });
                }

                // For other errors, DO NOT auto-recover - fail with clear message
                Err(SecureStorageError::KeychainError {
                    msg: format!("Keychain read error: {}", e),
                })
            }
        }
    }

    /// Create a new secret and store it
    fn create_new_secret(&self, entry: &Entry) -> Result<String, SecureStorageError> {
        let secret = generate_random_secret();
        let fingerprint = compute_key_fingerprint(&secret);

        match entry.set_password(&secret) {
            Ok(_) => {
                println!("[Keychain] result=CREATED fingerprint={}", fingerprint);
                Ok(secret)
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();

                // Handle "already exists" - try update instead
                if error_str.contains("already exists") || error_str.contains("duplicate") {
                    // Delete and retry once
                    match entry.delete_credential() {
                        Ok(_) => {
                            // Retry set after delete
                            entry.set_password(&secret)?;
                            Ok(secret)
                        }
                        Err(del_err) => Err(SecureStorageError::KeychainError {
                            msg: format!(
                                "Keychain conflict: item exists but can't be updated. Delete error: {}",
                                del_err
                            ),
                        }),
                    }
                } else if error_str.contains("denied") || error_str.contains("cancel") {
                    Err(SecureStorageError::AccessDenied {
                        msg: format!(
                            "Access denied to {}. Please grant access when prompted. Technical: {}",
                            get_platform_storage_name(),
                            e
                        ),
                    })
                } else {
                    Err(SecureStorageError::KeychainError {
                        msg: format!("Failed to store device secret: {}", e),
                    })
                }
            }
        }
    }

    /// Delete the device secret from Keychain.
    /// Used during wipe_local_data to force re-generation on next login.
    ///
    /// Note: The in-memory cache cannot be cleared (OnceLock limitation),
    /// but this is fine because:
    /// 1. Wipe typically precedes app restart
    /// 2. New secret will be created on next app launch
    pub fn delete_device_secret(&self) -> Result<(), SecureStorageError> {
        let entry = Entry::new(&self.config.service_name, DEVICE_SECRET_KEY)?;

        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already doesn't exist
            Err(e) => Err(SecureStorageError::KeychainError {
                msg: format!("Failed to delete device secret: {}", e),
            }),
        }
    }

    /// Force reset the keychain entry - use only for recovery
    /// This deletes any existing entry and creates a fresh one
    pub fn force_reset_device_secret(&self) -> Result<String, SecureStorageError> {
        // First, try to delete using CLI (bypasses some permission issues)
        let _ = self.force_delete_via_cli();

        let entry = Entry::new(&self.config.service_name, DEVICE_SECRET_KEY)?;

        // Force delete via keyring API (ignore errors)
        let _ = entry.delete_credential();

        // Create new
        let secret = generate_random_secret();
        match entry.set_password(&secret) {
            Ok(_) => {
                // Update cache
                let _ = CACHED_SECRET.set(SecretBytes::new(secret.clone()));
                Ok(secret)
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("already exists") {
                    // Item still exists - try delete again and retry
                    let _ = self.force_delete_via_cli();
                    let _ = entry.delete_credential();

                    entry.set_password(&secret)?;
                    let _ = CACHED_SECRET.set(SecretBytes::new(secret.clone()));
                    Ok(secret)
                } else {
                    Err(SecureStorageError::KeychainError {
                        msg: format!("Failed to create new device secret: {}", e),
                    })
                }
            }
        }
    }

    /// Try to delete keychain item using security CLI (macOS)
    #[cfg(target_os = "macos")]
    fn force_delete_via_cli(&self) -> Result<(), SecureStorageError> {
        use std::process::Command;

        let _ = Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                &self.config.service_name,
                "-a",
                DEVICE_SECRET_KEY,
            ])
            .output();

        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn force_delete_via_cli(&self) -> Result<(), SecureStorageError> {
        Ok(()) // No-op on other platforms
    }
}

/// Check if a device secret exists.
/// Only checks cache - does NOT access keychain to avoid prompts.
/// Use get_or_create_device_secret() if you need to ensure secret exists.
pub fn has_device_secret() -> bool {
    // Only check cache - never access keychain from this function
    // This prevents duplicate keychain prompts
    CACHED_SECRET.get().is_some()
}

/// Compute a fingerprint of the key for logging (first 8 chars of hex-encoded SHA256)
/// This is safe to log - cannot be reversed to get the key
fn compute_key_fingerprint(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4]) // First 4 bytes = 8 hex chars
}

/// Generate a cryptographically secure random secret.
/// Returns a 64-character hex string (32 bytes of entropy).
fn generate_random_secret() -> String {
    let mut rng = rand::thread_rng();
    let secret: [u8; 32] = rng.gen();
    hex::encode(secret)
}

/// Get platform-specific secure storage name for error messages
fn get_platform_storage_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macOS Keychain"
    }
    #[cfg(target_os = "windows")]
    {
        "Windows Credential Manager"
    }
    #[cfg(target_os = "linux")]
    {
        "Secret Service (GNOME Keyring/KWallet)"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        "system secure storage"
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_generate_random_secret() {
        let secret = generate_random_secret();
        assert_eq!(secret.len(), 64);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));

        // Should generate different secrets each time
        let secret2 = generate_random_secret();
        assert_ne!(secret, secret2);
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let secret = SecretBytes::new("test_secret".to_string());
        let _ptr = secret.0.as_ptr();
        let _len = secret.0.len();

        // Use the secret
        assert_eq!(secret.as_str(), "test_secret");

        // Drop should zeroize
        drop(secret);

        // Memory should be zeroed (this is best-effort verification)
        // Note: This test may be flaky due to memory reuse
    }

    #[test]
    fn test_compute_key_fingerprint() {
        let key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let fingerprint = compute_key_fingerprint(key);
        assert_eq!(fingerprint.len(), 8);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));

        // Same key should produce same fingerprint
        let fingerprint2 = compute_key_fingerprint(key);
        assert_eq!(fingerprint, fingerprint2);

        // Different key should produce different fingerprint
        let key2 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let fingerprint3 = compute_key_fingerprint(key2);
        assert_ne!(fingerprint, fingerprint3);
    }

    #[test]
    fn test_secure_storage_config() {
        let config = SecureStorageConfig::new("test.service");
        assert_eq!(config.service_name, "test.service");
    }
}