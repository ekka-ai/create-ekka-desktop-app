//! Workspaces Inventory Persistence - RAPTOR-2 Step 23/24 (Enterprise-Grade)
//!
//! Provides encrypted persistent storage for WorkspacesInventory using:
//! - AES-256-GCM authenticated encryption
//! - HKDF-SHA256 key derivation from a real secret root key
//! - Versioned envelope format for forward compatibility
//! - Atomic writes for data integrity
//!
//! ## Security Properties
//!
//! - Root key is a REAL SECRET (not derivable from node_id)
//! - node_id used ONLY as HKDF salt (not as key material)
//! - Per-store key derived via HKDF-SHA256
//! - AAD includes schema_version and key_version for integrity
//! - No paths leaked in errors or logs
//! - Atomic file writes prevent partial corruption
//!
//! ## Storage Format (Versioned Envelope)
//!
//! JSON file at `<data_home>/workspaces-inventory.json`:
//! ```json
//! {
//!   "schema_version": 1,
//!   "key_version": 1,
//!   "nonce_b64": "<base64>",
//!   "ciphertext_b64": "<base64>"
//! }
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// =============================================================================
// Constants
// =============================================================================

/// Current schema version for the inventory storage
pub const INVENTORY_SCHEMA_VERSION: u32 = 1;

/// Current key version (for key rotation support)
pub const CURRENT_KEY_VERSION: u32 = 1;

/// Default filename for persistent inventory
const INVENTORY_FILENAME: &str = "workspaces-inventory.json";

/// HKDF info string for inventory store key derivation
const HKDF_INFO_INVENTORY: &[u8] = b"ekka.workspaces.inventory.v1";

/// AAD prefix for authenticated encryption
const AAD_PREFIX: &str = "ekka.workspaces.inventory";

// =============================================================================
// Error Codes (stable, safe - no paths or secrets)
// =============================================================================

/// Error codes for persistence operations
/// These are safe to expose in HTTP responses (no paths, no secrets)
pub struct PersistErrorCode;

impl PersistErrorCode {
    /// Root key not configured (EKKA_DATA_KEY_B64 missing and no ephemeral allowed)
    pub const DATA_KEY_NOT_CONFIGURED: &'static str = "DATA_KEY_NOT_CONFIGURED";
    /// Decryption failed (wrong key, corrupted data, or tampered)
    pub const DATA_DECRYPT_FAILED: &'static str = "DATA_DECRYPT_FAILED";
    /// Encryption failed
    pub const DATA_ENCRYPT_FAILED: &'static str = "DATA_ENCRYPT_FAILED";
    /// Persist (write) failed
    pub const DATA_PERSIST_FAILED: &'static str = "DATA_PERSIST_FAILED";
    /// Load (read) failed
    pub const DATA_LOAD_FAILED: &'static str = "DATA_LOAD_FAILED";
    /// Schema version not supported
    pub const DATA_SCHEMA_UNSUPPORTED: &'static str = "DATA_SCHEMA_UNSUPPORTED";
}

// =============================================================================
// Serializable Types
// =============================================================================

/// Serializable workspace entry for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentWorkspaceEntry {
    pub workspace_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_ref: Option<String>,
}

/// Serializable inventory data (plaintext before encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryData {
    pub schema_version: u32,
    pub workspaces: Vec<PersistentWorkspaceEntry>,
}

/// On-disk format (versioned encrypted envelope)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedEnvelope {
    /// Schema version for the envelope format
    schema_version: u32,
    /// Key version used for encryption (for rotation support)
    key_version: u32,
    /// Base64-encoded 12-byte nonce
    nonce_b64: String,
    /// Base64-encoded ciphertext (AES-256-GCM output)
    ciphertext_b64: String,
}

// =============================================================================
// Data At Rest Key Configuration
// =============================================================================

/// Configuration for the data-at-rest encryption key
#[derive(Clone)]
pub struct DataKeyConfig {
    /// 32-byte root key (the actual secret)
    root_key: [u8; 32],
    /// Key version (for rotation support)
    key_version: u32,
}

impl DataKeyConfig {
    /// Create from a 32-byte root key
    pub fn from_key(root_key: [u8; 32], key_version: u32) -> Self {
        Self { root_key, key_version }
    }

    /// Create from base64-encoded key (for env var loading)
    pub fn from_base64(b64: &str, key_version: u32) -> Result<Self, PersistError> {
        let bytes = BASE64.decode(b64)
            .map_err(|_| PersistError::KeyConfig("Invalid key encoding".to_string()))?;

        if bytes.len() != 32 {
            return Err(PersistError::KeyConfig("Key must be 32 bytes".to_string()));
        }

        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&bytes);
        Ok(Self { root_key, key_version })
    }

    /// Generate a new random key (for ephemeral dev mode ONLY)
    pub fn generate_ephemeral() -> Self {
        let mut root_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut root_key);
        Self { root_key, key_version: CURRENT_KEY_VERSION }
    }
}

// Implement Debug without exposing the key
impl std::fmt::Debug for DataKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataKeyConfig")
            .field("key_version", &self.key_version)
            .field("root_key", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Persistence Store
// =============================================================================

/// Configuration for persistent inventory store
#[derive(Clone)]
pub struct InventoryStoreConfig {
    /// Directory where inventory file is stored
    pub data_dir: PathBuf,
    /// Node ID used as HKDF salt (NOT as key material)
    pub node_id: Uuid,
    /// Data encryption key configuration
    pub key_config: DataKeyConfig,
}

impl std::fmt::Debug for InventoryStoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InventoryStoreConfig")
            .field("data_dir", &"[REDACTED]")
            .field("node_id", &self.node_id)
            .field("key_config", &self.key_config)
            .finish()
    }
}

/// Persistent inventory store with enterprise-grade encryption
pub struct InventoryStore {
    config: InventoryStoreConfig,
    /// Derived encryption key (from HKDF)
    derived_key: [u8; 32],
}

impl InventoryStore {
    /// Create a new inventory store with the given configuration
    pub fn new(config: InventoryStoreConfig) -> Self {
        // Derive per-store key using HKDF-SHA256
        let derived_key = derive_store_key(
            &config.key_config.root_key,
            &config.node_id,
            HKDF_INFO_INVENTORY,
        );

        Self { config, derived_key }
    }

    /// Get the inventory file path
    fn inventory_path(&self) -> PathBuf {
        self.config.data_dir.join(INVENTORY_FILENAME)
    }

    /// Get temporary file path for atomic write
    fn temp_path(&self) -> PathBuf {
        let random_suffix: u64 = rand::random();
        self.config.data_dir.join(format!("{}.tmp.{}", INVENTORY_FILENAME, random_suffix))
    }

    /// Load inventory from disk (decrypts)
    /// Returns empty inventory if file doesn't exist
    pub fn load(&self) -> Result<InventoryData, PersistError> {
        let path = self.inventory_path();

        if !path.exists() {
            info!(
                op = "workspaces.persist.load.not_found",
                "No existing inventory file, starting fresh"
            );
            return Ok(InventoryData {
                schema_version: INVENTORY_SCHEMA_VERSION,
                workspaces: vec![],
            });
        }

        let content = fs::read_to_string(&path)
            .map_err(|_| PersistError::Load("Failed to read data".to_string()))?;

        let envelope: EncryptedEnvelope = serde_json::from_str(&content)
            .map_err(|_| PersistError::Load("Invalid data format".to_string()))?;

        // Check schema version
        if envelope.schema_version > INVENTORY_SCHEMA_VERSION {
            return Err(PersistError::Schema(format!(
                "Schema version {} not supported (max: {})",
                envelope.schema_version, INVENTORY_SCHEMA_VERSION
            )));
        }

        // Check key version (for future rotation support)
        if envelope.key_version != self.config.key_config.key_version {
            // Future: try to decrypt with old key version
            // For now: fail with safe error
            warn!(
                op = "workspaces.persist.load.key_version_mismatch",
                file_version = envelope.key_version,
                current_version = self.config.key_config.key_version,
                "Key version mismatch"
            );
            return Err(PersistError::Decrypt("Key version mismatch".to_string()));
        }

        // Decode nonce and ciphertext
        let nonce_bytes = BASE64.decode(&envelope.nonce_b64)
            .map_err(|_| PersistError::Decrypt("Invalid nonce".to_string()))?;

        if nonce_bytes.len() != 12 {
            return Err(PersistError::Decrypt("Invalid nonce length".to_string()));
        }

        let ciphertext = BASE64.decode(&envelope.ciphertext_b64)
            .map_err(|_| PersistError::Decrypt("Invalid ciphertext".to_string()))?;

        // Build AAD for authenticated decryption
        let aad = build_aad(envelope.schema_version, envelope.key_version);

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&self.derived_key)
            .map_err(|_| PersistError::Decrypt("Cipher init failed".to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: &ciphertext,
            aad: &aad,
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| PersistError::Decrypt("Decryption failed".to_string()))?;

        // Parse decrypted data
        let data: InventoryData = serde_json::from_slice(&plaintext)
            .map_err(|_| PersistError::Load("Invalid decrypted data".to_string()))?;

        info!(
            op = "workspaces.persist.load.ok",
            workspace_count = data.workspaces.len(),
            schema_version = data.schema_version,
            "Inventory loaded"
        );

        Ok(data)
    }

    /// Save inventory to disk (encrypts) with atomic write
    pub fn save(&self, data: &InventoryData) -> Result<(), PersistError> {
        // Ensure data directory exists with secure permissions
        create_secure_dir(&self.config.data_dir)?;

        // Serialize the plaintext data
        let plaintext = serde_json::to_vec(data)
            .map_err(|_| PersistError::Persist("Serialization failed".to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Build AAD
        let aad = build_aad(INVENTORY_SCHEMA_VERSION, self.config.key_config.key_version);

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&self.derived_key)
            .map_err(|_| PersistError::Encrypt("Cipher init failed".to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: &plaintext,
            aad: &aad,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| PersistError::Encrypt("Encryption failed".to_string()))?;

        // Build envelope
        let envelope = EncryptedEnvelope {
            schema_version: INVENTORY_SCHEMA_VERSION,
            key_version: self.config.key_config.key_version,
            nonce_b64: BASE64.encode(&nonce_bytes),
            ciphertext_b64: BASE64.encode(&ciphertext),
        };

        let content = serde_json::to_string_pretty(&envelope)
            .map_err(|_| PersistError::Persist("Envelope serialization failed".to_string()))?;

        // Atomic write: temp file -> fsync -> rename
        let temp_path = self.temp_path();
        let final_path = self.inventory_path();

        // Write to temp file
        {
            let mut file = File::create(&temp_path)
                .map_err(|_| PersistError::Persist("Failed to create temp file".to_string()))?;

            // Set permissions before writing (Unix)
            #[cfg(unix)]
            {
                let perms = fs::Permissions::from_mode(0o600);
                fs::set_permissions(&temp_path, perms).ok(); // Best effort
            }

            file.write_all(content.as_bytes())
                .map_err(|_| PersistError::Persist("Write failed".to_string()))?;

            // fsync the file
            file.sync_all()
                .map_err(|_| PersistError::Persist("Sync failed".to_string()))?;
        }

        // Atomic rename
        fs::rename(&temp_path, &final_path)
            .map_err(|_| {
                // Clean up temp file on failure
                let _ = fs::remove_file(&temp_path);
                PersistError::Persist("Atomic rename failed".to_string())
            })?;

        // Best-effort fsync directory (platform-dependent)
        #[cfg(unix)]
        {
            if let Ok(dir) = File::open(&self.config.data_dir) {
                let _ = dir.sync_all();
            }
        }

        info!(
            op = "workspaces.persist.save.ok",
            workspace_count = data.workspaces.len(),
            key_version = self.config.key_config.key_version,
            "Inventory saved"
        );

        Ok(())
    }

    /// Get the key version currently in use
    pub fn key_version(&self) -> u32 {
        self.config.key_config.key_version
    }
}

// =============================================================================
// Conversion Helpers
// =============================================================================

/// Convert in-memory inventory to persistent format
pub fn to_persistent_entries(
    workspaces: &HashMap<Uuid, super::WorkspaceInventoryEntry>,
) -> Vec<PersistentWorkspaceEntry> {
    workspaces
        .values()
        .map(|entry| PersistentWorkspaceEntry {
            workspace_id: entry.workspace_id,
            name: entry.name.clone(),
            created_at: entry.created_at,
            status: entry.status.clone(),
            repo_ref: entry.repo_ref.clone(),
        })
        .collect()
}

/// Convert persistent entries to in-memory format
pub fn from_persistent_entries(
    entries: Vec<PersistentWorkspaceEntry>,
) -> HashMap<Uuid, super::WorkspaceInventoryEntry> {
    entries
        .into_iter()
        .map(|entry| {
            (
                entry.workspace_id,
                super::WorkspaceInventoryEntry {
                    workspace_id: entry.workspace_id,
                    name: entry.name,
                    created_at: entry.created_at,
                    status: entry.status,
                    repo_ref: entry.repo_ref,
                },
            )
        })
        .collect()
}

// =============================================================================
// Key Derivation (HKDF-SHA256)
// =============================================================================

/// Derive a per-store encryption key using HKDF-SHA256
///
/// - IKM (Input Key Material): root_key (32 bytes, the actual secret)
/// - Salt: node_id bytes (16 bytes, NOT a secret - just for domain separation)
/// - Info: store-specific constant (e.g., "ekka.workspaces.inventory.v1")
/// - Output: 32-byte AES-256 key
fn derive_store_key(root_key: &[u8; 32], node_id: &Uuid, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(node_id.as_bytes()), root_key);
    let mut derived = [0u8; 32];
    hk.expand(info, &mut derived)
        .expect("HKDF expand should never fail with valid parameters");
    derived
}

/// Build AAD (Additional Authenticated Data) for AES-GCM
/// Includes schema_version and key_version for integrity
fn build_aad(schema_version: u32, key_version: u32) -> Vec<u8> {
    format!("{}:s{}:k{}", AAD_PREFIX, schema_version, key_version).into_bytes()
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Create directory with secure permissions
fn create_secure_dir(path: &Path) -> Result<(), PersistError> {
    if path.exists() {
        return Ok(());
    }

    fs::create_dir_all(path)
        .map_err(|_| PersistError::Persist("Directory creation failed".to_string()))?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms)
            .map_err(|_| PersistError::Persist("Directory permissions failed".to_string()))?;
    }

    Ok(())
}

// =============================================================================
// Errors
// =============================================================================

/// Persistence error types
/// SECURITY: Display impl NEVER includes paths, env var names, or secrets
#[derive(Debug)]
pub enum PersistError {
    /// Key configuration error (missing or invalid)
    KeyConfig(String),
    /// Load (read) error
    Load(String),
    /// Persist (write) error
    Persist(String),
    /// Encryption error
    Encrypt(String),
    /// Decryption error
    Decrypt(String),
    /// Schema version error
    Schema(String),
}

impl PersistError {
    /// Get the safe error code for HTTP responses
    pub fn code(&self) -> &'static str {
        match self {
            PersistError::KeyConfig(_) => PersistErrorCode::DATA_KEY_NOT_CONFIGURED,
            PersistError::Load(_) => PersistErrorCode::DATA_LOAD_FAILED,
            PersistError::Persist(_) => PersistErrorCode::DATA_PERSIST_FAILED,
            PersistError::Encrypt(_) => PersistErrorCode::DATA_ENCRYPT_FAILED,
            PersistError::Decrypt(_) => PersistErrorCode::DATA_DECRYPT_FAILED,
            PersistError::Schema(_) => PersistErrorCode::DATA_SCHEMA_UNSUPPORTED,
        }
    }
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SECURITY: Never include paths, env var names, or secrets in display
        match self {
            PersistError::KeyConfig(_) => write!(f, "Data key not configured"),
            PersistError::Load(_) => write!(f, "Data load failed"),
            PersistError::Persist(_) => write!(f, "Data persist failed"),
            PersistError::Encrypt(_) => write!(f, "Data encryption failed"),
            PersistError::Decrypt(_) => write!(f, "Data decryption failed"),
            PersistError::Schema(_) => write!(f, "Data schema not supported"),
        }
    }
}

impl std::error::Error for PersistError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn assert_no_path_leak(s: &str) {
        assert!(!s.contains("/Users"), "Leaked /Users path: {}", s);
        assert!(!s.contains("/home"), "Leaked /home path: {}", s);
        assert!(!s.contains("/var"), "Leaked /var path: {}", s);
        assert!(!s.contains("/tmp"), "Leaked /tmp path: {}", s);
        assert!(!s.contains("/private"), "Leaked /private path: {}", s);
        assert!(!s.contains("C:\\"), "Leaked C:\\ path: {}", s);
    }

    fn assert_no_env_var_leak(s: &str) {
        assert!(!s.contains("EKKA_DATA_KEY"), "Leaked env var name: {}", s);
        assert!(!s.contains("EKKA_DEV"), "Leaked env var name: {}", s);
    }

    fn create_test_key_config() -> DataKeyConfig {
        // Fixed test key for deterministic testing
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        DataKeyConfig::from_key(key, CURRENT_KEY_VERSION)
    }

    // =========================================================================
    // Basic Roundtrip Tests
    // =========================================================================

    #[test]
    fn test_save_load_roundtrip() {
        let tmp_dir = TempDir::new().unwrap();
        let config = InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = InventoryStore::new(config);

        let workspace_id = Uuid::new_v4();
        let data = InventoryData {
            schema_version: INVENTORY_SCHEMA_VERSION,
            workspaces: vec![PersistentWorkspaceEntry {
                workspace_id,
                name: "Test Workspace".to_string(),
                created_at: Utc::now(),
                status: "provisioned".to_string(),
                repo_ref: Some("owner/repo".to_string()),
            }],
        };

        // Save
        store.save(&data).unwrap();

        // Load
        let loaded = store.load().unwrap();
        assert_eq!(loaded.schema_version, INVENTORY_SCHEMA_VERSION);
        assert_eq!(loaded.workspaces.len(), 1);
        assert_eq!(loaded.workspaces[0].workspace_id, workspace_id);
        assert_eq!(loaded.workspaces[0].name, "Test Workspace");
        assert_eq!(loaded.workspaces[0].repo_ref, Some("owner/repo".to_string()));
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let tmp_dir = TempDir::new().unwrap();
        let config = InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = InventoryStore::new(config);

        let data = store.load().unwrap();
        assert_eq!(data.schema_version, INVENTORY_SCHEMA_VERSION);
        assert!(data.workspaces.is_empty());
    }

    // =========================================================================
    // Restart Simulation Test
    // =========================================================================

    #[test]
    fn test_persistence_survives_restart_simulation() {
        let tmp_dir = TempDir::new().unwrap();
        let node_id = Uuid::new_v4();
        let key_config = create_test_key_config();
        let workspace_id = Uuid::new_v4();

        // First "process" - create and save
        {
            let config = InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            };
            let store = InventoryStore::new(config);

            let data = InventoryData {
                schema_version: INVENTORY_SCHEMA_VERSION,
                workspaces: vec![PersistentWorkspaceEntry {
                    workspace_id,
                    name: "Persisted Workspace".to_string(),
                    created_at: Utc::now(),
                    status: "provisioned".to_string(),
                    repo_ref: Some("ekka-ai/demo".to_string()),
                }],
            };

            store.save(&data).unwrap();
        }

        // Second "process" - load and verify with same key
        {
            let config = InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id, // Same node_id (used as salt)
                key_config: key_config.clone(), // Same key
            };
            let store = InventoryStore::new(config);

            let loaded = store.load().unwrap();
            assert_eq!(loaded.workspaces.len(), 1);
            assert_eq!(loaded.workspaces[0].workspace_id, workspace_id);
            assert_eq!(loaded.workspaces[0].name, "Persisted Workspace");
            assert_eq!(loaded.workspaces[0].repo_ref, Some("ekka-ai/demo".to_string()));
        }
    }

    // =========================================================================
    // Key Security Tests
    // =========================================================================

    #[test]
    fn test_wrong_key_fails_decryption() {
        let tmp_dir = TempDir::new().unwrap();
        let node_id = Uuid::new_v4();

        // Key 1: Save
        let key1 = DataKeyConfig::from_key([1u8; 32], CURRENT_KEY_VERSION);
        {
            let config = InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key1,
            };
            let store = InventoryStore::new(config);

            let data = InventoryData {
                schema_version: INVENTORY_SCHEMA_VERSION,
                workspaces: vec![],
            };

            store.save(&data).unwrap();
        }

        // Key 2: Try to load (should fail)
        let key2 = DataKeyConfig::from_key([2u8; 32], CURRENT_KEY_VERSION);
        {
            let config = InventoryStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key2,
            };
            let store = InventoryStore::new(config);

            let result = store.load();
            assert!(result.is_err());

            let err = result.unwrap_err();
            assert_eq!(err.code(), PersistErrorCode::DATA_DECRYPT_FAILED);

            // Verify error message is safe
            let display = format!("{}", err);
            assert_no_path_leak(&display);
            assert_no_env_var_leak(&display);
        }
    }

    #[test]
    fn test_different_node_ids_produce_different_derived_keys() {
        let root_key = [0u8; 32];
        let key1 = derive_store_key(&root_key, &Uuid::new_v4(), HKDF_INFO_INVENTORY);
        let key2 = derive_store_key(&root_key, &Uuid::new_v4(), HKDF_INFO_INVENTORY);
        assert_ne!(key1, key2, "Different node_ids should produce different derived keys");
    }

    #[test]
    fn test_same_inputs_produce_same_derived_key() {
        let root_key = [0u8; 32];
        let node_id = Uuid::new_v4();
        let key1 = derive_store_key(&root_key, &node_id, HKDF_INFO_INVENTORY);
        let key2 = derive_store_key(&root_key, &node_id, HKDF_INFO_INVENTORY);
        assert_eq!(key1, key2, "Same inputs should produce same derived key");
    }

    // =========================================================================
    // Error Code and No-Leak Tests
    // =========================================================================

    #[test]
    fn test_persist_error_codes() {
        assert_eq!(PersistError::KeyConfig("test".into()).code(), PersistErrorCode::DATA_KEY_NOT_CONFIGURED);
        assert_eq!(PersistError::Load("test".into()).code(), PersistErrorCode::DATA_LOAD_FAILED);
        assert_eq!(PersistError::Persist("test".into()).code(), PersistErrorCode::DATA_PERSIST_FAILED);
        assert_eq!(PersistError::Encrypt("test".into()).code(), PersistErrorCode::DATA_ENCRYPT_FAILED);
        assert_eq!(PersistError::Decrypt("test".into()).code(), PersistErrorCode::DATA_DECRYPT_FAILED);
        assert_eq!(PersistError::Schema("test".into()).code(), PersistErrorCode::DATA_SCHEMA_UNSUPPORTED);
    }

    #[test]
    fn test_persist_error_no_path_leak() {
        let errors = [
            PersistError::KeyConfig("/Users/secret/path".to_string()),
            PersistError::Load("/home/user/file.json".to_string()),
            PersistError::Persist("/var/data/file".to_string()),
            PersistError::Encrypt("/tmp/data".to_string()),
            PersistError::Decrypt("/private/data".to_string()),
            PersistError::Schema("C:\\data".to_string()),
        ];

        for err in &errors {
            let display = format!("{}", err);
            assert_no_path_leak(&display);
            assert_no_env_var_leak(&display);
        }
    }

    #[test]
    fn test_key_config_debug_no_secret_leak() {
        let config = create_test_key_config();
        let debug_str = format!("{:?}", config);

        // Must not contain actual key bytes
        assert!(debug_str.contains("REDACTED"), "Key should be redacted in Debug output");
        assert!(!debug_str.contains("0x00"), "Key bytes should not appear in Debug");
    }

    #[test]
    fn test_store_config_debug_no_path_leak() {
        let tmp_dir = TempDir::new().unwrap();
        let config = InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("REDACTED"), "Path should be redacted in Debug output");
    }

    // =========================================================================
    // Envelope Format Tests
    // =========================================================================

    #[test]
    fn test_envelope_has_required_fields() {
        let tmp_dir = TempDir::new().unwrap();
        let config = InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = InventoryStore::new(config.clone());

        // Save data
        let data = InventoryData {
            schema_version: INVENTORY_SCHEMA_VERSION,
            workspaces: vec![],
        };
        store.save(&data).unwrap();

        // Read raw file and verify envelope fields
        let content = fs::read_to_string(config.data_dir.join(INVENTORY_FILENAME)).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert!(envelope.get("schema_version").is_some(), "Must have schema_version");
        assert!(envelope.get("key_version").is_some(), "Must have key_version");
        assert!(envelope.get("nonce_b64").is_some(), "Must have nonce_b64");
        assert!(envelope.get("ciphertext_b64").is_some(), "Must have ciphertext_b64");

        assert_eq!(envelope["schema_version"], INVENTORY_SCHEMA_VERSION);
        assert_eq!(envelope["key_version"], CURRENT_KEY_VERSION);

        // Verify no plaintext data in file
        assert!(!content.contains("workspaces"), "Plaintext should not be in file");
        assert!(!content.contains("provisioned"), "Status should not be in plaintext");
    }

    #[test]
    fn test_envelope_no_paths_or_urls() {
        let tmp_dir = TempDir::new().unwrap();
        let config = InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = InventoryStore::new(config.clone());

        let data = InventoryData {
            schema_version: INVENTORY_SCHEMA_VERSION,
            workspaces: vec![PersistentWorkspaceEntry {
                workspace_id: Uuid::new_v4(),
                name: "Test".to_string(),
                created_at: Utc::now(),
                status: "provisioned".to_string(),
                repo_ref: Some("owner/repo".to_string()),
            }],
        };
        store.save(&data).unwrap();

        let content = fs::read_to_string(config.data_dir.join(INVENTORY_FILENAME)).unwrap();
        assert_no_path_leak(&content);
        assert!(!content.contains("github.com"), "No URLs in file");
    }

    // =========================================================================
    // Atomic Write Test (Best Effort)
    // =========================================================================

    #[test]
    fn test_atomic_write_no_partial_file() {
        let tmp_dir = TempDir::new().unwrap();
        let config = InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = InventoryStore::new(config.clone());

        // Save data
        let data = InventoryData {
            schema_version: INVENTORY_SCHEMA_VERSION,
            workspaces: vec![PersistentWorkspaceEntry {
                workspace_id: Uuid::new_v4(),
                name: "Test".to_string(),
                created_at: Utc::now(),
                status: "provisioned".to_string(),
                repo_ref: None,
            }],
        };
        store.save(&data).unwrap();

        // Verify no temp files left behind
        let files: Vec<_> = fs::read_dir(config.data_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        assert!(files.contains(&INVENTORY_FILENAME.to_string()), "Main file must exist");

        for file in &files {
            assert!(!file.contains(".tmp."), "No temp files should remain: {}", file);
        }
    }

    // =========================================================================
    // Key Config Tests
    // =========================================================================

    #[test]
    fn test_key_config_from_base64() {
        let key_bytes = [0x42u8; 32];
        let b64 = BASE64.encode(&key_bytes);

        let config = DataKeyConfig::from_base64(&b64, CURRENT_KEY_VERSION).unwrap();
        assert_eq!(config.key_version, CURRENT_KEY_VERSION);
    }

    #[test]
    fn test_key_config_from_base64_invalid_length() {
        let b64 = BASE64.encode(&[0u8; 16]); // Only 16 bytes, not 32
        let result = DataKeyConfig::from_base64(&b64, CURRENT_KEY_VERSION);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_config_from_base64_invalid_encoding() {
        let result = DataKeyConfig::from_base64("not-valid-base64!!!", CURRENT_KEY_VERSION);
        assert!(result.is_err());
    }

    #[test]
    fn test_ephemeral_key_generation() {
        let config1 = DataKeyConfig::generate_ephemeral();
        let config2 = DataKeyConfig::generate_ephemeral();

        // Two ephemeral keys should be different
        assert_ne!(config1.root_key, config2.root_key);
        assert_eq!(config1.key_version, CURRENT_KEY_VERSION);
    }

    // =========================================================================
    // Inventory Data Tests
    // =========================================================================

    #[test]
    fn test_inventory_data_serialization() {
        let data = InventoryData {
            schema_version: INVENTORY_SCHEMA_VERSION,
            workspaces: vec![PersistentWorkspaceEntry {
                workspace_id: Uuid::new_v4(),
                name: "Test".to_string(),
                created_at: Utc::now(),
                status: "provisioned".to_string(),
                repo_ref: None,
            }],
        };

        let json = serde_json::to_string(&data).unwrap();
        assert_no_path_leak(&json);
        assert!(!json.contains("null")); // repo_ref should be skipped when None
    }

    // =========================================================================
    // File Permissions Test (Unix only)
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn test_file_permissions() {
        use std::os::unix::fs::MetadataExt;

        let tmp_dir = TempDir::new().unwrap();
        let config = InventoryStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = InventoryStore::new(config.clone());

        let data = InventoryData {
            schema_version: INVENTORY_SCHEMA_VERSION,
            workspaces: vec![],
        };
        store.save(&data).unwrap();

        let metadata = fs::metadata(config.data_dir.join(INVENTORY_FILENAME)).unwrap();
        let mode = metadata.mode() & 0o777;

        // File should be 0600 (owner read/write only)
        assert_eq!(mode, 0o600, "File permissions should be 0600, got {:o}", mode);
    }
}
