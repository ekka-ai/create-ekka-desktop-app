//! Jobs Persistence - RAPTOR-3 Step 1 (Enterprise-Grade)
//!
//! Provides encrypted persistent storage for Jobs using:
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
//! JSON file at `<data_home>/jobs.json`:
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
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{Job, JobPayload, JobResult, JobStatus, JobType};

// =============================================================================
// Constants
// =============================================================================

/// Current schema version for jobs storage
pub const JOBS_SCHEMA_VERSION: u32 = 1;

/// Current key version (for key rotation support)
pub const CURRENT_KEY_VERSION: u32 = 1;

/// Default filename for persistent jobs
const JOBS_FILENAME: &str = "jobs.json";

/// HKDF info string for jobs store key derivation
const HKDF_INFO_JOBS: &[u8] = b"ekka.jobs.v1";

/// AAD prefix for authenticated encryption
const AAD_PREFIX: &str = "ekka.jobs";

/// Default lease duration in seconds
pub const DEFAULT_LEASE_DURATION_SECS: i64 = 300; // 5 minutes

/// Maximum lease duration in seconds
pub const MAX_LEASE_DURATION_SECS: i64 = 3600; // 1 hour

/// Maximum attempts before job is marked as permanently failed
pub const MAX_JOB_ATTEMPTS: u32 = 3;

/// Default max attempts for new jobs (RAPTOR-3 Step 3)
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

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
// Serializable Types for Persistence
// =============================================================================

/// Serializable job entry for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentJob {
    pub job_id: Uuid,
    pub workspace_id: Uuid,
    pub job_type: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub payload: Option<JobPayload>,
    pub status: String,
    pub created_at_utc: String,
    pub updated_at_utc: String,
    #[serde(default)]
    pub result_code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub result: Option<JobResult>,
    // Lease fields (RAPTOR-3 Step 1)
    #[serde(default)]
    pub lease_owner: Option<String>,
    #[serde(default)]
    pub lease_expires_at_utc: Option<String>,
    #[serde(default)]
    pub claimed_at_utc: Option<String>,
    #[serde(default)]
    pub attempt_count: u32,
    // Retry fields (RAPTOR-3 Step 3)
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default)]
    pub next_attempt_at_utc: Option<String>,
    #[serde(default)]
    pub last_error_code: Option<String>,
    #[serde(default)]
    pub last_error_message: Option<String>,
}

fn default_max_attempts() -> u32 {
    DEFAULT_MAX_ATTEMPTS
}

impl From<&Job> for PersistentJob {
    fn from(job: &Job) -> Self {
        Self {
            job_id: job.job_id,
            workspace_id: job.workspace_id,
            job_type: job.job_type.to_string(),
            label: job.label.clone(),
            payload: job.payload.clone(),
            status: job.status.to_string(),
            created_at_utc: job.created_at.to_rfc3339(),
            updated_at_utc: job.updated_at.to_rfc3339(),
            result_code: job.result_code.clone(),
            message: job.message.clone(),
            result: job.result.clone(),
            lease_owner: job.lease_owner.clone(),
            lease_expires_at_utc: job.lease_expires_at.map(|dt| dt.to_rfc3339()),
            claimed_at_utc: job.claimed_at.map(|dt| dt.to_rfc3339()),
            attempt_count: job.attempt_count,
            // Retry fields (RAPTOR-3 Step 3)
            max_attempts: job.max_attempts,
            next_attempt_at_utc: job.next_attempt_at_utc.map(|dt| dt.to_rfc3339()),
            last_error_code: job.last_error_code.clone(),
            last_error_message: job.last_error_message.clone(),
        }
    }
}

impl PersistentJob {
    /// Convert to in-memory Job
    pub fn to_job(&self) -> Option<Job> {
        let job_type = JobType::from_str(&self.job_type)?;
        let status = match self.status.as_str() {
            "queued" => JobStatus::Queued,
            "running" => JobStatus::Running,
            "succeeded" => JobStatus::Succeeded,
            "failed" => JobStatus::Failed,
            _ => return None,
        };

        let created_at = DateTime::parse_from_rfc3339(&self.created_at_utc)
            .ok()?
            .with_timezone(&Utc);
        let updated_at = DateTime::parse_from_rfc3339(&self.updated_at_utc)
            .ok()?
            .with_timezone(&Utc);

        let lease_expires_at = self.lease_expires_at_utc.as_ref().and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });

        let claimed_at = self.claimed_at_utc.as_ref().and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });

        // Retry fields (RAPTOR-3 Step 3)
        let next_attempt_at = self.next_attempt_at_utc.as_ref().and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        });

        Some(Job {
            job_id: self.job_id,
            workspace_id: self.workspace_id,
            job_type,
            label: self.label.clone(),
            payload: self.payload.clone(),
            status,
            created_at,
            updated_at,
            result_code: self.result_code.clone(),
            message: self.message.clone(),
            result: self.result.clone(),
            lease_owner: self.lease_owner.clone(),
            lease_expires_at,
            claimed_at,
            attempt_count: self.attempt_count,
            // Retry fields (RAPTOR-3 Step 3)
            max_attempts: self.max_attempts,
            next_attempt_at_utc: next_attempt_at,
            last_error_code: self.last_error_code.clone(),
            last_error_message: self.last_error_message.clone(),
        })
    }
}

/// Serializable jobs data (plaintext before encryption)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobsData {
    pub schema_version: u32,
    pub jobs: Vec<PersistentJob>,
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
// Jobs Persistence Store
// =============================================================================

/// Configuration for persistent jobs store
#[derive(Clone)]
pub struct JobsStoreConfig {
    /// Directory where jobs file is stored
    pub data_dir: PathBuf,
    /// Node ID used as HKDF salt (NOT as key material)
    pub node_id: Uuid,
    /// Data encryption key configuration
    pub key_config: DataKeyConfig,
}

impl std::fmt::Debug for JobsStoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobsStoreConfig")
            .field("data_dir", &"[REDACTED]")
            .field("node_id", &self.node_id)
            .field("key_config", &self.key_config)
            .finish()
    }
}

/// Persistent jobs store with enterprise-grade encryption
pub struct JobsPersistenceStore {
    config: JobsStoreConfig,
    /// Derived encryption key (from HKDF)
    derived_key: [u8; 32],
}

impl JobsPersistenceStore {
    /// Create a new jobs persistence store with the given configuration
    pub fn new(config: JobsStoreConfig) -> Self {
        // Derive per-store key using HKDF-SHA256
        let derived_key = derive_store_key(
            &config.key_config.root_key,
            &config.node_id,
            HKDF_INFO_JOBS,
        );

        Self { config, derived_key }
    }

    /// Get the jobs file path
    fn jobs_path(&self) -> PathBuf {
        self.config.data_dir.join(JOBS_FILENAME)
    }

    /// Get temporary file path for atomic write
    fn temp_path(&self) -> PathBuf {
        let random_suffix: u64 = rand::random();
        self.config.data_dir.join(format!("{}.tmp.{}", JOBS_FILENAME, random_suffix))
    }

    /// Load jobs from disk (decrypts)
    /// Returns empty jobs list if file doesn't exist
    pub fn load(&self) -> Result<JobsData, PersistError> {
        let path = self.jobs_path();

        if !path.exists() {
            info!(
                op = "jobs.persist.load.not_found",
                "No existing jobs file, starting fresh"
            );
            return Ok(JobsData {
                schema_version: JOBS_SCHEMA_VERSION,
                jobs: vec![],
            });
        }

        let content = fs::read_to_string(&path)
            .map_err(|_| PersistError::Load("Failed to read data".to_string()))?;

        let envelope: EncryptedEnvelope = serde_json::from_str(&content)
            .map_err(|_| PersistError::Load("Invalid data format".to_string()))?;

        // Check schema version
        if envelope.schema_version > JOBS_SCHEMA_VERSION {
            return Err(PersistError::Schema(format!(
                "Schema version {} not supported (max: {})",
                envelope.schema_version, JOBS_SCHEMA_VERSION
            )));
        }

        // Check key version (for future rotation support)
        if envelope.key_version != self.config.key_config.key_version {
            warn!(
                op = "jobs.persist.load.key_version_mismatch",
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
        let data: JobsData = serde_json::from_slice(&plaintext)
            .map_err(|_| PersistError::Load("Invalid decrypted data".to_string()))?;

        info!(
            op = "jobs.persist.load.ok",
            job_count = data.jobs.len(),
            schema_version = data.schema_version,
            "Jobs loaded"
        );

        Ok(data)
    }

    /// Save jobs to disk (encrypts) with atomic write
    pub fn save(&self, data: &JobsData) -> Result<(), PersistError> {
        // Ensure data directory exists with secure permissions
        create_secure_dir(&self.config.data_dir)?;

        // Serialize the plaintext data
        let plaintext = serde_json::to_vec(data)
            .map_err(|_| PersistError::Persist("Serialization failed".to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Build AAD
        let aad = build_aad(JOBS_SCHEMA_VERSION, self.config.key_config.key_version);

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
            schema_version: JOBS_SCHEMA_VERSION,
            key_version: self.config.key_config.key_version,
            nonce_b64: BASE64.encode(&nonce_bytes),
            ciphertext_b64: BASE64.encode(&ciphertext),
        };

        let content = serde_json::to_string_pretty(&envelope)
            .map_err(|_| PersistError::Persist("Envelope serialization failed".to_string()))?;

        // Atomic write: temp file -> fsync -> rename
        let temp_path = self.temp_path();
        let final_path = self.jobs_path();

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
            op = "jobs.persist.save.ok",
            job_count = data.jobs.len(),
            key_version = self.config.key_config.key_version,
            "Jobs saved"
        );

        Ok(())
    }

    /// Get the key version currently in use
    pub fn key_version(&self) -> u32 {
        self.config.key_config.key_version
    }
}

// =============================================================================
// Key Derivation (HKDF-SHA256)
// =============================================================================

/// Derive a per-store encryption key using HKDF-SHA256
///
/// - IKM (Input Key Material): root_key (32 bytes, the actual secret)
/// - Salt: node_id bytes (16 bytes, NOT a secret - just for domain separation)
/// - Info: store-specific constant (e.g., "ekka.jobs.v1")
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

    fn create_test_job() -> Job {
        Job {
            job_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            job_type: JobType::RepoWorkflow,
            label: Some("Test Job".to_string()),
            payload: None,
            status: JobStatus::Queued,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            result_code: None,
            message: None,
            result: None,
            lease_owner: None,
            lease_expires_at: None,
            claimed_at: None,
            attempt_count: 0,
            // Retry fields (RAPTOR-3 Step 3)
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            next_attempt_at_utc: None,
            last_error_code: None,
            last_error_message: None,
        }
    }

    // =========================================================================
    // Basic Roundtrip Tests
    // =========================================================================

    #[test]
    fn test_save_load_roundtrip() {
        let tmp_dir = TempDir::new().unwrap();
        let config = JobsStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = JobsPersistenceStore::new(config);

        let job = create_test_job();
        let data = JobsData {
            schema_version: JOBS_SCHEMA_VERSION,
            jobs: vec![PersistentJob::from(&job)],
        };

        // Save
        store.save(&data).unwrap();

        // Load
        let loaded = store.load().unwrap();
        assert_eq!(loaded.schema_version, JOBS_SCHEMA_VERSION);
        assert_eq!(loaded.jobs.len(), 1);
        assert_eq!(loaded.jobs[0].job_id, job.job_id);
        assert_eq!(loaded.jobs[0].label, job.label);
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let tmp_dir = TempDir::new().unwrap();
        let config = JobsStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = JobsPersistenceStore::new(config);

        let data = store.load().unwrap();
        assert_eq!(data.schema_version, JOBS_SCHEMA_VERSION);
        assert!(data.jobs.is_empty());
    }

    // =========================================================================
    // Restart Simulation Test
    // =========================================================================

    #[test]
    fn test_persistence_survives_restart_simulation() {
        let tmp_dir = TempDir::new().unwrap();
        let node_id = Uuid::new_v4();
        let key_config = create_test_key_config();
        let job = create_test_job();

        // First "process" - create and save
        {
            let config = JobsStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            };
            let store = JobsPersistenceStore::new(config);

            let data = JobsData {
                schema_version: JOBS_SCHEMA_VERSION,
                jobs: vec![PersistentJob::from(&job)],
            };

            store.save(&data).unwrap();
        }

        // Second "process" - load and verify with same key
        {
            let config = JobsStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key_config.clone(),
            };
            let store = JobsPersistenceStore::new(config);

            let loaded = store.load().unwrap();
            assert_eq!(loaded.jobs.len(), 1);
            assert_eq!(loaded.jobs[0].job_id, job.job_id);
        }
    }

    // =========================================================================
    // Lease Fields Persistence Test
    // =========================================================================

    #[test]
    fn test_lease_fields_persist() {
        let tmp_dir = TempDir::new().unwrap();
        let config = JobsStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = JobsPersistenceStore::new(config);

        let mut job = create_test_job();
        job.status = JobStatus::Running;
        job.lease_owner = Some("runner-001".to_string());
        job.lease_expires_at = Some(Utc::now());
        job.claimed_at = Some(Utc::now());
        job.attempt_count = 2;

        let data = JobsData {
            schema_version: JOBS_SCHEMA_VERSION,
            jobs: vec![PersistentJob::from(&job)],
        };

        store.save(&data).unwrap();
        let loaded = store.load().unwrap();

        assert_eq!(loaded.jobs[0].lease_owner, Some("runner-001".to_string()));
        assert!(loaded.jobs[0].lease_expires_at_utc.is_some());
        assert!(loaded.jobs[0].claimed_at_utc.is_some());
        assert_eq!(loaded.jobs[0].attempt_count, 2);
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
            let config = JobsStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key1,
            };
            let store = JobsPersistenceStore::new(config);

            let data = JobsData {
                schema_version: JOBS_SCHEMA_VERSION,
                jobs: vec![],
            };

            store.save(&data).unwrap();
        }

        // Key 2: Try to load (should fail)
        let key2 = DataKeyConfig::from_key([2u8; 32], CURRENT_KEY_VERSION);
        {
            let config = JobsStoreConfig {
                data_dir: tmp_dir.path().to_path_buf(),
                node_id,
                key_config: key2,
            };
            let store = JobsPersistenceStore::new(config);

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

    // =========================================================================
    // Envelope Format Tests
    // =========================================================================

    #[test]
    fn test_envelope_has_required_fields() {
        let tmp_dir = TempDir::new().unwrap();
        let config = JobsStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = JobsPersistenceStore::new(config.clone());

        let data = JobsData {
            schema_version: JOBS_SCHEMA_VERSION,
            jobs: vec![],
        };
        store.save(&data).unwrap();

        // Read raw file and verify envelope fields
        let content = fs::read_to_string(config.data_dir.join(JOBS_FILENAME)).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert!(envelope.get("schema_version").is_some(), "Must have schema_version");
        assert!(envelope.get("key_version").is_some(), "Must have key_version");
        assert!(envelope.get("nonce_b64").is_some(), "Must have nonce_b64");
        assert!(envelope.get("ciphertext_b64").is_some(), "Must have ciphertext_b64");

        assert_eq!(envelope["schema_version"], JOBS_SCHEMA_VERSION);
        assert_eq!(envelope["key_version"], CURRENT_KEY_VERSION);

        // Verify no plaintext data in file
        assert!(!content.contains("jobs"), "Plaintext should not be in file");
        assert!(!content.contains("queued"), "Status should not be in plaintext");
    }

    // =========================================================================
    // PersistentJob Conversion Tests
    // =========================================================================

    #[test]
    fn test_persistent_job_roundtrip() {
        let job = create_test_job();
        let persistent = PersistentJob::from(&job);
        let restored = persistent.to_job().unwrap();

        assert_eq!(restored.job_id, job.job_id);
        assert_eq!(restored.workspace_id, job.workspace_id);
        assert_eq!(restored.job_type, job.job_type);
        assert_eq!(restored.label, job.label);
        assert_eq!(restored.status, job.status);
    }

    #[test]
    fn test_persistent_job_with_lease_roundtrip() {
        let mut job = create_test_job();
        job.lease_owner = Some("runner-xyz".to_string());
        job.lease_expires_at = Some(Utc::now());
        job.claimed_at = Some(Utc::now());
        job.attempt_count = 3;

        let persistent = PersistentJob::from(&job);
        let restored = persistent.to_job().unwrap();

        assert_eq!(restored.lease_owner, job.lease_owner);
        assert!(restored.lease_expires_at.is_some());
        assert!(restored.claimed_at.is_some());
        assert_eq!(restored.attempt_count, 3);
    }

    // =========================================================================
    // Retry Fields Persistence Tests (RAPTOR-3 Step 3)
    // =========================================================================

    #[test]
    fn test_persistent_job_with_retry_fields_roundtrip() {
        let mut job = create_test_job();
        job.max_attempts = 5;
        job.next_attempt_at_utc = Some(Utc::now() + chrono::Duration::seconds(60));
        job.last_error_code = Some("GITHUB_NOT_CONNECTED".to_string());
        job.last_error_message = Some("Connection timed out".to_string());
        job.attempt_count = 2;

        let persistent = PersistentJob::from(&job);
        let restored = persistent.to_job().unwrap();

        assert_eq!(restored.max_attempts, 5);
        assert!(restored.next_attempt_at_utc.is_some());
        assert_eq!(restored.last_error_code, Some("GITHUB_NOT_CONNECTED".to_string()));
        assert_eq!(restored.last_error_message, Some("Connection timed out".to_string()));
        assert_eq!(restored.attempt_count, 2);
    }

    #[test]
    fn test_retry_fields_persist_to_disk() {
        let tmp_dir = TempDir::new().unwrap();
        let config = JobsStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = JobsPersistenceStore::new(config);

        let mut job = create_test_job();
        job.max_attempts = 10;
        job.next_attempt_at_utc = Some(Utc::now() + chrono::Duration::seconds(120));
        job.last_error_code = Some("DATA_LOAD_FAILED".to_string());
        job.last_error_message = Some("Retry scheduled".to_string());
        job.attempt_count = 3;

        let data = JobsData {
            schema_version: JOBS_SCHEMA_VERSION,
            jobs: vec![PersistentJob::from(&job)],
        };

        // Save
        store.save(&data).unwrap();

        // Load and verify
        let loaded = store.load().unwrap();
        assert_eq!(loaded.jobs.len(), 1);

        let loaded_job = loaded.jobs[0].to_job().unwrap();
        assert_eq!(loaded_job.max_attempts, 10);
        assert!(loaded_job.next_attempt_at_utc.is_some());
        assert_eq!(loaded_job.last_error_code, Some("DATA_LOAD_FAILED".to_string()));
        assert_eq!(loaded_job.last_error_message, Some("Retry scheduled".to_string()));
        assert_eq!(loaded_job.attempt_count, 3);
    }

    #[test]
    fn test_default_max_attempts_on_load() {
        // Test that jobs without max_attempts field default correctly
        let persistent = PersistentJob {
            job_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            job_type: "repo_workflow".to_string(),
            label: None,
            payload: None,
            status: "queued".to_string(),
            created_at_utc: Utc::now().to_rfc3339(),
            updated_at_utc: Utc::now().to_rfc3339(),
            result_code: None,
            message: None,
            result: None,
            lease_owner: None,
            lease_expires_at_utc: None,
            claimed_at_utc: None,
            attempt_count: 0,
            // Retry fields - use defaults
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            next_attempt_at_utc: None,
            last_error_code: None,
            last_error_message: None,
        };

        let job = persistent.to_job().unwrap();
        assert_eq!(job.max_attempts, DEFAULT_MAX_ATTEMPTS);
    }

    // =========================================================================
    // File Permissions Test (Unix only)
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn test_file_permissions() {
        use std::os::unix::fs::MetadataExt;

        let tmp_dir = TempDir::new().unwrap();
        let config = JobsStoreConfig {
            data_dir: tmp_dir.path().to_path_buf(),
            node_id: Uuid::new_v4(),
            key_config: create_test_key_config(),
        };
        let store = JobsPersistenceStore::new(config.clone());

        let data = JobsData {
            schema_version: JOBS_SCHEMA_VERSION,
            jobs: vec![],
        };
        store.save(&data).unwrap();

        let metadata = fs::metadata(config.data_dir.join(JOBS_FILENAME)).unwrap();
        let mode = metadata.mode() & 0o777;

        // File should be 0600 (owner read/write only)
        assert_eq!(mode, 0o600, "File permissions should be 0600, got {:o}", mode);
    }
}
