//! Grant Store - Loading and Verification
//!
//! Handles loading grants from `<EKKA_HOME>/grants.json` and verifying
//! Ed25519 signatures from the engine.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

use crate::{GrantsFile, PathGrant, PathGuardError};

// =============================================================================
// Grant Store
// =============================================================================

/// Grant store for loading and verifying engine-signed grants
pub struct GrantStore {
    /// Path to grants.json file
    grants_path: PathBuf,
    /// Engine public key for signature verification
    engine_verify_key: VerifyingKey,
    /// Cached grants (loaded and verified)
    grants: Vec<PathGrant>,
}

impl GrantStore {
    /// Create a new grant store
    ///
    /// # Arguments
    /// * `grants_path` - Path to grants.json file (typically `<EKKA_HOME>/grants.json`)
    /// * `engine_verify_key_b64` - Base64-encoded Ed25519 public key from engine
    ///
    /// # Errors
    /// Returns error if key is invalid or cannot be decoded
    pub fn new(grants_path: PathBuf, engine_verify_key_b64: &str) -> Result<Self, PathGuardError> {
        let engine_verify_key = decode_verify_key(engine_verify_key_b64)?;

        info!(
            grants_path = %grants_path.display(),
            key_fingerprint = %key_fingerprint(engine_verify_key_b64),
            "Grant store initialized"
        );

        let mut store = Self {
            grants_path,
            engine_verify_key,
            grants: Vec::new(),
        };

        // Load grants on creation
        store.reload()?;

        Ok(store)
    }

    /// Load engine verify key from environment variable
    ///
    /// # Errors
    /// Returns `MissingVerificationKey` if env var not set or invalid
    pub fn key_from_env() -> Result<String, PathGuardError> {
        std::env::var("ENGINE_GRANT_VERIFY_KEY_B64").map_err(|_| {
            error!("ENGINE_GRANT_VERIFY_KEY_B64 not set");
            PathGuardError::MissingVerificationKey
        })
    }

    /// Reload grants from disk, verifying each signature
    pub fn reload(&mut self) -> Result<(), PathGuardError> {
        if !self.grants_path.exists() {
            debug!(
                grants_path = %self.grants_path.display(),
                "Grants file does not exist, starting empty"
            );
            self.grants = Vec::new();
            return Ok(());
        }

        let content = fs::read_to_string(&self.grants_path)?;
        let grants_file: GrantsFile = serde_json::from_str(&content).map_err(|e| {
            error!(error = %e, "Failed to parse grants.json");
            PathGuardError::InvalidGrant {
                reason: format!("Failed to parse grants.json: {}", e),
            }
        })?;

        // Verify each grant and filter out invalid ones
        let now = current_timestamp();
        let mut valid_grants = Vec::new();
        let total_count = grants_file.grants.len();

        for grant in grants_file.grants {
            match self.verify_grant(&grant, now) {
                Ok(()) => {
                    debug!(
                        path_prefix = %grant.path_prefix(),
                        tenant_id = %grant.tenant_id(),
                        "Grant verified"
                    );
                    valid_grants.push(grant);
                }
                Err(e) => {
                    warn!(
                        path_prefix = %grant.path_prefix(),
                        error = %e,
                        "Grant verification failed, skipping"
                    );
                }
            }
        }

        info!(
            total = total_count,
            valid = valid_grants.len(),
            "Grants loaded"
        );

        self.grants = valid_grants;
        Ok(())
    }

    /// Get all valid grants
    pub fn grants(&self) -> &[PathGrant] {
        &self.grants
    }

    /// Verify a grant's schema, signature, and expiration
    fn verify_grant(&self, grant: &PathGrant, now: i64) -> Result<(), PathGuardError> {
        // 1. Validate unified schema (REQUIRED - no legacy support)
        grant.validate_schema()?;

        // 2. Check expiration
        if grant.expires_at() < now {
            return Err(PathGuardError::ExpiredGrant {
                expired_at: grant.expires_at(),
                current_time: now,
            });
        }

        // 3. Verify signature
        verify_grant_signature(&grant.signed_grant, &self.engine_verify_key)?;

        Ok(())
    }

    /// Verify grant context matches session (tenant_id, subject)
    pub fn validate_grant_context(
        grant: &PathGrant,
        tenant_id: &str,
        subject: &str,
    ) -> Result<(), PathGuardError> {
        if grant.tenant_id() != tenant_id {
            return Err(PathGuardError::TenantMismatch {
                expected: tenant_id.to_string(),
                actual: grant.tenant_id().to_string(),
            });
        }

        if grant.subject() != subject {
            return Err(PathGuardError::SubjectMismatch {
                expected: subject.to_string(),
                actual: grant.subject().to_string(),
            });
        }

        Ok(())
    }

    /// Find grants that cover a path, sorted by specificity (most specific first)
    pub fn find_grants_for_path(&self, canonical_path: &Path) -> Vec<&PathGrant> {
        let mut matching: Vec<&PathGrant> = self
            .grants
            .iter()
            .filter(|g| g.covers_path(canonical_path))
            .collect();

        // Sort by specificity descending (longest prefix first)
        matching.sort_by(|a, b| b.specificity().cmp(&a.specificity()));

        matching
    }

    /// Add a grant (after verification)
    ///
    /// Typically called when receiving a new grant from the engine.
    pub fn add_grant(&mut self, grant: PathGrant) -> Result<(), PathGuardError> {
        let now = current_timestamp();
        self.verify_grant(&grant, now)?;
        self.grants.push(grant);
        Ok(())
    }

    /// Save grants to disk
    pub fn save(&self) -> Result<(), PathGuardError> {
        let grants_file = GrantsFile {
            schema_version: "1.0".to_string(),
            grants: self.grants.clone(),
        };

        let content = serde_json::to_string_pretty(&grants_file).map_err(|e| {
            PathGuardError::InvalidGrant {
                reason: format!("Failed to serialize grants: {}", e),
            }
        })?;

        // Ensure parent directory exists
        if let Some(parent) = self.grants_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.grants_path, content)?;

        info!(
            grants_path = %self.grants_path.display(),
            count = self.grants.len(),
            "Grants saved"
        );

        Ok(())
    }
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Decode base64-encoded Ed25519 public key
fn decode_verify_key(key_b64: &str) -> Result<VerifyingKey, PathGuardError> {
    let key_bytes = BASE64.decode(key_b64).map_err(|e| PathGuardError::InvalidGrant {
        reason: format!("Invalid base64 in verify key: {}", e),
    })?;

    if key_bytes.len() != 32 {
        return Err(PathGuardError::InvalidGrant {
            reason: format!("Verify key must be 32 bytes, got {}", key_bytes.len()),
        });
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    VerifyingKey::from_bytes(&key_array).map_err(|e| PathGuardError::InvalidGrant {
        reason: format!("Invalid Ed25519 public key: {}", e),
    })
}

/// Verify grant signature using engine public key
fn verify_grant_signature(
    signed_grant: &crate::SignedGrant,
    engine_key: &VerifyingKey,
) -> Result<(), PathGuardError> {
    // Decode canonical grant bytes
    let canonical_bytes = BASE64
        .decode(&signed_grant.grant_canonical_b64)
        .map_err(|e| PathGuardError::InvalidGrant {
            reason: format!("Invalid grant_canonical_b64: {}", e),
        })?;

    // Decode signature
    let signature_bytes = BASE64
        .decode(&signed_grant.signature_b64)
        .map_err(|e| PathGuardError::InvalidGrant {
            reason: format!("Invalid signature_b64: {}", e),
        })?;

    if signature_bytes.len() != 64 {
        return Err(PathGuardError::InvalidGrant {
            reason: format!("Signature must be 64 bytes, got {}", signature_bytes.len()),
        });
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_array);

    // Verify
    engine_key
        .verify(&canonical_bytes, &signature)
        .map_err(|_| PathGuardError::InvalidGrant {
            reason: "Signature verification failed".to_string(),
        })
}

/// Compute fingerprint of a key for logging (first 8 chars of base64)
fn key_fingerprint(key_b64: &str) -> String {
    if key_b64.len() >= 8 {
        format!("{}...", &key_b64[..8])
    } else {
        key_b64.to_string()
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Grant, GrantConsent, GrantPermissions, GrantResource, PathAccess,
        PathResourceAttrs, PathType, SignedGrant,
    };
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    /// Generate a test keypair
    fn test_keypair() -> (SigningKey, String) {
        // RFC 8032 test vector
        let secret_bytes: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verify_key = signing_key.verifying_key();
        let verify_key_b64 = BASE64.encode(verify_key.as_bytes());
        (signing_key, verify_key_b64)
    }

    /// Create a unified signed grant for testing
    fn create_test_grant(
        signing_key: &SigningKey,
        path_prefix: &str,
        tenant_id: &str,
        subject: &str,
        expires_at: i64,
    ) -> PathGrant {
        use ed25519_dalek::Signer;

        let expires_at_str = chrono::DateTime::from_timestamp(expires_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "2099-01-01T00:00:00Z".to_string());

        let grant = Grant {
            sub: subject.to_string(),
            tenant_id: tenant_id.to_string(),
            node_id: uuid::Uuid::new_v4(),
            grant_id: uuid::Uuid::new_v4().to_string(),
            issuer: "ekka-engine".to_string(),
            issued_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: Some(expires_at_str),
            resource: GrantResource::Path {
                path_prefix: path_prefix.to_string(),
                attrs: Some(PathResourceAttrs {
                    path_type: Some(PathType::Workspace),
                }),
            },
            permissions: GrantPermissions {
                ops: vec!["read".to_string(), "write".to_string(), "delete".to_string()],
                access: Some(PathAccess::ReadWrite),
            },
            purpose: "workspace_access".to_string(),
            consent: GrantConsent {
                mode: "user_click".to_string(),
                approved_at: "2024-01-01T00:00:00Z".to_string(),
                approved_by: subject.to_string(),
            },
        };

        // Canonical JSON (must match what engine produces)
        let canonical_json = serde_json::to_string(&grant).unwrap();
        let canonical_b64 = BASE64.encode(canonical_json.as_bytes());

        // Sign
        let signature = signing_key.sign(canonical_json.as_bytes());
        let signature_b64 = BASE64.encode(signature.to_bytes());

        PathGrant {
            signed_grant: SignedGrant {
                schema: "GRANT".to_string(),
                canon_alg: "SECURITY.CANONICALIZE.V1".to_string(),
                signing_alg: "ed25519".to_string(),
                grant,
                grant_canonical_b64: canonical_b64,
                signature_b64,
            },
            path_type: PathType::Workspace,
            path_access: PathAccess::ReadWrite,
        }
    }

    #[test]
    fn test_valid_grant_accepted() {
        let (signing_key, verify_key_b64) = test_keypair();
        let temp_dir = TempDir::new().unwrap();
        let grants_path = temp_dir.path().join("grants.json");

        let store = GrantStore::new(grants_path, &verify_key_b64).unwrap();

        let grant = create_test_grant(
            &signing_key,
            "/home/user/projects",
            "tenant-1",
            "user-1",
            current_timestamp() + 3600, // 1 hour from now
        );

        // Verify should succeed
        let result = store.verify_grant(&grant, current_timestamp());
        assert!(result.is_ok(), "Valid grant should be accepted");
    }

    #[test]
    fn test_invalid_signature_denied() {
        let (_signing_key, verify_key_b64) = test_keypair();
        let temp_dir = TempDir::new().unwrap();
        let grants_path = temp_dir.path().join("grants.json");

        let store = GrantStore::new(grants_path, &verify_key_b64).unwrap();

        // Create grant with wrong signature (but valid unified schema)
        let grant = PathGrant {
            signed_grant: SignedGrant {
                schema: "GRANT".to_string(),
                canon_alg: "SECURITY.CANONICALIZE.V1".to_string(),
                signing_alg: "ed25519".to_string(),
                grant: Grant {
                    sub: "user-1".to_string(),
                    tenant_id: "tenant-1".to_string(),
                    node_id: uuid::Uuid::new_v4(),
                    grant_id: uuid::Uuid::new_v4().to_string(),
                    issuer: "ekka-engine".to_string(),
                    issued_at: "2024-01-01T00:00:00Z".to_string(),
                    expires_at: Some("2099-01-01T00:00:00Z".to_string()),
                    resource: GrantResource::Path {
                        path_prefix: "/home/user/projects".to_string(),
                        attrs: Some(PathResourceAttrs {
                            path_type: Some(PathType::Workspace),
                        }),
                    },
                    permissions: GrantPermissions {
                        ops: vec!["read".to_string()],
                        access: Some(PathAccess::ReadWrite),
                    },
                    purpose: "workspace_access".to_string(),
                    consent: GrantConsent {
                        mode: "user_click".to_string(),
                        approved_at: "2024-01-01T00:00:00Z".to_string(),
                        approved_by: "user-1".to_string(),
                    },
                },
                grant_canonical_b64: BASE64.encode(b"some data"),
                signature_b64: BASE64.encode(&[0u8; 64]), // Invalid signature
            },
            path_type: PathType::Workspace,
            path_access: PathAccess::ReadWrite,
        };

        let result = store.verify_grant(&grant, current_timestamp());
        assert!(result.is_err(), "Invalid signature should be denied");
        assert!(matches!(
            result.unwrap_err(),
            PathGuardError::InvalidGrant { .. }
        ));
    }

    #[test]
    fn test_expired_grant_denied() {
        let (signing_key, verify_key_b64) = test_keypair();
        let temp_dir = TempDir::new().unwrap();
        let grants_path = temp_dir.path().join("grants.json");

        let store = GrantStore::new(grants_path, &verify_key_b64).unwrap();

        let grant = create_test_grant(
            &signing_key,
            "/home/user/projects",
            "tenant-1",
            "user-1",
            current_timestamp() - 3600, // Expired 1 hour ago
        );

        let result = store.verify_grant(&grant, current_timestamp());
        assert!(result.is_err(), "Expired grant should be denied");
        assert!(matches!(
            result.unwrap_err(),
            PathGuardError::ExpiredGrant { .. }
        ));
    }

    #[test]
    fn test_tenant_mismatch_denied() {
        let (signing_key, _verify_key_b64) = test_keypair();

        let grant = create_test_grant(
            &signing_key,
            "/home/user/projects",
            "tenant-1",
            "user-1",
            current_timestamp() + 3600,
        );

        let result = GrantStore::validate_grant_context(&grant, "tenant-2", "user-1");
        assert!(result.is_err(), "Tenant mismatch should be denied");
        assert!(matches!(
            result.unwrap_err(),
            PathGuardError::TenantMismatch { .. }
        ));
    }

    #[test]
    fn test_subject_mismatch_denied() {
        let (signing_key, _verify_key_b64) = test_keypair();

        let grant = create_test_grant(
            &signing_key,
            "/home/user/projects",
            "tenant-1",
            "user-1",
            current_timestamp() + 3600,
        );

        let result = GrantStore::validate_grant_context(&grant, "tenant-1", "user-2");
        assert!(result.is_err(), "Subject mismatch should be denied");
        assert!(matches!(
            result.unwrap_err(),
            PathGuardError::SubjectMismatch { .. }
        ));
    }

    #[test]
    fn test_grant_persistence() {
        let (signing_key, verify_key_b64) = test_keypair();
        let temp_dir = TempDir::new().unwrap();
        let grants_path = temp_dir.path().join("grants.json");

        // Create store and add grant
        let mut store = GrantStore::new(grants_path.clone(), &verify_key_b64).unwrap();

        let grant = create_test_grant(
            &signing_key,
            "/home/user/projects",
            "tenant-1",
            "user-1",
            current_timestamp() + 3600,
        );

        store.add_grant(grant).unwrap();
        store.save().unwrap();

        // Reload and verify
        let store2 = GrantStore::new(grants_path, &verify_key_b64).unwrap();
        assert_eq!(store2.grants().len(), 1);
        assert_eq!(
            store2.grants()[0].path_prefix(),
            "/home/user/projects"
        );
    }

    #[test]
    fn test_find_grants_by_specificity() {
        let (signing_key, verify_key_b64) = test_keypair();
        let temp_dir = TempDir::new().unwrap();
        let grants_path = temp_dir.path().join("grants.json");

        let mut store = GrantStore::new(grants_path, &verify_key_b64).unwrap();

        // Add grants with different specificities
        let exp = current_timestamp() + 3600;
        store
            .add_grant(create_test_grant(
                &signing_key,
                "/home/user",
                "t1",
                "u1",
                exp,
            ))
            .unwrap();
        store
            .add_grant(create_test_grant(
                &signing_key,
                "/home/user/projects",
                "t1",
                "u1",
                exp,
            ))
            .unwrap();
        store
            .add_grant(create_test_grant(
                &signing_key,
                "/home/user/projects/myapp",
                "t1",
                "u1",
                exp,
            ))
            .unwrap();

        // Find grants for a specific path
        let path = Path::new("/home/user/projects/myapp/src/main.rs");
        let matching = store.find_grants_for_path(path);

        // Should be sorted by specificity (most specific first)
        assert_eq!(matching.len(), 3);
        assert_eq!(matching[0].path_prefix(), "/home/user/projects/myapp");
        assert_eq!(matching[1].path_prefix(), "/home/user/projects");
        assert_eq!(matching[2].path_prefix(), "/home/user");
    }
}
