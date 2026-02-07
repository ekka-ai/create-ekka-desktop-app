//! Cryptographic utilities for EKKA - key derivation and AES-256-GCM encryption
//!
//! This crate provides:
//! - PBKDF2-based key derivation with configurable parameters
//! - AES-256-GCM authenticated encryption
//! - Versioned envelope format for future algorithm upgrades
//! - Zeroizing sensitive data on drop

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::Sha256;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Current crypto version for envelope format
pub const CRYPTO_VERSION: u8 = 1;

/// Default PBKDF2 iterations (100k for strong security)
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key size: expected 32 bytes, got {0}")]
    InvalidKeySize(usize),

    #[error("Ciphertext too short: {0} bytes (minimum 13)")]
    CiphertextTooShort(usize),

    #[error("Unsupported crypto version: {0}")]
    UnsupportedVersion(u8),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

/// Configuration for key derivation
#[derive(Debug, Clone)]
pub struct KeyDerivationConfig {
    /// Number of PBKDF2 iterations
    pub iterations: u32,
    /// Salt prefix for domain separation
    pub salt_prefix: String,
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            iterations: DEFAULT_PBKDF2_ITERATIONS,
            salt_prefix: "ekka-v1-".to_string(),
        }
    }
}

/// Key material that zeroizes on drop
#[derive(ZeroizeOnDrop)]
pub struct KeyMaterial {
    #[zeroize(skip)]
    version: u8,
    key: [u8; 32],
}

impl KeyMaterial {
    /// Create new key material
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            version: CRYPTO_VERSION,
            key,
        }
    }

    /// Get the raw key bytes (use with care)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Convert to hex string for SQLCipher
    pub fn to_hex(&self) -> String {
        hex::encode(&self.key)
    }
}

/// Derive an encryption key from user context and device secret
///
/// # Arguments
/// * `device_secret` - Device-specific secret from OS keychain
/// * `user_context` - User identifier or context
/// * `security_epoch` - Security epoch for key rotation
/// * `purpose_label` - Purpose-specific label for domain separation
/// * `config` - Key derivation configuration
pub fn derive_key(
    device_secret: &str,
    user_context: &str,
    security_epoch: u32,
    purpose_label: &str,
    config: &KeyDerivationConfig,
) -> KeyMaterial {
    // Combine inputs with clear separation
    let password = format!(
        "{}:{}:{}:{}",
        device_secret, user_context, security_epoch, purpose_label
    );

    // Create salt with prefix and purpose
    let salt = format!("{}{}", config.salt_prefix, purpose_label);

    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt.as_bytes(),
        config.iterations,
        &mut key,
    )
    .expect("PBKDF2 should not fail with valid parameters");

    KeyMaterial::new(key)
}

/// Versioned envelope for encrypted data
#[derive(Debug)]
pub struct EncryptedEnvelope {
    version: u8,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedEnvelope {
    /// Serialize to bytes: version || nonce || ciphertext
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 12 + self.ciphertext.len());
        result.push(self.version);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 13 {
            return Err(CryptoError::CiphertextTooShort(data.len()));
        }

        let version = data[0];
        if version != CRYPTO_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[1..13]);

        Ok(Self {
            version,
            nonce,
            ciphertext: data[13..].to_vec(),
        })
    }
}

/// Encrypt data using AES-256-GCM with versioned envelope
pub fn encrypt(plaintext: &[u8], key: &KeyMaterial) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Generate random nonce
    let mut rng = rand::thread_rng();
    let nonce_bytes: [u8; 12] = rng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let envelope = EncryptedEnvelope {
        version: CRYPTO_VERSION,
        nonce: nonce_bytes,
        ciphertext,
    };

    Ok(envelope.to_bytes())
}

/// Decrypt data using AES-256-GCM with versioned envelope
pub fn decrypt(encrypted: &[u8], key: &KeyMaterial) -> Result<Vec<u8>, CryptoError> {
    let envelope = EncryptedEnvelope::from_bytes(encrypted)?;

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&envelope.nonce);

    cipher
        .decrypt(nonce, envelope.ciphertext.as_slice())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt a string and return base64-encoded result
pub fn encrypt_string(plaintext: &str, key: &KeyMaterial) -> Result<String, CryptoError> {
    let encrypted = encrypt(plaintext.as_bytes(), key)?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted,
    ))
}

/// Decrypt a base64-encoded string
pub fn decrypt_string(ciphertext_base64: &str, key: &KeyMaterial) -> Result<String, CryptoError> {
    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        ciphertext_base64,
    )?;

    let plaintext = decrypt(&ciphertext, key)?;
    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let config = KeyDerivationConfig::default();
        let key1 = derive_key("device", "user", 1, "test", &config);
        let key2 = derive_key("device", "user", 1, "test", &config);
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_derivation_different_inputs() {
        let config = KeyDerivationConfig::default();
        let key1 = derive_key("device", "user", 1, "test", &config);
        let key2 = derive_key("device", "user", 2, "test", &config);
        let key3 = derive_key("device2", "user", 1, "test", &config);
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let config = KeyDerivationConfig::default();
        let key = derive_key("device", "user", 1, "test", &config);
        let plaintext = b"Hello, World!";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_string_roundtrip() {
        let config = KeyDerivationConfig::default();
        let key = derive_key("device", "user", 1, "test", &config);
        let plaintext = "Test with unicode: 你好";

        let encrypted = encrypt_string(plaintext, &key).unwrap();
        let decrypted = decrypt_string(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let config = KeyDerivationConfig::default();
        let key1 = derive_key("device", "user1", 1, "test", &config);
        let key2 = derive_key("device", "user2", 1, "test", &config);

        let encrypted = encrypt(b"secret", &key1).unwrap();
        let result = decrypt(&encrypted, &key2);

        assert!(result.is_err());
    }
}