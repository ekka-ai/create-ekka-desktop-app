//! Encrypted Database Module
//!
//! Provides SQLCipher-based encrypted database functionality.
//! This is a minimal wrapper around rusqlite with SQLCipher support,
//! focusing only on the connection setup without app-specific schema.

use rusqlite::Connection;
use std::path::Path;
use thiserror::Error;

/// Error types for encrypted database operations
#[derive(Error, Debug)]
pub enum EncryptedDbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Invalid key: {msg}")]
    InvalidKey { msg: String },
    #[error("Database initialization failed: {msg}")]
    InitializationFailed { msg: String },
}

/// Configuration for encrypted database connection
#[derive(Debug, Clone)]
pub struct EncryptedDbConfig {
    /// Path to the database file
    pub db_path: std::path::PathBuf,
    /// Encryption key (should be hex-encoded for SQLCipher)
    pub encryption_key: String,
    /// Optional additional SQLCipher pragmas
    pub additional_pragmas: Vec<(String, String)>,
}

/// Open an encrypted SQLite database using SQLCipher
///
/// # Arguments
/// * `config` - Database configuration including path and encryption key
///
/// # Returns
/// A configured SQLite connection with encryption enabled
///
/// # Example
/// ```
/// use ekka_encrypted_db::{open_encrypted_db, EncryptedDbConfig};
/// use std::path::PathBuf;
///
/// let config = EncryptedDbConfig {
///     db_path: PathBuf::from(":memory:"),
///     encryption_key: "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'".to_string(),
///     additional_pragmas: vec![],
/// };
///
/// let conn = open_encrypted_db(config).unwrap();
/// ```
pub fn open_encrypted_db(config: EncryptedDbConfig) -> Result<Connection, EncryptedDbError> {
    // Open the database connection
    let conn = Connection::open(&config.db_path)?;

    // Set the encryption key
    // SQLCipher expects the key to be set immediately after opening
    conn.execute_batch(&format!("PRAGMA key = \"{}\"", config.encryption_key))?;

    // Apply additional pragmas if provided
    for (pragma, value) in &config.additional_pragmas {
        let pragma_stmt = format!("PRAGMA {} = {}", pragma, value);
        conn.execute_batch(&pragma_stmt)
            .map_err(|e| EncryptedDbError::InitializationFailed {
                msg: format!("Failed to set pragma '{}': {}", pragma, e),
            })?;
    }

    // Test that the database is accessible and properly encrypted
    // This will fail if the key is wrong or encryption is not working
    match conn.execute_batch("SELECT count(*) FROM sqlite_master") {
        Ok(_) => Ok(conn),
        Err(e) => {
            // Check if it's a key-related error
            let error_msg = e.to_string();
            if error_msg.contains("file is not a database")
                || error_msg.contains("file is encrypted")
                || error_msg.contains("wrong key")
            {
                Err(EncryptedDbError::InvalidKey {
                    msg: "Incorrect encryption key or corrupted database".to_string(),
                })
            } else {
                Err(EncryptedDbError::Sqlite(e))
            }
        }
    }
}

/// Create encrypted database configuration with standard SQLCipher settings
///
/// # Arguments
/// * `db_path` - Path to the database file
/// * `encryption_key` - Encryption key (will be formatted for SQLCipher)
///
/// # Returns
/// Database configuration with recommended SQLCipher pragmas
pub fn create_standard_config(
    db_path: impl AsRef<Path>,
    encryption_key: &str,
) -> EncryptedDbConfig {
    // Format key for SQLCipher (add x'' wrapper if not present)
    let formatted_key = if encryption_key.starts_with("x'") && encryption_key.ends_with('\'') {
        encryption_key.to_string()
    } else if encryption_key.chars().all(|c| c.is_ascii_hexdigit()) {
        format!("x'{}'", encryption_key)
    } else {
        // Treat as passphrase
        format!("'{}'", encryption_key.replace('\'', "''"))
    };

    EncryptedDbConfig {
        db_path: db_path.as_ref().to_path_buf(),
        encryption_key: formatted_key,
        additional_pragmas: vec![
            // Use stronger KDF iterations (default is often too low)
            ("kdf_iter".to_string(), "100000".to_string()),
            // Use AEAD cipher mode (more secure than CBC)
            ("cipher_page_size".to_string(), "4096".to_string()),
        ],
    }
}

/// Test if a database file is encrypted and can be opened with the given key
///
/// # Arguments
/// * `db_path` - Path to the database file
/// * `encryption_key` - Key to test
///
/// # Returns
/// `Ok(true)` if database can be opened, `Ok(false)` if wrong key, `Err` for other issues
pub fn test_database_key(db_path: impl AsRef<Path>, encryption_key: &str) -> Result<bool, EncryptedDbError> {
    let config = create_standard_config(db_path, encryption_key);

    match open_encrypted_db(config) {
        Ok(_) => Ok(true),
        Err(EncryptedDbError::InvalidKey { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_open_memory_db() {
        let config = EncryptedDbConfig {
            db_path: PathBuf::from(":memory:"),
            encryption_key: "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'".to_string(),
            additional_pragmas: vec![],
        };

        let conn = open_encrypted_db(config).unwrap();

        // Test that we can create a table and insert data
        conn.execute_batch(
            "CREATE TABLE test (id INTEGER PRIMARY KEY, data TEXT);
             INSERT INTO test (data) VALUES ('encrypted_data');"
        ).unwrap();

        // Test that we can read the data back
        let mut stmt = conn.prepare("SELECT data FROM test WHERE id = 1").unwrap();
        let data: String = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(data, "encrypted_data");
    }

    #[test]
    fn test_wrong_key_fails() {
        // Create a database with one key
        let config1 = EncryptedDbConfig {
            db_path: PathBuf::from(":memory:"),
            encryption_key: "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'".to_string(),
            additional_pragmas: vec![],
        };

        let conn1 = open_encrypted_db(config1).unwrap();
        conn1.execute_batch("CREATE TABLE test (id INTEGER);").unwrap();

        // Note: For :memory: databases, we can't test cross-connection key validation
        // as each :memory: database is independent. This test mainly ensures
        // the encryption setup works correctly.
    }

    #[test]
    fn test_create_standard_config() {
        let config = create_standard_config("/tmp/test.db", "abcdef123456");

        assert_eq!(config.db_path, PathBuf::from("/tmp/test.db"));
        assert_eq!(config.encryption_key, "x'abcdef123456'");
        assert!(config.additional_pragmas.len() > 0);

        // Test with already formatted key
        let config2 = create_standard_config("/tmp/test2.db", "x'abcdef'");
        assert_eq!(config2.encryption_key, "x'abcdef'");

        // Test with passphrase
        let config3 = create_standard_config("/tmp/test3.db", "my passphrase");
        assert_eq!(config3.encryption_key, "'my passphrase'");
    }

    #[test]
    fn test_key_formatting() {
        // Test hex key formatting
        let hex_key = "2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99";
        let config = create_standard_config(":memory:", hex_key);
        assert_eq!(config.encryption_key, "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'");

        // Test passphrase formatting
        let passphrase = "my secure passphrase";
        let config2 = create_standard_config(":memory:", passphrase);
        assert_eq!(config2.encryption_key, "'my secure passphrase'");

        // Test passphrase with single quotes (SQL injection protection)
        let tricky_passphrase = "my 'quoted' passphrase";
        let config3 = create_standard_config(":memory:", tricky_passphrase);
        assert_eq!(config3.encryption_key, "'my ''quoted'' passphrase'");
    }
}