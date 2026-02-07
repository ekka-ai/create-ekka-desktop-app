//! EKKA Error Types
//!
//! Unified error handling for SDK operations.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// EKKA operation error
#[derive(Error, Debug)]
#[error("{message}")]
pub struct EkkaError {
    /// Error code (e.g., "NOT_AUTHENTICATED", "GRANT_DENIED")
    pub code: &'static str,
    /// Human-readable message
    pub message: String,
    /// Optional structured details
    pub details: Option<serde_json::Value>,
    /// Source error (for error chaining)
    #[source]
    pub source: Option<anyhow::Error>,
}

impl EkkaError {
    /// Create a new error with code and message
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            source: None,
        }
    }

    /// Create an error with details
    pub fn with_details(code: &'static str, message: impl Into<String>, details: serde_json::Value) -> Self {
        Self {
            code,
            message: message.into(),
            details: Some(details),
            source: None,
        }
    }

    /// Create an error from a source error
    pub fn from_source<E: std::error::Error + Send + Sync + 'static>(
        code: &'static str,
        message: impl Into<String>,
        source: E,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            source: Some(anyhow::Error::from(source)),
        }
    }

    /// Add source error to existing error
    pub fn with_source<E: std::error::Error + Send + Sync + 'static>(mut self, source: E) -> Self {
        self.source = Some(anyhow::Error::from(source));
        self
    }
}

/// Serializable error for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl From<&EkkaError> for ErrorResponse {
    fn from(err: &EkkaError) -> Self {
        Self {
            code: err.code.to_string(),
            message: err.message.clone(),
            details: err.details.clone(),
        }
    }
}

impl From<EkkaError> for ErrorResponse {
    fn from(err: EkkaError) -> Self {
        Self {
            code: err.code.to_string(),
            message: err.message,
            details: err.details,
        }
    }
}

// =============================================================================
// Common Error Codes
// =============================================================================

pub mod codes {
    pub const NOT_AUTHENTICATED: &str = "NOT_AUTHENTICATED";
    pub const HOME_NOT_INITIALIZED: &str = "HOME_NOT_INITIALIZED";
    pub const HOME_GRANT_REQUIRED: &str = "HOME_GRANT_REQUIRED";
    pub const GRANT_DENIED: &str = "GRANT_DENIED";
    pub const GRANT_NOT_FOUND: &str = "GRANT_NOT_FOUND";
    pub const GRANT_EXPIRED: &str = "GRANT_EXPIRED";
    pub const PATH_NOT_ALLOWED: &str = "PATH_NOT_ALLOWED";
    pub const PATH_NOT_FOUND: &str = "PATH_NOT_FOUND";
    pub const INVALID_PATH: &str = "INVALID_PATH";
    pub const ENGINE_ERROR: &str = "ENGINE_ERROR";
    pub const IO_ERROR: &str = "IO_ERROR";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";

    // Vault error codes
    pub const VAULT_NOT_INITIALIZED: &str = "VAULT_NOT_INITIALIZED";
    pub const VAULT_ERROR: &str = "VAULT_ERROR";
    pub const SECRET_NOT_FOUND: &str = "SECRET_NOT_FOUND";
    pub const SECRET_ALREADY_EXISTS: &str = "SECRET_ALREADY_EXISTS";
    pub const BUNDLE_NOT_FOUND: &str = "BUNDLE_NOT_FOUND";
    pub const BUNDLE_ALREADY_EXISTS: &str = "BUNDLE_ALREADY_EXISTS";
    pub const INVALID_SECRET_NAME: &str = "INVALID_SECRET_NAME";
    pub const AMBIGUOUS_SECRET_REF: &str = "AMBIGUOUS_SECRET_REF";

    // File error codes
    pub const FILE_NOT_FOUND: &str = "FILE_NOT_FOUND";
    pub const FILE_ALREADY_EXISTS: &str = "FILE_ALREADY_EXISTS";
    pub const DIRECTORY_NOT_EMPTY: &str = "DIRECTORY_NOT_EMPTY";
    pub const PATH_TRAVERSAL_DENIED: &str = "PATH_TRAVERSAL_DENIED";

    // Deferred operations
    pub const NOT_IMPLEMENTED: &str = "NOT_IMPLEMENTED";

    // Validation errors
    pub const VALIDATION_ERROR: &str = "VALIDATION_ERROR";
}

// =============================================================================
// Result Type Alias
// =============================================================================

/// Result type for EKKA operations
pub type EkkaResult<T> = Result<T, EkkaError>;
