//! Artifact store errors

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArtifactError {
    #[error("Artifact not found: {0}")]
    NotFound(String),

    #[error("Invalid artifact URI: {0}")]
    InvalidUri(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Decompression error: {0}")]
    Decompression(String),
}

pub type Result<T> = std::result::Result<T, ArtifactError>;
