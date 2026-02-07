//! Gzip compression utilities

use crate::error::{ArtifactError, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Gzip compress data.
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Gzip decompress data.
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| ArtifactError::Decompression(e.to_string()))?;
    Ok(decompressed)
}

/// Check if content type should be compressed.
pub fn should_compress(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.contains("json")
        || ct.contains("text")
        || ct.contains("jsonl")
        || ct.contains("xml")
        || ct.contains("csv")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"hello world, this is test data for compression";
        let compressed = gzip_compress(data).unwrap();
        let decompressed = gzip_decompress(&compressed).unwrap();
        assert_eq!(data.to_vec(), decompressed);
    }

    #[test]
    fn test_should_compress() {
        assert!(should_compress("application/json"));
        assert!(should_compress("text/plain"));
        assert!(should_compress("application/x-jsonl"));
        assert!(!should_compress("image/png"));
        assert!(!should_compress("application/octet-stream"));
    }
}
