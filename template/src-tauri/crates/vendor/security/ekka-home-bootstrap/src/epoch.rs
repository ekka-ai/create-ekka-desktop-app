//! Security Epoch Management
//!
//! Handles fetching current security epoch from various sources
//! and coordinating remote wipe operations when epochs mismatch.

use tracing::{debug, warn};

#[cfg(feature = "http-epoch")]
use std::time::Duration;
#[cfg(feature = "http-epoch")]
use tracing::info;

use crate::{BootstrapError, EpochSource};

// =============================================================================
// Security Epoch Manager
// =============================================================================

/// Manages security epoch fetching and validation
pub struct SecurityEpochManager {
    source: EpochSource,
}

impl SecurityEpochManager {
    /// Create new epoch manager with source configuration
    pub fn new(source: &EpochSource) -> Self {
        Self {
            source: source.clone(),
        }
    }

    /// Fetch current security epoch from configured source
    pub fn fetch_current_epoch(&self) -> Result<u32, BootstrapError> {
        match &self.source {
            EpochSource::EnvVar(env_var) => {
                let epoch_str = std::env::var(env_var)
                    .map_err(|_| BootstrapError::EpochFetch(
                        format!("Environment variable {} not set", env_var)
                    ))?;

                let epoch = epoch_str.parse::<u32>()
                    .map_err(|_| BootstrapError::EpochFetch(
                        format!("Invalid epoch value in {}: {}", env_var, epoch_str)
                    ))?;

                if epoch == 0 {
                    return Err(BootstrapError::EpochFetch(
                        "Epoch must be >= 1".to_string()
                    ));
                }

                debug!(
                    op = "epoch.fetch_env",
                    epoch = epoch,
                    source = env_var,
                    "Fetched epoch from environment variable"
                );

                Ok(epoch)
            }

            #[cfg(feature = "http-epoch")]
            EpochSource::Http { url, timeout_secs } => {
                self.fetch_epoch_http(url, *timeout_secs)
            }

            EpochSource::Fixed(epoch) => {
                debug!(
                    op = "epoch.fetch_fixed",
                    epoch = epoch,
                    "Using fixed epoch value"
                );
                Ok(*epoch)
            }
        }
    }

    #[cfg(feature = "http-epoch")]
    fn fetch_epoch_http(&self, url: &str, timeout_secs: u64) -> Result<u32, BootstrapError> {
        use reqwest::Client;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct EpochResponse {
            security_epoch: u32,
        }

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| BootstrapError::EpochFetch(format!("Failed to create tokio runtime: {}", e)))?;

        rt.block_on(async {
            let client = Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .build()
                .map_err(|e| BootstrapError::EpochFetch(format!("Failed to create HTTP client: {}", e)))?;

            debug!(
                op = "epoch.fetch_http",
                url = url,
                timeout = timeout_secs,
                "Fetching epoch from HTTP endpoint"
            );

            let response = client
                .get(url)
                .send()
                .await
                .map_err(|e| BootstrapError::EpochFetch(format!("HTTP request failed: {}", e)))?;

            if !response.status().is_success() {
                return Err(BootstrapError::EpochFetch(
                    format!("HTTP error: {}", response.status())
                ));
            }

            let epoch_response: EpochResponse = response
                .json()
                .await
                .map_err(|e| BootstrapError::EpochFetch(format!("Invalid JSON response: {}", e)))?;

            if epoch_response.security_epoch == 0 {
                return Err(BootstrapError::EpochFetch(
                    "Server returned invalid epoch (0)".to_string()
                ));
            }

            info!(
                op = "epoch.fetch_http_success",
                epoch = epoch_response.security_epoch,
                url = url,
                "Successfully fetched epoch from HTTP endpoint"
            );

            Ok(epoch_response.security_epoch)
        })
    }

    /// Check if epoch mismatch requires local wipe
    pub fn requires_wipe(&self, local_epoch: u32, remote_epoch: u32) -> bool {
        let needs_wipe = local_epoch != remote_epoch;

        if needs_wipe {
            warn!(
                op = "epoch.mismatch_detected",
                local_epoch = local_epoch,
                remote_epoch = remote_epoch,
                "Security epoch mismatch - wipe required"
            );
        } else {
            debug!(
                op = "epoch.match",
                epoch = local_epoch,
                "Security epoch matches - no wipe needed"
            );
        }

        needs_wipe
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_epoch_fetch() {
        std::env::set_var("TEST_EPOCH", "42");

        let source = EpochSource::EnvVar("TEST_EPOCH".to_string());
        let manager = SecurityEpochManager::new(&source);

        let epoch = manager.fetch_current_epoch().unwrap();
        assert_eq!(epoch, 42);

        std::env::remove_var("TEST_EPOCH");
    }

    #[test]
    fn test_env_epoch_missing() {
        let source = EpochSource::EnvVar("MISSING_EPOCH".to_string());
        let manager = SecurityEpochManager::new(&source);

        let result = manager.fetch_current_epoch();
        assert!(result.is_err());
    }

    #[test]
    fn test_env_epoch_invalid() {
        std::env::set_var("INVALID_EPOCH", "not-a-number");

        let source = EpochSource::EnvVar("INVALID_EPOCH".to_string());
        let manager = SecurityEpochManager::new(&source);

        let result = manager.fetch_current_epoch();
        assert!(result.is_err());

        std::env::remove_var("INVALID_EPOCH");
    }

    #[test]
    fn test_fixed_epoch() {
        let source = EpochSource::Fixed(123);
        let manager = SecurityEpochManager::new(&source);

        let epoch = manager.fetch_current_epoch().unwrap();
        assert_eq!(epoch, 123);
    }

    #[test]
    fn test_wipe_required() {
        let source = EpochSource::Fixed(1);
        let manager = SecurityEpochManager::new(&source);

        assert!(manager.requires_wipe(1, 2)); // Mismatch
        assert!(!manager.requires_wipe(2, 2)); // Match
    }
}