//! Well-Known Configuration Fetcher
//!
//! Fetches public configuration from the EKKA Engine's /.well-known/ekka-configuration endpoint.
//! This includes the grant verification key needed for cryptographic grant validation.

use crate::config;
use serde::Deserialize;

/// Response from /.well-known/ekka-configuration
#[derive(Debug, Deserialize)]
pub struct WellKnownConfig {
    pub grant_verify_key_b64: String,
    pub grant_signing_algorithm: String,
    #[serde(default)]
    pub api_version: Option<String>,
}

/// Fetch the well-known configuration from the engine.
/// Returns the grant verification key (base64).
pub async fn fetch_grant_verify_key() -> Result<String, String> {
    let engine_url = config::engine_url();
    let url = format!("{}/engine/.well-known/ekka-configuration", engine_url.trim_end_matches('/'));

    tracing::info!(
        op = "well_known.fetch.start",
        url = %url,
        "Fetching grant verification key from engine"
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(&url)
        .header("X-EKKA-CLIENT", config::app_slug())
        .send()
        .await
        .map_err(|e| format!("Failed to fetch well-known config: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Engine returned error: {} {}",
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ));
    }

    let config: WellKnownConfig = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse well-known config: {}", e))?;

    tracing::info!(
        op = "well_known.fetch.success",
        algorithm = %config.grant_signing_algorithm,
        "Grant verification key fetched successfully"
    );

    Ok(config.grant_verify_key_b64)
}

/// Fetch and cache the grant verification key in state.
/// Also sets ENGINE_GRANT_VERIFY_KEY_B64 env var for SDK compatibility.
/// This is called on app startup.
pub async fn fetch_and_cache_verify_key(state: &crate::state::EngineState) -> Result<(), String> {
    let key = fetch_grant_verify_key().await?;

    // Cache in state
    state.set_grant_verify_key(key.clone());

    // Also set env var for SDK compatibility (ekka-ops, ekka-path-guard use it)
    std::env::set_var("ENGINE_GRANT_VERIFY_KEY_B64", &key);

    Ok(())
}
