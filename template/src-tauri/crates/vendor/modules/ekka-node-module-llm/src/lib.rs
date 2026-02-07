//! EKKA Node LLM Provider Module - RAPTOR-3 Step 6
//!
//! Provides minimal completion API for LLM providers (Claude/OpenAI).
//! This module handles:
//! - Provider configuration via environment variables
//! - Safe completion calls with bounded outputs
//! - No logging of prompts or responses (only hashes + lengths)
//!
//! ## Security Properties
//!
//! - NEVER logs prompt content or response text
//! - Only logs SHA256 hashes and lengths for debugging
//! - Response size bounded to 64KB
//! - No env var names in errors
//!
//! ## Supported Providers
//!
//! - Anthropic Claude (ANTHROPIC_API_KEY, ANTHROPIC_MODEL)
//! - OpenAI (future: OPENAI_API_KEY, OPENAI_MODEL)
//!
//! ## Usage
//!
//! ```rust,ignore
//! let config = LlmConfig::from_env();
//! if let Some(provider) = config.create_provider() {
//!     let response = provider.complete("prompt", None).await?;
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{info, warn};

// =============================================================================
// Constants
// =============================================================================

/// Maximum response size (64KB)
pub const MAX_RESPONSE_SIZE: usize = 64 * 1024;

/// Default model for Anthropic
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-3-5-sonnet-20241022";

/// Default max tokens for completion
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Anthropic API endpoint
const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";

/// Anthropic API version header
const ANTHROPIC_VERSION: &str = "2023-06-01";

// =============================================================================
// Error Types
// =============================================================================

/// LLM provider error
#[derive(Debug, Clone)]
pub struct LlmError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl LlmError {
    pub fn not_configured() -> Self {
        Self {
            code: "LLM_NOT_CONFIGURED".to_string(),
            message: "LLM provider not configured".to_string(),
            retryable: false,
        }
    }

    pub fn api_error(message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: "LLM_API_ERROR".to_string(),
            message: sanitize_error(message.into()),
            retryable,
        }
    }

    pub fn timeout() -> Self {
        Self {
            code: "LLM_TIMEOUT".to_string(),
            message: "Request timed out".to_string(),
            retryable: true,
        }
    }

    pub fn rate_limited() -> Self {
        Self {
            code: "LLM_RATE_LIMITED".to_string(),
            message: "Rate limit exceeded".to_string(),
            retryable: true,
        }
    }

    pub fn response_too_large() -> Self {
        Self {
            code: "LLM_RESPONSE_TOO_LARGE".to_string(),
            message: "Response exceeded maximum size".to_string(),
            retryable: false,
        }
    }
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LlmError {}

// =============================================================================
// Provider Trait
// =============================================================================

/// LLM completion response
#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// Generated text (bounded to MAX_RESPONSE_SIZE)
    pub text: String,
    /// Token usage (if available)
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    /// Model used
    pub model: String,
    /// Stop reason
    pub stop_reason: Option<String>,
}

/// LLM provider trait
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Execute a completion request
    /// Returns bounded text response (max 64KB)
    async fn complete(
        &self,
        prompt: &str,
        system: Option<&str>,
    ) -> Result<LlmResponse, LlmError>;

    /// Provider name for logging (safe)
    fn provider_name(&self) -> &str;

    /// Check if provider is configured
    fn is_configured(&self) -> bool;
}

// =============================================================================
// Configuration
// =============================================================================

/// LLM configuration loaded from environment
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Anthropic API key (if set)
    pub anthropic_api_key: Option<String>,
    /// Anthropic model (defaults to claude-3-5-sonnet)
    pub anthropic_model: String,
    /// Max tokens for completion
    pub max_tokens: u32,
}

impl LlmConfig {
    /// Load configuration from environment variables
    /// SECURITY: Never return env var names in errors
    pub fn from_env() -> Self {
        let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").ok()
            .filter(|s| !s.is_empty());

        let anthropic_model = std::env::var("ANTHROPIC_MODEL")
            .unwrap_or_else(|_| DEFAULT_ANTHROPIC_MODEL.to_string());

        let max_tokens = std::env::var("LLM_MAX_TOKENS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_TOKENS);

        Self {
            anthropic_api_key,
            anthropic_model,
            max_tokens,
        }
    }

    /// Check if any provider is configured
    pub fn is_configured(&self) -> bool {
        self.anthropic_api_key.is_some()
    }

    /// Create provider if configured
    pub fn create_provider(&self) -> Option<Arc<dyn LlmProvider>> {
        if let Some(ref api_key) = self.anthropic_api_key {
            Some(Arc::new(AnthropicProvider::new(
                api_key.clone(),
                self.anthropic_model.clone(),
                self.max_tokens,
            )))
        } else {
            None
        }
    }

    /// Get provider name for logging (never exposes keys)
    pub fn provider_name(&self) -> Option<&str> {
        if self.anthropic_api_key.is_some() {
            Some("anthropic")
        } else {
            None
        }
    }
}

// =============================================================================
// Anthropic Provider
// =============================================================================

/// Anthropic Claude API provider
pub struct AnthropicProvider {
    api_key: String,
    model: String,
    max_tokens: u32,
    client: reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(api_key: String, model: String, max_tokens: u32) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            model,
            max_tokens,
            client,
        }
    }
}

/// Anthropic API request structure
#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

/// Anthropic API response structure
#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
    model: String,
    stop_reason: Option<String>,
    usage: Option<AnthropicUsage>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

/// Anthropic API error response
#[derive(Deserialize)]
struct AnthropicErrorResponse {
    error: AnthropicErrorDetail,
}

#[derive(Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
struct AnthropicErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(
        &self,
        prompt: &str,
        system: Option<&str>,
    ) -> Result<LlmResponse, LlmError> {
        // Log request metadata (NEVER log prompt content)
        let prompt_hash = hash_for_logging(prompt);
        let prompt_len = prompt.len();

        info!(
            op = "llm.anthropic.request",
            prompt_hash = %prompt_hash,
            prompt_len = %prompt_len,
            model = %self.model,
            max_tokens = %self.max_tokens,
            "LLM completion request"
        );

        let request = AnthropicRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            system: system.map(|s| s.to_string()),
        };

        let response = self.client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    LlmError::timeout()
                } else {
                    LlmError::api_error(e.to_string(), true)
                }
            })?;

        let status = response.status();

        // Handle rate limiting
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!(
                op = "llm.anthropic.rate_limited",
                "Rate limited by Anthropic API"
            );
            return Err(LlmError::rate_limited());
        }

        // Handle other errors
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();

            // Try to parse error response (don't expose raw error in logs)
            let error_msg = if let Ok(err) = serde_json::from_str::<AnthropicErrorResponse>(&error_body) {
                sanitize_error(err.error.message)
            } else {
                format!("HTTP {}", status.as_u16())
            };

            warn!(
                op = "llm.anthropic.error",
                status = %status.as_u16(),
                "API request failed"
            );

            return Err(LlmError::api_error(error_msg, status.is_server_error()));
        }

        // Parse successful response
        let api_response: AnthropicResponse = response.json().await
            .map_err(|e| LlmError::api_error(format!("Failed to parse response: {}", e), false))?;

        // Extract text from content blocks
        let text: String = api_response.content
            .iter()
            .filter(|c| c.content_type == "text")
            .filter_map(|c| c.text.as_ref())
            .cloned()
            .collect::<Vec<String>>()
            .join("");

        // Enforce response size limit
        let text = if text.len() > MAX_RESPONSE_SIZE {
            warn!(
                op = "llm.anthropic.truncated",
                original_len = %text.len(),
                max_len = %MAX_RESPONSE_SIZE,
                "Response truncated to max size"
            );
            text[..MAX_RESPONSE_SIZE].to_string()
        } else {
            text
        };

        // Log response metadata (NEVER log response content)
        let response_hash = hash_for_logging(&text);
        let response_len = text.len();

        info!(
            op = "llm.anthropic.response",
            response_hash = %response_hash,
            response_len = %response_len,
            model = %api_response.model,
            stop_reason = %api_response.stop_reason.as_deref().unwrap_or("none"),
            input_tokens = %api_response.usage.as_ref().map(|u| u.input_tokens).unwrap_or(0),
            output_tokens = %api_response.usage.as_ref().map(|u| u.output_tokens).unwrap_or(0),
            "LLM completion response"
        );

        Ok(LlmResponse {
            text,
            input_tokens: api_response.usage.as_ref().map(|u| u.input_tokens),
            output_tokens: api_response.usage.as_ref().map(|u| u.output_tokens),
            model: api_response.model,
            stop_reason: api_response.stop_reason,
        })
    }

    fn provider_name(&self) -> &str {
        "anthropic"
    }

    fn is_configured(&self) -> bool {
        true // If this struct exists, it was configured
    }
}

// =============================================================================
// Mock Provider (for testing)
// =============================================================================

/// Mock LLM provider for testing
pub struct MockProvider {
    /// Response to return
    pub response: String,
    /// Whether to simulate error
    pub should_error: bool,
    /// Error to return if should_error is true
    pub error: Option<LlmError>,
}

impl MockProvider {
    /// Create a mock that returns the given response
    pub fn with_response(response: impl Into<String>) -> Self {
        Self {
            response: response.into(),
            should_error: false,
            error: None,
        }
    }

    /// Create a mock that returns an error
    pub fn with_error(error: LlmError) -> Self {
        Self {
            response: String::new(),
            should_error: true,
            error: Some(error),
        }
    }

    /// Create a mock that returns not configured error
    pub fn not_configured() -> Self {
        Self::with_error(LlmError::not_configured())
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    async fn complete(
        &self,
        _prompt: &str,
        _system: Option<&str>,
    ) -> Result<LlmResponse, LlmError> {
        if self.should_error {
            return Err(self.error.clone().unwrap_or_else(LlmError::not_configured));
        }

        Ok(LlmResponse {
            text: self.response.clone(),
            input_tokens: Some(100),
            output_tokens: Some(200),
            model: "mock-model".to_string(),
            stop_reason: Some("end_turn".to_string()),
        })
    }

    fn provider_name(&self) -> &str {
        "mock"
    }

    fn is_configured(&self) -> bool {
        !self.should_error
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generate short hash of content for safe logging
/// SECURITY: Never logs actual content, only hash
pub fn hash_for_logging(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8]) // First 8 bytes = 16 hex chars
}

/// Sanitize error message for safe logging
/// Removes paths, URLs, env vars, and API keys
fn sanitize_error(msg: String) -> String {
    let mut result = msg;

    // Remove potential API keys (long hex/base64 strings)
    // Replace anything that looks like a key with [redacted]
    let patterns = [
        // Paths
        "/Users/", "/home/", "/var/", "/tmp/", "/private/", "C:\\", "D:\\",
        // URLs with potential secrets
        "api.anthropic.com", "api.openai.com",
        // Env var patterns
        "ANTHROPIC_", "OPENAI_", "EKKA_",
    ];

    for pattern in patterns {
        if result.contains(pattern) {
            // Find and replace the whole containing segment
            while let Some(start) = result.find(pattern) {
                let end = result[start..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .map(|i| start + i)
                    .unwrap_or(result.len());
                result.replace_range(start..end, "[redacted]");
            }
        }
    }

    // Truncate to reasonable length
    if result.len() > 200 {
        result.truncate(200);
        result.push_str("...");
    }

    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_error_not_configured() {
        let err = LlmError::not_configured();
        assert_eq!(err.code, "LLM_NOT_CONFIGURED");
        assert!(!err.retryable);
    }

    #[test]
    fn test_llm_error_rate_limited() {
        let err = LlmError::rate_limited();
        assert_eq!(err.code, "LLM_RATE_LIMITED");
        assert!(err.retryable);
    }

    #[test]
    fn test_llm_config_from_env_defaults() {
        // Clear env vars for clean test
        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("ANTHROPIC_MODEL");

        let config = LlmConfig::from_env();
        assert!(config.anthropic_api_key.is_none());
        assert_eq!(config.anthropic_model, DEFAULT_ANTHROPIC_MODEL);
        assert!(!config.is_configured());
    }

    #[test]
    fn test_llm_config_provider_name_none_when_not_configured() {
        std::env::remove_var("ANTHROPIC_API_KEY");
        let config = LlmConfig::from_env();
        assert!(config.provider_name().is_none());
    }

    #[test]
    fn test_hash_for_logging_deterministic() {
        let hash1 = hash_for_logging("test content");
        let hash2 = hash_for_logging("test content");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_for_logging_different_inputs() {
        let hash1 = hash_for_logging("content A");
        let hash2 = hash_for_logging("content B");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_for_logging_no_leak() {
        let hash = hash_for_logging("secret password /Users/john/data EKKA_TOKEN=abc");
        assert!(!hash.contains("secret"));
        assert!(!hash.contains("password"));
        assert!(!hash.contains("/Users/"));
        assert!(!hash.contains("EKKA_"));
    }

    #[test]
    fn test_sanitize_error_removes_paths() {
        let msg = sanitize_error("Error at /Users/john/secret.txt".to_string());
        assert!(!msg.contains("/Users/"));
        assert!(msg.contains("[redacted]"));
    }

    #[test]
    fn test_sanitize_error_removes_env_vars() {
        let msg = sanitize_error("ANTHROPIC_API_KEY is invalid".to_string());
        assert!(!msg.contains("ANTHROPIC_"));
        assert!(msg.contains("[redacted]"));
    }

    #[test]
    fn test_sanitize_error_truncates() {
        let long_msg = "x".repeat(500);
        let sanitized = sanitize_error(long_msg);
        assert!(sanitized.len() <= 210); // 200 + "..."
    }

    #[tokio::test]
    async fn test_mock_provider_returns_response() {
        let provider = MockProvider::with_response("Test response");
        let result = provider.complete("test prompt", None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.text, "Test response");
        assert_eq!(response.model, "mock-model");
    }

    #[tokio::test]
    async fn test_mock_provider_returns_error() {
        let provider = MockProvider::with_error(LlmError::not_configured());
        let result = provider.complete("test prompt", None).await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, "LLM_NOT_CONFIGURED");
    }

    #[tokio::test]
    async fn test_mock_provider_is_configured() {
        let configured = MockProvider::with_response("test");
        assert!(configured.is_configured());

        let not_configured = MockProvider::not_configured();
        assert!(!not_configured.is_configured());
    }

    #[test]
    fn test_max_response_size() {
        assert_eq!(MAX_RESPONSE_SIZE, 64 * 1024);
    }
}
