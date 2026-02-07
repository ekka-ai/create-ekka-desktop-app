//! LLM Result Data Contracts
//!
//! Canonical schemas for LLM execution results, artifact references, and retention policies.
//! These types are used by the runner/engine to persist and query prompt run records.
//!
//! ## Schema Versioning
//!
//! All types use explicit schema versioning:
//! - `LlmResultV1`: schema = "ekka.llm_result.v1"
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ekka_ops::llm_result::{LlmResultV1, ArtifactRef, RetentionPolicy, PromptRunRecord};
//!
//! let result = LlmResultV1::new(
//!     "model-name",
//!     "Generated text response",
//! );
//!
//! let record = PromptRunRecord {
//!     tenant_id: "tenant-1".into(),
//!     workflow_run_id: Uuid::new_v4(),
//!     task_id: "task-001".into(),
//!     correlation_id: "corr-123".into(),
//!     llm_result: result,
//!     artifacts: vec![],
//!     retention: RetentionPolicy::default(),
//! };
//!
//! // Validate before persisting
//! record.llm_result.validate()?;
//! record.retention.validate()?;
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{codes, EkkaError, EkkaResult};

// =============================================================================
// Schema Constants
// =============================================================================

/// Schema identifier for LlmResultV1
pub const SCHEMA_LLM_RESULT_V1: &str = "ekka.llm_result.v1";

// =============================================================================
// LLM Result V1
// =============================================================================

/// LLM execution result (v1 schema)
///
/// Captures the output of an LLM invocation including model info, usage stats,
/// and optional structured output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmResultV1 {
    /// Schema identifier - MUST be "ekka.llm_result.v1"
    pub schema: String,

    /// Model identifier (e.g., "gpt-4", "claude-3-opus")
    pub model: String,

    /// Provider identifier (e.g., "openai", "anthropic")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Generated text content
    pub content: String,

    /// Structured output (if the model produced JSON/tool calls)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<serde_json::Value>,

    /// Finish reason (e.g., "stop", "length", "tool_calls")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,

    /// Token usage statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<LlmUsage>,

    /// Latency in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,

    /// Timestamp when the result was generated
    pub created_at: DateTime<Utc>,

    /// Request ID from the provider (for debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,

    /// Additional metadata (provider-specific, non-sensitive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl LlmResultV1 {
    /// Create a new LLM result with required fields
    pub fn new(model: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            schema: SCHEMA_LLM_RESULT_V1.to_string(),
            model: model.into(),
            provider: None,
            content: content.into(),
            structured_output: None,
            finish_reason: None,
            usage: None,
            latency_ms: None,
            created_at: Utc::now(),
            provider_request_id: None,
            metadata: None,
        }
    }

    /// Create with provider specified
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Set usage statistics
    pub fn with_usage(mut self, usage: LlmUsage) -> Self {
        self.usage = Some(usage);
        self
    }

    /// Set finish reason
    pub fn with_finish_reason(mut self, reason: impl Into<String>) -> Self {
        self.finish_reason = Some(reason.into());
        self
    }

    /// Set latency
    pub fn with_latency(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// Set structured output
    pub fn with_structured_output(mut self, output: serde_json::Value) -> Self {
        self.structured_output = Some(output);
        self
    }
}

/// Token usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmUsage {
    /// Input/prompt tokens
    pub prompt_tokens: u32,

    /// Output/completion tokens
    pub completion_tokens: u32,

    /// Total tokens (should equal prompt_tokens + completion_tokens)
    pub total_tokens: u32,

    /// Cached tokens (if provider supports caching)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_tokens: Option<u32>,
}

impl LlmUsage {
    /// Create new usage stats
    pub fn new(prompt_tokens: u32, completion_tokens: u32) -> Self {
        Self {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
            cached_tokens: None,
        }
    }

    /// Create with cached tokens
    pub fn with_cached(mut self, cached: u32) -> Self {
        self.cached_tokens = Some(cached);
        self
    }
}

// =============================================================================
// Artifact Reference
// =============================================================================

/// Compression algorithm for artifacts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompressionAlgorithm {
    /// No compression
    #[default]
    None,
    /// Gzip compression
    Gzip,
    /// Zstd compression
    Zstd,
    /// LZ4 compression
    Lz4,
}

/// Reference to an artifact produced during LLM execution
///
/// Artifacts can be stored locally (vault://) or remotely (s3://, https://).
/// The sha256 hash provides content verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRef {
    /// URI pointing to the artifact
    /// Supported schemes: vault://, s3://, https://, file://
    pub uri: String,

    /// SHA-256 hash of the artifact content (hex-encoded)
    pub sha256: String,

    /// Size in bytes (after compression, if any)
    pub bytes: u64,

    /// MIME content type (e.g., "application/json", "text/plain")
    pub content_type: String,

    /// When the artifact was created
    pub created_at: DateTime<Utc>,

    /// When the artifact expires (for auto-cleanup)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Compression algorithm used (if any)
    #[serde(default)]
    pub compression: CompressionAlgorithm,

    /// Original size in bytes (before compression)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_bytes: Option<u64>,

    /// Human-readable label for the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Artifact category for filtering
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<ArtifactCategory>,
}

/// Artifact categories for classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactCategory {
    /// Raw LLM input/output
    RawLlm,
    /// Debug bundle
    DebugBundle,
    /// Generated code
    CodeOutput,
    /// Generated document
    DocumentOutput,
    /// Intermediate data
    Intermediate,
    /// Other/custom
    Other,
}

impl ArtifactRef {
    /// Create a new artifact reference
    pub fn new(
        uri: impl Into<String>,
        sha256: impl Into<String>,
        bytes: u64,
        content_type: impl Into<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            sha256: sha256.into(),
            bytes,
            content_type: content_type.into(),
            created_at: Utc::now(),
            expires_at: None,
            compression: CompressionAlgorithm::None,
            original_bytes: None,
            label: None,
            category: None,
        }
    }

    /// Set expiration time
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set compression info
    pub fn with_compression(mut self, algorithm: CompressionAlgorithm, original_bytes: u64) -> Self {
        self.compression = algorithm;
        self.original_bytes = Some(original_bytes);
        self
    }

    /// Set label
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set category
    pub fn with_category(mut self, category: ArtifactCategory) -> Self {
        self.category = Some(category);
        self
    }
}

// =============================================================================
// Retention Policy
// =============================================================================

/// Retention mode for prompt run data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetentionMode {
    /// Keep all data indefinitely
    #[default]
    Full,
    /// Keep structured results only, discard raw LLM output
    StructuredOnly,
    /// Keep metadata only (no content)
    MetadataOnly,
    /// Sampling mode - capture based on sample_rate
    Sampled,
    /// Delete after processing (audit log only)
    TransientOnly,
}

/// Retention policy for prompt run data
///
/// Controls how long data is retained and what gets captured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicy {
    /// Retention mode
    #[serde(default)]
    pub mode: RetentionMode,

    /// Number of days to retain data (0 = indefinite)
    #[serde(default)]
    pub days: u32,

    /// Whether to capture raw LLM input/output
    #[serde(default)]
    pub capture_raw_llm: bool,

    /// Sample rate for SAMPLED mode (0.0 to 1.0)
    /// 1.0 = capture all, 0.1 = capture 10%
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Maximum bytes to store per run (0 = unlimited)
    #[serde(default)]
    pub max_bytes_per_run: u64,

    /// Whether to redact PII before storage
    #[serde(default)]
    pub redact_pii: bool,
}

fn default_sample_rate() -> f64 {
    1.0
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            mode: RetentionMode::Full,
            days: 90,
            capture_raw_llm: false,
            sample_rate: 1.0,
            max_bytes_per_run: 0,
            redact_pii: false,
        }
    }
}

impl RetentionPolicy {
    /// Create a minimal retention policy (metadata only, 7 days)
    pub fn minimal() -> Self {
        Self {
            mode: RetentionMode::MetadataOnly,
            days: 7,
            capture_raw_llm: false,
            sample_rate: 1.0,
            max_bytes_per_run: 0,
            redact_pii: true,
        }
    }

    /// Create a full retention policy (all data, 90 days)
    pub fn full() -> Self {
        Self {
            mode: RetentionMode::Full,
            days: 90,
            capture_raw_llm: true,
            sample_rate: 1.0,
            max_bytes_per_run: 0,
            redact_pii: false,
        }
    }

    /// Create a debug retention policy (all data with raw LLM, 30 days)
    pub fn debug() -> Self {
        Self {
            mode: RetentionMode::Full,
            days: 30,
            capture_raw_llm: true,
            sample_rate: 1.0,
            max_bytes_per_run: 10 * 1024 * 1024, // 10MB
            redact_pii: false,
        }
    }

    /// Create a sampled retention policy
    pub fn sampled(sample_rate: f64, days: u32) -> Self {
        Self {
            mode: RetentionMode::Sampled,
            days,
            capture_raw_llm: true,
            sample_rate,
            max_bytes_per_run: 0,
            redact_pii: false,
        }
    }
}

// =============================================================================
// Prompt Run Record (Persistence Payload)
// =============================================================================

/// Persistence payload for a prompt run
///
/// This is the canonical structure that the runner/engine stores in DB/events.
/// Contains all information about a single LLM invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptRunRecord {
    /// Tenant identifier
    pub tenant_id: String,

    /// Workflow run ID (groups related prompt runs)
    pub workflow_run_id: Uuid,

    /// Task ID within the workflow
    pub task_id: String,

    /// Correlation ID for distributed tracing
    pub correlation_id: String,

    /// LLM result
    pub llm_result: LlmResultV1,

    /// Associated artifacts
    #[serde(default)]
    pub artifacts: Vec<ArtifactRef>,

    /// Retention policy for this record
    #[serde(default)]
    pub retention: RetentionPolicy,

    /// Record creation timestamp
    #[serde(default = "Utc::now")]
    pub recorded_at: DateTime<Utc>,

    /// Optional tags for filtering
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl PromptRunRecord {
    /// Create a new prompt run record
    pub fn new(
        tenant_id: impl Into<String>,
        workflow_run_id: Uuid,
        task_id: impl Into<String>,
        correlation_id: impl Into<String>,
        llm_result: LlmResultV1,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            workflow_run_id,
            task_id: task_id.into(),
            correlation_id: correlation_id.into(),
            llm_result,
            artifacts: vec![],
            retention: RetentionPolicy::default(),
            recorded_at: Utc::now(),
            tags: vec![],
        }
    }

    /// Add artifacts
    pub fn with_artifacts(mut self, artifacts: Vec<ArtifactRef>) -> Self {
        self.artifacts = artifacts;
        self
    }

    /// Set retention policy
    pub fn with_retention(mut self, retention: RetentionPolicy) -> Self {
        self.retention = retention;
        self
    }

    /// Add tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

// =============================================================================
// Validation Functions
// =============================================================================

/// Validate an LlmResultV1 struct
///
/// # Errors
///
/// Returns an error if:
/// - Schema is not "ekka.llm_result.v1"
/// - Model is empty
/// - Usage has invalid totals (total_tokens != prompt_tokens + completion_tokens)
pub fn validate_llm_result_v1(result: &LlmResultV1) -> EkkaResult<()> {
    // Validate schema
    if result.schema != SCHEMA_LLM_RESULT_V1 {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "Invalid schema: expected '{}', got '{}'",
                SCHEMA_LLM_RESULT_V1, result.schema
            ),
            serde_json::json!({
                "field": "schema",
                "expected": SCHEMA_LLM_RESULT_V1,
                "actual": result.schema
            }),
        ));
    }

    // Validate model is not empty
    if result.model.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "Model identifier cannot be empty",
            serde_json::json!({
                "field": "model",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate usage if present
    if let Some(ref usage) = result.usage {
        let expected_total = usage.prompt_tokens + usage.completion_tokens;
        if usage.total_tokens != expected_total {
            return Err(EkkaError::with_details(
                codes::VALIDATION_ERROR,
                format!(
                    "Usage total_tokens ({}) does not equal prompt_tokens ({}) + completion_tokens ({})",
                    usage.total_tokens, usage.prompt_tokens, usage.completion_tokens
                ),
                serde_json::json!({
                    "field": "usage.total_tokens",
                    "expected": expected_total,
                    "actual": usage.total_tokens
                }),
            ));
        }
    }

    Ok(())
}

/// Validate a RetentionPolicy struct
///
/// # Errors
///
/// Returns an error if:
/// - sample_rate is not in range [0.0, 1.0]
/// - SAMPLED mode with sample_rate of 0.0 (would capture nothing)
pub fn validate_retention_policy(policy: &RetentionPolicy) -> EkkaResult<()> {
    // Validate sample_rate range
    if !(0.0..=1.0).contains(&policy.sample_rate) {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "sample_rate must be between 0.0 and 1.0, got {}",
                policy.sample_rate
            ),
            serde_json::json!({
                "field": "sample_rate",
                "min": 0.0,
                "max": 1.0,
                "actual": policy.sample_rate
            }),
        ));
    }

    // Validate SAMPLED mode with non-zero sample rate
    if policy.mode == RetentionMode::Sampled && policy.sample_rate == 0.0 {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "SAMPLED retention mode requires sample_rate > 0.0",
            serde_json::json!({
                "field": "sample_rate",
                "mode": "SAMPLED",
                "reason": "zero_sample_rate"
            }),
        ));
    }

    Ok(())
}

/// Validate an ArtifactRef struct
///
/// # Errors
///
/// Returns an error if:
/// - URI is empty
/// - SHA256 is not a valid hex string of 64 characters
/// - content_type is empty
pub fn validate_artifact_ref(artifact: &ArtifactRef) -> EkkaResult<()> {
    // Validate URI is not empty
    if artifact.uri.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "Artifact URI cannot be empty",
            serde_json::json!({
                "field": "uri",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate SHA256 format (64 hex characters)
    if artifact.sha256.len() != 64 {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "SHA256 hash must be 64 hex characters, got {} characters",
                artifact.sha256.len()
            ),
            serde_json::json!({
                "field": "sha256",
                "expected_length": 64,
                "actual_length": artifact.sha256.len()
            }),
        ));
    }

    // Validate SHA256 is valid hex
    if !artifact.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "SHA256 hash must contain only hexadecimal characters",
            serde_json::json!({
                "field": "sha256",
                "reason": "invalid_hex"
            }),
        ));
    }

    // Validate content_type is not empty
    if artifact.content_type.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "Artifact content_type cannot be empty",
            serde_json::json!({
                "field": "content_type",
                "reason": "empty_string"
            }),
        ));
    }

    Ok(())
}

/// Validate a complete PromptRunRecord
///
/// # Errors
///
/// Returns an error if any nested validation fails
pub fn validate_prompt_run_record(record: &PromptRunRecord) -> EkkaResult<()> {
    // Validate tenant_id
    if record.tenant_id.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "tenant_id cannot be empty",
            serde_json::json!({
                "field": "tenant_id",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate task_id
    if record.task_id.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "task_id cannot be empty",
            serde_json::json!({
                "field": "task_id",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate correlation_id
    if record.correlation_id.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "correlation_id cannot be empty",
            serde_json::json!({
                "field": "correlation_id",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate nested structs
    validate_llm_result_v1(&record.llm_result)?;
    validate_retention_policy(&record.retention)?;

    for (i, artifact) in record.artifacts.iter().enumerate() {
        validate_artifact_ref(artifact).map_err(|e| {
            EkkaError::with_details(
                codes::VALIDATION_ERROR,
                format!("Invalid artifact at index {}: {}", i, e.message),
                serde_json::json!({
                    "field": format!("artifacts[{}]", i),
                    "nested_error": e.message
                }),
            )
        })?;
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_result_v1_creation() {
        let result = LlmResultV1::new("gpt-4", "Hello, world!")
            .with_provider("openai")
            .with_finish_reason("stop")
            .with_latency(150)
            .with_usage(LlmUsage::new(10, 5));

        assert_eq!(result.schema, SCHEMA_LLM_RESULT_V1);
        assert_eq!(result.model, "gpt-4");
        assert_eq!(result.provider, Some("openai".to_string()));
        assert_eq!(result.content, "Hello, world!");
        assert_eq!(result.finish_reason, Some("stop".to_string()));
        assert_eq!(result.latency_ms, Some(150));
        assert!(result.usage.is_some());
        let usage = result.usage.unwrap();
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 5);
        assert_eq!(usage.total_tokens, 15);
    }

    #[test]
    fn test_validate_llm_result_v1_valid() {
        let result = LlmResultV1::new("gpt-4", "Hello!")
            .with_usage(LlmUsage::new(10, 5));

        assert!(validate_llm_result_v1(&result).is_ok());
    }

    #[test]
    fn test_validate_llm_result_v1_invalid_schema() {
        let mut result = LlmResultV1::new("gpt-4", "Hello!");
        result.schema = "invalid.schema".to_string();

        let err = validate_llm_result_v1(&result).unwrap_err();
        assert_eq!(err.code, codes::VALIDATION_ERROR);
        assert!(err.message.contains("Invalid schema"));
    }

    #[test]
    fn test_validate_llm_result_v1_empty_model() {
        let mut result = LlmResultV1::new("gpt-4", "Hello!");
        result.model = "  ".to_string();

        let err = validate_llm_result_v1(&result).unwrap_err();
        assert_eq!(err.code, codes::VALIDATION_ERROR);
        assert!(err.message.contains("Model identifier"));
    }

    #[test]
    fn test_validate_llm_result_v1_invalid_usage() {
        let mut result = LlmResultV1::new("gpt-4", "Hello!");
        result.usage = Some(LlmUsage {
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 100, // Wrong!
            cached_tokens: None,
        });

        let err = validate_llm_result_v1(&result).unwrap_err();
        assert_eq!(err.code, codes::VALIDATION_ERROR);
        assert!(err.message.contains("total_tokens"));
    }

    #[test]
    fn test_retention_policy_defaults() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.mode, RetentionMode::Full);
        assert_eq!(policy.days, 90);
        assert!(!policy.capture_raw_llm);
        assert_eq!(policy.sample_rate, 1.0);
    }

    #[test]
    fn test_validate_retention_policy_valid() {
        let policy = RetentionPolicy::sampled(0.5, 30);
        assert!(validate_retention_policy(&policy).is_ok());
    }

    #[test]
    fn test_validate_retention_policy_invalid_sample_rate() {
        let mut policy = RetentionPolicy::default();
        policy.sample_rate = 1.5; // Invalid!

        let err = validate_retention_policy(&policy).unwrap_err();
        assert_eq!(err.code, codes::VALIDATION_ERROR);
        assert!(err.message.contains("sample_rate"));
    }

    #[test]
    fn test_validate_retention_policy_sampled_zero_rate() {
        let mut policy = RetentionPolicy::default();
        policy.mode = RetentionMode::Sampled;
        policy.sample_rate = 0.0; // Invalid for SAMPLED mode

        let err = validate_retention_policy(&policy).unwrap_err();
        assert_eq!(err.code, codes::VALIDATION_ERROR);
        assert!(err.message.contains("SAMPLED"));
    }

    #[test]
    fn test_artifact_ref_creation() {
        let artifact = ArtifactRef::new(
            "vault://tmp/artifacts/output.json",
            "a".repeat(64),
            1024,
            "application/json",
        )
        .with_label("LLM Output")
        .with_category(ArtifactCategory::RawLlm);

        assert_eq!(artifact.uri, "vault://tmp/artifacts/output.json");
        assert_eq!(artifact.bytes, 1024);
        assert_eq!(artifact.content_type, "application/json");
        assert_eq!(artifact.label, Some("LLM Output".to_string()));
        assert_eq!(artifact.category, Some(ArtifactCategory::RawLlm));
    }

    #[test]
    fn test_validate_artifact_ref_valid() {
        let artifact = ArtifactRef::new(
            "vault://tmp/test.json",
            "a".repeat(64),
            100,
            "application/json",
        );
        assert!(validate_artifact_ref(&artifact).is_ok());
    }

    #[test]
    fn test_validate_artifact_ref_invalid_sha256_length() {
        let artifact = ArtifactRef::new(
            "vault://tmp/test.json",
            "abc", // Too short
            100,
            "application/json",
        );
        let err = validate_artifact_ref(&artifact).unwrap_err();
        assert!(err.message.contains("64 hex characters"));
    }

    #[test]
    fn test_validate_artifact_ref_invalid_sha256_chars() {
        let artifact = ArtifactRef::new(
            "vault://tmp/test.json",
            "g".repeat(64), // 'g' is not hex
            100,
            "application/json",
        );
        let err = validate_artifact_ref(&artifact).unwrap_err();
        assert!(err.message.contains("hexadecimal"));
    }

    #[test]
    fn test_prompt_run_record_creation() {
        let result = LlmResultV1::new("claude-3-opus", "Generated response");
        let record = PromptRunRecord::new(
            "tenant-123",
            Uuid::new_v4(),
            "task-001",
            "corr-abc",
            result,
        )
        .with_retention(RetentionPolicy::debug())
        .with_tags(vec!["test".to_string()]);

        assert_eq!(record.tenant_id, "tenant-123");
        assert_eq!(record.task_id, "task-001");
        assert_eq!(record.correlation_id, "corr-abc");
        assert!(record.tags.contains(&"test".to_string()));
    }

    #[test]
    fn test_validate_prompt_run_record_valid() {
        let result = LlmResultV1::new("gpt-4", "Hello!");
        let record = PromptRunRecord::new(
            "tenant-1",
            Uuid::new_v4(),
            "task-1",
            "corr-1",
            result,
        );

        assert!(validate_prompt_run_record(&record).is_ok());
    }

    #[test]
    fn test_validate_prompt_run_record_empty_tenant() {
        let result = LlmResultV1::new("gpt-4", "Hello!");
        let record = PromptRunRecord::new(
            "", // Empty!
            Uuid::new_v4(),
            "task-1",
            "corr-1",
            result,
        );

        let err = validate_prompt_run_record(&record).unwrap_err();
        assert!(err.message.contains("tenant_id"));
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let result = LlmResultV1::new("gpt-4", "Hello, world!")
            .with_provider("openai")
            .with_usage(LlmUsage::new(10, 5));

        let artifact = ArtifactRef::new(
            "vault://tmp/output.json",
            "a".repeat(64),
            1024,
            "application/json",
        )
        .with_category(ArtifactCategory::RawLlm);

        let record = PromptRunRecord::new(
            "tenant-abc",
            Uuid::parse_str("12345678-1234-1234-1234-123456789012").unwrap(),
            "task-xyz",
            "corr-123",
            result,
        )
        .with_artifacts(vec![artifact])
        .with_retention(RetentionPolicy::debug());

        // Serialize
        let json = serde_json::to_string_pretty(&record).unwrap();
        println!("Example PromptRunRecord JSON:\n{}", json);

        // Deserialize
        let deserialized: PromptRunRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tenant_id, record.tenant_id);
        assert_eq!(deserialized.task_id, record.task_id);
        assert_eq!(deserialized.llm_result.model, "gpt-4");
        assert_eq!(deserialized.artifacts.len(), 1);

        // Validate roundtrip
        assert!(validate_prompt_run_record(&deserialized).is_ok());
    }

    /// Print example JSON for documentation purposes
    #[test]
    fn test_print_example_json() {
        let result = LlmResultV1::new("claude-3-opus", "The answer to your question is 42.")
            .with_provider("anthropic")
            .with_finish_reason("stop")
            .with_latency(245)
            .with_usage(LlmUsage::new(150, 25));

        let artifact = ArtifactRef::new(
            "vault://tmp/telemetry/llm_debug/tenant-abc/run-xyz/raw_output.txt",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            2048,
            "text/plain",
        )
        .with_label("Raw LLM Output")
        .with_category(ArtifactCategory::RawLlm)
        .with_compression(CompressionAlgorithm::Gzip, 4096);

        let record = PromptRunRecord::new(
            "tenant-abc",
            Uuid::parse_str("12345678-1234-1234-1234-123456789012").unwrap(),
            "task-summarize-doc",
            "corr-req-001",
            result,
        )
        .with_artifacts(vec![artifact])
        .with_retention(RetentionPolicy::debug())
        .with_tags(vec!["production".to_string(), "summarization".to_string()]);

        let json = serde_json::to_string_pretty(&record).unwrap();
        println!("\n=== Example PromptRunRecord JSON ===\n{}\n", json);

        // Ensure it's valid
        assert!(validate_prompt_run_record(&record).is_ok());
    }
}
