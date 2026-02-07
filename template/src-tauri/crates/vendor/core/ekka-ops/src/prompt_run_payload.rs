//! Prompt Run Engine Payload Contracts
//!
//! Canonical schema definitions for prompt_run results sent to the engine.
//! These types define the LOCKED contract between runner and engine.
//!
//! ## Schema Versioning
//!
//! All payloads include `schema_version` for forward/backward compatibility:
//! - `prompt_run.output.v1` - Success output schema
//! - `prompt_run.result.v1` - Result envelope schema
//!
//! ## Serde Naming Convention
//!
//! - Envelope fields: snake_case (Rust default, matches engine expectation)
//! - ArtifactRef fields: camelCase (nested type from llm_result module)
//!
//! This mixed convention is intentional for engine compatibility.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ekka_ops::prompt_run_payload::{
//!     PromptRunOutputV1, PromptRunSuccessEnvelope, PromptRunFailureEnvelope,
//!     PROMPT_RUN_OUTPUT_SCHEMA_VERSION,
//! };
//!
//! let output = PromptRunOutputV1::new("ACCEPT", "output text", "claude-3-opus")
//!     .with_usage(100, 50)
//!     .with_latency(1500);
//!
//! let envelope = PromptRunSuccessEnvelope::new("task-123", output);
//! ```

use serde::{Deserialize, Serialize};

use crate::error::{codes, EkkaError, EkkaResult};
use crate::llm_result::ArtifactRef;

// =============================================================================
// Schema Version Constants
// =============================================================================

/// Schema version for prompt run task input
pub const PROMPT_RUN_TASK_SCHEMA_VERSION: &str = "prompt_run_task.v1";

/// Schema version for prompt run result envelope
pub const PROMPT_RUN_RESULT_SCHEMA_VERSION: &str = "prompt_run.result.v1";

/// Schema version for prompt run output payload
pub const PROMPT_RUN_OUTPUT_SCHEMA_VERSION: &str = "prompt_run.output.v1";

// =============================================================================
// LLM Usage and Timings
// =============================================================================

/// LLM token usage statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PromptRunUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
}

impl PromptRunUsage {
    pub fn new(input_tokens: u32, output_tokens: u32) -> Self {
        Self {
            input_tokens: Some(input_tokens),
            output_tokens: Some(output_tokens),
        }
    }
}

/// LLM timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRunTimings {
    pub llm_latency_ms: u64,
}

impl PromptRunTimings {
    pub fn new(llm_latency_ms: u64) -> Self {
        Self { llm_latency_ms }
    }
}

// =============================================================================
// Success Payload
// =============================================================================

/// Prompt run output payload (inside success envelope)
///
/// This is the canonical schema for successful prompt_run results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRunOutputV1 {
    /// Schema version - MUST be "prompt_run.output.v1"
    pub schema_version: String,

    /// Decision: ACCEPT, UPDATE, or REJECT
    pub decision: String,

    /// LLM output text
    pub output_text: String,

    /// Model identifier (e.g., "claude-3-opus", "gpt-4")
    pub model: String,

    /// Token usage statistics
    pub usage: PromptRunUsage,

    /// Timing information
    pub timings_ms: PromptRunTimings,

    /// Artifact references (stdout.gz, debug artifacts, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRef>,
}

impl PromptRunOutputV1 {
    /// Create a new output with required fields
    pub fn new(
        decision: impl Into<String>,
        output_text: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: PROMPT_RUN_OUTPUT_SCHEMA_VERSION.to_string(),
            decision: decision.into(),
            output_text: output_text.into(),
            model: model.into(),
            usage: PromptRunUsage::default(),
            timings_ms: PromptRunTimings::new(0),
            artifacts: vec![],
        }
    }

    /// Set usage statistics
    pub fn with_usage(mut self, input_tokens: u32, output_tokens: u32) -> Self {
        self.usage = PromptRunUsage::new(input_tokens, output_tokens);
        self
    }

    /// Set latency
    pub fn with_latency(mut self, llm_latency_ms: u64) -> Self {
        self.timings_ms = PromptRunTimings::new(llm_latency_ms);
        self
    }

    /// Add artifacts
    pub fn with_artifacts(mut self, artifacts: Vec<ArtifactRef>) -> Self {
        self.artifacts = artifacts;
        self
    }

    /// Add a single artifact
    pub fn add_artifact(mut self, artifact: ArtifactRef) -> Self {
        self.artifacts.push(artifact);
        self
    }
}

/// Success envelope for prompt_run result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRunSuccessEnvelope {
    /// Always true for success
    pub success: bool,

    /// Schema version - MUST be "prompt_run.result.v1"
    pub schema_version: String,

    /// Task subtype - always "prompt_run"
    pub task_subtype: String,

    /// Task ID
    pub task_id: String,

    /// Output payload
    pub output: PromptRunOutputV1,
}

impl PromptRunSuccessEnvelope {
    /// Create a new success envelope
    pub fn new(task_id: impl Into<String>, output: PromptRunOutputV1) -> Self {
        Self {
            success: true,
            schema_version: PROMPT_RUN_RESULT_SCHEMA_VERSION.to_string(),
            task_subtype: "prompt_run".to_string(),
            task_id: task_id.into(),
            output,
        }
    }
}

// =============================================================================
// Failure Payload
// =============================================================================

/// Failure codes for prompt_run
pub mod failure_codes {
    pub const PROMPT_FETCH_FAILED: &str = "PROMPT_FETCH_FAILED";
    pub const HASH_MISMATCH: &str = "HASH_MISMATCH";
    pub const LLM_TIMEOUT: &str = "LLM_TIMEOUT";
    pub const LLM_ERROR: &str = "LLM_ERROR";
    pub const OUTPUT_PARSE_FAILED: &str = "OUTPUT_PARSE_FAILED";
    pub const OUTPUT_CONTRACT_INVALID: &str = "OUTPUT_CONTRACT_INVALID";
    pub const REPORT_INVALID: &str = "REPORT_INVALID";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    pub const PATH_NOT_ALLOWED: &str = "PATH_NOT_ALLOWED";
}

/// Failure envelope for prompt_run result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRunFailureEnvelope {
    /// Always false for failure
    pub success: bool,

    /// Schema version - MUST be "prompt_run.result.v1"
    pub schema_version: String,

    /// Task subtype - always "prompt_run"
    pub task_subtype: String,

    /// Task ID
    pub task_id: String,

    /// Failure code (e.g., "PROMPT_FETCH_FAILED", "LLM_TIMEOUT")
    pub failure_code: String,

    /// Human-readable error message
    pub message: String,

    /// Artifact references captured on failure (debug artifacts, prompts, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRef>,
}

impl PromptRunFailureEnvelope {
    /// Create a new failure envelope
    pub fn new(
        task_id: impl Into<String>,
        failure_code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            success: false,
            schema_version: PROMPT_RUN_RESULT_SCHEMA_VERSION.to_string(),
            task_subtype: "prompt_run".to_string(),
            task_id: task_id.into(),
            failure_code: failure_code.into(),
            message: message.into(),
            artifacts: vec![],
        }
    }

    /// Add artifacts (debug bundles, etc.)
    pub fn with_artifacts(mut self, artifacts: Vec<ArtifactRef>) -> Self {
        self.artifacts = artifacts;
        self
    }

    /// Add a single artifact
    pub fn add_artifact(mut self, artifact: ArtifactRef) -> Self {
        self.artifacts.push(artifact);
        self
    }
}

// =============================================================================
// Validation
// =============================================================================

/// Valid decision values
const VALID_DECISIONS: &[&str] = &["ACCEPT", "UPDATE", "REJECT"];

/// Validate a PromptRunOutputV1 struct
pub fn validate_prompt_run_output_v1(output: &PromptRunOutputV1) -> EkkaResult<()> {
    // Validate schema version
    if output.schema_version != PROMPT_RUN_OUTPUT_SCHEMA_VERSION {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "Invalid schema_version: expected '{}', got '{}'",
                PROMPT_RUN_OUTPUT_SCHEMA_VERSION, output.schema_version
            ),
            serde_json::json!({
                "field": "schema_version",
                "expected": PROMPT_RUN_OUTPUT_SCHEMA_VERSION,
                "actual": output.schema_version
            }),
        ));
    }

    // Validate decision
    if !VALID_DECISIONS.contains(&output.decision.as_str()) {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "Invalid decision: expected one of {:?}, got '{}'",
                VALID_DECISIONS, output.decision
            ),
            serde_json::json!({
                "field": "decision",
                "valid_values": VALID_DECISIONS,
                "actual": output.decision
            }),
        ));
    }

    // Validate model is not empty
    if output.model.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "Model identifier cannot be empty",
            serde_json::json!({
                "field": "model",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate artifacts if present
    for (i, artifact) in output.artifacts.iter().enumerate() {
        crate::llm_result::validate_artifact_ref(artifact).map_err(|e| {
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

/// Validate a PromptRunSuccessEnvelope struct
pub fn validate_prompt_run_success_envelope(envelope: &PromptRunSuccessEnvelope) -> EkkaResult<()> {
    // Validate success flag
    if !envelope.success {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "Success envelope must have success=true",
            serde_json::json!({
                "field": "success",
                "expected": true,
                "actual": envelope.success
            }),
        ));
    }

    // Validate schema version
    if envelope.schema_version != PROMPT_RUN_RESULT_SCHEMA_VERSION {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "Invalid schema_version: expected '{}', got '{}'",
                PROMPT_RUN_RESULT_SCHEMA_VERSION, envelope.schema_version
            ),
            serde_json::json!({
                "field": "schema_version",
                "expected": PROMPT_RUN_RESULT_SCHEMA_VERSION,
                "actual": envelope.schema_version
            }),
        ));
    }

    // Validate task_subtype
    if envelope.task_subtype != "prompt_run" {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "Invalid task_subtype: expected 'prompt_run', got '{}'",
                envelope.task_subtype
            ),
            serde_json::json!({
                "field": "task_subtype",
                "expected": "prompt_run",
                "actual": envelope.task_subtype
            }),
        ));
    }

    // Validate task_id is not empty
    if envelope.task_id.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "task_id cannot be empty",
            serde_json::json!({
                "field": "task_id",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate nested output
    validate_prompt_run_output_v1(&envelope.output)?;

    Ok(())
}

/// Validate a PromptRunFailureEnvelope struct
pub fn validate_prompt_run_failure_envelope(envelope: &PromptRunFailureEnvelope) -> EkkaResult<()> {
    // Validate success flag
    if envelope.success {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "Failure envelope must have success=false",
            serde_json::json!({
                "field": "success",
                "expected": false,
                "actual": envelope.success
            }),
        ));
    }

    // Validate schema version
    if envelope.schema_version != PROMPT_RUN_RESULT_SCHEMA_VERSION {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "Invalid schema_version: expected '{}', got '{}'",
                PROMPT_RUN_RESULT_SCHEMA_VERSION, envelope.schema_version
            ),
            serde_json::json!({
                "field": "schema_version",
                "expected": PROMPT_RUN_RESULT_SCHEMA_VERSION,
                "actual": envelope.schema_version
            }),
        ));
    }

    // Validate task_subtype
    if envelope.task_subtype != "prompt_run" {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            format!(
                "Invalid task_subtype: expected 'prompt_run', got '{}'",
                envelope.task_subtype
            ),
            serde_json::json!({
                "field": "task_subtype",
                "expected": "prompt_run",
                "actual": envelope.task_subtype
            }),
        ));
    }

    // Validate task_id is not empty
    if envelope.task_id.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "task_id cannot be empty",
            serde_json::json!({
                "field": "task_id",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate failure_code is not empty
    if envelope.failure_code.trim().is_empty() {
        return Err(EkkaError::with_details(
            codes::VALIDATION_ERROR,
            "failure_code cannot be empty",
            serde_json::json!({
                "field": "failure_code",
                "reason": "empty_string"
            }),
        ));
    }

    // Validate artifacts if present
    for (i, artifact) in envelope.artifacts.iter().enumerate() {
        crate::llm_result::validate_artifact_ref(artifact).map_err(|e| {
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
    use chrono::Utc;

    fn make_valid_artifact() -> ArtifactRef {
        ArtifactRef {
            uri: "ekka://artifacts/tenant-1/debug/abc123/stdout.gz".to_string(),
            sha256: "a".repeat(64),
            bytes: 1024,
            content_type: "application/gzip".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            compression: crate::llm_result::CompressionAlgorithm::Gzip,
            original_bytes: Some(4096),
            label: Some("stdout".to_string()),
            category: Some(crate::llm_result::ArtifactCategory::RawLlm),
        }
    }

    #[test]
    fn test_success_envelope_creation() {
        let output = PromptRunOutputV1::new("ACCEPT", "Generated output text", "claude-3-opus")
            .with_usage(150, 50)
            .with_latency(1500)
            .with_artifacts(vec![make_valid_artifact()]);

        let envelope = PromptRunSuccessEnvelope::new("task-12345", output);

        assert!(envelope.success);
        assert_eq!(envelope.schema_version, PROMPT_RUN_RESULT_SCHEMA_VERSION);
        assert_eq!(envelope.task_subtype, "prompt_run");
        assert_eq!(envelope.task_id, "task-12345");
        assert_eq!(envelope.output.decision, "ACCEPT");
        assert_eq!(envelope.output.artifacts.len(), 1);
    }

    #[test]
    fn test_failure_envelope_creation() {
        let envelope = PromptRunFailureEnvelope::new(
            "task-12345",
            failure_codes::LLM_TIMEOUT,
            "LLM request timed out after 60s",
        )
        .with_artifacts(vec![make_valid_artifact()]);

        assert!(!envelope.success);
        assert_eq!(envelope.schema_version, PROMPT_RUN_RESULT_SCHEMA_VERSION);
        assert_eq!(envelope.task_subtype, "prompt_run");
        assert_eq!(envelope.failure_code, "LLM_TIMEOUT");
        assert_eq!(envelope.artifacts.len(), 1);
    }

    #[test]
    fn test_validate_success_envelope_valid() {
        let output = PromptRunOutputV1::new("ACCEPT", "output", "gpt-4")
            .with_usage(10, 5)
            .with_latency(100);

        let envelope = PromptRunSuccessEnvelope::new("task-1", output);

        assert!(validate_prompt_run_success_envelope(&envelope).is_ok());
    }

    #[test]
    fn test_validate_success_envelope_invalid_decision() {
        let mut output = PromptRunOutputV1::new("ACCEPT", "output", "gpt-4");
        output.decision = "INVALID_DECISION".to_string();

        let envelope = PromptRunSuccessEnvelope::new("task-1", output);

        let err = validate_prompt_run_success_envelope(&envelope).unwrap_err();
        assert_eq!(err.code, codes::VALIDATION_ERROR);
        assert!(err.message.contains("decision"));
    }

    #[test]
    fn test_validate_failure_envelope_valid() {
        let envelope = PromptRunFailureEnvelope::new(
            "task-1",
            failure_codes::LLM_ERROR,
            "API error",
        );

        assert!(validate_prompt_run_failure_envelope(&envelope).is_ok());
    }

    #[test]
    fn test_validate_failure_envelope_empty_failure_code() {
        let envelope = PromptRunFailureEnvelope::new("task-1", "", "error message");

        let err = validate_prompt_run_failure_envelope(&envelope).unwrap_err();
        assert_eq!(err.code, codes::VALIDATION_ERROR);
        assert!(err.message.contains("failure_code"));
    }

    #[test]
    fn test_json_serialization_success() {
        let artifact = make_valid_artifact();
        let output = PromptRunOutputV1::new("ACCEPT", "The answer is 42.", "claude-3-opus")
            .with_usage(150, 25)
            .with_latency(1500)
            .with_artifacts(vec![artifact]);

        let envelope = PromptRunSuccessEnvelope::new("task-abc123", output);

        let json = serde_json::to_string_pretty(&envelope).unwrap();
        println!("\n=== Success Envelope JSON ===\n{}\n", json);

        // Deserialize and validate roundtrip
        let deserialized: PromptRunSuccessEnvelope = serde_json::from_str(&json).unwrap();
        assert!(validate_prompt_run_success_envelope(&deserialized).is_ok());
        assert_eq!(deserialized.output.artifacts.len(), 1);
        assert_eq!(
            deserialized.output.artifacts[0].uri,
            "ekka://artifacts/tenant-1/debug/abc123/stdout.gz"
        );
    }

    #[test]
    fn test_json_serialization_failure() {
        let artifact = make_valid_artifact();
        let envelope = PromptRunFailureEnvelope::new(
            "task-abc123",
            failure_codes::REPORT_INVALID,
            "Output failed contract validation: missing required field 'status'",
        )
        .with_artifacts(vec![artifact]);

        let json = serde_json::to_string_pretty(&envelope).unwrap();
        println!("\n=== Failure Envelope JSON ===\n{}\n", json);

        // Deserialize and validate roundtrip
        let deserialized: PromptRunFailureEnvelope = serde_json::from_str(&json).unwrap();
        assert!(validate_prompt_run_failure_envelope(&deserialized).is_ok());
        assert_eq!(deserialized.artifacts.len(), 1);
    }

    #[test]
    fn test_deserialize_success_from_json() {
        let json = r#"{
            "success": true,
            "schema_version": "prompt_run.result.v1",
            "task_subtype": "prompt_run",
            "task_id": "task-xyz-789",
            "output": {
                "schema_version": "prompt_run.output.v1",
                "decision": "UPDATE",
                "output_text": "I suggest updating the configuration.",
                "model": "gpt-4-turbo",
                "usage": {
                    "input_tokens": 200,
                    "output_tokens": 75
                },
                "timings_ms": {
                    "llm_latency_ms": 2345
                },
                "artifacts": [
                    {
                        "uri": "ekka://artifacts/tenant-abc/run-123/stdout.gz",
                        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "bytes": 2048,
                        "contentType": "application/gzip",
                        "createdAt": "2026-01-30T12:00:00Z",
                        "compression": "GZIP",
                        "originalBytes": 8192,
                        "label": "LLM stdout"
                    }
                ]
            }
        }"#;

        let envelope: PromptRunSuccessEnvelope = serde_json::from_str(json).unwrap();

        assert!(envelope.success);
        assert_eq!(envelope.task_id, "task-xyz-789");
        assert_eq!(envelope.output.decision, "UPDATE");
        assert_eq!(envelope.output.model, "gpt-4-turbo");
        assert_eq!(envelope.output.usage.input_tokens, Some(200));
        assert_eq!(envelope.output.timings_ms.llm_latency_ms, 2345);
        assert_eq!(envelope.output.artifacts.len(), 1);
        assert_eq!(
            envelope.output.artifacts[0].uri,
            "ekka://artifacts/tenant-abc/run-123/stdout.gz"
        );
        assert_eq!(envelope.output.artifacts[0].label, Some("LLM stdout".to_string()));

        // Validate
        assert!(validate_prompt_run_success_envelope(&envelope).is_ok());
    }

    #[test]
    fn test_deserialize_failure_from_json() {
        let json = r#"{
            "success": false,
            "schema_version": "prompt_run.result.v1",
            "task_subtype": "prompt_run",
            "task_id": "task-fail-001",
            "failure_code": "OUTPUT_CONTRACT_INVALID",
            "message": "Output validation failed: expected object with 'result' field",
            "artifacts": [
                {
                    "uri": "ekka://artifacts/tenant-abc/debug/fail-001/debug_bundle.tar.gz",
                    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "bytes": 4096,
                    "contentType": "application/gzip",
                    "createdAt": "2026-01-30T12:00:00Z",
                    "compression": "GZIP",
                    "category": "DEBUG_BUNDLE",
                    "label": "Debug bundle"
                }
            ]
        }"#;

        let envelope: PromptRunFailureEnvelope = serde_json::from_str(json).unwrap();

        assert!(!envelope.success);
        assert_eq!(envelope.task_id, "task-fail-001");
        assert_eq!(envelope.failure_code, "OUTPUT_CONTRACT_INVALID");
        assert_eq!(envelope.artifacts.len(), 1);
        assert_eq!(envelope.artifacts[0].label, Some("Debug bundle".to_string()));

        // Validate
        assert!(validate_prompt_run_failure_envelope(&envelope).is_ok());
    }

    /// Print canonical example JSON for documentation
    #[test]
    fn test_print_example_payloads() {
        // Success example
        let success_artifact = ArtifactRef {
            uri: "ekka://artifacts/tenant-acme/prompt-runs/run-12345/stdout.gz".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            bytes: 1536,
            content_type: "application/gzip".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            compression: crate::llm_result::CompressionAlgorithm::Gzip,
            original_bytes: Some(4096),
            label: Some("LLM stdout".to_string()),
            category: Some(crate::llm_result::ArtifactCategory::RawLlm),
        };

        let success_output =
            PromptRunOutputV1::new("ACCEPT", "Based on my analysis, I recommend approving this change.", "claude-3-opus")
                .with_usage(250, 45)
                .with_latency(1850)
                .with_artifacts(vec![success_artifact]);

        let success_envelope = PromptRunSuccessEnvelope::new("task-prompt-run-12345", success_output);

        println!("\n========== SUCCESS ENVELOPE ==========");
        println!("{}", serde_json::to_string_pretty(&success_envelope).unwrap());

        // Failure example
        let failure_artifact = ArtifactRef {
            uri: "ekka://artifacts/tenant-acme/debug/run-67890/debug_bundle.tar.gz".to_string(),
            sha256: "a".repeat(64),
            bytes: 8192,
            content_type: "application/gzip".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            compression: crate::llm_result::CompressionAlgorithm::Gzip,
            original_bytes: Some(32768),
            label: Some("Debug bundle".to_string()),
            category: Some(crate::llm_result::ArtifactCategory::DebugBundle),
        };

        let failure_envelope = PromptRunFailureEnvelope::new(
            "task-prompt-run-67890",
            failure_codes::REPORT_INVALID,
            "Output contract validation failed: missing required field 'recommendation'",
        )
        .with_artifacts(vec![failure_artifact]);

        println!("\n========== FAILURE ENVELOPE ==========");
        println!("{}", serde_json::to_string_pretty(&failure_envelope).unwrap());
    }
}
