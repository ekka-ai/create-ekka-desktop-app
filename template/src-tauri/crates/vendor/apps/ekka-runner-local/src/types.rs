//! API types for ekka-runner-local
//!
//! These types mirror the engine API schemas for runner task operations.
//!
//! ## Security Invariants (prompt_run)
//! - Variables are NEVER logged
//! - Prompt text is NEVER logged
//! - Secrets in variables are detected and rejected
//! - Prompt hash is verified before execution

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Engine Runner Types (RAPTOR-3 Step 4)
// =============================================================================

/// Engine task info from poll response
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
pub struct EngineTaskInfo {
    pub id: String,
    pub workflow_id: String,
    pub correlation_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub task_type: String,
    pub task_subtype: Option<String>,
    pub input_json: serde_json::Value,
    pub status: String,
}

/// Engine poll response
#[derive(Debug, Deserialize)]
pub struct EnginePollResponse {
    pub tasks: Vec<EngineTaskInfo>,
}

/// Engine claim response
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
pub struct EngineClaimResponse {
    pub success: bool,
    pub task_id: String,
    pub input_json: serde_json::Value,
    pub lease_expires_at: String,
}

/// Engine complete request body
#[derive(Debug, Serialize)]
pub struct EngineCompleteRequest {
    pub runner_id: String,
    pub output: EngineCompleteOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Engine complete output (decision + reason)
#[derive(Debug, Clone, Serialize)]
pub struct EngineCompleteOutput {
    pub decision: String,
    pub reason: String,
    /// Output artifacts as array (engine schema expects array, not object)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_patch: Option<Vec<serde_json::Value>>,
}

/// Engine fail request body
#[derive(Debug, Serialize)]
pub struct EngineFailRequest {
    pub runner_id: String,
    pub error: String,
    pub error_code: Option<String>,
    pub retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

// =============================================================================
// Dispatch Context (passed to executors)
// =============================================================================

/// Context for task execution - contains data needed by executors
#[derive(Debug, Clone)]
pub struct TaskExecutionContext {
    #[allow(dead_code)] // Reserved for future use (e.g., prompt_run)
    pub task_id: String,
    pub task_id_short: String,
    pub input_json: serde_json::Value,
}

impl TaskExecutionContext {
    pub fn new(task_id: String, input_json: serde_json::Value) -> Self {
        let task_id_short = task_id[..8.min(task_id.len())].to_string();
        Self {
            task_id,
            task_id_short,
            input_json,
        }
    }
}

// =============================================================================
// Prompt Run Types (prompt_run executor)
// =============================================================================

/// Expected schema version for prompt_run task input
pub const PROMPT_RUN_TASK_SCHEMA_VERSION: &str = "prompt_run_task.v1";

/// Result schema version for prompt_run output
pub const PROMPT_RUN_RESULT_SCHEMA_VERSION: &str = "prompt_run.result.v1";

/// Output schema version for prompt_run success output
pub const PROMPT_RUN_OUTPUT_SCHEMA_VERSION: &str = "prompt_run.output.v1";

/// LLM execution timeout in seconds (production default: 20 minutes)
/// See TECH_DEBT.md TD-TIMEOUT-001 for future per-prompt timeout configuration.
pub const LLM_TIMEOUT_SECS_DEFAULT: u64 = 1200;

/// Get effective LLM timeout in seconds.
/// Reads EKKA_LLM_TIMEOUT_SECS env var if set, otherwise uses default.
/// This allows testing with short timeouts without changing production defaults.
pub fn get_llm_timeout_secs() -> u64 {
    std::env::var("EKKA_LLM_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(LLM_TIMEOUT_SECS_DEFAULT)
}

/// Heartbeat interval in seconds during LLM execution
pub const HEARTBEAT_INTERVAL_SECS: u64 = 90;

/// Prompt identity reference (provider/slug/version/hash)
#[derive(Debug, Clone, Deserialize)]
pub struct PromptIdentity {
    pub provider: String,
    pub prompt_slug: String,
    pub prompt_version: serde_json::Value, // String or Number
    pub prompt_hash: String,
}

/// Prompt run task payload (input schema)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization and future features
pub struct PromptRunTaskPayloadV1 {
    pub schema_version: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub request_id: String,
    #[serde(default)]
    pub execution_nonce: Option<String>,
    #[serde(default)]
    pub retry_attempt: u32,
    pub prompt: PromptIdentity,
    #[serde(default)]
    pub variables: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Generic input directories for Claude sandbox access.
    /// If present, each directory is PathGuard-validated and passed to Claude CLI via --add-dir.
    /// Backward compat: if absent but INPUT_PATH variable exists, treated as input_dirs=[INPUT_PATH].
    #[serde(default)]
    pub input_dirs: Option<Vec<String>>,
    /// Output directory for Claude sandbox. If absent, defaults to cwd or EKKA_HOME.
    #[serde(default)]
    pub output_dir: Option<String>,
}

/// Request body for engine prompt fetch endpoint
#[derive(Debug, Serialize)]
pub struct PromptFetchRequest {
    pub tenant_id: String,
    pub workspace_id: String,
    pub prompt_slug: String,
    pub prompt_version: String,
}

/// Output contract from engine (for output validation)
#[derive(Debug, Clone, Deserialize)]
pub struct OutputContract {
    pub schema_id: String,
    pub schema: serde_json::Value,
    pub enforce: bool,
}

/// Response from engine prompt fetch endpoint
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for response validation
pub struct PromptFetchResponse {
    pub prompt_slug: String,
    pub prompt_version: String,
    pub prompt_text: String,
    pub prompt_hash: String,
    /// Output contract for validation (if enforce=true, runner must validate)
    #[serde(default)]
    pub output_contract: Option<OutputContract>,
}

/// Claude CLI JSON output structure (normalized)
#[derive(Debug, Clone)]
pub struct ClaudeCliOutput {
    pub result: String,
    pub model: Option<String>,
    pub usage: Option<ClaudeUsage>,
}

/// Claude CLI usage stats
#[derive(Debug, Clone, Deserialize)]
pub struct ClaudeUsage {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
}

/// Claude CLI event (for NDJSON/array parsing)
#[derive(Debug, Deserialize)]
struct ClaudeCliEvent {
    #[serde(rename = "type")]
    event_type: Option<String>,
    result: Option<String>,
    model: Option<String>,
    #[serde(default)]
    usage: Option<ClaudeUsage>,
}

/// Parse Claude CLI output which may be:
/// - NDJSON lines (one JSON object per line, find type="result")
/// - JSON array of events (find element with type="result")
/// - Single object with "result" field (legacy format)
pub fn parse_claude_cli_output(stdout: &str) -> Result<ClaudeCliOutput, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err("Empty output".to_string());
    }

    // Try 1: Parse as JSON array of events
    if trimmed.starts_with('[') {
        if let Ok(events) = serde_json::from_str::<Vec<ClaudeCliEvent>>(trimmed) {
            if let Some(result_event) = events.iter().rev().find(|e| {
                e.event_type.as_deref() == Some("result")
            }) {
                if let Some(ref result) = result_event.result {
                    return Ok(ClaudeCliOutput {
                        result: result.clone(),
                        model: result_event.model.clone(),
                        usage: result_event.usage.clone(),
                    });
                }
            }
        }
    }

    // Try 2: Parse as NDJSON (newline-delimited JSON)
    let mut last_result: Option<ClaudeCliOutput> = None;
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<ClaudeCliEvent>(line) {
            if event.event_type.as_deref() == Some("result") {
                if let Some(ref result) = event.result {
                    last_result = Some(ClaudeCliOutput {
                        result: result.clone(),
                        model: event.model.clone(),
                        usage: event.usage.clone(),
                    });
                }
            }
        }
    }
    if let Some(output) = last_result {
        return Ok(output);
    }

    // Try 3: Parse as single object with "result" field (legacy format)
    #[derive(Deserialize)]
    struct LegacyOutput {
        result: String,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        usage: Option<ClaudeUsage>,
    }
    if let Ok(legacy) = serde_json::from_str::<LegacyOutput>(trimmed) {
        return Ok(ClaudeCliOutput {
            result: legacy.result,
            model: legacy.model,
            usage: legacy.usage,
        });
    }

    Err(format!(
        "Failed to parse Claude CLI output: no result event found (first 200 chars: {})",
        trimmed.chars().take(200).collect::<String>()
    ))
}

/// Streaming-safe parser for Claude CLI output.
///
/// Handles large outputs by scanning for result events without full materialization:
/// - JSON array: First tries full parse, then falls back to line-by-line scanning
/// - NDJSON: Scans line-by-line, keeps last event with type="result"
/// - Single object: Falls back to direct parse
///
/// This handles outputs with many events/tool outputs that could be hundreds of KB.
pub fn parse_claude_cli_output_streaming(stdout: &str) -> Result<ClaudeCliOutput, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err("Empty output".to_string());
    }

    // Try 1: JSON array - first try full parse (fast for small outputs)
    if trimmed.starts_with('[') {
        if let Ok(events) = serde_json::from_str::<Vec<ClaudeCliEvent>>(trimmed) {
            if let Some(result_event) = events.iter().rev().find(|e| {
                e.event_type.as_deref() == Some("result")
            }) {
                if let Some(ref result) = result_event.result {
                    return Ok(ClaudeCliOutput {
                        result: result.clone(),
                        model: result_event.model.clone(),
                        usage: result_event.usage.clone(),
                    });
                }
            }
            // Array parsed but no result - will fall through
        }
        // Full array parse failed - try line-by-line for large/malformed arrays
    }

    // Try 2: NDJSON or line-by-line array scanning
    // This handles both:
    // - NDJSON format (one JSON object per line)
    // - JSON array where each element is on its own line (pretty-printed)
    let mut last_result: Option<ClaudeCliOutput> = None;
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip array brackets
        if line == "[" || line == "]" {
            continue;
        }
        // Strip trailing comma (JSON array elements)
        let json_str = line.trim_end_matches(',');
        if json_str.is_empty() || json_str == "[" || json_str == "]" {
            continue;
        }

        // Try to parse as a single event
        if let Ok(event) = serde_json::from_str::<ClaudeCliEvent>(json_str) {
            if event.event_type.as_deref() == Some("result") {
                if let Some(ref result) = event.result {
                    last_result = Some(ClaudeCliOutput {
                        result: result.clone(),
                        model: event.model.clone(),
                        usage: event.usage.clone(),
                    });
                }
            }
        }
    }
    if let Some(output) = last_result {
        return Ok(output);
    }

    // Try 3: Single object with "result" field (legacy format)
    #[derive(Deserialize)]
    struct LegacyOutput {
        result: String,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        usage: Option<ClaudeUsage>,
    }
    if let Ok(legacy) = serde_json::from_str::<LegacyOutput>(trimmed) {
        return Ok(ClaudeCliOutput {
            result: legacy.result,
            model: legacy.model,
            usage: legacy.usage,
        });
    }

    // Check if result marker exists anywhere (diagnostic)
    let has_result_marker = trimmed.contains(r#""type":"result""#) || trimmed.contains(r#""type": "result""#);

    Err(format!(
        "Failed to parse Claude CLI output: no result event found (stdout_len={}, has_result_marker={})",
        trimmed.len(),
        has_result_marker
    ))
}

/// LLM usage in result envelope
#[derive(Debug, Clone, Serialize)]
pub struct LlmUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
}

/// LLM timing information
#[derive(Debug, Clone, Serialize)]
pub struct LlmTimings {
    pub llm_latency_ms: u64,
}

/// Prompt run output (inside success envelope)
#[derive(Debug, Clone, Serialize)]
pub struct PromptRunOutputV1 {
    pub schema_version: String,
    pub decision: String,
    pub output_text: String,
    pub model: String,
    pub usage: LlmUsage,
    pub timings_ms: LlmTimings,
    /// Artifacts produced during execution (sealed to vault)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ekka_ops::llm_result::ArtifactRef>,
}

/// Success envelope for prompt_run result
#[derive(Debug, Serialize)]
pub struct PromptRunSuccessEnvelope {
    pub success: bool,
    pub schema_version: String,
    pub task_subtype: String,
    pub task_id: String,
    pub output: PromptRunOutputV1,
}

/// Debug bundle info for REPORT_INVALID failures (dev mode only)
#[derive(Debug, Clone, Serialize)]
pub struct DebugBundleInfo {
    /// Vault URI (e.g., "vault://tmp/telemetry/llm_debug/{tenant}/{run_id}/")
    pub debug_bundle_ref: String,
    /// SHA256 hash of raw output (for verification)
    pub raw_output_sha256: String,
    /// Length of raw output in bytes
    pub raw_output_len: usize,
    /// Files in the bundle (static list)
    pub files: Vec<String>,
}

/// Failure envelope for prompt_run result
#[derive(Debug, Serialize)]
pub struct PromptRunFailureEnvelope {
    pub success: bool,
    pub schema_version: String,
    pub task_subtype: String,
    pub task_id: String,
    pub failure_code: String,
    pub message: String,
    /// Debug bundle info (only present for REPORT_INVALID in dev mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_bundle: Option<DebugBundleInfo>,
}

/// Authentication type for engine requests
#[derive(Debug, Clone, Default)]
pub enum AuthType {
    /// Internal service key authentication (X-EKKA-INTERNAL-SERVICE-KEY header)
    #[default]
    InternalKey,
    /// Node session token authentication (Authorization: Bearer header)
    NodeSession,
}

/// Engine context for prompt_run executor (needs engine URL and auth)
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used by prompt_run executor
pub struct EngineContext {
    pub engine_url: String,
    /// For InternalKey: the internal service key
    /// For NodeSession: the session token
    pub internal_key: String,
    pub tenant_id: String,
    pub workspace_id: String,
    /// Authentication type (defaults to InternalKey for backward compatibility)
    pub auth_type: AuthType,
    /// EKKA home path for PathGuard (injected from desktop, falls back to env var)
    pub ekka_home_path: Option<std::path::PathBuf>,
    /// User subject (from JWT) for PathGuard grant validation
    /// Required for desktop runner to match grants issued to the user
    pub user_sub: Option<String>,
}

impl EngineContext {
    /// Create context with internal key auth (legacy CLI runner - uses env var for home)
    pub fn with_internal_key(
        engine_url: String,
        internal_key: String,
        tenant_id: String,
        workspace_id: String,
    ) -> Self {
        Self {
            engine_url,
            internal_key,
            tenant_id,
            workspace_id,
            auth_type: AuthType::InternalKey,
            ekka_home_path: None, // CLI runner uses EKKA_HOME env var
            user_sub: None,       // CLI runner has no user context
        }
    }

    /// Create context with node session auth (desktop runner - home path injected)
    pub fn with_node_session(
        engine_url: String,
        session_token: String,
        tenant_id: String,
        workspace_id: String,
    ) -> Self {
        Self {
            engine_url,
            internal_key: session_token,
            tenant_id,
            workspace_id,
            auth_type: AuthType::NodeSession,
            ekka_home_path: None, // Set via set_ekka_home_path()
            user_sub: None,       // Set via set_user_sub()
        }
    }

    /// Set the EKKA home path (for desktop runner where path is known)
    pub fn set_ekka_home_path(mut self, path: std::path::PathBuf) -> Self {
        self.ekka_home_path = Some(path);
        self
    }

    /// Set the user subject (for desktop runner to match grants)
    pub fn set_user_sub(mut self, sub: String) -> Self {
        self.user_sub = Some(sub);
        self
    }
}

// =============================================================================
// Contract Tests - Engine Schema Compatibility
// =============================================================================
//
// These tests validate that runner payload structures match engine API schemas.
// They catch schema mismatches at compile/test time, not at runtime.
//
// Engine schema reference (runner-tasks.ts):
//   completeSchema = z.object({
//     runner_id: z.string().min(1).max(100),
//     output: z.object({
//       decision: z.enum(['ACCEPT', 'UPDATE', 'REJECT']),
//       reason: z.string().min(1).max(5000),
//       proposed_patch: z.array(z.unknown()).optional(),
//     }),
//     duration_ms: z.number().int().min(0).optional(),
//   });

#[cfg(test)]
mod contract_tests {
    use super::*;

    /// Contract test: EngineCompleteRequest must serialize to engine-compatible JSON.
    ///
    /// This test caught a real bug where proposed_patch was sent as an object
    /// instead of an array, causing 400 validation errors.
    #[test]
    fn complete_request_schema_matches_engine() {
        // Build a typical complete request with proposed_patch
        let output_artifact = serde_json::json!({
            "success": true,
            "schema_version": "prompt_run.result.v1",
            "task_subtype": "prompt_run",
            "task_id": "test-task-id",
            "output": {
                "decision": "ACCEPT",
                "output_text": "test output",
                "model": "claude-sonnet-4-20250514"
            }
        });

        let request = EngineCompleteRequest {
            runner_id: "test-runner-123".to_string(),
            output: EngineCompleteOutput {
                decision: "ACCEPT".to_string(),
                reason: "Task executed successfully".to_string(),
                proposed_patch: Some(vec![output_artifact]),
            },
            duration_ms: Some(1234),
        };

        let json = serde_json::to_value(&request).expect("serialize complete request");

        // Validate structure matches engine schema
        assert!(json.get("runner_id").is_some(), "must have runner_id");
        assert!(
            json["runner_id"].is_string(),
            "runner_id must be string"
        );

        assert!(json.get("output").is_some(), "must have output");
        let output = &json["output"];

        assert!(
            output.get("decision").is_some(),
            "output must have decision"
        );
        assert!(
            output["decision"].is_string(),
            "decision must be string"
        );
        let decision = output["decision"].as_str().unwrap();
        assert!(
            ["ACCEPT", "UPDATE", "REJECT"].contains(&decision),
            "decision must be ACCEPT/UPDATE/REJECT, got: {}",
            decision
        );

        assert!(output.get("reason").is_some(), "output must have reason");
        assert!(output["reason"].is_string(), "reason must be string");

        // CRITICAL: proposed_patch must be an ARRAY, not an object
        // This was the root cause of the schema mismatch bug
        assert!(
            output.get("proposed_patch").is_some(),
            "output must have proposed_patch when set"
        );
        assert!(
            output["proposed_patch"].is_array(),
            "proposed_patch MUST be an array (engine schema: z.array(z.unknown()))"
        );

        // duration_ms is optional but must be integer when present
        assert!(json.get("duration_ms").is_some(), "must have duration_ms");
        assert!(
            json["duration_ms"].is_u64() || json["duration_ms"].is_i64(),
            "duration_ms must be integer"
        );
    }

    /// Contract test: EngineCompleteRequest serializes correctly without proposed_patch
    #[test]
    fn complete_request_without_proposed_patch() {
        let request = EngineCompleteRequest {
            runner_id: "test-runner".to_string(),
            output: EngineCompleteOutput {
                decision: "REJECT".to_string(),
                reason: "Invalid input".to_string(),
                proposed_patch: None,
            },
            duration_ms: None,
        };

        let json = serde_json::to_value(&request).expect("serialize");

        // proposed_patch should be absent when None (skip_serializing_if)
        assert!(
            json["output"].get("proposed_patch").is_none(),
            "proposed_patch should be omitted when None"
        );

        // duration_ms should be absent when None
        assert!(
            json.get("duration_ms").is_none(),
            "duration_ms should be omitted when None"
        );
    }

    /// Contract test: Decision values match engine enum
    #[test]
    fn decision_values_match_engine_enum() {
        // Engine schema: z.enum(['ACCEPT', 'UPDATE', 'REJECT'])
        let valid_decisions = ["ACCEPT", "UPDATE", "REJECT"];

        for decision in valid_decisions {
            let output = EngineCompleteOutput {
                decision: decision.to_string(),
                reason: "test".to_string(),
                proposed_patch: None,
            };
            let json = serde_json::to_value(&output).expect("serialize");
            assert_eq!(json["decision"].as_str().unwrap(), decision);
        }
    }
}

#[cfg(test)]
mod claude_parser_tests {
    use super::*;

    #[test]
    fn test_parse_ndjson_format() {
        // NDJSON format (one JSON object per line)
        let ndjson = r#"{"type":"system","content":"init"}
{"type":"assistant","content":"thinking..."}
{"type":"result","result":"The answer is 42","model":"claude-3-opus"}"#;

        let output = parse_claude_cli_output(ndjson).unwrap();
        assert_eq!(output.result, "The answer is 42");
        assert_eq!(output.model, Some("claude-3-opus".to_string()));
    }

    #[test]
    fn test_parse_array_format() {
        // JSON array format
        let array = r#"[
            {"type":"system","content":"init"},
            {"type":"assistant","content":"thinking..."},
            {"type":"result","result":"Array result","model":"gpt-4"}
        ]"#;

        let output = parse_claude_cli_output(array).unwrap();
        assert_eq!(output.result, "Array result");
        assert_eq!(output.model, Some("gpt-4".to_string()));
    }

    #[test]
    fn test_parse_legacy_format() {
        // Legacy single object format
        let legacy = r#"{"result":"Legacy output","model":"claude-2"}"#;

        let output = parse_claude_cli_output(legacy).unwrap();
        assert_eq!(output.result, "Legacy output");
        assert_eq!(output.model, Some("claude-2".to_string()));
    }

    #[test]
    fn test_parse_empty_fails() {
        let result = parse_claude_cli_output("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Empty"));
    }

    #[test]
    fn test_parse_no_result_fails() {
        let no_result = r#"{"type":"system","content":"no result event"}"#;
        let result = parse_claude_cli_output(no_result);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no result event found"));
    }

    #[test]
    fn test_parse_with_usage() {
        let with_usage = r#"{"type":"result","result":"output","usage":{"input_tokens":100,"output_tokens":50}}"#;

        let output = parse_claude_cli_output(with_usage).unwrap();
        assert_eq!(output.result, "output");
        assert!(output.usage.is_some());
        let usage = output.usage.unwrap();
        assert_eq!(usage.input_tokens, Some(100));
        assert_eq!(usage.output_tokens, Some(50));
    }

    // =========================================================================
    // Streaming Parser Tests
    // =========================================================================

    #[test]
    fn test_streaming_parse_ndjson_format() {
        let ndjson = r#"{"type":"system","content":"init"}
{"type":"assistant","content":"thinking..."}
{"type":"result","result":"Streaming NDJSON result","model":"claude-sonnet"}"#;

        let output = parse_claude_cli_output_streaming(ndjson).unwrap();
        assert_eq!(output.result, "Streaming NDJSON result");
        assert_eq!(output.model, Some("claude-sonnet".to_string()));
    }

    #[test]
    fn test_streaming_parse_array_format() {
        let array = r#"[
            {"type":"system","content":"init"},
            {"type":"assistant","content":"thinking..."},
            {"type":"result","result":"Streaming array result","model":"claude-opus"}
        ]"#;

        let output = parse_claude_cli_output_streaming(array).unwrap();
        assert_eq!(output.result, "Streaming array result");
        assert_eq!(output.model, Some("claude-opus".to_string()));
    }

    #[test]
    fn test_streaming_parse_line_by_line_array() {
        // JSON array with each element on its own line (what Claude CLI actually outputs)
        // This simulates pretty-printed JSON array output
        let array = r#"[
{"type":"system","subtype":"init","session_id":"abc123"},
{"type":"assistant","message":"I'll help you with that."},
{"type":"tool_use","name":"read_file","input":{"path":"test.txt"}},
{"type":"tool_result","content":"file contents here"},
{"type":"result","result":"The final answer is here","model":"claude-sonnet-4","usage":{"input_tokens":500,"output_tokens":200}}
]"#;

        let output = parse_claude_cli_output_streaming(array).unwrap();
        assert_eq!(output.result, "The final answer is here");
        assert_eq!(output.model, Some("claude-sonnet-4".to_string()));
        assert!(output.usage.is_some());
    }

    #[test]
    fn test_streaming_parse_large_output_simulation() {
        // Simulate a large output with many events (like docgen with many files)
        let mut events = String::from("[\n");
        for i in 0..100 {
            events.push_str(&format!(
                r#"{{"type":"tool_use","name":"write_file","input":{{"path":"file{}.md"}}}},"#,
                i
            ));
            events.push('\n');
            events.push_str(&format!(
                r#"{{"type":"tool_result","content":"wrote {} bytes"}},"#,
                i * 100
            ));
            events.push('\n');
        }
        events.push_str(r#"{"type":"result","result":"Generated 100 files successfully","model":"claude-sonnet"}"#);
        events.push_str("\n]");

        let output = parse_claude_cli_output_streaming(&events).unwrap();
        assert_eq!(output.result, "Generated 100 files successfully");
        assert!(events.len() > 10000, "Test data should be >10KB, got {} bytes", events.len());
    }

    #[test]
    fn test_streaming_parse_empty_fails() {
        let result = parse_claude_cli_output_streaming("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Empty"));
    }

    #[test]
    fn test_streaming_parse_no_result_diagnostics() {
        // Should include diagnostic info about has_result_marker
        let no_result = r#"{"type":"system","content":"no result event"}"#;
        let result = parse_claude_cli_output_streaming(no_result);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("no result event found"));
        assert!(err.contains("has_result_marker=false"));
    }
}
