//! API types for ekka-runner-core
//!
//! These types mirror the engine API schemas for runner task operations (v2).

use ekka_ops::llm_result::ArtifactRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Engine Runner Types (V2)
// =============================================================================

/// Engine task info from v2 poll response
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EngineTaskInfo {
    pub id: String,
    pub run_id: String,
    #[serde(default)]
    pub step_index: i32,
    #[serde(default)]
    pub step_id: Option<String>,
    /// Capability identity (e.g., "prompts.run.v1") - maps to task_subtype for dispatch
    pub capability_identity: String,
    #[serde(default)]
    pub target_type: Option<String>,
    pub input_json: serde_json::Value,
    #[serde(default)]
    pub config_json: Option<serde_json::Value>,
    #[serde(default)]
    pub priority: Option<String>,
    pub status: String,
    #[serde(default)]
    pub claimed_by: Option<String>,
    #[serde(default)]
    pub claimed_at: Option<String>,
    #[serde(default)]
    pub deadline_at: Option<String>,
    #[serde(default)]
    pub attempt_number: Option<i32>,
    #[serde(default)]
    pub max_attempts: Option<i32>,
    pub tenant_id: String,
    pub workspace_id: String,
    pub correlation_id: String,
    pub created_at: String,
}

impl EngineTaskInfo {
    /// Map capability_identity to legacy task_subtype for dispatch compatibility
    pub fn task_subtype(&self) -> Option<&str> {
        // Map capability identities to task subtypes
        if self.capability_identity.contains("prompt") {
            Some("prompt_run")
        } else if self.capability_identity.contains("node_exec") {
            Some("node_exec")
        } else {
            // Return capability_identity as-is, dispatch will handle unknown types
            Some(self.capability_identity.as_str())
        }
    }
}

/// Pagination info from v2 poll response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EnginePollPagination {
    pub limit: i32,
    pub offset: i32,
    pub has_more: bool,
}

/// Engine poll response (v2)
#[derive(Debug, Deserialize)]
pub struct EnginePollResponse {
    pub tasks: Vec<EngineTaskInfo>,
    #[serde(default)]
    pub pagination: Option<EnginePollPagination>,
}

/// Engine claim response (v2)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EngineClaimResponse {
    pub success: bool,
    pub task_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub step_index: Option<i32>,
    #[serde(default)]
    pub capability_identity: Option<String>,
    pub input_json: serde_json::Value,
    #[serde(default)]
    pub config_json: Option<serde_json::Value>,
    #[serde(default)]
    pub claimed_at: Option<String>,
    #[serde(default)]
    pub deadline_at: Option<String>,
}

/// Engine complete request body (v2)
/// V2 uses simpler output: just a JSON object, no decision/reason wrapper
#[derive(Debug, Serialize)]
pub struct EngineCompleteRequest {
    pub runner_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
}

/// Engine complete output (decision + reason) - used internally before sending to v2
#[derive(Debug, Clone, Serialize)]
pub struct EngineCompleteOutput {
    pub decision: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_patch: Option<Vec<serde_json::Value>>,
}

/// Engine fail request body (v2)
/// V2 uses error_code (required), error_message, error_details
#[derive(Debug, Serialize)]
pub struct EngineFailRequest {
    pub runner_id: String,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

// =============================================================================
// Dispatch Context
// =============================================================================

/// Context for task execution
#[derive(Debug, Clone)]
pub struct TaskExecutionContext {
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
// Prompt Run Types
// =============================================================================

pub const PROMPT_RUN_TASK_SCHEMA_VERSION: &str = "prompt_run_task.v1";
pub const PROMPT_RUN_RESULT_SCHEMA_VERSION: &str = "prompt_run.result.v1";
pub const PROMPT_RUN_OUTPUT_SCHEMA_VERSION: &str = "prompt_run.output.v1";
pub const LLM_TIMEOUT_SECS: u64 = 60;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 90;

#[derive(Debug, Clone, Deserialize)]
pub struct PromptIdentity {
    pub provider: String,
    pub prompt_slug: String,
    pub prompt_version: serde_json::Value,
    pub prompt_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
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
}

#[derive(Debug, Serialize)]
pub struct PromptFetchRequest {
    pub tenant_id: String,
    pub workspace_id: String,
    pub prompt_slug: String,
    pub prompt_version: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PromptFetchResponse {
    pub prompt_slug: String,
    pub prompt_version: String,
    pub prompt_text: String,
    pub prompt_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeCliOutput {
    pub result: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub usage: Option<ClaudeUsage>,
}

#[derive(Debug, Deserialize)]
pub struct ClaudeUsage {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LlmUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LlmTimings {
    pub llm_latency_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromptRunOutputV1 {
    pub schema_version: String,
    pub decision: String,
    pub output_text: String,
    pub model: String,
    pub usage: LlmUsage,
    pub timings_ms: LlmTimings,
    /// Artifact references (stdout.gz, stderr.gz, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRef>,
}

#[derive(Debug, Serialize)]
pub struct PromptRunSuccessEnvelope {
    pub success: bool,
    pub schema_version: String,
    pub task_subtype: String,
    pub task_id: String,
    pub output: PromptRunOutputV1,
}

#[derive(Debug, Serialize)]
pub struct PromptRunFailureEnvelope {
    pub success: bool,
    pub schema_version: String,
    pub task_subtype: String,
    pub task_id: String,
    pub failure_code: String,
    pub message: String,
    /// Artifact references captured on failure (debug artifacts)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRef>,
}

/// Engine context for prompt_run executor
///
/// Contains the node session token and tenant/workspace IDs for authenticating
/// with the engine when fetching prompts and other resources.
#[derive(Debug, Clone)]
pub struct EngineContext {
    pub engine_url: String,
    /// Node session JWT token (from POST /engine/nodes/auth)
    pub session_token: String,
    pub tenant_id: String,
    pub workspace_id: String,
}

impl EngineContext {
    /// Create context with node session auth
    pub fn with_node_session(engine_url: String, session_token: String, tenant_id: String, workspace_id: String) -> Self {
        Self {
            engine_url,
            session_token,
            tenant_id,
            workspace_id,
        }
    }
}
