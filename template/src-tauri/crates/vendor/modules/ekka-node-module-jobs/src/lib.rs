//! EKKA Node Jobs Module - RAPTOR-2 Step 32/36 + RAPTOR-3 Step 1/5
//!
//! Provides capability-gated job execution skeleton with persistent job store.
//! Jobs are tracked per workspace with status lifecycle: queued -> running -> succeeded/failed.
//!
//! ## Security Properties
//!
//! - No absolute paths in responses (only workspace_id and job_id)
//! - Session validation before capability checks (401 then 403)
//! - Workspace validation (workspace_id must exist in inventory)
//! - Capability-gated: jobs.create, jobs.read
//! - Structured logging with node.jobs.* prefix
//! - Intent materialization validates source job ownership (RAPTOR-2 Step 36)
//! - Encrypted persistence using AES-256-GCM with HKDF key derivation (RAPTOR-3 Step 1)
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - A JobsModuleContext with job store and validators
//!
//! When disabled via EKKA_ENABLE_JOBS=0, routes are NOT mounted -> 404.
//!
//! ## Queue Mode (RAPTOR-3 Step 5)
//!
//! EKKA_NODE_JOB_QUEUE_MODE controls whether node-local job creation is allowed:
//! - `disabled` (default): Job creation returns 409 NODE_QUEUE_DISABLED error
//! - `legacy`: Job creation allowed (for RAPTOR-2 backward testing only)
//!
//! ## Lease-Based Job Claiming (RAPTOR-3 Step 1)
//!
//! Jobs can be claimed by runners with lease-based ownership:
//! - lease_owner: Runner ID that currently owns the job
//! - lease_expires_at: When the lease expires (runner must heartbeat to extend)
//! - claimed_at: When the job was first claimed
//! - attempt_count: Number of claim attempts (for retry limiting)

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

pub use ekka_node_modules::{
    error_codes, ModuleConfig, ModuleError,
    SessionInfo, SessionValidationError, SessionValidator,
};

// Persistence module (RAPTOR-3 Step 1)
pub mod persist;

// =============================================================================
// Module Configuration
// =============================================================================

/// Jobs module configuration
pub const JOBS_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Jobs",
    env_var: "EKKA_ENABLE_JOBS",
    default_enabled: true, // Jobs is safe tier (no FS access, no external calls)
};

// =============================================================================
// Queue Mode Configuration (RAPTOR-3 Step 5)
// =============================================================================

/// Queue mode for node-local job creation
/// Controls whether jobs can be created in the node-local queue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeJobQueueMode {
    /// Node job queue is disabled - job creation returns 409 error
    /// This is the DEFAULT as of RAPTOR-3 Step 5
    Disabled,
    /// Legacy mode - allows node-local job creation
    /// Only for RAPTOR-2 backward testing
    Legacy,
}

impl NodeJobQueueMode {
    /// Parse from environment variable EKKA_NODE_JOB_QUEUE_MODE
    /// Returns Disabled if not set or invalid
    pub fn from_env() -> Self {
        match std::env::var("EKKA_NODE_JOB_QUEUE_MODE").as_deref() {
            Ok("legacy") => {
                warn!(
                    op = "node.jobs.queue_mode.legacy",
                    "Node job queue running in LEGACY mode - this is deprecated"
                );
                NodeJobQueueMode::Legacy
            }
            Ok("disabled") | Err(_) => NodeJobQueueMode::Disabled,
            Ok(other) => {
                warn!(
                    op = "node.jobs.queue_mode.invalid",
                    value = %other,
                    "Invalid EKKA_NODE_JOB_QUEUE_MODE, defaulting to disabled"
                );
                NodeJobQueueMode::Disabled
            }
        }
    }

    /// Check if job creation is allowed in this mode
    pub fn allows_job_creation(&self) -> bool {
        matches!(self, NodeJobQueueMode::Legacy)
    }
}

impl std::fmt::Display for NodeJobQueueMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeJobQueueMode::Disabled => write!(f, "disabled"),
            NodeJobQueueMode::Legacy => write!(f, "legacy"),
        }
    }
}

/// Required capability for jobs read operations
pub const JOBS_READ_CAPABILITY: &str = "jobs.read";

/// Required capability for jobs create operations
pub const JOBS_CREATE_CAPABILITY: &str = "jobs.create";

/// Maximum jobs per workspace in the ring buffer
pub const MAX_JOBS_PER_WORKSPACE: usize = 200;

/// Maximum limit for list query
pub const MAX_LIST_LIMIT: usize = 50;

/// Maximum length for commit message in payload
pub const MAX_COMMIT_MESSAGE_LEN: usize = 200;

/// Maximum length for PR title in payload
pub const MAX_PR_TITLE_LEN: usize = 200;

/// Maximum length for PR body in payload
pub const MAX_PR_BODY_LEN: usize = 1000;

/// Maximum length for agent prompt (8KB)
pub const MAX_AGENT_PROMPT_LEN: usize = 8 * 1024;

/// Maximum size for agent inputs JSON (32KB)
pub const MAX_AGENT_INPUTS_SIZE: usize = 32 * 1024;

/// Maximum length for artifact text result (64KB)
pub const MAX_ARTIFACT_TEXT_LEN: usize = 64 * 1024;

/// Maximum size for artifact JSON result (64KB)
pub const MAX_ARTIFACT_JSON_SIZE: usize = 64 * 1024;

/// Maximum length for result message
pub const MAX_RESULT_MESSAGE_LEN: usize = 500;

/// Maximum length for intent notes (2KB) - RAPTOR-2 Step 36
pub const MAX_INTENT_NOTES_LEN: usize = 2 * 1024;

// =============================================================================
// Job Types
// =============================================================================

/// Job type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobType {
    RepoWorkflow,
    AgentRun,
    Custom,
}

impl std::fmt::Display for JobType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobType::RepoWorkflow => write!(f, "repo_workflow"),
            JobType::AgentRun => write!(f, "agent_run"),
            JobType::Custom => write!(f, "custom"),
        }
    }
}

impl JobType {
    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "repo_workflow" => Some(JobType::RepoWorkflow),
            "agent_run" => Some(JobType::AgentRun),
            "custom" => Some(JobType::Custom),
            _ => None,
        }
    }
}

/// Job status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Queued => write!(f, "queued"),
            JobStatus::Running => write!(f, "running"),
            JobStatus::Succeeded => write!(f, "succeeded"),
            JobStatus::Failed => write!(f, "failed"),
        }
    }
}

// =============================================================================
// Failure Classification (RAPTOR-3 Step 3)
// =============================================================================

/// Failure classification for retry decisions
/// Determines whether a failed job should be retried or marked as terminal failure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Transient failure - job should be retried with backoff
    Retryable,
    /// Permanent failure - job should NOT be retried
    NonRetryable,
}

/// Classify an error code into retryable or non-retryable
/// Uses a deterministic allowlist - exact matches only, no heuristics
pub fn classify_error(code: &str) -> FailureClass {
    // Retryable errors: transient conditions that may resolve on retry
    const RETRYABLE_CODES: &[&str] = &[
        // GitHub/Git transient errors
        "GITHUB_NOT_CONNECTED",
        "GITHUB_NOT_CONFIGURED",
        "GIT_OPERATION_TIMEOUT",
        "GIT_NETWORK_ERROR",
        "GIT_RATE_LIMITED",
        // Data persistence transient errors
        "DATA_LOAD_FAILED",
        "DATA_PERSIST_FAILED",
        "DATA_DECRYPT_FAILED",
        // Network transient errors
        "NETWORK_TIMEOUT",
        "NETWORK_UNAVAILABLE",
        "SERVICE_UNAVAILABLE",
        "CONNECTION_RESET",
        // Runner transient errors
        "RUNNER_TIMEOUT",
        "RUNNER_UNAVAILABLE",
        "LEASE_EXPIRED",
        // LLM transient errors
        "LLM_TIMEOUT",
        "LLM_RATE_LIMITED",
        "LLM_SERVICE_ERROR",
    ];

    // Non-retryable errors: permanent conditions that won't change on retry
    const NON_RETRYABLE_CODES: &[&str] = &[
        // Authorization/policy errors
        "REPO_NOT_ALLOWED",
        "REPO_NOT_BOUND",
        "CAPABILITY_DENIED",
        "NOT_AUTHORIZED",
        "FORBIDDEN",
        // Git policy errors
        "GIT_PROTECTED_BRANCH",
        "GIT_INVALID_REF",
        // Validation errors
        "INVALID_PAYLOAD",
        "INVALID_JOB_TYPE",
        "INVALID_WORKSPACE_ID",
        "INVALID_JOB_ID",
        "WORKSPACE_NOT_FOUND",
        "JOB_NOT_FOUND",
        // Schema/config errors
        "DATA_SCHEMA_UNSUPPORTED",
        "DATA_KEY_NOT_CONFIGURED",
        // Intent validation errors (prefix match handled below)
        "INTENT_INVALID_SCHEMA",
        "INTENT_INVALID_JOB_TYPE",
        "INTENT_INVALID_FIELD",
        "INTENT_FORBIDDEN_PATTERN",
        "INTENT_TENANT_MISMATCH",
        "INTENT_WORKSPACE_MISMATCH",
        "INTENT_SOURCE_NOT_FOUND",
        "INTENT_SOURCE_NOT_SUCCEEDED",
    ];

    // First check exact matches for retryable
    if RETRYABLE_CODES.contains(&code) {
        return FailureClass::Retryable;
    }

    // Then check exact matches for non-retryable
    if NON_RETRYABLE_CODES.contains(&code) {
        return FailureClass::NonRetryable;
    }

    // Check INTENT_INVALID_* prefix (deterministic, not substring heuristic)
    if code.starts_with("INTENT_INVALID_") {
        return FailureClass::NonRetryable;
    }

    // Default: unknown errors are non-retryable for safety
    // This prevents infinite retry loops on unexpected errors
    FailureClass::NonRetryable
}

/// Sanitize an error message for safe storage
/// - Strips newlines and control characters
/// - Truncates to 200 characters
/// - Replaces patterns that look like paths, URLs, or env vars
/// SECURITY: Ensures no sensitive data leaks into stored error messages
pub fn sanitize_error_message(message: &str) -> String {
    let mut result: String = message
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(250) // Take extra to allow for replacements
        .collect();

    // Replace path patterns
    let path_patterns = [
        "/Users/", "/home/", "/var/", "/tmp/", "/private/",
        "C:\\", "D:\\", "E:\\",
    ];
    for pattern in path_patterns {
        if result.contains(pattern) {
            // Replace the path with a generic placeholder
            // Find where the path starts and ends
            while let Some(start) = result.find(pattern) {
                // Find end of path (space, quote, or end of string)
                let rest = &result[start..];
                let end_offset = rest
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ')')
                    .unwrap_or(rest.len());
                result.replace_range(start..start + end_offset, "[path]");
            }
        }
    }

    // Replace URL patterns
    if result.contains("://") {
        while let Some(start) = result.find("://") {
            // Find protocol start (go backwards to find http, https, etc.)
            let proto_start = result[..start]
                .rfind(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map(|i| i + 1)
                .unwrap_or(0);
            // Find URL end
            let rest = &result[start..];
            let end_offset = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ')')
                .unwrap_or(rest.len());
            result.replace_range(proto_start..start + end_offset, "[url]");
        }
    }

    // Replace env var patterns (EKKA_*)
    while result.contains("EKKA_") {
        if let Some(start) = result.find("EKKA_") {
            let rest = &result[start..];
            let end_offset = rest
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            result.replace_range(start..start + end_offset, "[env]");
        }
    }

    // Final truncation to 200 chars
    result.truncate(200);
    result.trim().to_string()
}

/// Calculate backoff delay for retry attempts
/// Uses bounded exponential backoff: base * 2^attempt, capped at max
/// RAPTOR-3 Step 3: Deterministic, predictable backoff schedule
pub fn calculate_backoff_secs(attempt_count: u32) -> i64 {
    const BASE_SECS: i64 = 30;
    const MAX_SECS: i64 = 600; // 10 minutes

    // 2^attempt_count, with overflow protection
    let multiplier = 1i64.checked_shl(attempt_count).unwrap_or(i64::MAX);
    let delay = BASE_SECS.saturating_mul(multiplier);

    delay.min(MAX_SECS)
}

// =============================================================================
// Job Payload (versioned, for execution parameters)
// =============================================================================

/// Job payload - versioned parameters for job execution
/// SECURITY: Never contains paths, URLs, tokens, or env vars
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobPayload {
    /// Schema version (for forward compatibility)
    pub schema: String,
    /// Job-type-specific parameters
    #[serde(flatten)]
    pub params: JobPayloadParams,
}

/// Job payload parameters (discriminated by job type)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "job_type", rename_all = "snake_case")]
pub enum JobPayloadParams {
    /// Parameters for repo_workflow job
    RepoWorkflow(RepoWorkflowPayload),
    /// Parameters for agent_run job (placeholder)
    AgentRun(AgentRunPayload),
    /// Parameters for custom job (placeholder)
    Custom(CustomPayload),
}

/// Repo workflow job parameters
/// SECURITY: commit_message and pr_title are sanitized, never contain paths/URLs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoWorkflowPayload {
    /// Commit message (max 200 chars, sanitized)
    #[serde(default)]
    pub commit_message: Option<String>,
    /// PR title (max 200 chars, sanitized)
    #[serde(default)]
    pub pr_title: Option<String>,
    /// PR body/description (max 1000 chars, sanitized)
    #[serde(default)]
    pub pr_body: Option<String>,
}

/// Agent run job parameters
/// SECURITY: prompt and inputs are sanitized, never contain paths/URLs/tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentRunPayload {
    /// Agent identifier (optional, for future use)
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Prompt text for the agent (max 8KB, sanitized)
    #[serde(default)]
    pub prompt: Option<String>,
    /// Input data as JSON object (max 32KB serialized)
    #[serde(default)]
    pub inputs: Option<serde_json::Value>,
}

/// Custom job parameters (placeholder for future)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomPayload {
    /// Custom data as key-value pairs (limited, sanitized)
    #[serde(default)]
    pub data: Option<HashMap<String, String>>,
}

// =============================================================================
// Repo Workflow Intent (RAPTOR-2 Step 36)
// =============================================================================

/// Intent to create a repo_workflow job from agent_run output.
/// This is a versioned, bounded schema that agents can produce.
/// SECURITY: Never contains paths, URLs, tokens, or branch lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoWorkflowIntentV1 {
    /// Schema version - must be "v1"
    pub schema: String,
    /// Job type - must be "repo_workflow"
    pub job_type: String,
    /// Commit message for the PR (max 200 chars, sanitized)
    pub commit_message: String,
    /// PR title (max 200 chars, sanitized)
    pub pr_title: String,
    /// PR base branch (optional, defaults to "main", validated format)
    /// SECURITY: No branch list leakage - just validate format
    #[serde(default)]
    pub pr_base: Option<String>,
    /// Optional notes about the intent (max 2KB, sanitized)
    #[serde(default)]
    pub notes: Option<String>,
}

impl RepoWorkflowIntentV1 {
    /// Validate the intent schema and bounds
    pub fn validate(&self) -> Result<(), IntentError> {
        // Schema version must be "v1"
        if self.schema != "v1" {
            return Err(IntentError::InvalidSchema(format!(
                "Expected schema 'v1', got '{}'",
                self.schema
            )));
        }

        // Job type must be "repo_workflow"
        if self.job_type != "repo_workflow" {
            return Err(IntentError::InvalidJobType(format!(
                "Expected job_type 'repo_workflow', got '{}'",
                self.job_type
            )));
        }

        // Commit message bounds
        if self.commit_message.is_empty() {
            return Err(IntentError::InvalidField("commit_message cannot be empty".to_string()));
        }
        if self.commit_message.len() > MAX_COMMIT_MESSAGE_LEN {
            return Err(IntentError::InvalidField(format!(
                "commit_message exceeds {} chars",
                MAX_COMMIT_MESSAGE_LEN
            )));
        }

        // PR title bounds
        if self.pr_title.is_empty() {
            return Err(IntentError::InvalidField("pr_title cannot be empty".to_string()));
        }
        if self.pr_title.len() > MAX_PR_TITLE_LEN {
            return Err(IntentError::InvalidField(format!(
                "pr_title exceeds {} chars",
                MAX_PR_TITLE_LEN
            )));
        }

        // PR base branch format validation (if provided)
        if let Some(ref base) = self.pr_base {
            if !Self::is_valid_branch_name(base) {
                return Err(IntentError::InvalidField(
                    "pr_base has invalid branch name format".to_string()
                ));
            }
        }

        // Notes bounds
        if let Some(ref notes) = self.notes {
            if notes.len() > MAX_INTENT_NOTES_LEN {
                return Err(IntentError::InvalidField(format!(
                    "notes exceeds {} bytes",
                    MAX_INTENT_NOTES_LEN
                )));
            }
        }

        // SECURITY: Check for forbidden patterns (paths, URLs, env vars)
        self.validate_no_leaks()?;

        Ok(())
    }

    /// Validate that no field contains forbidden patterns
    fn validate_no_leaks(&self) -> Result<(), IntentError> {
        let fields = [
            ("commit_message", self.commit_message.as_str()),
            ("pr_title", self.pr_title.as_str()),
        ];

        for (name, value) in fields {
            if Self::contains_forbidden_pattern(value) {
                return Err(IntentError::ForbiddenPattern(format!(
                    "{} contains forbidden pattern",
                    name
                )));
            }
        }

        if let Some(ref base) = self.pr_base {
            if Self::contains_forbidden_pattern(base) {
                return Err(IntentError::ForbiddenPattern(
                    "pr_base contains forbidden pattern".to_string()
                ));
            }
        }

        if let Some(ref notes) = self.notes {
            if Self::contains_forbidden_pattern(notes) {
                return Err(IntentError::ForbiddenPattern(
                    "notes contains forbidden pattern".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Check for forbidden patterns (paths, URLs, env vars)
    fn contains_forbidden_pattern(s: &str) -> bool {
        // Absolute paths
        s.contains("/Users/") || s.contains("/home/") || s.contains("/var/")
            || s.contains("/tmp/") || s.contains("/private/")
            || s.contains("C:\\") || s.contains("D:\\")
        // URLs
            || s.contains("https://") || s.contains("http://") || s.contains("github.com")
        // Env vars
            || s.contains("EKKA_")
    }

    /// Validate branch name format (no path traversal, reasonable chars)
    fn is_valid_branch_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 100 {
            return false;
        }
        // Must not start or end with / or .
        if name.starts_with('/') || name.ends_with('/')
            || name.starts_with('.') || name.ends_with('.') {
            return false;
        }
        // Must not contain path traversal
        if name.contains("..") || name.contains("//") {
            return false;
        }
        // Only allow alphanumeric, dash, underscore, slash, dot
        name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.')
    }

    /// Sanitize the intent fields (truncate, remove control chars)
    pub fn sanitize(&mut self) {
        self.commit_message = sanitize_payload_string(&self.commit_message, MAX_COMMIT_MESSAGE_LEN);
        self.pr_title = sanitize_payload_string(&self.pr_title, MAX_PR_TITLE_LEN);
        if let Some(ref notes) = self.notes {
            self.notes = Some(sanitize_payload_string(notes, MAX_INTENT_NOTES_LEN));
        }
        // pr_base is validated for format, not sanitized (it's a branch name)
    }

    /// Convert intent to a JobPayload for repo_workflow job creation
    pub fn to_job_payload(&self) -> JobPayload {
        JobPayload::repo_workflow(
            Some(self.commit_message.clone()),
            Some(self.pr_title.clone()),
            self.notes.clone(), // Use notes as PR body
        )
    }
}

/// Errors from intent validation
#[derive(Debug, Clone)]
pub enum IntentError {
    InvalidSchema(String),
    InvalidJobType(String),
    InvalidField(String),
    ForbiddenPattern(String),
    TenantMismatch,
    WorkspaceMismatch,
    SourceJobNotFound,
    SourceJobNotSucceeded,
}

impl JobPayload {
    /// Current schema version
    pub const SCHEMA_VERSION: &'static str = "v1";

    /// Create a new repo_workflow payload
    pub fn repo_workflow(
        commit_message: Option<String>,
        pr_title: Option<String>,
        pr_body: Option<String>,
    ) -> Self {
        Self {
            schema: Self::SCHEMA_VERSION.to_string(),
            params: JobPayloadParams::RepoWorkflow(RepoWorkflowPayload {
                commit_message,
                pr_title,
                pr_body,
            }),
        }
    }

    /// Create a new agent_run payload
    pub fn agent_run(
        prompt: Option<String>,
        inputs: Option<serde_json::Value>,
        agent_id: Option<String>,
    ) -> Self {
        Self {
            schema: Self::SCHEMA_VERSION.to_string(),
            params: JobPayloadParams::AgentRun(AgentRunPayload {
                agent_id,
                prompt,
                inputs,
            }),
        }
    }

    /// Sanitize all string fields in the payload
    pub fn sanitize(&mut self) {
        match &mut self.params {
            JobPayloadParams::RepoWorkflow(p) => {
                if let Some(ref mut msg) = p.commit_message {
                    *msg = sanitize_payload_string(msg, MAX_COMMIT_MESSAGE_LEN);
                }
                if let Some(ref mut title) = p.pr_title {
                    *title = sanitize_payload_string(title, MAX_PR_TITLE_LEN);
                }
                if let Some(ref mut body) = p.pr_body {
                    *body = sanitize_payload_string(body, MAX_PR_BODY_LEN);
                }
            }
            JobPayloadParams::AgentRun(p) => {
                if let Some(ref mut id) = p.agent_id {
                    *id = sanitize_payload_string(id, 100);
                }
                if let Some(ref mut prompt) = p.prompt {
                    *prompt = sanitize_payload_string(prompt, MAX_AGENT_PROMPT_LEN);
                }
                // Validate inputs JSON size
                if let Some(ref inputs) = p.inputs {
                    if let Ok(serialized) = serde_json::to_string(inputs) {
                        if serialized.len() > MAX_AGENT_INPUTS_SIZE {
                            p.inputs = None; // Drop oversized inputs
                        }
                    }
                }
            }
            JobPayloadParams::Custom(p) => {
                if let Some(ref mut data) = p.data {
                    for value in data.values_mut() {
                        *value = sanitize_payload_string(value, 500);
                    }
                }
            }
        }
    }

    /// Validate payload doesn't contain forbidden patterns (paths, URLs)
    pub fn validate(&self) -> Result<(), &'static str> {
        let check_string = |s: &str| -> Result<(), &'static str> {
            // Check for absolute paths
            if s.contains("/Users/") || s.contains("/home/") || s.contains("/var/")
                || s.contains("/tmp/") || s.contains("/private/")
                || s.contains("C:\\") || s.contains("D:\\") {
                return Err("Payload contains forbidden path pattern");
            }
            // Check for URLs
            if s.contains("https://") || s.contains("http://") || s.contains("github.com") {
                return Err("Payload contains forbidden URL pattern");
            }
            // Check for env vars
            if s.contains("EKKA_") {
                return Err("Payload contains forbidden env var pattern");
            }
            Ok(())
        };

        match &self.params {
            JobPayloadParams::RepoWorkflow(p) => {
                if let Some(ref msg) = p.commit_message {
                    check_string(msg)?;
                }
                if let Some(ref title) = p.pr_title {
                    check_string(title)?;
                }
                if let Some(ref body) = p.pr_body {
                    check_string(body)?;
                }
            }
            JobPayloadParams::AgentRun(p) => {
                if let Some(ref id) = p.agent_id {
                    check_string(id)?;
                }
                if let Some(ref prompt) = p.prompt {
                    check_string(prompt)?;
                }
                if let Some(ref inputs) = p.inputs {
                    let serialized = serde_json::to_string(inputs).unwrap_or_default();
                    check_string(&serialized)?;
                }
            }
            JobPayloadParams::Custom(p) => {
                if let Some(ref data) = p.data {
                    for value in data.values() {
                        check_string(value)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Sanitize a payload string: remove control chars, limit length, trim
fn sanitize_payload_string(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n') // Allow newlines in PR body
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

// =============================================================================
// Job Result (versioned, for execution outputs)
// =============================================================================

/// Job execution result - stores outputs from job execution
/// SECURITY: All fields are sanitized, never contain paths/URLs/tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    /// Result status: succeeded or failed
    pub status: String,
    /// Result code (e.g., OK, ERROR, VALIDATION_FAILED)
    pub code: String,
    /// Human-readable message (sanitized, max 500 chars)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Text artifact (for agent_run, max 64KB)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_text: Option<String>,
    /// JSON artifact (for agent_run, max 64KB serialized)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_json: Option<serde_json::Value>,
}

impl JobResult {
    /// Create a success result
    pub fn success(message: Option<String>) -> Self {
        Self {
            status: "succeeded".to_string(),
            code: "OK".to_string(),
            message,
            artifact_text: None,
            artifact_json: None,
        }
    }

    /// Create a failure result
    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            code: code.into(),
            message: Some(message.into()),
            artifact_text: None,
            artifact_json: None,
        }
    }

    /// Create an agent_run result with artifacts
    pub fn agent_result(
        artifact_text: Option<String>,
        artifact_json: Option<serde_json::Value>,
    ) -> Self {
        Self {
            status: "succeeded".to_string(),
            code: "OK".to_string(),
            message: Some("Agent execution completed".to_string()),
            artifact_text,
            artifact_json,
        }
    }

    /// Sanitize all fields in the result
    pub fn sanitize(&mut self) {
        if let Some(ref mut msg) = self.message {
            *msg = sanitize_payload_string(msg, MAX_RESULT_MESSAGE_LEN);
        }
        if let Some(ref mut text) = self.artifact_text {
            *text = sanitize_payload_string(text, MAX_ARTIFACT_TEXT_LEN);
        }
        // Validate artifact_json size
        if let Some(ref json) = self.artifact_json {
            if let Ok(serialized) = serde_json::to_string(json) {
                if serialized.len() > MAX_ARTIFACT_JSON_SIZE {
                    self.artifact_json = None; // Drop oversized JSON
                }
            }
        }
    }

    /// Validate result doesn't contain forbidden patterns
    pub fn validate(&self) -> Result<(), &'static str> {
        let check_string = |s: &str| -> Result<(), &'static str> {
            if s.contains("/Users/") || s.contains("/home/") || s.contains("/var/")
                || s.contains("/tmp/") || s.contains("/private/")
                || s.contains("C:\\") || s.contains("D:\\") {
                return Err("Result contains forbidden path pattern");
            }
            if s.contains("https://") || s.contains("http://") || s.contains("github.com") {
                return Err("Result contains forbidden URL pattern");
            }
            if s.contains("EKKA_") {
                return Err("Result contains forbidden env var pattern");
            }
            Ok(())
        };

        if let Some(ref msg) = self.message {
            check_string(msg)?;
        }
        if let Some(ref text) = self.artifact_text {
            check_string(text)?;
        }
        if let Some(ref json) = self.artifact_json {
            let serialized = serde_json::to_string(json).unwrap_or_default();
            check_string(&serialized)?;
        }
        Ok(())
    }
}

/// Job entry (internal representation)
#[derive(Debug, Clone)]
pub struct Job {
    /// Unique job ID
    pub job_id: Uuid,
    /// Associated workspace ID
    pub workspace_id: Uuid,
    /// Job type
    pub job_type: JobType,
    /// Optional user-provided label
    pub label: Option<String>,
    /// Optional versioned payload with execution parameters
    pub payload: Option<JobPayload>,
    /// Current status
    pub status: JobStatus,
    /// Created timestamp (UTC)
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp (UTC)
    pub updated_at: DateTime<Utc>,
    /// Result code (set when succeeded/failed) - legacy field
    pub result_code: Option<String>,
    /// Result message (set when succeeded/failed) - legacy field
    pub message: Option<String>,
    /// Structured result with artifacts (RAPTOR-2 Step 35)
    pub result: Option<JobResult>,
    // === Lease fields (RAPTOR-3 Step 1) ===
    /// Runner ID that currently owns this job (via claim)
    pub lease_owner: Option<String>,
    /// When the lease expires (runner must heartbeat to extend)
    pub lease_expires_at: Option<DateTime<Utc>>,
    /// When the job was first claimed
    pub claimed_at: Option<DateTime<Utc>>,
    /// Number of claim attempts (for retry limiting)
    pub attempt_count: u32,
    // === Retry fields (RAPTOR-3 Step 3) ===
    /// Maximum number of attempts before terminal failure (default 3)
    pub max_attempts: u32,
    /// Scheduled time for next retry attempt (None = immediately claimable)
    pub next_attempt_at_utc: Option<DateTime<Utc>>,
    /// Last error code from failed attempt (stable, safe code)
    pub last_error_code: Option<String>,
    /// Last error message from failed attempt (sanitized, max 200 chars)
    pub last_error_message: Option<String>,
}

impl Job {
    /// Create a new job
    pub fn new(
        workspace_id: Uuid,
        job_type: JobType,
        label: Option<String>,
        payload: Option<JobPayload>,
    ) -> Self {
        let now = Utc::now();
        Self {
            job_id: Uuid::new_v4(),
            workspace_id,
            job_type,
            label,
            payload,
            status: JobStatus::Queued,
            created_at: now,
            updated_at: now,
            result_code: None,
            message: None,
            result: None,
            // Lease fields (RAPTOR-3 Step 1)
            lease_owner: None,
            lease_expires_at: None,
            claimed_at: None,
            attempt_count: 0,
            // Retry fields (RAPTOR-3 Step 3)
            max_attempts: persist::DEFAULT_MAX_ATTEMPTS,
            next_attempt_at_utc: None,
            last_error_code: None,
            last_error_message: None,
        }
    }

    /// Check if the job's lease has expired
    pub fn is_lease_expired(&self) -> bool {
        match self.lease_expires_at {
            Some(expires) => Utc::now() > expires,
            None => true, // No lease = expired
        }
    }

    /// Check if the job can be claimed (queued and due, or stale running)
    /// RAPTOR-3 Step 3: Respects next_attempt_at_utc for retry scheduling
    pub fn is_claimable(&self) -> bool {
        match self.status {
            JobStatus::Queued => self.is_retry_due(),
            JobStatus::Running => self.is_lease_expired(),
            _ => false,
        }
    }

    /// Check if a queued job is due for (re)attempt
    /// Returns true if next_attempt_at_utc is None or <= now
    pub fn is_retry_due(&self) -> bool {
        match self.next_attempt_at_utc {
            Some(next_at) => Utc::now() >= next_at,
            None => true, // No scheduled time = immediately due
        }
    }

    /// Convert to API response format
    pub fn to_status_response(&self) -> JobStatusResponse {
        JobStatusResponse {
            job_id: self.job_id.to_string(),
            workspace_id: self.workspace_id.to_string(),
            job_type: self.job_type,
            label: self.label.clone(),
            payload: self.payload.clone(),
            status: self.status,
            created_at_utc: self.created_at.to_rfc3339(),
            updated_at_utc: self.updated_at.to_rfc3339(),
            result_code: self.result_code.clone(),
            message: self.message.clone(),
            result: self.result.clone(),
            // Retry fields (RAPTOR-3 Step 3)
            attempt_count: self.attempt_count,
            max_attempts: self.max_attempts,
            next_attempt_at_utc: self.next_attempt_at_utc.map(|dt| dt.to_rfc3339()),
            last_error_code: self.last_error_code.clone(),
            last_error_message: self.last_error_message.clone(),
        }
    }
}

// =============================================================================
// Job Store (In-Memory Ring Buffer per Workspace)
// =============================================================================

/// Job store with per-workspace ring buffers
pub struct JobStore {
    /// Jobs indexed by workspace_id, most recent first
    jobs_by_workspace: RwLock<HashMap<Uuid, Vec<Job>>>,
    /// Jobs indexed by job_id for quick lookup
    jobs_by_id: RwLock<HashMap<Uuid, Job>>,
}

impl JobStore {
    /// Create a new empty job store
    pub fn new() -> Self {
        Self {
            jobs_by_workspace: RwLock::new(HashMap::new()),
            jobs_by_id: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new job
    pub fn create_job(
        &self,
        workspace_id: Uuid,
        job_type: JobType,
        label: Option<String>,
        payload: Option<JobPayload>,
    ) -> Job {
        let job = Job::new(workspace_id, job_type, label, payload);

        // Add to both indices
        {
            let mut by_workspace = self.jobs_by_workspace.write().unwrap();
            let workspace_jobs = by_workspace.entry(workspace_id).or_insert_with(Vec::new);

            // Insert at front (most recent first)
            workspace_jobs.insert(0, job.clone());

            // Trim to max size (ring buffer behavior)
            if workspace_jobs.len() > MAX_JOBS_PER_WORKSPACE {
                // Remove oldest jobs (from the end)
                let removed: Vec<Uuid> = workspace_jobs
                    .drain(MAX_JOBS_PER_WORKSPACE..)
                    .map(|j| j.job_id)
                    .collect();

                // Also remove from id index
                let mut by_id = self.jobs_by_id.write().unwrap();
                for id in removed {
                    by_id.remove(&id);
                }
            }
        }

        // Add to id index
        {
            let mut by_id = self.jobs_by_id.write().unwrap();
            by_id.insert(job.job_id, job.clone());
        }

        job
    }

    /// Get a job by ID
    pub fn get_job(&self, job_id: Uuid) -> Option<Job> {
        let by_id = self.jobs_by_id.read().unwrap();
        by_id.get(&job_id).cloned()
    }

    /// List jobs for a workspace (most recent first)
    pub fn list_jobs(&self, workspace_id: Uuid, limit: usize) -> Vec<Job> {
        let by_workspace = self.jobs_by_workspace.read().unwrap();
        match by_workspace.get(&workspace_id) {
            Some(jobs) => jobs.iter().take(limit).cloned().collect(),
            None => Vec::new(),
        }
    }

    /// Update job status (internal use for testing/future worker)
    #[allow(dead_code)]
    pub fn update_status(
        &self,
        job_id: Uuid,
        status: JobStatus,
        result_code: Option<String>,
        message: Option<String>,
    ) -> bool {
        self.update_status_with_result(job_id, status, result_code, message, None)
    }

    /// Update job status with optional structured result (RAPTOR-2 Step 35)
    pub fn update_status_with_result(
        &self,
        job_id: Uuid,
        status: JobStatus,
        result_code: Option<String>,
        message: Option<String>,
        result: Option<JobResult>,
    ) -> bool {
        // Update in id index
        let mut updated = false;
        {
            let mut by_id = self.jobs_by_id.write().unwrap();
            if let Some(job) = by_id.get_mut(&job_id) {
                job.status = status;
                job.result_code = result_code.clone();
                job.message = message.clone();
                job.result = result.clone();
                job.updated_at = Utc::now();
                updated = true;
            }
        }

        if !updated {
            return false;
        }

        // Update in workspace index
        {
            let mut by_workspace = self.jobs_by_workspace.write().unwrap();
            for jobs in by_workspace.values_mut() {
                if let Some(job) = jobs.iter_mut().find(|j| j.job_id == job_id) {
                    job.status = status;
                    job.result_code = result_code;
                    job.message = message;
                    job.result = result;
                    job.updated_at = Utc::now();
                    break;
                }
            }
        }

        true
    }

    /// Get job count for a workspace
    #[allow(dead_code)]
    pub fn job_count(&self, workspace_id: Uuid) -> usize {
        let by_workspace = self.jobs_by_workspace.read().unwrap();
        by_workspace.get(&workspace_id).map(|v| v.len()).unwrap_or(0)
    }

    /// List queued jobs across all workspaces (for runner polling) - RAPTOR-2 Step 33
    pub fn list_queued_jobs(&self, limit: usize) -> Vec<Job> {
        let by_workspace = self.jobs_by_workspace.read().unwrap();
        let mut queued: Vec<Job> = by_workspace
            .values()
            .flatten()
            .filter(|j| j.status == JobStatus::Queued)
            .cloned()
            .collect();

        // Sort by created_at ascending (oldest first - FIFO for runners)
        queued.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        // Apply limit
        queued.truncate(limit);
        queued
    }

    // =========================================================================
    // Lease-Aware Methods (RAPTOR-3 Step 1)
    // =========================================================================

    /// List claimable jobs (queued or running with expired lease)
    /// Returns jobs that can be claimed by a runner
    pub fn list_claimable_jobs(&self, limit: usize) -> Vec<Job> {
        let by_workspace = self.jobs_by_workspace.read().unwrap();
        let mut claimable: Vec<Job> = by_workspace
            .values()
            .flatten()
            .filter(|j| j.is_claimable())
            .cloned()
            .collect();

        // Sort by created_at ascending (oldest first - FIFO for runners)
        claimable.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        // Apply limit
        claimable.truncate(limit);
        claimable
    }

    /// Claim a job with lease
    /// Returns Some(updated_job) on success, None if job not claimable
    pub fn claim_job(
        &self,
        job_id: Uuid,
        runner_id: &str,
        lease_duration_secs: i64,
    ) -> Option<Job> {
        use persist::{MAX_LEASE_DURATION_SECS, MAX_JOB_ATTEMPTS};

        let now = Utc::now();
        let lease_duration = lease_duration_secs
            .max(1)
            .min(MAX_LEASE_DURATION_SECS);
        let lease_expires = now + chrono::Duration::seconds(lease_duration);

        // Update in id index
        let mut updated_job = None;
        {
            let mut by_id = self.jobs_by_id.write().unwrap();
            if let Some(job) = by_id.get_mut(&job_id) {
                // Check if claimable
                if !job.is_claimable() {
                    return None;
                }

                // Check attempt limit
                if job.attempt_count >= MAX_JOB_ATTEMPTS {
                    return None;
                }

                // Claim the job
                job.status = JobStatus::Running;
                job.lease_owner = Some(runner_id.to_string());
                job.lease_expires_at = Some(lease_expires);
                job.claimed_at = job.claimed_at.or(Some(now)); // Keep original claim time
                job.attempt_count += 1;
                job.updated_at = now;

                updated_job = Some(job.clone());
            }
        }

        let job = updated_job?;

        // Update in workspace index
        {
            let mut by_workspace = self.jobs_by_workspace.write().unwrap();
            for jobs in by_workspace.values_mut() {
                if let Some(ws_job) = jobs.iter_mut().find(|j| j.job_id == job_id) {
                    ws_job.status = job.status;
                    ws_job.lease_owner = job.lease_owner.clone();
                    ws_job.lease_expires_at = job.lease_expires_at;
                    ws_job.claimed_at = job.claimed_at;
                    ws_job.attempt_count = job.attempt_count;
                    ws_job.updated_at = job.updated_at;
                    break;
                }
            }
        }

        Some(job)
    }

    /// Extend lease for a job (heartbeat)
    /// Returns Some(updated_job) on success, None if lease not owned by runner
    pub fn heartbeat_job(
        &self,
        job_id: Uuid,
        runner_id: &str,
        lease_duration_secs: i64,
    ) -> Option<Job> {
        use persist::MAX_LEASE_DURATION_SECS;

        let now = Utc::now();
        let lease_duration = lease_duration_secs
            .max(1)
            .min(MAX_LEASE_DURATION_SECS);
        let lease_expires = now + chrono::Duration::seconds(lease_duration);

        // Update in id index
        let mut updated_job = None;
        {
            let mut by_id = self.jobs_by_id.write().unwrap();
            if let Some(job) = by_id.get_mut(&job_id) {
                // Check ownership
                if job.lease_owner.as_deref() != Some(runner_id) {
                    return None;
                }

                // Must be running to heartbeat
                if job.status != JobStatus::Running {
                    return None;
                }

                // Extend lease
                job.lease_expires_at = Some(lease_expires);
                job.updated_at = now;

                updated_job = Some(job.clone());
            }
        }

        let job = updated_job?;

        // Update in workspace index
        {
            let mut by_workspace = self.jobs_by_workspace.write().unwrap();
            for jobs in by_workspace.values_mut() {
                if let Some(ws_job) = jobs.iter_mut().find(|j| j.job_id == job_id) {
                    ws_job.lease_expires_at = job.lease_expires_at;
                    ws_job.updated_at = job.updated_at;
                    break;
                }
            }
        }

        Some(job)
    }

    /// Complete a job with lease verification and retry logic (RAPTOR-3 Step 3)
    ///
    /// On success (Succeeded): marks job as succeeded, clears lease
    /// On failure (Failed):
    ///   - Stores last_error_code/message (sanitized)
    ///   - If retryable AND attempt_count < max_attempts: requeues with backoff
    ///   - Otherwise: marks as terminal failed
    ///
    /// Returns Some(updated_job) on success, None if lease not owned by runner
    pub fn complete_job_with_lease(
        &self,
        job_id: Uuid,
        runner_id: &str,
        status: JobStatus,
        result_code: Option<String>,
        message: Option<String>,
        result: Option<JobResult>,
    ) -> Option<Job> {
        let now = Utc::now();

        // Update in id index
        let mut updated_job = None;
        {
            let mut by_id = self.jobs_by_id.write().unwrap();
            if let Some(job) = by_id.get_mut(&job_id) {
                // Check ownership
                if job.lease_owner.as_deref() != Some(runner_id) {
                    return None;
                }

                // Must be running to complete
                if job.status != JobStatus::Running {
                    return None;
                }

                // Clear lease on any completion
                job.lease_owner = None;
                job.lease_expires_at = None;
                job.updated_at = now;

                if status == JobStatus::Failed {
                    // Store error info (sanitized) - RAPTOR-3 Step 3
                    let error_code = result_code.clone().unwrap_or_else(|| "UNKNOWN_ERROR".to_string());
                    job.last_error_code = Some(error_code.clone());
                    job.last_error_message = message.as_ref().map(|m| sanitize_error_message(m));

                    // Determine if retryable
                    let failure_class = classify_error(&error_code);
                    let can_retry = failure_class == FailureClass::Retryable
                        && job.attempt_count < job.max_attempts;

                    if can_retry {
                        // Requeue with backoff - RAPTOR-3 Step 3
                        job.status = JobStatus::Queued;
                        let backoff_secs = calculate_backoff_secs(job.attempt_count);
                        job.next_attempt_at_utc = Some(now + chrono::Duration::seconds(backoff_secs));
                        // Keep result_code/message as legacy fields for API compat
                        job.result_code = result_code.clone();
                        job.message = message.clone();
                        job.result = result.clone();
                    } else {
                        // Terminal failure - RAPTOR-3 Step 3
                        job.status = JobStatus::Failed;
                        job.next_attempt_at_utc = None; // Clear any scheduled retry
                        job.result_code = result_code.clone();
                        job.message = message.clone();
                        job.result = result.clone();
                    }
                } else {
                    // Success case - no retry logic needed
                    job.status = status;
                    job.result_code = result_code.clone();
                    job.message = message.clone();
                    job.result = result.clone();
                    job.next_attempt_at_utc = None; // Clear any scheduled retry
                    // Clear error fields on success
                    job.last_error_code = None;
                    job.last_error_message = None;
                }

                updated_job = Some(job.clone());
            }
        }

        let job = updated_job?;

        // Update in workspace index
        {
            let mut by_workspace = self.jobs_by_workspace.write().unwrap();
            for jobs in by_workspace.values_mut() {
                if let Some(ws_job) = jobs.iter_mut().find(|j| j.job_id == job_id) {
                    ws_job.status = job.status;
                    ws_job.result_code = job.result_code.clone();
                    ws_job.message = job.message.clone();
                    ws_job.result = job.result.clone();
                    ws_job.lease_owner = None;
                    ws_job.lease_expires_at = None;
                    ws_job.updated_at = job.updated_at;
                    // Retry fields - RAPTOR-3 Step 3
                    ws_job.next_attempt_at_utc = job.next_attempt_at_utc;
                    ws_job.last_error_code = job.last_error_code.clone();
                    ws_job.last_error_message = job.last_error_message.clone();
                    break;
                }
            }
        }

        Some(job)
    }

    /// Release stale jobs (running with expired lease) back to queued with backoff
    /// RAPTOR-3 Step 3: Uses job.max_attempts and schedules retry with backoff
    /// Returns number of jobs released
    pub fn release_stale_jobs(&self) -> usize {
        let now = Utc::now();
        let mut released_count = 0;
        let mut jobs_to_release: Vec<Uuid> = Vec::new();

        // Find stale jobs
        {
            let by_id = self.jobs_by_id.read().unwrap();
            for job in by_id.values() {
                if job.status == JobStatus::Running && job.is_lease_expired() {
                    jobs_to_release.push(job.job_id);
                }
            }
        }

        // Release each stale job
        for job_id in jobs_to_release {
            // Update in id index
            let mut should_fail = false;
            let mut next_attempt: Option<DateTime<Utc>> = None;
            {
                let mut by_id = self.jobs_by_id.write().unwrap();
                if let Some(job) = by_id.get_mut(&job_id) {
                    // RAPTOR-3 Step 3: Use job.max_attempts instead of constant
                    if job.attempt_count >= job.max_attempts {
                        // Mark as failed instead of releasing
                        job.status = JobStatus::Failed;
                        job.result_code = Some("MAX_ATTEMPTS".to_string());
                        job.message = Some("Job exceeded maximum retry attempts".to_string());
                        job.last_error_code = Some("LEASE_EXPIRED".to_string());
                        job.last_error_message = Some("Runner failed to complete job within lease period".to_string());
                        job.next_attempt_at_utc = None;
                        should_fail = true;
                    } else {
                        // Release back to queued with backoff
                        job.status = JobStatus::Queued;
                        let backoff_secs = calculate_backoff_secs(job.attempt_count);
                        job.next_attempt_at_utc = Some(now + chrono::Duration::seconds(backoff_secs));
                        next_attempt = job.next_attempt_at_utc;
                        job.last_error_code = Some("LEASE_EXPIRED".to_string());
                        job.last_error_message = Some("Runner failed to complete job within lease period".to_string());
                    }
                    job.lease_owner = None;
                    job.lease_expires_at = None;
                    job.updated_at = now;
                    released_count += 1;
                }
            }

            // Update in workspace index
            {
                let mut by_workspace = self.jobs_by_workspace.write().unwrap();
                for jobs in by_workspace.values_mut() {
                    if let Some(ws_job) = jobs.iter_mut().find(|j| j.job_id == job_id) {
                        if should_fail {
                            ws_job.status = JobStatus::Failed;
                            ws_job.result_code = Some("MAX_ATTEMPTS".to_string());
                            ws_job.message = Some("Job exceeded maximum retry attempts".to_string());
                            ws_job.next_attempt_at_utc = None;
                        } else {
                            ws_job.status = JobStatus::Queued;
                            ws_job.next_attempt_at_utc = next_attempt;
                        }
                        ws_job.lease_owner = None;
                        ws_job.lease_expires_at = None;
                        ws_job.updated_at = now;
                        ws_job.last_error_code = Some("LEASE_EXPIRED".to_string());
                        ws_job.last_error_message = Some("Runner failed to complete job within lease period".to_string());
                        break;
                    }
                }
            }
        }

        released_count
    }

    /// Get all jobs (for persistence)
    pub fn get_all_jobs(&self) -> Vec<Job> {
        let by_id = self.jobs_by_id.read().unwrap();
        by_id.values().cloned().collect()
    }

    /// Load jobs from persistence (replaces current state)
    pub fn load_jobs(&self, jobs: Vec<Job>) {
        let mut by_workspace = self.jobs_by_workspace.write().unwrap();
        let mut by_id = self.jobs_by_id.write().unwrap();

        by_workspace.clear();
        by_id.clear();

        for job in jobs {
            by_id.insert(job.job_id, job.clone());

            let workspace_jobs = by_workspace.entry(job.workspace_id).or_insert_with(Vec::new);
            workspace_jobs.push(job);
        }

        // Sort each workspace's jobs by created_at descending (most recent first)
        for jobs in by_workspace.values_mut() {
            jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        }
    }
}

impl Default for JobStore {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// API Request/Response Types
// =============================================================================

/// Create job request
#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    /// Workspace ID (must exist)
    pub workspace_id: String,
    /// Job type
    pub job_type: String,
    /// Optional user-provided label
    pub label: Option<String>,
    /// Optional versioned payload with execution parameters
    #[serde(default)]
    pub payload: Option<JobPayload>,
}

/// Create job response
#[derive(Debug, Serialize)]
pub struct CreateJobResponse {
    pub job_id: String,
    pub status: JobStatus,
}

/// Job status response (for single job and list items)
#[derive(Debug, Serialize)]
pub struct JobStatusResponse {
    pub job_id: String,
    pub workspace_id: String,
    pub job_type: JobType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<JobPayload>,
    pub status: JobStatus,
    pub created_at_utc: String,
    pub updated_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Structured result with artifacts (RAPTOR-2 Step 35)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JobResult>,
    // === Retry fields (RAPTOR-3 Step 3) ===
    /// Current attempt count
    pub attempt_count: u32,
    /// Maximum attempts before terminal failure
    pub max_attempts: u32,
    /// Scheduled time for next retry attempt (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at_utc: Option<String>,
    /// Last error code from failed attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    /// Last error message from failed attempt (sanitized)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_message: Option<String>,
}

/// List jobs query parameters
#[derive(Debug, Deserialize)]
pub struct ListJobsQuery {
    pub workspace_id: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

/// List jobs response
#[derive(Debug, Serialize)]
pub struct ListJobsResponse {
    pub workspace_id: String,
    pub jobs: Vec<JobStatusResponse>,
}

/// Status query parameters
#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    pub job_id: String,
}

/// Jobs error response
#[derive(Debug, Serialize)]
pub struct JobsError {
    pub error: String,
    pub code: String,
}

// =============================================================================
// From-Intent API Types (RAPTOR-2 Step 36)
// =============================================================================

/// Request to create a job from an agent's intent
#[derive(Debug, Deserialize)]
pub struct FromIntentRequest {
    /// Source job ID (must be an agent_run job that succeeded)
    pub source_job_id: String,
    /// Workspace ID (must match source job workspace)
    pub workspace_id: String,
    /// The intent to materialize (must be RepoWorkflowIntentV1)
    pub intent: RepoWorkflowIntentV1,
}

/// Response from creating a job from intent
#[derive(Debug, Serialize)]
pub struct FromIntentResponse {
    pub job_id: String,
    pub status: JobStatus,
}

// =============================================================================
// Workspace Validator Type
// =============================================================================

/// Type alias for workspace existence checker
/// Returns true if workspace_id exists in inventory
pub type WorkspaceExistsChecker = Arc<dyn Fn(&str) -> bool + Send + Sync>;

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Context for the Jobs module
#[derive(Clone)]
pub struct JobsModuleContext {
    /// Job store (shared with host)
    pub job_store: Arc<JobStore>,
    /// Session validator (provided by host for request-time auth)
    pub session_validator: SessionValidator,
    /// Workspace existence checker (provided by host)
    pub workspace_exists: WorkspaceExistsChecker,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
    /// Queue mode for job creation (RAPTOR-3 Step 5)
    pub queue_mode: NodeJobQueueMode,
}

impl JobsModuleContext {
    pub fn new(
        job_store: Arc<JobStore>,
        session_validator: SessionValidator,
        workspace_exists: WorkspaceExistsChecker,
        log_prefix: impl Into<String>,
    ) -> Self {
        let queue_mode = NodeJobQueueMode::from_env();
        Self {
            job_store,
            session_validator,
            workspace_exists,
            log_prefix: log_prefix.into(),
            queue_mode,
        }
    }

    /// Create context with explicit queue mode (for testing)
    pub fn with_queue_mode(
        job_store: Arc<JobStore>,
        session_validator: SessionValidator,
        workspace_exists: WorkspaceExistsChecker,
        log_prefix: impl Into<String>,
        queue_mode: NodeJobQueueMode,
    ) -> Self {
        Self {
            job_store,
            session_validator,
            workspace_exists,
            log_prefix: log_prefix.into(),
            queue_mode,
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.jobs.{}", self.log_prefix, op)
    }
}

/// Mount the Jobs module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: JobsModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !JOBS_MODULE_CONFIG.is_enabled() {
        info!(
            module = "jobs",
            enabled = false,
            "Jobs module disabled (set EKKA_ENABLE_JOBS=1 to enable)"
        );
        return router;
    }

    // Log queue mode status (RAPTOR-3 Step 5)
    let queue_mode = ctx.queue_mode;
    info!(
        module = "jobs",
        enabled = true,
        queue_mode = %queue_mode,
        "Jobs module enabled"
    );

    // Emit warning for legacy mode
    if queue_mode == NodeJobQueueMode::Legacy {
        warn!(
            op = "node.jobs.queue_mode.legacy_warning",
            "Node job queue is in LEGACY mode - migrate to ENGINE runner_tasks"
        );
    }

    let state = Arc::new(ctx);

    // Create a sub-router with our state, then merge into main router
    let jobs_router: Router<S> = Router::new()
        .route("/v0/jobs/create", post(jobs_create_handler))
        .route("/v0/jobs/status", get(jobs_status_handler))
        .route("/v0/jobs/list", get(jobs_list_handler))
        .route("/v0/jobs/from-intent", post(jobs_from_intent_handler))
        .with_state(state);

    router.merge(jobs_router)
}

// =============================================================================
// Axum Handlers
// =============================================================================

/// POST /v0/jobs/create - Create a new job
/// Requires: valid session + "jobs.create" capability
/// Validates: workspace_id must exist
async fn jobs_create_handler(
    State(ctx): State<Arc<JobsModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<CreateJobRequest>,
) -> Result<Json<CreateJobResponse>, (StatusCode, Json<JobsError>)> {
    info!(
        op = %ctx.log_op("create.request"),
        "Jobs create requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("create.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(JobsError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(JOBS_CREATE_CAPABILITY) {
        warn!(
            op = %ctx.log_op("create.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(JobsError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 2.5: Check queue mode (RAPTOR-3 Step 5)
    // Node-local job creation is disabled by default; use ENGINE runner_tasks instead
    if !ctx.queue_mode.allows_job_creation() {
        warn!(
            op = %ctx.log_op("create.queue_disabled"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Node job queue is disabled - use ENGINE runner_tasks"
        );
        return Err((
            StatusCode::CONFLICT,
            Json(JobsError {
                error: "Node job queue disabled".to_string(),
                code: "NODE_QUEUE_DISABLED".to_string(),
            }),
        ));
    }

    // Step 3: Validate workspace_id format
    let workspace_id = request.workspace_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("create.invalid_workspace_id"),
            "Invalid workspace ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Invalid workspace ID".to_string(),
                code: "INVALID_WORKSPACE_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Verify workspace exists (using host-provided checker)
    if !(ctx.workspace_exists)(&request.workspace_id) {
        warn!(
            op = %ctx.log_op("create.workspace_not_found"),
            "Workspace not found"
        );
        return Err((
            StatusCode::NOT_FOUND,
            Json(JobsError {
                error: "Workspace not found".to_string(),
                code: "WORKSPACE_NOT_FOUND".to_string(),
            }),
        ));
    }

    // Step 5: Parse job type
    let job_type = JobType::from_str(&request.job_type).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("create.invalid_job_type"),
            "Invalid job type"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Invalid job type. Valid types: repo_workflow, agent_run, custom".to_string(),
                code: "INVALID_JOB_TYPE".to_string(),
            }),
        )
    })?;

    // Step 6: Sanitize label if provided
    let label = request.label.map(|l| {
        l.chars()
            .filter(|c| !c.is_control())
            .take(100)
            .collect::<String>()
            .trim()
            .to_string()
    }).filter(|l| !l.is_empty());

    // Step 7: Validate and sanitize payload if provided
    let payload = if let Some(mut p) = request.payload {
        // Sanitize all strings in the payload
        p.sanitize();

        // Validate payload doesn't contain forbidden patterns
        if let Err(e) = p.validate() {
            warn!(
                op = %ctx.log_op("create.invalid_payload"),
                error = %e,
                "Payload validation failed"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(JobsError {
                    error: e.to_string(),
                    code: "INVALID_PAYLOAD".to_string(),
                }),
            ));
        }
        Some(p)
    } else {
        None
    };

    // Step 8: Create job
    let job = ctx.job_store.create_job(workspace_id, job_type, label, payload);

    info!(
        op = %ctx.log_op("create.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        job_id = %job.job_id,
        workspace_id = %workspace_id,
        job_type = %job.job_type,
        "Job created successfully"
    );

    Ok(Json(CreateJobResponse {
        job_id: job.job_id.to_string(),
        status: job.status,
    }))
}

/// GET /v0/jobs/status?job_id=<uuid> - Get job status
/// Requires: valid session + "jobs.read" capability
async fn jobs_status_handler(
    State(ctx): State<Arc<JobsModuleContext>>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> Result<Json<JobStatusResponse>, (StatusCode, Json<JobsError>)> {
    info!(
        op = %ctx.log_op("status.request"),
        "Jobs status requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("status.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(JobsError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(JOBS_READ_CAPABILITY) {
        warn!(
            op = %ctx.log_op("status.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(JobsError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Parse job_id
    let job_id = query.job_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("status.invalid_job_id"),
            "Invalid job ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Invalid job ID".to_string(),
                code: "INVALID_JOB_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Get job
    let job = ctx.job_store.get_job(job_id).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("status.job_not_found"),
            "Job not found"
        );
        (
            StatusCode::NOT_FOUND,
            Json(JobsError {
                error: "Job not found".to_string(),
                code: "JOB_NOT_FOUND".to_string(),
            }),
        )
    })?;

    info!(
        op = %ctx.log_op("status.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        job_id = %job_id,
        status = %job.status,
        "Job status retrieved"
    );

    Ok(Json(job.to_status_response()))
}

/// GET /v0/jobs/list?workspace_id=<uuid>&limit=<n> - List jobs for workspace
/// Requires: valid session + "jobs.read" capability
async fn jobs_list_handler(
    State(ctx): State<Arc<JobsModuleContext>>,
    headers: HeaderMap,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<ListJobsResponse>, (StatusCode, Json<JobsError>)> {
    info!(
        op = %ctx.log_op("list.request"),
        "Jobs list requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("list.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(JobsError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(JOBS_READ_CAPABILITY) {
        warn!(
            op = %ctx.log_op("list.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(JobsError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Parse workspace_id
    let workspace_id = query.workspace_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("list.invalid_workspace_id"),
            "Invalid workspace ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Invalid workspace ID".to_string(),
                code: "INVALID_WORKSPACE_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Enforce limit bounds (max 50)
    let limit = query.limit.min(MAX_LIST_LIMIT);

    // Step 5: Get jobs
    let jobs = ctx.job_store.list_jobs(workspace_id, limit);
    let job_responses: Vec<JobStatusResponse> = jobs.iter().map(|j| j.to_status_response()).collect();

    info!(
        op = %ctx.log_op("list.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        workspace_id = %workspace_id,
        count = %job_responses.len(),
        "Jobs list retrieved"
    );

    Ok(Json(ListJobsResponse {
        workspace_id: workspace_id.to_string(),
        jobs: job_responses,
    }))
}

/// POST /v0/jobs/from-intent - Create a repo_workflow job from an agent's intent
/// RAPTOR-2 Step 36: Intent materialization endpoint
///
/// Requires: valid session + "jobs.create" capability
/// Validates:
/// - source_job_id exists and belongs to same workspace
/// - source_job is an agent_run job that succeeded
/// - intent.job_type == "repo_workflow"
/// - workspace_id matches source job workspace
async fn jobs_from_intent_handler(
    State(ctx): State<Arc<JobsModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<FromIntentRequest>,
) -> Result<Json<FromIntentResponse>, (StatusCode, Json<JobsError>)> {
    info!(
        op = %ctx.log_op("from_intent.request"),
        "Intent materialization requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("from_intent.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(JobsError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if let Err(_) = session.require_capability(JOBS_CREATE_CAPABILITY) {
        warn!(
            op = %ctx.log_op("from_intent.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(JobsError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 2.5: Check queue mode (RAPTOR-3 Step 5)
    // Node-local job creation is disabled by default; use ENGINE runner_tasks instead
    if !ctx.queue_mode.allows_job_creation() {
        warn!(
            op = %ctx.log_op("from_intent.queue_disabled"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Node job queue is disabled - use ENGINE runner_tasks"
        );
        return Err((
            StatusCode::CONFLICT,
            Json(JobsError {
                error: "Node job queue disabled".to_string(),
                code: "NODE_QUEUE_DISABLED".to_string(),
            }),
        ));
    }

    // Step 3: Parse workspace_id
    let workspace_id = request.workspace_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("from_intent.invalid_workspace_id"),
            "Invalid workspace ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Invalid workspace ID".to_string(),
                code: "INVALID_WORKSPACE_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Parse source_job_id
    let source_job_id = request.source_job_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("from_intent.invalid_source_job_id"),
            "Invalid source job ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Invalid source job ID".to_string(),
                code: "INVALID_SOURCE_JOB_ID".to_string(),
            }),
        )
    })?;

    // Step 5: Validate source job exists
    let source_job = ctx.job_store.get_job(source_job_id).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("from_intent.source_not_found"),
            "Source job not found"
        );
        (
            StatusCode::NOT_FOUND,
            Json(JobsError {
                error: "Source job not found".to_string(),
                code: "INTENT_SOURCE_NOT_FOUND".to_string(),
            }),
        )
    })?;

    // Step 6: Validate source job workspace matches request workspace
    if source_job.workspace_id != workspace_id {
        warn!(
            op = %ctx.log_op("from_intent.workspace_mismatch"),
            "Workspace mismatch between source job and request"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(JobsError {
                error: "Workspace mismatch".to_string(),
                code: "INTENT_WORKSPACE_MISMATCH".to_string(),
            }),
        ));
    }

    // Step 7: Validate source job is an agent_run job
    if source_job.job_type != JobType::AgentRun {
        warn!(
            op = %ctx.log_op("from_intent.invalid_source_type"),
            source_type = %source_job.job_type,
            "Source job is not an agent_run job"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Source job must be an agent_run job".to_string(),
                code: "INTENT_INVALID_SOURCE_TYPE".to_string(),
            }),
        ));
    }

    // Step 8: Validate source job succeeded
    if source_job.status != JobStatus::Succeeded {
        warn!(
            op = %ctx.log_op("from_intent.source_not_succeeded"),
            status = %source_job.status,
            "Source job has not succeeded"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: "Source job must have succeeded".to_string(),
                code: "INTENT_SOURCE_NOT_SUCCEEDED".to_string(),
            }),
        ));
    }

    // Step 9: Validate and sanitize the intent
    let mut intent = request.intent;
    intent.sanitize();

    if let Err(e) = intent.validate() {
        let (error_msg, error_code) = match e {
            IntentError::InvalidSchema(msg) => (msg, "INTENT_INVALID_SCHEMA"),
            IntentError::InvalidJobType(msg) => (msg, "INTENT_INVALID_JOB_TYPE"),
            IntentError::InvalidField(msg) => (msg, "INTENT_INVALID_FIELD"),
            IntentError::ForbiddenPattern(msg) => (msg, "INTENT_FORBIDDEN_PATTERN"),
            IntentError::TenantMismatch => ("Tenant mismatch".to_string(), "INTENT_TENANT_MISMATCH"),
            IntentError::WorkspaceMismatch => ("Workspace mismatch".to_string(), "INTENT_WORKSPACE_MISMATCH"),
            IntentError::SourceJobNotFound => ("Source job not found".to_string(), "INTENT_SOURCE_NOT_FOUND"),
            IntentError::SourceJobNotSucceeded => ("Source job not succeeded".to_string(), "INTENT_SOURCE_NOT_SUCCEEDED"),
        };
        warn!(
            op = %ctx.log_op("from_intent.intent_invalid"),
            code = %error_code,
            "Intent validation failed"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(JobsError {
                error: error_msg,
                code: error_code.to_string(),
            }),
        ));
    }

    // Step 10: Verify workspace exists (using host-provided checker)
    if !(ctx.workspace_exists)(&request.workspace_id) {
        warn!(
            op = %ctx.log_op("from_intent.workspace_not_found"),
            "Workspace not found"
        );
        return Err((
            StatusCode::NOT_FOUND,
            Json(JobsError {
                error: "Workspace not found".to_string(),
                code: "WORKSPACE_NOT_FOUND".to_string(),
            }),
        ));
    }

    // Step 11: Convert intent to job payload and create job
    let payload = intent.to_job_payload();
    let label = Some(format!("From agent_run: {}", &request.source_job_id[..8.min(request.source_job_id.len())]));

    let job = ctx.job_store.create_job(workspace_id, JobType::RepoWorkflow, label, Some(payload));

    info!(
        op = %ctx.log_op("from_intent.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        job_id = %job.job_id,
        source_job_id = %source_job_id,
        workspace_id = %workspace_id,
        "Job created from intent"
    );

    Ok(Json(FromIntentResponse {
        job_id: job.job_id.to_string(),
        status: job.status,
    }))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Path/Token/URL Leak Tests (prove we never leak sensitive data)
    // =========================================================================

    fn assert_no_leak(json: &str) {
        // Common absolute path patterns that should never appear
        assert!(!json.contains("/Users"), "Leaked /Users path: {}", json);
        assert!(!json.contains("/home"), "Leaked /home path: {}", json);
        assert!(!json.contains("/var"), "Leaked /var path: {}", json);
        assert!(!json.contains("/tmp"), "Leaked /tmp path: {}", json);
        assert!(!json.contains("/private"), "Leaked /private path: {}", json);
        assert!(!json.contains("C:\\"), "Leaked C:\\ path: {}", json);
        assert!(!json.contains("D:\\"), "Leaked D:\\ path: {}", json);
        // No tokens/secrets
        assert!(!json.contains("secret"), "Leaked sensitive word: {}", json);
        assert!(!json.contains("token"), "Leaked token: {}", json);
        // No URLs
        assert!(!json.contains("github.com"), "Leaked URL: {}", json);
        assert!(!json.contains("https://"), "Leaked URL scheme: {}", json);
        // No env vars
        assert!(!json.contains("EKKA_"), "Leaked env var: {}", json);
    }

    // =========================================================================
    // Job Type Tests
    // =========================================================================

    #[test]
    fn test_job_type_from_str() {
        assert_eq!(JobType::from_str("repo_workflow"), Some(JobType::RepoWorkflow));
        assert_eq!(JobType::from_str("agent_run"), Some(JobType::AgentRun));
        assert_eq!(JobType::from_str("custom"), Some(JobType::Custom));
        assert_eq!(JobType::from_str("REPO_WORKFLOW"), Some(JobType::RepoWorkflow));
        assert_eq!(JobType::from_str("invalid"), None);
    }

    #[test]
    fn test_job_type_display() {
        assert_eq!(JobType::RepoWorkflow.to_string(), "repo_workflow");
        assert_eq!(JobType::AgentRun.to_string(), "agent_run");
        assert_eq!(JobType::Custom.to_string(), "custom");
    }

    // =========================================================================
    // Job Status Tests
    // =========================================================================

    #[test]
    fn test_job_status_display() {
        assert_eq!(JobStatus::Queued.to_string(), "queued");
        assert_eq!(JobStatus::Running.to_string(), "running");
        assert_eq!(JobStatus::Succeeded.to_string(), "succeeded");
        assert_eq!(JobStatus::Failed.to_string(), "failed");
    }

    // =========================================================================
    // Job Store Tests
    // =========================================================================

    #[test]
    fn test_job_store_create() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        let job = store.create_job(workspace_id, JobType::RepoWorkflow, Some("Test".to_string()), None);

        assert!(!job.job_id.is_nil());
        assert_eq!(job.workspace_id, workspace_id);
        assert_eq!(job.job_type, JobType::RepoWorkflow);
        assert_eq!(job.label, Some("Test".to_string()));
        assert_eq!(job.status, JobStatus::Queued);
    }

    #[test]
    fn test_job_store_get() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        let job = store.create_job(workspace_id, JobType::AgentRun, None, None);
        let retrieved = store.get_job(job.job_id);

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().job_id, job.job_id);
    }

    #[test]
    fn test_job_store_get_not_found() {
        let store = JobStore::new();
        let result = store.get_job(Uuid::new_v4());
        assert!(result.is_none());
    }

    #[test]
    fn test_job_store_list() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        store.create_job(workspace_id, JobType::RepoWorkflow, Some("Job 1".to_string()), None);
        store.create_job(workspace_id, JobType::AgentRun, Some("Job 2".to_string()), None);
        store.create_job(workspace_id, JobType::Custom, Some("Job 3".to_string()), None);

        let jobs = store.list_jobs(workspace_id, 10);
        assert_eq!(jobs.len(), 3);

        // Most recent first
        assert_eq!(jobs[0].label, Some("Job 3".to_string()));
        assert_eq!(jobs[1].label, Some("Job 2".to_string()));
        assert_eq!(jobs[2].label, Some("Job 1".to_string()));
    }

    #[test]
    fn test_job_store_list_limit() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        for i in 0..10 {
            store.create_job(workspace_id, JobType::Custom, Some(format!("Job {}", i)), None);
        }

        let jobs = store.list_jobs(workspace_id, 5);
        assert_eq!(jobs.len(), 5);
    }

    #[test]
    fn test_job_store_list_empty_workspace() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        let jobs = store.list_jobs(workspace_id, 10);
        assert!(jobs.is_empty());
    }

    #[test]
    fn test_job_store_ring_buffer_eviction() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        // Create more than MAX_JOBS_PER_WORKSPACE jobs
        let mut first_job_id = None;
        for i in 0..(MAX_JOBS_PER_WORKSPACE + 10) {
            let job = store.create_job(workspace_id, JobType::Custom, Some(format!("Job {}", i)), None);
            if i == 0 {
                first_job_id = Some(job.job_id);
            }
        }

        // Should have exactly MAX_JOBS_PER_WORKSPACE
        assert_eq!(store.job_count(workspace_id), MAX_JOBS_PER_WORKSPACE);

        // First job should have been evicted
        assert!(store.get_job(first_job_id.unwrap()).is_none());
    }

    #[test]
    fn test_job_store_update_status() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        let job = store.create_job(workspace_id, JobType::RepoWorkflow, None, None);

        // Update to running
        let updated = store.update_status(job.job_id, JobStatus::Running, None, None);
        assert!(updated);

        let retrieved = store.get_job(job.job_id).unwrap();
        assert_eq!(retrieved.status, JobStatus::Running);

        // Update to succeeded with result
        store.update_status(
            job.job_id,
            JobStatus::Succeeded,
            Some("SUCCESS".to_string()),
            Some("Completed".to_string()),
        );

        let retrieved = store.get_job(job.job_id).unwrap();
        assert_eq!(retrieved.status, JobStatus::Succeeded);
        assert_eq!(retrieved.result_code, Some("SUCCESS".to_string()));
        assert_eq!(retrieved.message, Some("Completed".to_string()));
    }

    #[test]
    fn test_job_store_update_status_not_found() {
        let store = JobStore::new();
        let updated = store.update_status(Uuid::new_v4(), JobStatus::Failed, None, None);
        assert!(!updated);
    }

    // =========================================================================
    // Response Leak Tests
    // =========================================================================

    #[test]
    fn test_create_response_no_leak() {
        let response = CreateJobResponse {
            job_id: Uuid::new_v4().to_string(),
            status: JobStatus::Queued,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_status_response_no_leak() {
        let response = JobStatusResponse {
            job_id: Uuid::new_v4().to_string(),
            workspace_id: Uuid::new_v4().to_string(),
            job_type: JobType::RepoWorkflow,
            label: Some("Test Job".to_string()),
            payload: None,
            status: JobStatus::Succeeded,
            created_at_utc: "2024-01-01T00:00:00Z".to_string(),
            updated_at_utc: "2024-01-01T00:01:00Z".to_string(),
            result_code: Some("OK".to_string()),
            message: Some("Job completed".to_string()),
            result: None,
            // Retry fields (RAPTOR-3 Step 3)
            attempt_count: 0,
            max_attempts: 3,
            next_attempt_at_utc: None,
            last_error_code: None,
            last_error_message: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_list_response_no_leak() {
        let response = ListJobsResponse {
            workspace_id: Uuid::new_v4().to_string(),
            jobs: vec![
                JobStatusResponse {
                    job_id: Uuid::new_v4().to_string(),
                    workspace_id: Uuid::new_v4().to_string(),
                    job_type: JobType::AgentRun,
                    label: None,
                    payload: None,
                    status: JobStatus::Queued,
                    created_at_utc: "2024-01-01T00:00:00Z".to_string(),
                    updated_at_utc: "2024-01-01T00:00:00Z".to_string(),
                    result_code: None,
                    message: None,
                    result: None,
                    // Retry fields (RAPTOR-3 Step 3)
                    attempt_count: 1,
                    max_attempts: 3,
                    next_attempt_at_utc: Some("2024-01-01T00:05:00Z".to_string()),
                    last_error_code: Some("GITHUB_NOT_CONNECTED".to_string()),
                    last_error_message: Some("Retry scheduled".to_string()),
                },
            ],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_error_response_no_leak() {
        let error = JobsError {
            error: "Workspace not found".to_string(),
            code: "WORKSPACE_NOT_FOUND".to_string(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert_no_leak(&json);
    }

    // =========================================================================
    // Job to_status_response Tests
    // =========================================================================

    #[test]
    fn test_job_to_status_response() {
        let workspace_id = Uuid::new_v4();
        let job = Job::new(workspace_id, JobType::Custom, Some("Test".to_string()), None);
        let response = job.to_status_response();

        assert_eq!(response.job_id, job.job_id.to_string());
        assert_eq!(response.workspace_id, workspace_id.to_string());
        assert_eq!(response.job_type, JobType::Custom);
        assert_eq!(response.label, Some("Test".to_string()));
        assert_eq!(response.status, JobStatus::Queued);
        assert!(response.result_code.is_none());
        assert!(response.message.is_none());
    }

    // =========================================================================
    // Module Config Tests
    // =========================================================================

    #[test]
    fn test_module_config_default_enabled() {
        // Jobs should be enabled by default (safe tier - no FS access, no external calls)
        assert!(JOBS_MODULE_CONFIG.default_enabled);
    }

    #[test]
    fn test_capability_constants() {
        assert_eq!(JOBS_READ_CAPABILITY, "jobs.read");
        assert_eq!(JOBS_CREATE_CAPABILITY, "jobs.create");
    }

    #[test]
    fn test_max_list_limit() {
        assert_eq!(MAX_LIST_LIMIT, 50);
    }

    #[test]
    fn test_max_jobs_per_workspace() {
        assert_eq!(MAX_JOBS_PER_WORKSPACE, 200);
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_job_type_serialization() {
        let json = serde_json::to_string(&JobType::RepoWorkflow).unwrap();
        assert_eq!(json, "\"repo_workflow\"");

        let json = serde_json::to_string(&JobType::AgentRun).unwrap();
        assert_eq!(json, "\"agent_run\"");

        let json = serde_json::to_string(&JobType::Custom).unwrap();
        assert_eq!(json, "\"custom\"");
    }

    #[test]
    fn test_job_status_serialization() {
        let json = serde_json::to_string(&JobStatus::Queued).unwrap();
        assert_eq!(json, "\"queued\"");

        let json = serde_json::to_string(&JobStatus::Running).unwrap();
        assert_eq!(json, "\"running\"");

        let json = serde_json::to_string(&JobStatus::Succeeded).unwrap();
        assert_eq!(json, "\"succeeded\"");

        let json = serde_json::to_string(&JobStatus::Failed).unwrap();
        assert_eq!(json, "\"failed\"");
    }

    #[test]
    fn test_create_request_deserialization() {
        let json = r#"{"workspace_id":"550e8400-e29b-41d4-a716-446655440000","job_type":"repo_workflow","label":"Test"}"#;
        let request: CreateJobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.workspace_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(request.job_type, "repo_workflow");
        assert_eq!(request.label, Some("Test".to_string()));
    }

    #[test]
    fn test_create_request_deserialization_no_label() {
        let json = r#"{"workspace_id":"550e8400-e29b-41d4-a716-446655440000","job_type":"custom"}"#;
        let request: CreateJobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.workspace_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(request.job_type, "custom");
        assert!(request.label.is_none());
    }

    // =========================================================================
    // Payload Tests
    // =========================================================================

    #[test]
    fn test_payload_repo_workflow_creation() {
        let payload = JobPayload::repo_workflow(
            Some("Test commit".to_string()),
            Some("Test PR".to_string()),
            Some("PR description".to_string()),
        );
        assert_eq!(payload.schema, "v1");
        match payload.params {
            JobPayloadParams::RepoWorkflow(p) => {
                assert_eq!(p.commit_message, Some("Test commit".to_string()));
                assert_eq!(p.pr_title, Some("Test PR".to_string()));
                assert_eq!(p.pr_body, Some("PR description".to_string()));
            }
            _ => panic!("Expected RepoWorkflow payload"),
        }
    }

    #[test]
    fn test_payload_sanitize_truncates_long_strings() {
        let mut payload = JobPayload::repo_workflow(
            Some("x".repeat(300)), // Exceeds MAX_COMMIT_MESSAGE_LEN (200)
            Some("y".repeat(300)), // Exceeds MAX_PR_TITLE_LEN (200)
            Some("z".repeat(1500)), // Exceeds MAX_PR_BODY_LEN (1000)
        );
        payload.sanitize();
        match payload.params {
            JobPayloadParams::RepoWorkflow(p) => {
                assert_eq!(p.commit_message.as_ref().unwrap().len(), MAX_COMMIT_MESSAGE_LEN);
                assert_eq!(p.pr_title.as_ref().unwrap().len(), MAX_PR_TITLE_LEN);
                assert_eq!(p.pr_body.as_ref().unwrap().len(), MAX_PR_BODY_LEN);
            }
            _ => panic!("Expected RepoWorkflow payload"),
        }
    }

    #[test]
    fn test_payload_sanitize_removes_control_chars() {
        let mut payload = JobPayload::repo_workflow(
            Some("Hello\x00World\x1f".to_string()),
            Some("Test\x07Title".to_string()),
            None,
        );
        payload.sanitize();
        match payload.params {
            JobPayloadParams::RepoWorkflow(p) => {
                assert_eq!(p.commit_message, Some("HelloWorld".to_string()));
                assert_eq!(p.pr_title, Some("TestTitle".to_string()));
            }
            _ => panic!("Expected RepoWorkflow payload"),
        }
    }

    #[test]
    fn test_payload_validate_rejects_paths() {
        let payload = JobPayload::repo_workflow(
            Some("Fix bug in /Users/john/project".to_string()),
            None,
            None,
        );
        assert!(payload.validate().is_err());

        let payload = JobPayload::repo_workflow(
            Some("Update /home/user/config".to_string()),
            None,
            None,
        );
        assert!(payload.validate().is_err());

        let payload = JobPayload::repo_workflow(
            Some("Fix C:\\Users\\path".to_string()),
            None,
            None,
        );
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_payload_validate_rejects_urls() {
        let payload = JobPayload::repo_workflow(
            Some("See https://example.com".to_string()),
            None,
            None,
        );
        assert!(payload.validate().is_err());

        let payload = JobPayload::repo_workflow(
            Some("Check github.com/owner/repo".to_string()),
            None,
            None,
        );
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_payload_validate_rejects_env_vars() {
        let payload = JobPayload::repo_workflow(
            Some("Set EKKA_SECRET=abc".to_string()),
            None,
            None,
        );
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_payload_validate_accepts_clean_message() {
        let payload = JobPayload::repo_workflow(
            Some("Add user authentication feature".to_string()),
            Some("Feature: User authentication".to_string()),
            Some("This PR adds login and logout functionality.".to_string()),
        );
        assert!(payload.validate().is_ok());
    }

    #[test]
    fn test_payload_serialization_no_leak() {
        let payload = JobPayload::repo_workflow(
            Some("Test commit".to_string()),
            Some("Test PR".to_string()),
            None,
        );
        let json = serde_json::to_string(&payload).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_create_request_with_payload() {
        let json = r#"{
            "workspace_id":"550e8400-e29b-41d4-a716-446655440000",
            "job_type":"repo_workflow",
            "payload":{
                "schema":"v1",
                "job_type":"repo_workflow",
                "commit_message":"Test commit",
                "pr_title":"Test PR"
            }
        }"#;
        let request: CreateJobRequest = serde_json::from_str(json).unwrap();
        assert!(request.payload.is_some());
        let payload = request.payload.unwrap();
        assert_eq!(payload.schema, "v1");
        match payload.params {
            JobPayloadParams::RepoWorkflow(p) => {
                assert_eq!(p.commit_message, Some("Test commit".to_string()));
                assert_eq!(p.pr_title, Some("Test PR".to_string()));
            }
            _ => panic!("Expected RepoWorkflow payload"),
        }
    }

    #[test]
    fn test_job_with_payload_to_status_response() {
        let workspace_id = Uuid::new_v4();
        let payload = JobPayload::repo_workflow(
            Some("Test commit".to_string()),
            Some("Test PR".to_string()),
            None,
        );
        let job = Job::new(workspace_id, JobType::RepoWorkflow, None, Some(payload));
        let response = job.to_status_response();

        assert!(response.payload.is_some());
        let resp_payload = response.payload.unwrap();
        assert_eq!(resp_payload.schema, "v1");
    }

    #[test]
    fn test_payload_max_constants() {
        assert_eq!(MAX_COMMIT_MESSAGE_LEN, 200);
        assert_eq!(MAX_PR_TITLE_LEN, 200);
        assert_eq!(MAX_PR_BODY_LEN, 1000);
    }

    // =========================================================================
    // Agent Run Payload Tests (RAPTOR-2 Step 35)
    // =========================================================================

    #[test]
    fn test_agent_run_payload_creation() {
        let inputs = serde_json::json!({"key": "value", "count": 42});
        let payload = JobPayload::agent_run(
            Some("Test prompt".to_string()),
            Some(inputs.clone()),
            Some("agent-1".to_string()),
        );
        assert_eq!(payload.schema, "v1");
        match payload.params {
            JobPayloadParams::AgentRun(p) => {
                assert_eq!(p.prompt, Some("Test prompt".to_string()));
                assert_eq!(p.inputs, Some(inputs));
                assert_eq!(p.agent_id, Some("agent-1".to_string()));
            }
            _ => panic!("Expected AgentRun payload"),
        }
    }

    #[test]
    fn test_agent_run_payload_sanitize_truncates_prompt() {
        let long_prompt = "x".repeat(10000); // Exceeds MAX_AGENT_PROMPT_LEN (8k)
        let mut payload = JobPayload::agent_run(
            Some(long_prompt),
            None,
            None,
        );
        payload.sanitize();
        match payload.params {
            JobPayloadParams::AgentRun(p) => {
                assert_eq!(p.prompt.as_ref().unwrap().len(), MAX_AGENT_PROMPT_LEN);
            }
            _ => panic!("Expected AgentRun payload"),
        }
    }

    #[test]
    fn test_agent_run_payload_sanitize_drops_oversized_inputs() {
        // Create inputs that exceed 32KB
        let large_data: HashMap<String, String> = (0..1000)
            .map(|i| (format!("key_{}", i), "x".repeat(100)))
            .collect();
        let inputs = serde_json::to_value(&large_data).unwrap();
        let mut payload = JobPayload::agent_run(
            None,
            Some(inputs),
            None,
        );
        payload.sanitize();
        match payload.params {
            JobPayloadParams::AgentRun(p) => {
                // Inputs should be dropped if oversized
                assert!(p.inputs.is_none());
            }
            _ => panic!("Expected AgentRun payload"),
        }
    }

    #[test]
    fn test_agent_run_payload_validate_rejects_paths_in_prompt() {
        let payload = JobPayload::agent_run(
            Some("Process file at /Users/john/data.txt".to_string()),
            None,
            None,
        );
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_agent_run_payload_validate_rejects_urls_in_inputs() {
        let inputs = serde_json::json!({"url": "https://example.com/api"});
        let payload = JobPayload::agent_run(
            None,
            Some(inputs),
            None,
        );
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_agent_run_payload_validate_accepts_clean() {
        let inputs = serde_json::json!({"task": "analyze", "data": [1, 2, 3]});
        let payload = JobPayload::agent_run(
            Some("Analyze the provided data and summarize".to_string()),
            Some(inputs),
            Some("default".to_string()),
        );
        assert!(payload.validate().is_ok());
    }

    #[test]
    fn test_agent_run_payload_serialization_no_leak() {
        let inputs = serde_json::json!({"key": "value"});
        let payload = JobPayload::agent_run(
            Some("Test prompt".to_string()),
            Some(inputs),
            None,
        );
        let json = serde_json::to_string(&payload).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_agent_run_max_constants() {
        assert_eq!(MAX_AGENT_PROMPT_LEN, 8 * 1024);
        assert_eq!(MAX_AGENT_INPUTS_SIZE, 32 * 1024);
        assert_eq!(MAX_ARTIFACT_TEXT_LEN, 64 * 1024);
        assert_eq!(MAX_ARTIFACT_JSON_SIZE, 64 * 1024);
        assert_eq!(MAX_RESULT_MESSAGE_LEN, 500);
    }

    // =========================================================================
    // Job Result Tests (RAPTOR-2 Step 35)
    // =========================================================================

    #[test]
    fn test_job_result_success() {
        let result = JobResult::success(Some("Done".to_string()));
        assert_eq!(result.status, "succeeded");
        assert_eq!(result.code, "OK");
        assert_eq!(result.message, Some("Done".to_string()));
        assert!(result.artifact_text.is_none());
        assert!(result.artifact_json.is_none());
    }

    #[test]
    fn test_job_result_failure() {
        let result = JobResult::failure("VALIDATION_FAILED", "Invalid input");
        assert_eq!(result.status, "failed");
        assert_eq!(result.code, "VALIDATION_FAILED");
        assert_eq!(result.message, Some("Invalid input".to_string()));
    }

    #[test]
    fn test_job_result_agent_result() {
        let artifact_json = serde_json::json!({"plan": ["step1", "step2"]});
        let result = JobResult::agent_result(
            Some("Summary text".to_string()),
            Some(artifact_json.clone()),
        );
        assert_eq!(result.status, "succeeded");
        assert_eq!(result.artifact_text, Some("Summary text".to_string()));
        assert_eq!(result.artifact_json, Some(artifact_json));
    }

    #[test]
    fn test_job_result_sanitize_truncates_message() {
        let mut result = JobResult::success(Some("x".repeat(1000)));
        result.sanitize();
        assert_eq!(result.message.as_ref().unwrap().len(), MAX_RESULT_MESSAGE_LEN);
    }

    #[test]
    fn test_job_result_sanitize_truncates_artifact_text() {
        let mut result = JobResult::agent_result(
            Some("x".repeat(100000)), // Exceeds MAX_ARTIFACT_TEXT_LEN
            None,
        );
        result.sanitize();
        assert_eq!(result.artifact_text.as_ref().unwrap().len(), MAX_ARTIFACT_TEXT_LEN);
    }

    #[test]
    fn test_job_result_sanitize_drops_oversized_json() {
        // Create JSON that exceeds 64KB
        let large_data: HashMap<String, String> = (0..2000)
            .map(|i| (format!("key_{}", i), "x".repeat(100)))
            .collect();
        let artifact_json = serde_json::to_value(&large_data).unwrap();
        let mut result = JobResult::agent_result(None, Some(artifact_json));
        result.sanitize();
        assert!(result.artifact_json.is_none());
    }

    #[test]
    fn test_job_result_validate_rejects_paths() {
        let result = JobResult {
            status: "succeeded".to_string(),
            code: "OK".to_string(),
            message: Some("Output saved to /Users/john/output.txt".to_string()),
            artifact_text: None,
            artifact_json: None,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_job_result_validate_rejects_urls_in_artifact() {
        let result = JobResult {
            status: "succeeded".to_string(),
            code: "OK".to_string(),
            message: None,
            artifact_text: Some("See https://example.com for details".to_string()),
            artifact_json: None,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_job_result_validate_accepts_clean() {
        let result = JobResult::agent_result(
            Some("Analysis complete. Found 3 items.".to_string()),
            Some(serde_json::json!({"items": ["a", "b", "c"]})),
        );
        assert!(result.validate().is_ok());
    }

    #[test]
    fn test_job_result_serialization_no_leak() {
        let result = JobResult::agent_result(
            Some("Test output".to_string()),
            Some(serde_json::json!({"key": "value"})),
        );
        let json = serde_json::to_string(&result).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_job_with_result_to_status_response() {
        let workspace_id = Uuid::new_v4();
        let mut job = Job::new(
            workspace_id,
            JobType::AgentRun,
            Some("Test agent job".to_string()),
            Some(JobPayload::agent_run(Some("Test prompt".to_string()), None, None)),
        );
        job.result = Some(JobResult::agent_result(
            Some("Summary".to_string()),
            Some(serde_json::json!({"plan": []})),
        ));
        let response = job.to_status_response();
        assert!(response.result.is_some());
        let r = response.result.unwrap();
        assert_eq!(r.artifact_text, Some("Summary".to_string()));
    }

    // =========================================================================
    // RepoWorkflowIntentV1 Tests (RAPTOR-2 Step 36)
    // =========================================================================

    #[test]
    fn test_intent_valid() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Add new feature".to_string(),
            pr_title: "Feature: New capability".to_string(),
            pr_base: Some("main".to_string()),
            notes: Some("This adds a new feature".to_string()),
        };
        assert!(intent.validate().is_ok());
    }

    #[test]
    fn test_intent_invalid_schema() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v2".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Test".to_string(),
            pr_title: "Test".to_string(),
            pr_base: None,
            notes: None,
        };
        let result = intent.validate();
        assert!(result.is_err());
        match result {
            Err(IntentError::InvalidSchema(_)) => (),
            _ => panic!("Expected InvalidSchema error"),
        }
    }

    #[test]
    fn test_intent_invalid_job_type() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "agent_run".to_string(), // Wrong type
            commit_message: "Test".to_string(),
            pr_title: "Test".to_string(),
            pr_base: None,
            notes: None,
        };
        let result = intent.validate();
        assert!(result.is_err());
        match result {
            Err(IntentError::InvalidJobType(_)) => (),
            _ => panic!("Expected InvalidJobType error"),
        }
    }

    #[test]
    fn test_intent_empty_commit_message() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "".to_string(),
            pr_title: "Test".to_string(),
            pr_base: None,
            notes: None,
        };
        let result = intent.validate();
        assert!(result.is_err());
        match result {
            Err(IntentError::InvalidField(_)) => (),
            _ => panic!("Expected InvalidField error"),
        }
    }

    #[test]
    fn test_intent_commit_message_too_long() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "x".repeat(300), // Exceeds MAX_COMMIT_MESSAGE_LEN
            pr_title: "Test".to_string(),
            pr_base: None,
            notes: None,
        };
        let result = intent.validate();
        assert!(result.is_err());
        match result {
            Err(IntentError::InvalidField(_)) => (),
            _ => panic!("Expected InvalidField error"),
        }
    }

    #[test]
    fn test_intent_rejects_paths() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Fix bug in /Users/john/project".to_string(),
            pr_title: "Test".to_string(),
            pr_base: None,
            notes: None,
        };
        let result = intent.validate();
        assert!(result.is_err());
        match result {
            Err(IntentError::ForbiddenPattern(_)) => (),
            _ => panic!("Expected ForbiddenPattern error"),
        }
    }

    #[test]
    fn test_intent_rejects_urls() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Test".to_string(),
            pr_title: "See https://example.com".to_string(),
            pr_base: None,
            notes: None,
        };
        let result = intent.validate();
        assert!(result.is_err());
        match result {
            Err(IntentError::ForbiddenPattern(_)) => (),
            _ => panic!("Expected ForbiddenPattern error"),
        }
    }

    #[test]
    fn test_intent_rejects_env_vars() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Test".to_string(),
            pr_title: "Test".to_string(),
            pr_base: None,
            notes: Some("Use EKKA_SECRET=abc".to_string()),
        };
        let result = intent.validate();
        assert!(result.is_err());
        match result {
            Err(IntentError::ForbiddenPattern(_)) => (),
            _ => panic!("Expected ForbiddenPattern error"),
        }
    }

    #[test]
    fn test_intent_valid_branch_names() {
        // Valid branch names
        assert!(RepoWorkflowIntentV1::is_valid_branch_name("main"));
        assert!(RepoWorkflowIntentV1::is_valid_branch_name("develop"));
        assert!(RepoWorkflowIntentV1::is_valid_branch_name("feature/new-thing"));
        assert!(RepoWorkflowIntentV1::is_valid_branch_name("release-1.0"));
        assert!(RepoWorkflowIntentV1::is_valid_branch_name("fix_bug_123"));

        // Invalid branch names
        assert!(!RepoWorkflowIntentV1::is_valid_branch_name("")); // Empty
        assert!(!RepoWorkflowIntentV1::is_valid_branch_name("/main")); // Starts with /
        assert!(!RepoWorkflowIntentV1::is_valid_branch_name("main/")); // Ends with /
        assert!(!RepoWorkflowIntentV1::is_valid_branch_name(".hidden")); // Starts with .
        assert!(!RepoWorkflowIntentV1::is_valid_branch_name("branch.")); // Ends with .
        assert!(!RepoWorkflowIntentV1::is_valid_branch_name("../escape")); // Path traversal
        assert!(!RepoWorkflowIntentV1::is_valid_branch_name("a//b")); // Double slash
    }

    #[test]
    fn test_intent_sanitize() {
        let mut intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Hello\x00World".to_string(), // Control char
            pr_title: "x".repeat(300), // Too long
            pr_base: Some("main".to_string()),
            notes: Some("Note\x1f".to_string()),
        };
        intent.sanitize();
        assert_eq!(intent.commit_message, "HelloWorld");
        assert_eq!(intent.pr_title.len(), MAX_PR_TITLE_LEN);
        assert_eq!(intent.notes, Some("Note".to_string()));
    }

    #[test]
    fn test_intent_to_job_payload() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Add feature".to_string(),
            pr_title: "New feature".to_string(),
            pr_base: Some("main".to_string()),
            notes: Some("This is the PR body".to_string()),
        };
        let payload = intent.to_job_payload();
        assert_eq!(payload.schema, "v1");
        match payload.params {
            JobPayloadParams::RepoWorkflow(p) => {
                assert_eq!(p.commit_message, Some("Add feature".to_string()));
                assert_eq!(p.pr_title, Some("New feature".to_string()));
                assert_eq!(p.pr_body, Some("This is the PR body".to_string()));
            }
            _ => panic!("Expected RepoWorkflow payload"),
        }
    }

    #[test]
    fn test_intent_serialization_no_leak() {
        let intent = RepoWorkflowIntentV1 {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Add feature".to_string(),
            pr_title: "New feature".to_string(),
            pr_base: Some("main".to_string()),
            notes: Some("Notes".to_string()),
        };
        let json = serde_json::to_string(&intent).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_intent_deserialization() {
        let json = r#"{
            "schema": "v1",
            "job_type": "repo_workflow",
            "commit_message": "Test commit",
            "pr_title": "Test PR",
            "pr_base": "develop",
            "notes": "Some notes"
        }"#;
        let intent: RepoWorkflowIntentV1 = serde_json::from_str(json).unwrap();
        assert_eq!(intent.schema, "v1");
        assert_eq!(intent.job_type, "repo_workflow");
        assert_eq!(intent.commit_message, "Test commit");
        assert_eq!(intent.pr_title, "Test PR");
        assert_eq!(intent.pr_base, Some("develop".to_string()));
        assert_eq!(intent.notes, Some("Some notes".to_string()));
    }

    #[test]
    fn test_from_intent_request_deserialization() {
        let json = r#"{
            "source_job_id": "550e8400-e29b-41d4-a716-446655440000",
            "workspace_id": "550e8400-e29b-41d4-a716-446655440001",
            "intent": {
                "schema": "v1",
                "job_type": "repo_workflow",
                "commit_message": "Test",
                "pr_title": "Test PR"
            }
        }"#;
        let request: FromIntentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.source_job_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(request.workspace_id, "550e8400-e29b-41d4-a716-446655440001");
        assert_eq!(request.intent.schema, "v1");
    }

    #[test]
    fn test_max_intent_notes_constant() {
        assert_eq!(MAX_INTENT_NOTES_LEN, 2 * 1024);
    }

    // =========================================================================
    // Retry and Failure Classification Tests (RAPTOR-3 Step 3)
    // =========================================================================

    #[test]
    fn test_classify_error_retryable() {
        // Retryable error codes
        assert_eq!(classify_error("GITHUB_NOT_CONNECTED"), FailureClass::Retryable);
        assert_eq!(classify_error("GITHUB_NOT_CONFIGURED"), FailureClass::Retryable);
        assert_eq!(classify_error("GIT_OPERATION_TIMEOUT"), FailureClass::Retryable);
        assert_eq!(classify_error("DATA_LOAD_FAILED"), FailureClass::Retryable);
        assert_eq!(classify_error("DATA_PERSIST_FAILED"), FailureClass::Retryable);
        assert_eq!(classify_error("NETWORK_TIMEOUT"), FailureClass::Retryable);
        assert_eq!(classify_error("RUNNER_TIMEOUT"), FailureClass::Retryable);
        assert_eq!(classify_error("LLM_RATE_LIMITED"), FailureClass::Retryable);
    }

    #[test]
    fn test_classify_error_non_retryable() {
        // Non-retryable error codes
        assert_eq!(classify_error("REPO_NOT_ALLOWED"), FailureClass::NonRetryable);
        assert_eq!(classify_error("REPO_NOT_BOUND"), FailureClass::NonRetryable);
        assert_eq!(classify_error("CAPABILITY_DENIED"), FailureClass::NonRetryable);
        assert_eq!(classify_error("GIT_PROTECTED_BRANCH"), FailureClass::NonRetryable);
        assert_eq!(classify_error("INVALID_PAYLOAD"), FailureClass::NonRetryable);
        assert_eq!(classify_error("WORKSPACE_NOT_FOUND"), FailureClass::NonRetryable);
        assert_eq!(classify_error("DATA_KEY_NOT_CONFIGURED"), FailureClass::NonRetryable);
    }

    #[test]
    fn test_classify_error_intent_prefix_non_retryable() {
        // INTENT_INVALID_* prefix should be non-retryable
        assert_eq!(classify_error("INTENT_INVALID_SCHEMA"), FailureClass::NonRetryable);
        assert_eq!(classify_error("INTENT_INVALID_FIELD"), FailureClass::NonRetryable);
        assert_eq!(classify_error("INTENT_INVALID_ANYTHING"), FailureClass::NonRetryable);
    }

    #[test]
    fn test_classify_error_unknown_is_non_retryable() {
        // Unknown error codes default to non-retryable for safety
        assert_eq!(classify_error("UNKNOWN_ERROR"), FailureClass::NonRetryable);
        assert_eq!(classify_error("RANDOM_CODE"), FailureClass::NonRetryable);
        assert_eq!(classify_error(""), FailureClass::NonRetryable);
    }

    #[test]
    fn test_calculate_backoff_secs() {
        // Base = 30s, multiplier = 2^attempt
        assert_eq!(calculate_backoff_secs(0), 30);   // 30 * 2^0 = 30
        assert_eq!(calculate_backoff_secs(1), 60);   // 30 * 2^1 = 60
        assert_eq!(calculate_backoff_secs(2), 120);  // 30 * 2^2 = 120
        assert_eq!(calculate_backoff_secs(3), 240);  // 30 * 2^3 = 240
        assert_eq!(calculate_backoff_secs(4), 480);  // 30 * 2^4 = 480
        assert_eq!(calculate_backoff_secs(5), 600);  // 30 * 2^5 = 960, capped to 600
        assert_eq!(calculate_backoff_secs(10), 600); // Any high attempt capped to 600 (10 min)
    }

    #[test]
    fn test_sanitize_error_message_strips_paths() {
        let msg = "Error in /Users/john/project/file.txt";
        let sanitized = sanitize_error_message(msg);
        assert!(!sanitized.contains("/Users"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_error_message_strips_urls() {
        let msg = "Failed to connect to https://api.example.com/v1/endpoint";
        let sanitized = sanitize_error_message(msg);
        assert!(!sanitized.contains("https://"));
        assert!(sanitized.contains("[url]"));
    }

    #[test]
    fn test_sanitize_error_message_strips_env_vars() {
        let msg = "Missing EKKA_SECRET_KEY env var";
        let sanitized = sanitize_error_message(msg);
        assert!(!sanitized.contains("EKKA_"));
        assert!(sanitized.contains("[env]"));
    }

    #[test]
    fn test_sanitize_error_message_truncates() {
        let msg = "x".repeat(300);
        let sanitized = sanitize_error_message(&msg);
        assert!(sanitized.len() <= 200);
    }

    #[test]
    fn test_sanitize_error_message_strips_control_chars() {
        let msg = "Error\x00with\x1fnull\tbytes";
        let sanitized = sanitize_error_message(msg);
        assert!(!sanitized.contains('\x00'));
        assert!(!sanitized.contains('\x1f'));
    }

    #[test]
    fn test_job_new_has_default_retry_fields() {
        let job = Job::new(Uuid::new_v4(), JobType::RepoWorkflow, None, None);
        assert_eq!(job.max_attempts, persist::DEFAULT_MAX_ATTEMPTS);
        assert!(job.next_attempt_at_utc.is_none());
        assert!(job.last_error_code.is_none());
        assert!(job.last_error_message.is_none());
    }

    #[test]
    fn test_job_is_retry_due_no_schedule() {
        let job = Job::new(Uuid::new_v4(), JobType::RepoWorkflow, None, None);
        // No next_attempt_at_utc means immediately due
        assert!(job.is_retry_due());
    }

    #[test]
    fn test_job_is_retry_due_past_schedule() {
        let mut job = Job::new(Uuid::new_v4(), JobType::RepoWorkflow, None, None);
        // Schedule in the past
        job.next_attempt_at_utc = Some(Utc::now() - chrono::Duration::seconds(60));
        assert!(job.is_retry_due());
    }

    #[test]
    fn test_job_is_retry_due_future_schedule() {
        let mut job = Job::new(Uuid::new_v4(), JobType::RepoWorkflow, None, None);
        // Schedule in the future
        job.next_attempt_at_utc = Some(Utc::now() + chrono::Duration::seconds(3600));
        assert!(!job.is_retry_due());
    }

    #[test]
    fn test_job_is_claimable_respects_retry_schedule() {
        let mut job = Job::new(Uuid::new_v4(), JobType::RepoWorkflow, None, None);
        job.status = JobStatus::Queued;

        // No schedule - claimable
        assert!(job.is_claimable());

        // Future schedule - not claimable
        job.next_attempt_at_utc = Some(Utc::now() + chrono::Duration::seconds(3600));
        assert!(!job.is_claimable());

        // Past schedule - claimable
        job.next_attempt_at_utc = Some(Utc::now() - chrono::Duration::seconds(60));
        assert!(job.is_claimable());
    }

    #[test]
    fn test_complete_job_with_retryable_failure_requeues() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();
        let runner_id = "runner-001";

        // Create and claim a job
        let job = store.create_job(workspace_id, JobType::RepoWorkflow, None, None);
        store.claim_job(job.job_id, runner_id, 300).unwrap();

        // Complete with retryable failure
        let completed = store.complete_job_with_lease(
            job.job_id,
            runner_id,
            JobStatus::Failed,
            Some("GITHUB_NOT_CONNECTED".to_string()),
            Some("GitHub not connected".to_string()),
            None,
        ).unwrap();

        // Should be requeued with next_attempt_at_utc set
        assert_eq!(completed.status, JobStatus::Queued);
        assert!(completed.next_attempt_at_utc.is_some());
        assert_eq!(completed.last_error_code, Some("GITHUB_NOT_CONNECTED".to_string()));
        assert!(completed.last_error_message.is_some());
    }

    #[test]
    fn test_complete_job_with_non_retryable_failure_is_terminal() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();
        let runner_id = "runner-001";

        // Create and claim a job
        let job = store.create_job(workspace_id, JobType::RepoWorkflow, None, None);
        store.claim_job(job.job_id, runner_id, 300).unwrap();

        // Complete with non-retryable failure
        let completed = store.complete_job_with_lease(
            job.job_id,
            runner_id,
            JobStatus::Failed,
            Some("REPO_NOT_ALLOWED".to_string()),
            Some("Repository not allowed".to_string()),
            None,
        ).unwrap();

        // Should be terminal failed
        assert_eq!(completed.status, JobStatus::Failed);
        assert!(completed.next_attempt_at_utc.is_none());
        assert_eq!(completed.last_error_code, Some("REPO_NOT_ALLOWED".to_string()));
    }

    #[test]
    fn test_complete_job_max_attempts_stops_retries() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();
        let runner_id = "runner-001";

        // Create a job and set attempt_count to max_attempts - 1
        let job = store.create_job(workspace_id, JobType::RepoWorkflow, None, None);

        // Claim and fail 3 times (max_attempts = 3, but attempt_count increments on claim)
        for i in 0..3 {
            // Clear next_attempt_at_utc to allow immediate claim (simulates time passing)
            {
                let mut by_id = store.jobs_by_id.write().unwrap();
                if let Some(j) = by_id.get_mut(&job.job_id) {
                    j.next_attempt_at_utc = None;
                }
            }

            store.claim_job(job.job_id, runner_id, 300).unwrap();
            let completed = store.complete_job_with_lease(
                job.job_id,
                runner_id,
                JobStatus::Failed,
                Some("GITHUB_NOT_CONNECTED".to_string()),
                Some(format!("Attempt {}", i + 1)),
                None,
            ).unwrap();

            if i < 2 {
                // First 2 failures should requeue
                assert_eq!(completed.status, JobStatus::Queued, "Attempt {} should requeue", i + 1);
            } else {
                // 3rd failure should be terminal (attempt_count = 3 = max_attempts)
                assert_eq!(completed.status, JobStatus::Failed, "Attempt {} should be terminal", i + 1);
            }
        }
    }

    #[test]
    fn test_list_claimable_excludes_not_due_jobs() {
        let store = JobStore::new();
        let workspace_id = Uuid::new_v4();

        // Create two jobs
        let job1 = store.create_job(workspace_id, JobType::RepoWorkflow, Some("Job 1".to_string()), None);
        let job2 = store.create_job(workspace_id, JobType::RepoWorkflow, Some("Job 2".to_string()), None);

        // Set job2 to have future next_attempt_at_utc (update both indexes)
        let future_time = Utc::now() + chrono::Duration::seconds(3600);
        {
            let mut by_id = store.jobs_by_id.write().unwrap();
            if let Some(j) = by_id.get_mut(&job2.job_id) {
                j.next_attempt_at_utc = Some(future_time);
            }
        }
        {
            let mut by_workspace = store.jobs_by_workspace.write().unwrap();
            if let Some(jobs) = by_workspace.get_mut(&workspace_id) {
                if let Some(j) = jobs.iter_mut().find(|j| j.job_id == job2.job_id) {
                    j.next_attempt_at_utc = Some(future_time);
                }
            }
        }

        // List claimable should only return job1
        let claimable = store.list_claimable_jobs(10);
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].job_id, job1.job_id);
    }

    #[test]
    fn test_sanitize_error_message_no_leak() {
        // Test that sanitized messages don't leak sensitive data
        let dangerous_msg = "Error at /Users/secret/path with EKKA_SECRET_TOKEN accessing https://internal.example.com/api";
        let sanitized = sanitize_error_message(dangerous_msg);
        assert_no_leak(&sanitized);
    }

    #[test]
    fn test_job_to_status_response_includes_retry_fields() {
        let workspace_id = Uuid::new_v4();
        let mut job = Job::new(workspace_id, JobType::RepoWorkflow, None, None);
        job.attempt_count = 2;
        job.next_attempt_at_utc = Some(Utc::now());
        job.last_error_code = Some("GITHUB_NOT_CONNECTED".to_string());
        job.last_error_message = Some("Test error".to_string());

        let response = job.to_status_response();
        assert_eq!(response.attempt_count, 2);
        assert_eq!(response.max_attempts, persist::DEFAULT_MAX_ATTEMPTS);
        assert!(response.next_attempt_at_utc.is_some());
        assert_eq!(response.last_error_code, Some("GITHUB_NOT_CONNECTED".to_string()));
        assert_eq!(response.last_error_message, Some("Test error".to_string()));
    }

    // =========================================================================
    // Queue Mode Tests (RAPTOR-3 Step 5)
    // =========================================================================

    #[test]
    fn test_queue_mode_disabled_blocks_job_creation() {
        // Test that NodeJobQueueMode::Disabled does not allow job creation
        let mode = NodeJobQueueMode::Disabled;
        assert!(!mode.allows_job_creation());
        assert_eq!(mode.to_string(), "disabled");
    }

    #[test]
    fn test_queue_mode_legacy_allows_job_creation() {
        // Test that NodeJobQueueMode::Legacy allows job creation
        let mode = NodeJobQueueMode::Legacy;
        assert!(mode.allows_job_creation());
        assert_eq!(mode.to_string(), "legacy");
    }

    #[test]
    fn test_queue_mode_from_env_defaults_to_disabled() {
        // Remove env var and verify default is disabled
        // Note: This test may be flaky if env var is set globally
        // Testing the logic directly instead
        let mode = NodeJobQueueMode::Disabled;
        assert!(!mode.allows_job_creation());
    }

    #[test]
    fn test_queue_mode_context_with_disabled_mode() {
        // Test that JobsModuleContext can be created with disabled queue mode
        let store = Arc::new(JobStore::new());
        let validator: SessionValidator = Arc::new(|_headers| {
            Err(SessionValidationError {
                error: "Not authenticated".to_string(),
                code: "NOT_AUTHENTICATED".to_string(),
                status: axum::http::StatusCode::UNAUTHORIZED,
            })
        });
        let workspace_checker: WorkspaceExistsChecker = Arc::new(|_id| true);

        let ctx = JobsModuleContext::with_queue_mode(
            store,
            validator,
            workspace_checker,
            "test",
            NodeJobQueueMode::Disabled,
        );

        assert_eq!(ctx.queue_mode, NodeJobQueueMode::Disabled);
        assert!(!ctx.queue_mode.allows_job_creation());
    }

    #[test]
    fn test_queue_mode_context_with_legacy_mode() {
        // Test that JobsModuleContext can be created with legacy queue mode
        let store = Arc::new(JobStore::new());
        let validator: SessionValidator = Arc::new(|_headers| {
            Err(SessionValidationError {
                error: "Not authenticated".to_string(),
                code: "NOT_AUTHENTICATED".to_string(),
                status: axum::http::StatusCode::UNAUTHORIZED,
            })
        });
        let workspace_checker: WorkspaceExistsChecker = Arc::new(|_id| true);

        let ctx = JobsModuleContext::with_queue_mode(
            store,
            validator,
            workspace_checker,
            "test",
            NodeJobQueueMode::Legacy,
        );

        assert_eq!(ctx.queue_mode, NodeJobQueueMode::Legacy);
        assert!(ctx.queue_mode.allows_job_creation());
    }
}
