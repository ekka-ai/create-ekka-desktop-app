//! EKKA Node Agent Module - RAPTOR-2 Step 35 + RAPTOR-3 Step 6
//!
//! Provides LLM-backed agent engine for executing agent_run jobs.
//! When LLM is configured, uses real Claude API. Otherwise returns LLM_NOT_CONFIGURED.
//!
//! ## Security Properties
//!
//! - No absolute paths in responses (only safe artifact text/JSON)
//! - Session validation before capability checks (401 then 403)
//! - Capability-gated: agent.run
//! - Structured logging with node.agent.* prefix
//! - All outputs are bounded and sanitized
//! - NEVER logs prompts or LLM responses (only hashes + lengths)
//!
//! ## Intent Extraction (RAPTOR-3 Step 6)
//!
//! LLM output is parsed for JSON blocks containing RepoWorkflowIntentV1.
//! If found and valid, the intent is included in artifact_json under "intent" key.
//! Invalid intents are silently ignored (no failure).
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - An AgentModuleContext with session validator and optional LLM provider
//!
//! When disabled via EKKA_ENABLE_AGENT=0, routes are NOT mounted -> 404.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{info, warn};

pub use ekka_node_modules::{
    error_codes, ModuleConfig, ModuleError,
    SessionInfo, SessionValidationError, SessionValidator,
};

pub use ekka_node_module_llm::{
    LlmConfig, LlmError, LlmProvider, LlmResponse, MockProvider,
    hash_for_logging, MAX_RESPONSE_SIZE,
};

// =============================================================================
// Module Configuration
// =============================================================================

/// Agent module configuration
pub const AGENT_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Agent",
    env_var: "EKKA_ENABLE_AGENT",
    default_enabled: false, // Disabled by default, opt-in for agent execution
};

/// Required capability for agent run operations
pub const AGENT_RUN_CAPABILITY: &str = "agent.run";

/// Maximum length for prompt
pub const MAX_PROMPT_LEN: usize = 8 * 1024;

/// Maximum size for inputs JSON
pub const MAX_INPUTS_SIZE: usize = 32 * 1024;

/// Maximum length for artifact text output
pub const MAX_ARTIFACT_TEXT_LEN: usize = 64 * 1024;

/// Maximum size for artifact JSON output
pub const MAX_ARTIFACT_JSON_SIZE: usize = 64 * 1024;

/// Maximum length for intent fields
pub const MAX_COMMIT_MESSAGE_LEN: usize = 200;
pub const MAX_PR_TITLE_LEN: usize = 200;
pub const MAX_PR_BODY_LEN: usize = 1000;
pub const MAX_INTENT_NOTES_LEN: usize = 2 * 1024;

// =============================================================================
// API Request/Response Types
// =============================================================================

/// Agent run request
#[derive(Debug, Deserialize)]
pub struct AgentRunRequest {
    /// Job ID (for correlation)
    pub job_id: String,
    /// Prompt text (max 8KB)
    pub prompt: String,
    /// Input data as JSON (max 32KB serialized)
    #[serde(default)]
    pub inputs: Option<serde_json::Value>,
}

/// Agent run response
#[derive(Debug, Serialize)]
pub struct AgentRunResponse {
    /// Job ID (echoed for correlation)
    pub job_id: String,
    /// Text artifact (summary/output)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_text: Option<String>,
    /// JSON artifact (structured output, may include intent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_json: Option<serde_json::Value>,
}

/// Agent error response
#[derive(Debug, Serialize)]
pub struct AgentError {
    pub error: String,
    pub code: String,
}

// =============================================================================
// RepoWorkflowIntent (extracted from LLM output)
// =============================================================================

/// Repo workflow intent that can be extracted from LLM output
/// Same schema as jobs module's RepoWorkflowIntentV1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoWorkflowIntent {
    /// Schema version - must be "v1"
    pub schema: String,
    /// Job type - must be "repo_workflow"
    pub job_type: String,
    /// Commit message (max 200 chars)
    pub commit_message: String,
    /// PR title (max 200 chars)
    pub pr_title: String,
    /// PR base branch (optional)
    #[serde(default)]
    pub pr_base: Option<String>,
    /// Notes (max 2KB)
    #[serde(default)]
    pub notes: Option<String>,
}

impl RepoWorkflowIntent {
    /// Validate the intent
    pub fn validate(&self) -> Result<(), &'static str> {
        // Schema must be v1
        if self.schema != "v1" {
            return Err("Invalid schema version");
        }

        // Job type must be repo_workflow
        if self.job_type != "repo_workflow" {
            return Err("Invalid job type");
        }

        // Commit message bounds
        if self.commit_message.is_empty() || self.commit_message.len() > MAX_COMMIT_MESSAGE_LEN {
            return Err("Invalid commit message length");
        }

        // PR title bounds
        if self.pr_title.is_empty() || self.pr_title.len() > MAX_PR_TITLE_LEN {
            return Err("Invalid PR title length");
        }

        // PR base branch format (if provided)
        if let Some(ref base) = self.pr_base {
            if !is_valid_branch_name(base) {
                return Err("Invalid branch name format");
            }
        }

        // Notes bounds
        if let Some(ref notes) = self.notes {
            if notes.len() > MAX_INTENT_NOTES_LEN {
                return Err("Notes too long");
            }
        }

        // Check for forbidden patterns
        if contains_forbidden_pattern(&self.commit_message)
            || contains_forbidden_pattern(&self.pr_title)
            || self.pr_base.as_ref().map(|s| contains_forbidden_pattern(s)).unwrap_or(false)
            || self.notes.as_ref().map(|s| contains_forbidden_pattern(s)).unwrap_or(false)
        {
            return Err("Contains forbidden patterns");
        }

        Ok(())
    }

    /// Sanitize intent fields
    pub fn sanitize(&mut self) {
        self.commit_message = sanitize_string(&self.commit_message, MAX_COMMIT_MESSAGE_LEN);
        self.pr_title = sanitize_string(&self.pr_title, MAX_PR_TITLE_LEN);
        if let Some(ref mut base) = self.pr_base {
            *base = sanitize_string(base, 100);
        }
        if let Some(ref mut notes) = self.notes {
            *notes = sanitize_string(notes, MAX_INTENT_NOTES_LEN);
        }
    }
}

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Context for the Agent module
#[derive(Clone)]
pub struct AgentModuleContext {
    /// Session validator (provided by host for request-time auth)
    pub session_validator: SessionValidator,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
    /// LLM provider (optional, if None returns LLM_NOT_CONFIGURED)
    pub llm_provider: Option<Arc<dyn LlmProvider>>,
    /// LLM configured flag
    pub llm_configured: bool,
}

impl AgentModuleContext {
    pub fn new(
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
    ) -> Self {
        let llm_config = LlmConfig::from_env();
        let llm_configured = llm_config.is_configured();
        let llm_provider = llm_config.create_provider();

        Self {
            session_validator,
            log_prefix: log_prefix.into(),
            llm_provider,
            llm_configured,
        }
    }

    /// Create context with explicit LLM provider (for testing)
    pub fn with_provider(
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
        provider: Option<Arc<dyn LlmProvider>>,
    ) -> Self {
        let llm_configured = provider.is_some();
        Self {
            session_validator,
            log_prefix: log_prefix.into(),
            llm_provider: provider,
            llm_configured,
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.agent.{}", self.log_prefix, op)
    }
}

/// Mount the Agent module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: AgentModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !AGENT_MODULE_CONFIG.is_enabled() {
        info!(
            module = "agent",
            enabled = false,
            "Agent module disabled (set EKKA_ENABLE_AGENT=1 to enable)"
        );
        return router;
    }

    info!(
        module = "agent",
        enabled = true,
        llm_configured = %ctx.llm_configured,
        "Agent module enabled"
    );

    let state = Arc::new(ctx);

    let agent_router: Router<S> = Router::new()
        .route("/v0/agent/run", post(agent_run_handler))
        .with_state(state);

    router.merge(agent_router)
}

// =============================================================================
// Axum Handler
// =============================================================================

/// POST /v0/agent/run - Execute agent with LLM or return LLM_NOT_CONFIGURED
/// Requires: valid session + "agent.run" capability
async fn agent_run_handler(
    State(ctx): State<Arc<AgentModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<AgentRunRequest>,
) -> Result<Json<AgentRunResponse>, (StatusCode, Json<AgentError>)> {
    let job_id_short = &request.job_id[..8.min(request.job_id.len())];

    info!(
        op = %ctx.log_op("run.request"),
        job_id = %job_id_short,
        prompt_len = %request.prompt.len(),
        llm_configured = %ctx.llm_configured,
        "Agent run requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("run.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(AgentError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if session.require_capability(AGENT_RUN_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("run.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(AgentError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Validate input bounds
    if request.prompt.len() > MAX_PROMPT_LEN {
        warn!(
            op = %ctx.log_op("run.prompt_too_large"),
            prompt_len = %request.prompt.len(),
            max_len = %MAX_PROMPT_LEN,
            "Prompt exceeds maximum length"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AgentError {
                error: "Prompt exceeds maximum length".to_string(),
                code: "PROMPT_TOO_LARGE".to_string(),
            }),
        ));
    }

    if let Some(ref inputs) = request.inputs {
        if let Ok(serialized) = serde_json::to_string(inputs) {
            if serialized.len() > MAX_INPUTS_SIZE {
                warn!(
                    op = %ctx.log_op("run.inputs_too_large"),
                    inputs_size = %serialized.len(),
                    max_size = %MAX_INPUTS_SIZE,
                    "Inputs JSON exceeds maximum size"
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(AgentError {
                        error: "Inputs JSON exceeds maximum size".to_string(),
                        code: "INPUTS_TOO_LARGE".to_string(),
                    }),
                ));
            }
        }
    }

    // Step 4: Validate no forbidden patterns in prompt/inputs
    if let Err(msg) = validate_no_leaks(&request.prompt) {
        warn!(
            op = %ctx.log_op("run.invalid_prompt"),
            "Prompt contains forbidden patterns"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AgentError {
                error: msg.to_string(),
                code: "INVALID_PROMPT".to_string(),
            }),
        ));
    }

    if let Some(ref inputs) = request.inputs {
        let serialized = serde_json::to_string(inputs).unwrap_or_default();
        if let Err(msg) = validate_no_leaks(&serialized) {
            warn!(
                op = %ctx.log_op("run.invalid_inputs"),
                "Inputs contain forbidden patterns"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(AgentError {
                    error: msg.to_string(),
                    code: "INVALID_INPUTS".to_string(),
                }),
            ));
        }
    }

    // Step 5: Check if LLM is configured
    let provider = match &ctx.llm_provider {
        Some(p) => p.clone(),
        None => {
            warn!(
                op = %ctx.log_op("run.llm_not_configured"),
                job_id = %job_id_short,
                "LLM provider not configured"
            );
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AgentError {
                    error: "LLM provider not configured".to_string(),
                    code: "LLM_NOT_CONFIGURED".to_string(),
                }),
            ));
        }
    };

    // Step 6: Build LLM prompt with context
    let llm_prompt = build_llm_prompt(&request.prompt, request.inputs.as_ref());

    // Step 7: Call LLM provider
    let llm_result = provider.complete(&llm_prompt, Some(SYSTEM_PROMPT)).await;

    let llm_response = match llm_result {
        Ok(response) => response,
        Err(e) => {
            warn!(
                op = %ctx.log_op("run.llm_error"),
                job_id = %job_id_short,
                code = %e.code,
                retryable = %e.retryable,
                "LLM request failed"
            );
            return Err((
                if e.retryable { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::BAD_REQUEST },
                Json(AgentError {
                    error: e.message,
                    code: e.code,
                }),
            ));
        }
    };

    // Step 8: Process LLM response - extract intent and build artifacts
    let (artifact_text, artifact_json) = process_llm_response(
        &request.job_id,
        &llm_response.text,
        llm_response.model.as_str(),
    );

    info!(
        op = %ctx.log_op("run.ok"),
        job_id = %job_id_short,
        artifact_text_len = %artifact_text.as_ref().map(|t| t.len()).unwrap_or(0),
        has_intent = %artifact_json.as_ref()
            .and_then(|j| j.get("intent"))
            .is_some(),
        "Agent run completed"
    );

    Ok(Json(AgentRunResponse {
        job_id: request.job_id,
        artifact_text,
        artifact_json,
    }))
}

// =============================================================================
// System Prompt
// =============================================================================

const SYSTEM_PROMPT: &str = r#"You are a helpful software development assistant. Analyze the user's request and provide a clear, actionable response.

If the request involves creating, modifying, or fixing code that should result in a git commit and pull request, include a JSON block in your response with this exact format:

```json
{
  "schema": "v1",
  "job_type": "repo_workflow",
  "commit_message": "Your concise commit message here",
  "pr_title": "Your PR title here",
  "notes": "Optional additional context"
}
```

Guidelines:
- Keep commit messages under 200 characters
- Keep PR titles under 200 characters
- Do not include file paths, URLs, or environment variable names in the JSON
- Only include the JSON block if the task warrants a git workflow
- Provide a summary of your analysis and recommendations in plain text"#;

// =============================================================================
// LLM Prompt Building
// =============================================================================

/// Build the LLM prompt with user request and inputs
fn build_llm_prompt(prompt: &str, inputs: Option<&serde_json::Value>) -> String {
    let mut llm_prompt = format!("User Request:\n{}\n", prompt);

    if let Some(inputs) = inputs {
        // Serialize inputs without sensitive data
        if let Ok(inputs_str) = serde_json::to_string_pretty(inputs) {
            llm_prompt.push_str("\nInput Data:\n");
            llm_prompt.push_str(&inputs_str);
            llm_prompt.push('\n');
        }
    }

    llm_prompt
}

// =============================================================================
// Response Processing
// =============================================================================

/// Process LLM response: extract text, find intent, build artifact JSON
fn process_llm_response(
    job_id: &str,
    response_text: &str,
    model: &str,
) -> (Option<String>, Option<serde_json::Value>) {
    // Sanitize the response text
    let sanitized_text = sanitize_output(response_text, MAX_ARTIFACT_TEXT_LEN);

    // Try to extract intent from JSON blocks
    let intent = extract_intent_from_response(&sanitized_text);

    // Generate execution hash for tracking
    let mut hasher = Sha256::new();
    hasher.update(job_id.as_bytes());
    hasher.update(response_text.as_bytes());
    let execution_id = hex::encode(&hasher.finalize()[..8]);

    // Build artifact JSON
    let mut artifact_json = serde_json::json!({
        "execution_id": execution_id,
        "model": model,
        "metadata": {
            "engine": "llm-v1",
            "schema_version": "v1"
        }
    });

    // Add intent if found and valid
    if let Some(mut valid_intent) = intent {
        valid_intent.sanitize();
        if valid_intent.validate().is_ok() {
            artifact_json["intent"] = serde_json::to_value(&valid_intent)
                .unwrap_or(serde_json::Value::Null);
        }
    }

    (Some(sanitized_text), Some(artifact_json))
}

/// Extract RepoWorkflowIntent from JSON blocks in LLM response
fn extract_intent_from_response(text: &str) -> Option<RepoWorkflowIntent> {
    // Match JSON blocks (```json ... ```)
    let json_block_re = Regex::new(r"```json\s*\n?([\s\S]*?)\n?```").ok()?;

    for cap in json_block_re.captures_iter(text) {
        if let Some(json_str) = cap.get(1) {
            if let Ok(intent) = serde_json::from_str::<RepoWorkflowIntent>(json_str.as_str()) {
                // Validate schema and job_type
                if intent.schema == "v1" && intent.job_type == "repo_workflow" {
                    return Some(intent);
                }
            }
        }
    }

    // Also try to find JSON objects by looking for opening braces
    // and attempting to parse valid JSON from them
    for (i, _) in text.match_indices('{') {
        // Find matching closing brace (simple heuristic)
        let mut depth = 0;
        let mut end_pos = None;
        for (j, c) in text[i..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end_pos = Some(i + j + 1);
                        break;
                    }
                }
                _ => {}
            }
        }

        if let Some(end) = end_pos {
            let candidate = &text[i..end];
            if let Ok(intent) = serde_json::from_str::<RepoWorkflowIntent>(candidate) {
                if intent.schema == "v1" && intent.job_type == "repo_workflow" {
                    return Some(intent);
                }
            }
        }
    }

    None
}

// =============================================================================
// Validation Helpers
// =============================================================================

/// Check if string contains forbidden patterns (paths, URLs, env vars)
fn contains_forbidden_pattern(s: &str) -> bool {
    s.contains("/Users/") || s.contains("/home/") || s.contains("/var/")
        || s.contains("/tmp/") || s.contains("/private/")
        || s.contains("C:\\") || s.contains("D:\\")
        || s.contains("https://") || s.contains("http://")
        || s.contains("github.com")
        || s.contains("EKKA_")
}

/// Validate string doesn't contain forbidden patterns
fn validate_no_leaks(s: &str) -> Result<(), &'static str> {
    if contains_forbidden_pattern(s) {
        return Err("Contains forbidden pattern");
    }
    Ok(())
}

/// Validate branch name format
fn is_valid_branch_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 100 {
        return false;
    }
    if name.starts_with('/') || name.ends_with('/') {
        return false;
    }
    if name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    if name.contains("..") || name.contains("//") {
        return false;
    }
    // Only allow alphanumeric, dash, underscore, slash, dot
    name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.')
}

/// Sanitize string: remove control chars, limit length
fn sanitize_string(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Sanitize output string: remove control chars, limit length, strip forbidden patterns
fn sanitize_output(s: &str, max_len: usize) -> String {
    let mut result = sanitize_string(s, max_len);

    // Replace forbidden patterns with placeholders
    let patterns = [
        ("/Users/", "[path]"),
        ("/home/", "[path]"),
        ("/var/", "[path]"),
        ("/tmp/", "[path]"),
        ("/private/", "[path]"),
        ("C:\\", "[path]"),
        ("D:\\", "[path]"),
    ];

    for (pattern, replacement) in patterns {
        while let Some(start) = result.find(pattern) {
            let end = result[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ')')
                .map(|i| start + i)
                .unwrap_or(result.len());
            result.replace_range(start..end, replacement);
        }
    }

    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_leak(s: &str) {
        assert!(!s.contains("/Users/"), "Found /Users/ path leak");
        assert!(!s.contains("/home/"), "Found /home/ path leak");
        assert!(!s.contains("/var/"), "Found /var/ path leak");
        assert!(!s.contains("/tmp/"), "Found /tmp/ path leak");
        assert!(!s.contains("https://"), "Found https:// URL leak");
        assert!(!s.contains("http://"), "Found http:// URL leak");
        assert!(!s.contains("github.com"), "Found github.com leak");
        assert!(!s.contains("EKKA_"), "Found EKKA_ env var leak");
    }

    // =========================================================================
    // Module Config Tests
    // =========================================================================

    #[test]
    fn test_module_config_default_disabled() {
        assert!(!AGENT_MODULE_CONFIG.default_enabled);
    }

    #[test]
    fn test_capability_constant() {
        assert_eq!(AGENT_RUN_CAPABILITY, "agent.run");
    }

    #[test]
    fn test_max_constants() {
        assert_eq!(MAX_PROMPT_LEN, 8 * 1024);
        assert_eq!(MAX_INPUTS_SIZE, 32 * 1024);
        assert_eq!(MAX_ARTIFACT_TEXT_LEN, 64 * 1024);
        assert_eq!(MAX_ARTIFACT_JSON_SIZE, 64 * 1024);
    }

    // =========================================================================
    // Request/Response Serialization Tests
    // =========================================================================

    #[test]
    fn test_request_deserialization() {
        let json = r#"{"job_id":"test-123","prompt":"Test prompt"}"#;
        let request: AgentRunRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.job_id, "test-123");
        assert_eq!(request.prompt, "Test prompt");
        assert!(request.inputs.is_none());
    }

    #[test]
    fn test_request_with_inputs() {
        let json = r#"{"job_id":"test-123","prompt":"Test prompt","inputs":{"key":"value"}}"#;
        let request: AgentRunRequest = serde_json::from_str(json).unwrap();
        assert!(request.inputs.is_some());
        let inputs = request.inputs.unwrap();
        assert_eq!(inputs["key"], "value");
    }

    #[test]
    fn test_response_serialization_no_leak() {
        let response = AgentRunResponse {
            job_id: "test-123".to_string(),
            artifact_text: Some("Test output".to_string()),
            artifact_json: Some(serde_json::json!({"key": "value"})),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_error_response_no_leak() {
        let error = AgentError {
            error: "Not permitted".to_string(),
            code: "CAPABILITY_DENIED".to_string(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert_no_leak(&json);
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_no_leaks_accepts_clean() {
        assert!(validate_no_leaks("This is a clean prompt").is_ok());
        assert!(validate_no_leaks("Analyze the data and summarize").is_ok());
    }

    #[test]
    fn test_validate_no_leaks_rejects_paths() {
        assert!(validate_no_leaks("Process /Users/john/data.txt").is_err());
        assert!(validate_no_leaks("Read /home/user/config").is_err());
        assert!(validate_no_leaks("Check C:\\Users\\data").is_err());
    }

    #[test]
    fn test_validate_no_leaks_rejects_urls() {
        assert!(validate_no_leaks("Fetch https://example.com/api").is_err());
        assert!(validate_no_leaks("Clone github.com/owner/repo").is_err());
    }

    #[test]
    fn test_validate_no_leaks_rejects_env_vars() {
        assert!(validate_no_leaks("Set EKKA_SECRET=abc").is_err());
    }

    // =========================================================================
    // Intent Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_intent_from_json_block() {
        let response = r#"
Here's my analysis.

```json
{
  "schema": "v1",
  "job_type": "repo_workflow",
  "commit_message": "Fix authentication bug",
  "pr_title": "Fix login issue"
}
```

That should fix the problem.
"#;
        let intent = extract_intent_from_response(response);
        assert!(intent.is_some());
        let intent = intent.unwrap();
        assert_eq!(intent.schema, "v1");
        assert_eq!(intent.job_type, "repo_workflow");
        assert_eq!(intent.commit_message, "Fix authentication bug");
        assert_eq!(intent.pr_title, "Fix login issue");
    }

    #[test]
    fn test_extract_intent_ignores_invalid_schema() {
        let response = r#"
```json
{
  "schema": "v2",
  "job_type": "repo_workflow",
  "commit_message": "Test",
  "pr_title": "Test"
}
```
"#;
        let intent = extract_intent_from_response(response);
        assert!(intent.is_none());
    }

    #[test]
    fn test_extract_intent_ignores_wrong_job_type() {
        let response = r#"
```json
{
  "schema": "v1",
  "job_type": "other_type",
  "commit_message": "Test",
  "pr_title": "Test"
}
```
"#;
        let intent = extract_intent_from_response(response);
        assert!(intent.is_none());
    }

    #[test]
    fn test_extract_intent_no_json_block() {
        let response = "Just a plain text response without any JSON.";
        let intent = extract_intent_from_response(response);
        assert!(intent.is_none());
    }

    // =========================================================================
    // Intent Validation Tests
    // =========================================================================

    #[test]
    fn test_intent_validate_valid() {
        let intent = RepoWorkflowIntent {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Fix bug".to_string(),
            pr_title: "Bug fix".to_string(),
            pr_base: None,
            notes: None,
        };
        assert!(intent.validate().is_ok());
    }

    #[test]
    fn test_intent_validate_wrong_schema() {
        let intent = RepoWorkflowIntent {
            schema: "v2".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Fix bug".to_string(),
            pr_title: "Bug fix".to_string(),
            pr_base: None,
            notes: None,
        };
        assert!(intent.validate().is_err());
    }

    #[test]
    fn test_intent_validate_empty_commit_message() {
        let intent = RepoWorkflowIntent {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "".to_string(),
            pr_title: "Bug fix".to_string(),
            pr_base: None,
            notes: None,
        };
        assert!(intent.validate().is_err());
    }

    #[test]
    fn test_intent_validate_forbidden_pattern() {
        let intent = RepoWorkflowIntent {
            schema: "v1".to_string(),
            job_type: "repo_workflow".to_string(),
            commit_message: "Fix /Users/john/secret.txt".to_string(),
            pr_title: "Bug fix".to_string(),
            pr_base: None,
            notes: None,
        };
        assert!(intent.validate().is_err());
    }

    // =========================================================================
    // Sanitization Tests
    // =========================================================================

    #[test]
    fn test_sanitize_output_removes_control_chars() {
        let result = sanitize_output("Hello\x00World\x1f", 100);
        assert_eq!(result, "HelloWorld");
    }

    #[test]
    fn test_sanitize_output_preserves_newlines() {
        let result = sanitize_output("Line1\nLine2", 100);
        assert_eq!(result, "Line1\nLine2");
    }

    #[test]
    fn test_sanitize_output_limits_length() {
        let result = sanitize_output(&"x".repeat(200), 100);
        assert_eq!(result.len(), 100);
    }

    #[test]
    fn test_sanitize_output_replaces_paths() {
        let result = sanitize_output("Error at /Users/john/secret.txt here", 1000);
        assert!(!result.contains("/Users/"));
        assert!(result.contains("[path]"));
    }

    // =========================================================================
    // Branch Name Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_branch_names() {
        assert!(is_valid_branch_name("main"));
        assert!(is_valid_branch_name("feature/new-thing"));
        assert!(is_valid_branch_name("fix-bug-123"));
        assert!(is_valid_branch_name("release/v1.0.0"));
    }

    #[test]
    fn test_invalid_branch_names() {
        assert!(!is_valid_branch_name(""));
        assert!(!is_valid_branch_name("/leading-slash"));
        assert!(!is_valid_branch_name("trailing-slash/"));
        assert!(!is_valid_branch_name(".hidden"));
        assert!(!is_valid_branch_name("has..double"));
        assert!(!is_valid_branch_name("has//double"));
    }

    // =========================================================================
    // Response Processing Tests
    // =========================================================================

    #[test]
    fn test_process_llm_response_with_intent() {
        let response = r#"
Here's a fix for the bug.

```json
{
  "schema": "v1",
  "job_type": "repo_workflow",
  "commit_message": "Fix login bug",
  "pr_title": "Fix authentication"
}
```
"#;
        let (text, json) = process_llm_response("job-123", response, "claude-3");
        assert!(text.is_some());
        assert!(json.is_some());
        let json = json.unwrap();
        assert!(json.get("intent").is_some());
        assert_eq!(json["intent"]["commit_message"], "Fix login bug");
    }

    #[test]
    fn test_process_llm_response_without_intent() {
        let response = "Just a regular response without any intent.";
        let (text, json) = process_llm_response("job-123", response, "claude-3");
        assert!(text.is_some());
        assert!(json.is_some());
        let json = json.unwrap();
        assert!(json.get("intent").is_none());
    }

    #[test]
    fn test_process_llm_response_no_leak() {
        let response = "Response with /Users/john/path";
        let (text, json) = process_llm_response("job-123", response, "claude-3");
        assert_no_leak(text.as_ref().unwrap());
        assert_no_leak(&serde_json::to_string(&json).unwrap());
    }

    // =========================================================================
    // Context Tests
    // =========================================================================

    #[test]
    fn test_context_without_provider() {
        let validator: SessionValidator = Arc::new(|_| {
            Err(SessionValidationError {
                error: "Test".to_string(),
                code: "TEST".to_string(),
                status: StatusCode::UNAUTHORIZED,
            })
        });
        let ctx = AgentModuleContext::with_provider(validator, "test", None);
        assert!(!ctx.llm_configured);
        assert!(ctx.llm_provider.is_none());
    }

    #[test]
    fn test_context_with_mock_provider() {
        let validator: SessionValidator = Arc::new(|_| {
            Err(SessionValidationError {
                error: "Test".to_string(),
                code: "TEST".to_string(),
                status: StatusCode::UNAUTHORIZED,
            })
        });
        let provider: Arc<dyn LlmProvider> = Arc::new(MockProvider::with_response("test"));
        let ctx = AgentModuleContext::with_provider(validator, "test", Some(provider));
        assert!(ctx.llm_configured);
        assert!(ctx.llm_provider.is_some());
    }
}
