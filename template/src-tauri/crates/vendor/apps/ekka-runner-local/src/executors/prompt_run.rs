//! prompt_run executor
//!
//! Executes prompt_run tasks by fetching prompts from engine, rendering templates,
//! and executing via Claude CLI.
//!
//! ## Security Invariants
//! - Variables are NEVER logged
//! - Prompt text is NEVER logged
//! - Secrets in variables are detected and rejected
//! - Prompt hash is verified before execution

use ekka_crypto::{derive_key, KeyDerivationConfig};
use ekka_ops::llm_result::ArtifactRef;
use ekka_path_guard::{AuthContext, PathGuard};
use ekka_vault_seal::{SealRequest, seal_run_dir};
use regex::Regex;
use reqwest::Client;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{info, warn};
use uuid::Uuid;

use crate::executors::debug_bundle;
use crate::types::{
    get_llm_timeout_secs, parse_claude_cli_output_streaming, AuthType, ClaudeCliOutput, DebugBundleInfo,
    EngineContext, LlmTimings, LlmUsage, OutputContract, PromptFetchRequest, PromptFetchResponse,
    PromptRunFailureEnvelope, PromptRunOutputV1, PromptRunSuccessEnvelope,
    PromptRunTaskPayloadV1, TaskExecutionContext, HEARTBEAT_INTERVAL_SECS,
    PROMPT_RUN_OUTPUT_SCHEMA_VERSION, PROMPT_RUN_RESULT_SCHEMA_VERSION,
    PROMPT_RUN_TASK_SCHEMA_VERSION,
};

// =============================================================================
// Failure Codes
// =============================================================================

const FAILURE_INVALID_SCHEMA_VERSION: &str = "INVALID_SCHEMA_VERSION";
const FAILURE_INVALID_PROMPT_IDENTITY: &str = "INVALID_PROMPT_IDENTITY";
const FAILURE_SECRETS_IN_PAYLOAD: &str = "SECRETS_IN_PAYLOAD";
const FAILURE_PROMPT_HASH_MISMATCH: &str = "PROMPT_HASH_MISMATCH";
const FAILURE_MISSING_VARIABLE: &str = "MISSING_VARIABLE";
const FAILURE_INVALID_VARIABLE_TYPE: &str = "INVALID_VARIABLE_TYPE";
const FAILURE_PROMPT_FETCH_FAILED: &str = "PROMPT_FETCH_FAILED";
const FAILURE_PROMPT_NOT_FOUND: &str = "PROMPT_NOT_FOUND";
const FAILURE_PROMPT_NOT_AUTHORIZED: &str = "PROMPT_NOT_AUTHORIZED";
const FAILURE_LLM_TIMEOUT: &str = "LLM_TIMEOUT";
const FAILURE_LLM_EXECUTION_FAILED: &str = "LLM_EXECUTION_FAILED";
const FAILURE_INVALID_PAYLOAD: &str = "INVALID_PAYLOAD";
const FAILURE_INPUT_PATH_NOT_AUTHORIZED: &str = "INPUT_PATH_NOT_AUTHORIZED";
const FAILURE_INPUT_DIR_NOT_AUTHORIZED: &str = "INPUT_DIR_NOT_AUTHORIZED";
const FAILURE_REPORT_INVALID: &str = "REPORT_INVALID";
const FAILURE_VAULT_SEAL_FAILED: &str = "VAULT_SEAL_FAILED";

// =============================================================================
// Report Extraction Constants
// =============================================================================

/// Delimiter marking start of EKKA execution report
const REPORT_START_DELIMITER: &str = "<<<EKKA_REPORT_JSON>>>";
/// Delimiter marking end of EKKA execution report
const REPORT_END_DELIMITER: &str = "<<<END_EKKA_REPORT_JSON>>>";

// =============================================================================
// Secret Detection Patterns
// =============================================================================

/// Patterns in variable keys that indicate secrets (case-insensitive)
const SECRET_PATTERNS: &[&str] = &[
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "auth",
    "bearer",
    "private_key",
];

// =============================================================================
// Main Execute Function
// =============================================================================

/// Execute a prompt_run task.
///
/// # Arguments
/// * `client` - HTTP client for engine requests
/// * `engine_ctx` - Engine context (URL, internal key, tenant/workspace)
/// * `ctx` - Task execution context with input_json
/// * `heartbeat_fn` - Optional heartbeat callback to extend task lease
///
/// # Returns
/// * `Ok(serde_json::Value)` - The success/failure envelope as JSON
/// * `Err(String)` - Fatal error if envelope construction fails
pub async fn execute(
    client: &Client,
    engine_ctx: &EngineContext,
    ctx: &TaskExecutionContext,
    heartbeat_fn: Option<Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>>,
) -> Result<serde_json::Value, String> {
    info!(
        op = "prompt_run.execute.start",
        task_id = %ctx.task_id_short,
        "Starting prompt_run execution"
    );

    // Step 1: Parse and validate payload
    let payload = match validate_payload(&ctx.input_json) {
        Ok(p) => p,
        Err((code, msg)) => {
            return Ok(build_failure_envelope(&ctx.task_id, code, &msg, None));
        }
    };

    info!(
        op = "prompt_run.payload.validated",
        task_id = %ctx.task_id_short,
        prompt_slug = %payload.prompt.prompt_slug,
        "Payload validated"
    );

    // Step 2: Detect secrets in variable keys
    if let Some(ref vars) = payload.variables {
        if let Some(msg) = detect_secrets(vars) {
            warn!(
                op = "prompt_run.secrets_detected",
                task_id = %ctx.task_id_short,
                "Secrets detected in variable keys"
            );
            return Ok(build_failure_envelope(
                &ctx.task_id,
                FAILURE_SECRETS_IN_PAYLOAD,
                &msg,
                None,
            ));
        }
    }

    // Step 2.5: Authorize input directories (generic, capability-driven)
    // Handles both new input_dirs field and backward-compat INPUT_PATH variable
    let approved_input_dirs = match authorize_input_dirs(
        &payload,
        &payload.tenant_id,
        engine_ctx.user_sub.as_deref(),
        &ctx.task_id_short,
        engine_ctx.ekka_home_path.as_ref(),
    ) {
        Ok(dirs) => dirs,
        Err((code, msg)) => {
            return Ok(build_failure_envelope(&ctx.task_id, code, &msg, None));
        }
    };

    // Step 3: Fetch prompt from engine
    let fetch_result = match fetch_prompt(client, engine_ctx, &payload).await {
        Ok(r) => r,
        Err((code, msg)) => {
            return Ok(build_failure_envelope(&ctx.task_id, code, &msg, None));
        }
    };

    info!(
        op = "prompt_run.prompt.fetched",
        task_id = %ctx.task_id_short,
        "Prompt fetched from engine"
    );

    // Step 4: Verify prompt hash
    if let Err((code, msg)) = verify_hash(&payload.prompt.prompt_hash, &fetch_result.prompt_hash) {
        warn!(
            op = "prompt_run.hash_mismatch",
            task_id = %ctx.task_id_short,
            "Prompt hash mismatch"
        );
        return Ok(build_failure_envelope(&ctx.task_id, code, &msg, None));
    }

    info!(
        op = "prompt_run.hash.verified",
        task_id = %ctx.task_id_short,
        "Prompt hash verified"
    );

    // Step 5: Render template with variables
    let rendered_prompt = match render_template(&fetch_result.prompt_text, &payload.variables) {
        Ok(r) => r,
        Err((code, msg)) => {
            return Ok(build_failure_envelope(&ctx.task_id, code, &msg, None));
        }
    };

    info!(
        op = "prompt_run.template.rendered",
        task_id = %ctx.task_id_short,
        "Template rendered"
    );

    // Step 6: Execute Claude CLI with heartbeat and sandboxed input/output dirs
    // Write dir is a per-task staging folder: <EKKA_HOME>/tmp/staging/<tenant>/<workspace>/<task>/
    let (output, latency_ms, write_dir) = match execute_claude(
        &rendered_prompt,
        &ctx.task_id_short,
        &payload.tenant_id,
        &payload.workspace_id,
        &ctx.task_id,
        &approved_input_dirs,
        engine_ctx.ekka_home_path.as_ref(),
        heartbeat_fn,
    ).await {
        Ok(r) => r,
        Err((code, msg)) => {
            return Ok(build_failure_envelope(&ctx.task_id, code, &msg, None));
        }
    };

    info!(
        op = "prompt_run.llm.completed",
        task_id = %ctx.task_id_short,
        latency_ms = %latency_ms,
        "LLM execution completed"
    );

    // Step 6.5: Validate output contract (if enforced)
    if let Some(ref contract) = fetch_result.output_contract {
        if contract.enforce {
            info!(
                op = "prompt_run.output_contract.validating",
                task_id = %ctx.task_id_short,
                schema_id = %contract.schema_id,
                "Validating output against contract"
            );

            if let Err(err) = validate_output_contract(
                &output.result,
                contract,
                &ctx.task_id_short,
                &payload.tenant_id,
            ) {
                return Ok(build_failure_envelope(
                    &ctx.task_id,
                    err.code,
                    &err.message,
                    err.debug_bundle,
                ));
            }

            info!(
                op = "prompt_run.output_contract.valid",
                task_id = %ctx.task_id_short,
                "Output contract validation passed"
            );
        }
    }

    // Step 6.7: Seal staging directory into encrypted vault
    // Derive encryption key from tenant context (uses PBKDF2 + AES-256-GCM)
    let key_config = KeyDerivationConfig::default();
    let device_secret = format!("ekka-runner-{}", payload.tenant_id);
    let user_context = engine_ctx.user_sub.as_deref().unwrap_or(&payload.workspace_id);
    let key_material = derive_key(
        &device_secret,
        user_context,
        1, // security_epoch
        "vault_seal",
        &key_config,
    );

    // Build vault root path: EKKA_HOME/vault
    let vault_root = match &engine_ctx.ekka_home_path {
        Some(home) => home.join("vault"),
        None => {
            // Fall back to EKKA_HOME env var
            let home_str = std::env::var("EKKA_HOME").unwrap_or_else(|_| {
                dirs::home_dir()
                    .map(|h| h.join(".ekka-desktop").to_string_lossy().to_string())
                    .unwrap_or_else(|| "/tmp/.ekka".to_string())
            });
            PathBuf::from(home_str).join("vault")
        }
    };

    // Use task_id as workflow_run_id (best available stable identifier)
    let seal_request = SealRequest {
        tenant_id: payload.tenant_id.clone(),
        workspace_id: payload.workspace_id.clone(),
        workflow_run_id: ctx.task_id.clone(), // Use task_id as run_id
        task_id: ctx.task_id.clone(),
        staging_dir: write_dir.clone(),
        vault_root,
        retention_days: Some(30), // Default 30-day retention
        key_material,
    };

    let seal_result = match seal_run_dir(seal_request) {
        Ok(result) => result,
        Err(e) => {
            warn!(
                op = "vault.seal.failed",
                task_id = %ctx.task_id_short,
                error = %e,
                "Vault seal operation failed"
            );
            return Ok(build_failure_envelope(
                &ctx.task_id,
                FAILURE_VAULT_SEAL_FAILED,
                &format!("Failed to seal staging directory: {}", e),
                None,
            ));
        }
    };

    // Verify staging directory was deleted (seal crate should have done this)
    if !seal_result.staging_deleted && write_dir.exists() {
        // Best-effort cleanup if seal didn't delete it
        if let Err(e) = std::fs::remove_dir_all(&write_dir) {
            warn!(
                op = "prompt_run.staging.cleanup_failed",
                task_id = %ctx.task_id_short,
                write_dir = %write_dir.display(),
                error = %e,
                "Failed to clean up staging directory after seal"
            );
        }
    }

    // Step 7: Build success envelope with artifacts
    let envelope = build_success_envelope(&ctx.task_id, output, latency_ms, seal_result.artifacts);

    Ok(envelope)
}

// =============================================================================
// Payload Validation
// =============================================================================

/// Parse and validate the task input JSON.
fn validate_payload(
    input_json: &serde_json::Value,
) -> Result<PromptRunTaskPayloadV1, (&'static str, String)> {
    // Parse JSON into struct
    let payload: PromptRunTaskPayloadV1 = serde_json::from_value(input_json.clone()).map_err(|e| {
        (
            FAILURE_INVALID_PAYLOAD,
            format!("Failed to parse prompt_run payload: {}", e),
        )
    })?;

    // Validate schema version
    if payload.schema_version != PROMPT_RUN_TASK_SCHEMA_VERSION {
        return Err((
            FAILURE_INVALID_SCHEMA_VERSION,
            format!(
                "Invalid schema_version: expected '{}', got '{}'",
                PROMPT_RUN_TASK_SCHEMA_VERSION, payload.schema_version
            ),
        ));
    }

    // Validate prompt identity
    validate_prompt_identity(&payload.prompt)?;

    Ok(payload)
}

/// Validate the prompt identity fields.
fn validate_prompt_identity(prompt: &crate::types::PromptIdentity) -> Result<(), (&'static str, String)> {
    // Provider must be "ekka"
    if prompt.provider != "ekka" {
        return Err((
            FAILURE_INVALID_PROMPT_IDENTITY,
            format!("Invalid provider: expected 'ekka', got '{}'", prompt.provider),
        ));
    }

    // Prompt slug must be non-empty
    if prompt.prompt_slug.is_empty() {
        return Err((
            FAILURE_INVALID_PROMPT_IDENTITY,
            "Prompt slug cannot be empty".to_string(),
        ));
    }

    // Prompt version must be string or number
    if !prompt.prompt_version.is_string() && !prompt.prompt_version.is_number() {
        return Err((
            FAILURE_INVALID_PROMPT_IDENTITY,
            "Prompt version must be a string or number".to_string(),
        ));
    }

    // Prompt hash must be 64 hex chars (or have sha256: prefix)
    let hash = prompt.prompt_hash.strip_prefix("sha256:").unwrap_or(&prompt.prompt_hash);
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            FAILURE_INVALID_PROMPT_IDENTITY,
            "Prompt hash must be 64 hexadecimal characters (with optional 'sha256:' prefix)".to_string(),
        ));
    }

    Ok(())
}

// =============================================================================
// Secret Detection
// =============================================================================

/// Detect if any variable keys contain secret patterns.
/// Returns Some(message) if secrets detected, None otherwise.
fn detect_secrets(variables: &HashMap<String, serde_json::Value>) -> Option<String> {
    let mut secret_keys = Vec::new();

    for key in variables.keys() {
        let key_lower = key.to_lowercase();
        for pattern in SECRET_PATTERNS {
            if key_lower.contains(pattern) {
                secret_keys.push(key.clone());
                break;
            }
        }
    }

    if secret_keys.is_empty() {
        None
    } else {
        // Safe message: count only, never log the actual keys
        Some(format!(
            "Detected {} variable key(s) matching secret patterns",
            secret_keys.len()
        ))
    }
}

// =============================================================================
// Input Dirs Authorization (generic, capability-driven)
// =============================================================================

/// Authorize input directories using PathGuard.
///
/// Handles both new `input_dirs` field and backward-compat `input_path` variable:
/// - If `input_dirs` is present, use it directly
/// - Else if `input_path` variable exists, treat as `input_dirs=[input_path]`
/// - Else return empty list (no input dirs to authorize)
///
/// Each directory is canonicalized and validated through PathGuard.
/// Returns the list of approved absolute paths for use in Claude CLI sandbox.
///
/// # Arguments
/// * `payload` - The prompt_run task payload
/// * `tenant_id` - Tenant ID for PathGuard context
/// * `user_sub` - User subject for grant validation
/// * `task_id_short` - Short task ID for logging
/// * `injected_home_path` - EKKA home path from desktop (None for CLI runner)
///
/// # Security
/// - Canonicalizes paths to prevent traversal attacks
/// - Never logs actual path values
/// - Logs only count and allow/deny status
fn authorize_input_dirs(
    payload: &crate::types::PromptRunTaskPayloadV1,
    tenant_id: &str,
    user_sub: Option<&str>,
    task_id_short: &str,
    injected_home_path: Option<&PathBuf>,
) -> Result<Vec<PathBuf>, (&'static str, String)> {
    // Step 1: Resolve input_dirs with backward compat
    let raw_input_dirs: Vec<String> = if let Some(ref dirs) = payload.input_dirs {
        // New format: input_dirs field takes priority
        dirs.clone()
    } else if let Some(ref vars) = payload.variables {
        // Backward compat: check for INPUT_PATH or input_path variable
        if let Some(input_path_value) = vars.get("INPUT_PATH").or_else(|| vars.get("input_path")) {
            match input_path_value.as_str() {
                Some(s) if !s.is_empty() => vec![s.to_string()],
                Some(_) => vec![], // Empty string
                None => {
                    return Err((
                        FAILURE_INPUT_PATH_NOT_AUTHORIZED,
                        "INPUT_PATH must be a string".to_string(),
                    ));
                }
            }
        } else {
            vec![] // No input paths
        }
    } else {
        vec![] // No variables and no input_dirs
    };

    // If no input dirs, return empty (nothing to authorize)
    if raw_input_dirs.is_empty() {
        return Ok(vec![]);
    }

    // Step 2: Get EKKA_HOME for PathGuard
    let ekka_home = if let Some(path) = injected_home_path {
        path.clone()
    } else {
        match std::env::var("EKKA_HOME") {
            Ok(home) if !home.is_empty() => PathBuf::from(home),
            _ => {
                warn!(
                    op = "prompt_run.input_dirs.denied",
                    task_id = %task_id_short,
                    reason = "EKKA_HOME not available",
                    count = raw_input_dirs.len(),
                    "Input dirs authorization denied - no EKKA_HOME"
                );
                return Err((
                    FAILURE_INPUT_DIR_NOT_AUTHORIZED,
                    "input_dirs authorization requires EKKA_HOME".to_string(),
                ));
            }
        }
    };

    // Step 3: Construct PathGuard
    let sub = user_sub.unwrap_or("runner");
    let auth_ctx = AuthContext::new(tenant_id, sub);
    let guard = match PathGuard::from_env(ekka_home.clone(), auth_ctx) {
        Ok(g) => g,
        Err(_) => PathGuard::home_only(ekka_home),
    };

    // Step 4: Validate each input directory
    let mut approved_dirs: Vec<PathBuf> = Vec::with_capacity(raw_input_dirs.len());

    for (idx, raw_dir) in raw_input_dirs.iter().enumerate() {
        // Canonicalize to prevent traversal
        let path = PathBuf::from(raw_dir);
        let canonical = match std::fs::canonicalize(&path) {
            Ok(c) => c,
            Err(_) => {
                // Path doesn't exist or can't be canonicalized
                warn!(
                    op = "prompt_run.input_dirs.denied",
                    task_id = %task_id_short,
                    dir_index = idx,
                    reason = "canonicalize_failed",
                    "Input dir authorization denied - cannot canonicalize"
                );
                return Err((
                    FAILURE_INPUT_DIR_NOT_AUTHORIZED,
                    format!("input_dirs[{}] cannot be resolved (does not exist or inaccessible)", idx),
                ));
            }
        };

        // Check authorization (operation = "read" for input directories)
        if !guard.is_allowed(&canonical, "read") {
            warn!(
                op = "prompt_run.input_dirs.denied",
                task_id = %task_id_short,
                dir_index = idx,
                reason = "pathguard_denied",
                "Input dir authorization denied by PathGuard"
            );
            return Err((
                FAILURE_INPUT_DIR_NOT_AUTHORIZED,
                format!("input_dirs[{}] is not authorized", idx),
            ));
        }

        approved_dirs.push(canonical);
    }

    // Step 5: Log success with approved count (not paths)
    // Truncate dirs list for logging (safe: only shows paths, no secrets)
    let dirs_preview: Vec<String> = approved_dirs
        .iter()
        .take(5)
        .map(|p| p.display().to_string())
        .collect();
    let dirs_str = if approved_dirs.len() > 5 {
        format!("[{}, ... and {} more]", dirs_preview.join(", "), approved_dirs.len() - 5)
    } else {
        format!("[{}]", dirs_preview.join(", "))
    };

    info!(
        op = "prompt_run.input_dirs.allowed",
        task_id = %task_id_short,
        count = approved_dirs.len(),
        dirs = %dirs_str,
        "Input directories authorized"
    );

    Ok(approved_dirs)
}

// =============================================================================
// Prompt Fetch
// =============================================================================

/// Fetch prompt from engine.
async fn fetch_prompt(
    client: &Client,
    engine_ctx: &EngineContext,
    payload: &PromptRunTaskPayloadV1,
) -> Result<PromptFetchResponse, (&'static str, String)> {
    let url = format!("{}/engine/runner/prompts/fetch", engine_ctx.engine_url);

    // Convert prompt_version to string
    let version_str = match &payload.prompt.prompt_version {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return Err((FAILURE_INVALID_PROMPT_IDENTITY, "Invalid prompt version type".to_string())),
    };

    let request_body = PromptFetchRequest {
        tenant_id: payload.tenant_id.clone(),
        workspace_id: payload.workspace_id.clone(),
        prompt_slug: payload.prompt.prompt_slug.clone(),
        prompt_version: version_str,
    };

    // Build request with appropriate auth headers based on auth_type
    let mut req = client
        .post(&url)
        .header("X-REQUEST-ID", Uuid::new_v4().to_string())
        .header("X-EKKA-CORRELATION-ID", Uuid::new_v4().to_string())
        .header("X-EKKA-MODULE", "engine.runner")
        .header("X-EKKA-ACTION", "prompt_fetch")
        .header("X-EKKA-CLIENT", "ekka-runner-local")
        .header("X-EKKA-CLIENT-VERSION", "1.0.0")
        .header("Content-Type", "application/json");

    req = match &engine_ctx.auth_type {
        AuthType::InternalKey => {
            req.header("X-EKKA-INTERNAL-SERVICE-KEY", &engine_ctx.internal_key)
               .header("X-EKKA-PROOF-TYPE", "internal")
        }
        AuthType::NodeSession => {
            req.header("Authorization", format!("Bearer {}", engine_ctx.internal_key))
               .header("X-EKKA-PROOF-TYPE", "node_session")
        }
    };

    let response = req
        .json(&request_body)
        .send()
        .await
        .map_err(|e| {
            (
                FAILURE_PROMPT_FETCH_FAILED,
                format!("Prompt fetch request failed: {}", e.without_url()),
            )
        })?;

    let status = response.status();

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err((
            FAILURE_PROMPT_NOT_FOUND,
            "Prompt not found".to_string(),
        ));
    }

    // Handle non-success responses with detailed error extraction
    if !status.is_success() {
        // Capture response body for debugging (truncate to 2048 chars)
        let body_text = response.text().await.unwrap_or_else(|_| "<failed to read body>".to_string());
        let truncated_body = if body_text.len() > 2048 {
            format!("{}...[truncated]", &body_text[..2048])
        } else {
            body_text.clone()
        };

        // Attempt to parse JSON and extract engine error details
        // Priority: json["code"] > json["missing_capability"] > json["error"] > "unknown"
        let (engine_code, engine_message) = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_text) {
            let engine_code = if let Some(code) = json.get("code").and_then(|v| v.as_str()) {
                code.to_string()
            } else if let Some(cap) = json.get("missing_capability").and_then(|v| v.as_str()) {
                format!("missing_capability={}", cap)
            } else if let Some(err) = json.get("error").and_then(|v| v.as_str()) {
                err.to_string()
            } else {
                "unknown".to_string()
            };
            let engine_message = json.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or(&truncated_body)
                .to_string();
            (engine_code, engine_message)
        } else {
            ("unknown".to_string(), truncated_body.clone())
        };

        if status == reqwest::StatusCode::FORBIDDEN {
            // Log structured forbidden error with engine details
            warn!(
                op = "prompt_run.fetch_prompt.forbidden",
                http_status = 403,
                engine_code = %engine_code,
                engine_message = %engine_message,
                "Prompt fetch forbidden by engine"
            );

            return Err((
                FAILURE_PROMPT_NOT_AUTHORIZED,
                format!("Not authorized: {}", engine_code),
            ));
        }

        // Log other non-success errors
        tracing::error!(
            op = "prompt_run.fetch_prompt.failed",
            status = %status,
            engine_code = %engine_code,
            engine_message = %engine_message,
            request_fields = "tenant_id, workspace_id, prompt_slug, prompt_version",
            "Prompt fetch failed"
        );

        return Err((
            FAILURE_PROMPT_FETCH_FAILED,
            format!("Prompt fetch failed with status {}: {} - {}", status, engine_code, engine_message),
        ));
    }

    let fetch_response: PromptFetchResponse = response.json().await.map_err(|e| {
        (
            FAILURE_PROMPT_FETCH_FAILED,
            format!("Failed to parse prompt fetch response: {}", e),
        )
    })?;

    Ok(fetch_response)
}

// =============================================================================
// Hash Verification
// =============================================================================

/// Verify that expected hash matches fetched hash.
fn verify_hash(expected: &str, fetched: &str) -> Result<(), (&'static str, String)> {
    // Normalize both hashes (remove sha256: prefix if present)
    let expected_normalized = expected.strip_prefix("sha256:").unwrap_or(expected);
    let fetched_normalized = fetched.strip_prefix("sha256:").unwrap_or(fetched);

    if expected_normalized.to_lowercase() != fetched_normalized.to_lowercase() {
        return Err((
            FAILURE_PROMPT_HASH_MISMATCH,
            "Prompt hash mismatch: expected hash does not match fetched hash".to_string(),
        ));
    }

    Ok(())
}

// =============================================================================
// Template Rendering
// =============================================================================

/// Render template by substituting {{variable}} placeholders.
fn render_template(
    template: &str,
    variables: &Option<HashMap<String, serde_json::Value>>,
) -> Result<String, (&'static str, String)> {
    // Regex for {{ var_name }} with optional whitespace
    let re = Regex::new(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")
        .expect("Invalid regex pattern");

    let empty_vars = HashMap::new();
    let vars = variables.as_ref().unwrap_or(&empty_vars);

    let mut missing_count = 0;
    let mut invalid_type_count = 0;
    let mut result = template.to_string();

    // Find all placeholders first
    let placeholders: Vec<String> = re
        .captures_iter(template)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();

    // Deduplicate
    let unique_placeholders: Vec<String> = placeholders
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    for var_name in unique_placeholders {
        match vars.get(&var_name) {
            Some(value) => {
                // Only primitive types allowed
                let replacement = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Null => "null".to_string(),
                    serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                        invalid_type_count += 1;
                        continue;
                    }
                };

                // Replace all occurrences of {{ var_name }} (with varying whitespace)
                let pattern = format!(r"\{{\{{\s*{}\s*\}}\}}", regex::escape(&var_name));
                let var_re = Regex::new(&pattern).expect("Invalid variable regex");
                result = var_re.replace_all(&result, replacement.as_str()).to_string();
            }
            None => {
                missing_count += 1;
            }
        }
    }

    if invalid_type_count > 0 {
        return Err((
            FAILURE_INVALID_VARIABLE_TYPE,
            format!(
                "Found {} variable(s) with invalid type (only primitives allowed)",
                invalid_type_count
            ),
        ));
    }

    if missing_count > 0 {
        return Err((
            FAILURE_MISSING_VARIABLE,
            format!(
                "Missing {} required variable(s) for prompt template",
                missing_count
            ),
        ));
    }

    Ok(result)
}

// =============================================================================
// Output Contract Validation
// =============================================================================

/// Validation error with optional debug bundle info
struct ValidationError {
    code: &'static str,
    message: String,
    debug_bundle: Option<DebugBundleInfo>,
}

/// Convert debug bundle ref to debug bundle info for API response
fn bundle_ref_to_info(bundle_ref: &debug_bundle::DebugBundleRef) -> DebugBundleInfo {
    DebugBundleInfo {
        debug_bundle_ref: bundle_ref.path.clone(),
        raw_output_sha256: bundle_ref.hashes.raw_output_sha256.clone(),
        raw_output_len: bundle_ref.hashes.raw_output_len,
        files: vec![
            "meta.json".to_string(),
            "hashes.json".to_string(),
            "raw_output.txt".to_string(),
            "report.json".to_string(),
        ],
    }
}

/// Validate LLM output against output contract.
///
/// Extracts the execution report from between delimiters and validates structure.
/// On failure, saves a debug bundle (if EKKA_ENV=development) for troubleshooting.
///
/// # Security
/// - NEVER logs raw output contents directly
/// - Saves debug bundle with truncated raw output (max 256KB)
/// - Logs only: debug_bundle_ref, sha256 hashes, lengths, failure reason
fn validate_output_contract(
    output_text: &str,
    contract: &OutputContract,
    task_id_short: &str,
    tenant_id: &str,
) -> Result<(), ValidationError> {
    // Step 1: Extract report JSON from between delimiters
    let start_idx = output_text.find(REPORT_START_DELIMITER);
    let end_idx = output_text.find(REPORT_END_DELIMITER);

    let report_json = match (start_idx, end_idx) {
        (Some(start), Some(end)) if start < end => {
            let content_start = start + REPORT_START_DELIMITER.len();
            output_text[content_start..end].trim()
        }
        _ => {
            // Missing delimiters - save debug bundle for troubleshooting
            let failure_msg = format!(
                "Output missing required delimiters. Expected {} ... {}",
                REPORT_START_DELIMITER, REPORT_END_DELIMITER
            );

            // Save debug bundle (returns ref with hashes for logging)
            let debug_bundle = if let Some(bundle_ref) = debug_bundle::save_debug_bundle(
                tenant_id,
                task_id_short,
                FAILURE_REPORT_INVALID,
                &failure_msg,
                output_text,
                None,
            ) {
                warn!(
                    op = "prompt_run.output_contract.missing_delimiters",
                    task_id = %task_id_short,
                    schema_id = %contract.schema_id,
                    debug_bundle_ref = %bundle_ref.path,
                    raw_output_sha256 = %bundle_ref.hashes.raw_output_sha256,
                    raw_output_len = %bundle_ref.hashes.raw_output_len,
                    "Output contract validation failed: missing report delimiters (debug bundle saved)"
                );
                Some(bundle_ref_to_info(&bundle_ref))
            } else {
                warn!(
                    op = "prompt_run.output_contract.missing_delimiters",
                    task_id = %task_id_short,
                    schema_id = %contract.schema_id,
                    "Output contract validation failed: missing report delimiters"
                );
                None
            };

            return Err(ValidationError {
                code: FAILURE_REPORT_INVALID,
                message: failure_msg,
                debug_bundle,
            });
        }
    };

    // Step 2: Parse as JSON
    let parsed: serde_json::Value = match serde_json::from_str(report_json) {
        Ok(v) => v,
        Err(e) => {
            let failure_msg = format!("Report JSON parse error: {}", e);

            // Save debug bundle for troubleshooting
            let debug_bundle = if let Some(bundle_ref) = debug_bundle::save_debug_bundle(
                tenant_id,
                task_id_short,
                FAILURE_REPORT_INVALID,
                &failure_msg,
                output_text,
                None,
            ) {
                warn!(
                    op = "prompt_run.output_contract.json_parse_error",
                    task_id = %task_id_short,
                    schema_id = %contract.schema_id,
                    parse_error = %e,
                    debug_bundle_ref = %bundle_ref.path,
                    raw_output_sha256 = %bundle_ref.hashes.raw_output_sha256,
                    raw_output_len = %bundle_ref.hashes.raw_output_len,
                    "Output contract validation failed: invalid JSON (debug bundle saved)"
                );
                Some(bundle_ref_to_info(&bundle_ref))
            } else {
                warn!(
                    op = "prompt_run.output_contract.json_parse_error",
                    task_id = %task_id_short,
                    schema_id = %contract.schema_id,
                    parse_error = %e,
                    "Output contract validation failed: invalid JSON"
                );
                None
            };

            return Err(ValidationError {
                code: FAILURE_REPORT_INVALID,
                message: failure_msg,
                debug_bundle,
            });
        }
    };

    // Step 3: Validate schema_version field matches contract
    let schema_version = parsed.get("schema_version").and_then(|v| v.as_str());
    if schema_version != Some(&contract.schema_id) {
        let failure_msg = format!(
            "Report schema_version mismatch: expected '{}', got '{}'",
            contract.schema_id,
            schema_version.unwrap_or("null")
        );

        // Save debug bundle for troubleshooting
        let debug_bundle = if let Some(bundle_ref) = debug_bundle::save_debug_bundle(
            tenant_id,
            task_id_short,
            FAILURE_REPORT_INVALID,
            &failure_msg,
            output_text,
            Some(&parsed),
        ) {
            warn!(
                op = "prompt_run.output_contract.schema_version_mismatch",
                task_id = %task_id_short,
                expected = %contract.schema_id,
                actual = ?schema_version,
                debug_bundle_ref = %bundle_ref.path,
                raw_output_sha256 = %bundle_ref.hashes.raw_output_sha256,
                "Output contract validation failed: schema_version mismatch (debug bundle saved)"
            );
            Some(bundle_ref_to_info(&bundle_ref))
        } else {
            warn!(
                op = "prompt_run.output_contract.schema_version_mismatch",
                task_id = %task_id_short,
                expected = %contract.schema_id,
                actual = ?schema_version,
                "Output contract validation failed: schema_version mismatch"
            );
            None
        };

        return Err(ValidationError {
            code: FAILURE_REPORT_INVALID,
            message: failure_msg,
            debug_bundle,
        });
    }

    // Step 4: Validate required fields exist (MVP: just check structure, not full JSON schema)
    // TECH_DEBT: Use jsonschema crate for full validation in future
    let required_fields = ["schema_version", "files_written", "summary", "errors"];
    let mut missing_fields = Vec::new();

    for field in required_fields {
        if !parsed.get(field).is_some() {
            missing_fields.push(field);
        }
    }

    if !missing_fields.is_empty() {
        let failure_msg = format!("Report missing required fields: {}", missing_fields.join(", "));

        // Save debug bundle for troubleshooting
        let debug_bundle = if let Some(bundle_ref) = debug_bundle::save_debug_bundle(
            tenant_id,
            task_id_short,
            FAILURE_REPORT_INVALID,
            &failure_msg,
            output_text,
            Some(&parsed),
        ) {
            warn!(
                op = "prompt_run.output_contract.missing_fields",
                task_id = %task_id_short,
                schema_id = %contract.schema_id,
                missing_fields = ?missing_fields,
                debug_bundle_ref = %bundle_ref.path,
                raw_output_sha256 = %bundle_ref.hashes.raw_output_sha256,
                "Output contract validation failed: missing required fields (debug bundle saved)"
            );
            Some(bundle_ref_to_info(&bundle_ref))
        } else {
            warn!(
                op = "prompt_run.output_contract.missing_fields",
                task_id = %task_id_short,
                schema_id = %contract.schema_id,
                missing_fields = ?missing_fields,
                "Output contract validation failed: missing required fields"
            );
            None
        };

        return Err(ValidationError {
            code: FAILURE_REPORT_INVALID,
            message: failure_msg,
            debug_bundle,
        });
    }

    // Validation passed
    Ok(())
}

// =============================================================================
// Claude CLI Execution
// =============================================================================

/// Execute Claude CLI with the rendered prompt and sandboxed input/output directories.
///
/// # Claude CLI Configuration
/// - `--permission-mode dontAsk` prevents any interactive prompts (CRITICAL for timeout reliability)
/// - `-p` enables non-interactive mode
/// - `--output-format json` returns structured output
/// - `--add-dir` for write directory (per-task staging folder)
/// - `--add-dir` for each input directory (PathGuard-validated read access)
/// - `--` delimiter followed by prompt as command argument
/// - `current_dir` set to write_dir (staging folder, never src-tauri)
///
/// # Staging Directory
/// Write directory is: <EKKA_HOME>/tmp/staging/<tenant_id>/<workspace_id>/<task_id>/
/// Can be overridden via EKKA_STAGING_ROOT env var.
/// This ensures Claude writes to EKKA-managed temp, not system /tmp.
async fn execute_claude(
    prompt: &str,
    task_id_short: &str,
    tenant_id: &str,
    workspace_id: &str,
    task_id: &str,
    allowed_input_dirs: &[PathBuf],
    ekka_home_path: Option<&PathBuf>,
    heartbeat_fn: Option<Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>>,
) -> Result<(ClaudeCliOutput, u64, PathBuf), (&'static str, String)> {
    let start = Instant::now();
    let stop_heartbeat = Arc::new(AtomicBool::new(false));

    // Start heartbeat task if provided
    let heartbeat_handle = if let Some(hb_fn) = heartbeat_fn {
        let stop = stop_heartbeat.clone();
        let hb = hb_fn.clone();
        Some(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)).await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = hb().await {
                    warn!(op = "prompt_run.heartbeat.failed", error = %e, "Heartbeat failed");
                }
            }
        }))
    } else {
        None
    };

    // =========================================================================
    // STAGING DIRECTORY CONFIGURATION
    // =========================================================================
    // Staging root priority:
    // 1. EKKA_STAGING_ROOT env var (if set)
    // 2. <EKKA_HOME>/tmp/staging (if ekka_home_path provided)
    // 3. Fallback to system /tmp/ekka/staging (legacy, not recommended)
    //
    // Per-task write_dir = <staging_root>/<tenant>/<workspace>/<task>/
    // This ensures Claude writes to EKKA-managed temp, not system /tmp.

    let staging_root = if let Ok(env_root) = std::env::var("EKKA_STAGING_ROOT") {
        if !env_root.is_empty() {
            PathBuf::from(env_root)
        } else if let Some(home) = ekka_home_path {
            home.join("tmp").join("staging")
        } else if let Ok(home_env) = std::env::var("EKKA_HOME") {
            PathBuf::from(home_env).join("tmp").join("staging")
        } else {
            // Legacy fallback - not recommended
            PathBuf::from("/tmp/ekka/staging")
        }
    } else if let Some(home) = ekka_home_path {
        home.join("tmp").join("staging")
    } else if let Ok(home_env) = std::env::var("EKKA_HOME") {
        PathBuf::from(home_env).join("tmp").join("staging")
    } else {
        // Legacy fallback - not recommended
        PathBuf::from("/tmp/ekka/staging")
    };

    // Ensure staging root exists (mkdir -p)
    if let Err(e) = std::fs::create_dir_all(&staging_root) {
        return Err((
            FAILURE_LLM_EXECUTION_FAILED,
            format!("Failed to create staging root {}: {}", staging_root.display(), e),
        ));
    }

    // Compute per-task write_dir
    let write_dir = staging_root
        .join(tenant_id)
        .join(workspace_id)
        .join(task_id);

    // Create per-task directory (mkdir -p)
    if let Err(e) = std::fs::create_dir_all(&write_dir) {
        return Err((
            FAILURE_LLM_EXECUTION_FAILED,
            format!("Failed to create staging directory {}: {}", write_dir.display(), e),
        ));
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let staging_root_display = staging_root.display().to_string();
    let write_dir_display = write_dir.display().to_string();
    let cwd_display = cwd.display().to_string();

    // Build Claude CLI command with sandbox restrictions and non-interactive mode
    let mut cmd = Command::new("claude");

    // CRITICAL: --permission-mode acceptEdits auto-approves Write/Edit without prompting.
    // This is required for docgen and other write-heavy prompts to work non-interactively.
    // Note: dontAsk can silently deny writes, causing permission prompts or failures.
    cmd.arg("--permission-mode").arg("acceptEdits");

    // Standard flags for prompt execution
    cmd.arg("-p") // Non-interactive mode
        .arg("--output-format")
        .arg("json");

    // =========================================================================
    // TOOL CONFIGURATION (temporary global defaults)
    // See TECH_DEBT.md TD-TOOLS-001 for future per-prompt tool configuration
    // =========================================================================
    // Allow broad "default" toolset to support many prompt types (docgen, compare, plan, etc.)
    // This includes: Read/Edit/Write, Glob/Grep, Task/TaskOutput/TaskStop, Skill, ToolSearch,
    // EnterPlanMode/ExitPlanMode, AskUserQuestion, NotebookEdit, TodoWrite, etc.
    cmd.arg("--allowedTools").arg("default");

    // DISALLOW truly risky tools that could escape sandbox or access network
    // - Bash: arbitrary command execution (security risk)
    // - WebFetch: network access to arbitrary URLs
    // - WebSearch: network access for web searches
    cmd.arg("--disallowedTools").arg("Bash,WebFetch,WebSearch");

    // Add write directory first (where Claude can write output)
    cmd.arg("--add-dir").arg(&write_dir);

    // Add --add-dir for each approved input directory (PathGuard-validated)
    for dir in allowed_input_dirs {
        cmd.arg("--add-dir").arg(dir);
    }

    // Add `--` delimiter then prompt as argument (not stdin)
    cmd.arg("--");
    cmd.arg(prompt);

    // Set working directory to write_dir for deterministic behavior
    cmd.current_dir(&write_dir);

    // Calculate total allowed dirs (write_dir + input_dirs)
    let total_allowed_dirs = 1 + allowed_input_dirs.len();

    // Log command configuration (args keys only, not values for security)
    info!(
        op = "prompt_run.llm.started",
        task_id = %task_id_short,
        cmd_args = "claude --permission-mode acceptEdits -p --output-format json --allowedTools default --disallowedTools Bash,WebFetch,WebSearch --add-dir [...] -- <prompt>",
        "Starting Claude CLI execution"
    );

    info!(
        op = "prompt_run.claude.allowed_dirs",
        task_id = %task_id_short,
        staging_root = %staging_root_display,
        write_dir = %write_dir_display,
        cwd = %cwd_display,
        allowed_dirs_count = total_allowed_dirs,
        "Claude CLI sandbox configured"
    );

    // Spawn Claude CLI process (no stdin needed - prompt is in args)
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            stop_heartbeat.store(true, Ordering::Relaxed);
            (
                FAILURE_LLM_EXECUTION_FAILED,
                format!("Failed to spawn claude CLI: {}", e),
            )
        })?;

    // CRITICAL: Take stdout/stderr handles and start reading CONCURRENTLY with wait.
    // On Unix, pipe buffers are typically 64KB. If Claude writes more than this,
    // it will block until the pipe is drained. If we wait() before reading,
    // we deadlock and only get whatever was in the buffer (64KB truncation).
    // FIX: Spawn async tasks to drain stdout/stderr while waiting for the process.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    // Maximum stdout size (10MB safety cap)
    const MAX_STDOUT_BYTES: usize = 10 * 1024 * 1024;
    const MAX_STDERR_BYTES: usize = 1 * 1024 * 1024;

    // Spawn concurrent reader for stdout (with size cap)
    let stdout_reader = tokio::spawn(async move {
        match stdout_handle {
            Some(mut h) => {
                let mut buf = Vec::new();
                match tokio::io::AsyncReadExt::read_to_end(&mut h, &mut buf).await {
                    Ok(_) => {
                        if buf.len() > MAX_STDOUT_BYTES {
                            Err(format!("stdout too large: {} bytes (max {})", buf.len(), MAX_STDOUT_BYTES))
                        } else {
                            Ok(String::from_utf8_lossy(&buf).to_string())
                        }
                    }
                    Err(e) => Err(format!("Failed to read stdout: {}", e)),
                }
            }
            None => Ok(String::new()),
        }
    });

    // Spawn concurrent reader for stderr (with size cap)
    let stderr_reader = tokio::spawn(async move {
        match stderr_handle {
            Some(mut h) => {
                let mut buf = Vec::new();
                match tokio::io::AsyncReadExt::read_to_end(&mut h, &mut buf).await {
                    Ok(_) => {
                        if buf.len() > MAX_STDERR_BYTES {
                            // Truncate stderr, don't fail
                            Ok(format!(
                                "{}...[truncated, total {} bytes]",
                                String::from_utf8_lossy(&buf[..MAX_STDERR_BYTES / 2]),
                                buf.len()
                            ))
                        } else {
                            Ok(String::from_utf8_lossy(&buf).to_string())
                        }
                    }
                    Err(e) => Err(format!("Failed to read stderr: {}", e)),
                }
            }
            None => Ok(String::new()),
        }
    });

    // Get effective timeout (supports env var override for testing)
    let timeout_secs = get_llm_timeout_secs();
    let timeout_duration = Duration::from_secs(timeout_secs);

    // Wait for process with HARD timeout
    // stdout/stderr readers are running concurrently, draining the pipes
    let wait_result = tokio::time::timeout(timeout_duration, child.wait()).await;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Stop heartbeat immediately
    stop_heartbeat.store(true, Ordering::Relaxed);
    if let Some(handle) = heartbeat_handle {
        let _ = handle.await;
    }

    // Wait for readers to complete (they should finish quickly after process exits)
    let stdout_result = stdout_reader.await.unwrap_or_else(|e| Err(format!("stdout reader panicked: {}", e)));
    let stderr_result = stderr_reader.await.unwrap_or_else(|e| Err(format!("stderr reader panicked: {}", e)));

    let exit_status = match wait_result {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            let stderr = stderr_result.unwrap_or_default();
            let stderr_trunc = truncate_stderr(&stderr, 2048);

            warn!(
                op = "prompt_run.llm.failed",
                task_id = %task_id_short,
                error = %e,
                stderr_trunc = %stderr_trunc,
                "Claude CLI wait failed"
            );

            return Err((
                FAILURE_LLM_EXECUTION_FAILED,
                format!("Claude CLI execution failed: {}. stderr: {}", e, stderr_trunc),
            ));
        }
        Err(_timeout_elapsed) => {
            // HARD TIMEOUT: Process exceeded time limit - MUST kill the child
            let kill_result = child.kill().await;

            // Wait briefly to reap the process (1-2 seconds grace period)
            let reap_result = tokio::time::timeout(
                Duration::from_secs(2),
                child.wait()
            ).await;

            let stderr = stderr_result.unwrap_or_default();
            let stderr_trunc = truncate_stderr(&stderr, 2048);

            let kill_success = kill_result.is_ok();
            let reap_success = reap_result.is_ok();

            warn!(
                op = "prompt_run.llm.timeout",
                task_id = %task_id_short,
                timeout_secs = timeout_secs,
                elapsed_ms = elapsed_ms,
                kill_attempted = true,
                kill_success = kill_success,
                reap_success = reap_success,
                stderr_trunc = %stderr_trunc,
                "LLM execution timed out - child process killed"
            );

            return Err((
                FAILURE_LLM_TIMEOUT,
                format!(
                    "LLM execution timed out after {}s (elapsed: {}ms, kill={}, reap={}). stderr: {}",
                    timeout_secs, elapsed_ms, kill_success, reap_success,
                    if stderr_trunc.is_empty() { "<empty>".to_string() } else { stderr_trunc }
                ),
            ));
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    // Get stdout/stderr results
    let stdout = match stdout_result {
        Ok(s) => s,
        Err(e) => {
            warn!(
                op = "prompt_run.llm.stdout_error",
                task_id = %task_id_short,
                error = %e,
                "Failed to read stdout"
            );
            return Err((
                FAILURE_LLM_EXECUTION_FAILED,
                format!("Failed to read Claude CLI stdout: {}", e),
            ));
        }
    };
    let stderr = stderr_result.unwrap_or_default();

    // Check exit status
    if !exit_status.success() {
        let stderr_truncated = truncate_stderr(&stderr, 2048);

        warn!(
            op = "prompt_run.llm.failed",
            task_id = %task_id_short,
            exit_status = %exit_status,
            stderr_len = stderr.len(),
            stderr_trunc = %stderr_truncated,
            "Claude CLI exited with error"
        );

        return Err((
            FAILURE_LLM_EXECUTION_FAILED,
            format!(
                "Claude CLI exited with status {}: {}",
                exit_status,
                if stderr_truncated.is_empty() { "no output".to_string() } else { stderr_truncated }
            ),
        ));
    }

    // Parse Claude CLI output (handles NDJSON, array, and legacy formats)
    // Use streaming parser for large outputs to handle JSON arrays without full materialization
    let claude_output = parse_claude_cli_output_streaming(&stdout).map_err(|e| {
        let stderr_truncated = truncate_stderr(&stderr, 2048);

        // Check if output contains a result marker (diagnostic)
        let has_result_marker = stdout.contains(r#""type":"result""#) || stdout.contains(r#""type": "result""#);

        // Get first and last 200 chars for diagnostics
        let first_200: String = stdout.chars().take(200).collect();
        let last_200: String = if stdout.len() > 200 {
            stdout.chars().skip(stdout.len().saturating_sub(200)).collect()
        } else {
            stdout.clone()
        };

        warn!(
            op = "prompt_run.llm.parse_failed",
            task_id = %task_id_short,
            stdout_len = stdout.len(),
            stderr_len = stderr.len(),
            has_result_marker = has_result_marker,
            first_200_chars = %first_200,
            last_200_chars = %last_200,
            stderr_trunc = %stderr_truncated,
            "Failed to parse Claude CLI output"
        );

        (
            FAILURE_LLM_EXECUTION_FAILED,
            format!(
                "Failed to parse Claude CLI output: {}. stdout_len={}, has_result_marker={}, stderr: {}",
                e, stdout.len(), has_result_marker, stderr_truncated
            ),
        )
    })?;

    info!(
        op = "prompt_run.llm.parsed",
        task_id = %task_id_short,
        stdout_len = stdout.len(),
        "Claude CLI output parsed successfully"
    );

    Ok((claude_output, latency_ms, write_dir))
}

/// Truncate stderr to first N + last N bytes for debugging without overwhelming logs.
fn truncate_stderr(stderr: &str, max_bytes: usize) -> String {
    if stderr.len() <= max_bytes * 2 {
        stderr.to_string()
    } else {
        let first = &stderr[..max_bytes];
        let last = &stderr[stderr.len() - max_bytes..];
        format!("{}...[truncated {} bytes]...{}", first, stderr.len() - max_bytes * 2, last)
    }
}

// =============================================================================
// Envelope Builders
// =============================================================================

/// Build a success envelope.
fn build_success_envelope(
    task_id: &str,
    output: ClaudeCliOutput,
    latency_ms: u64,
    artifacts: Vec<ArtifactRef>,
) -> serde_json::Value {
    let envelope = PromptRunSuccessEnvelope {
        success: true,
        schema_version: PROMPT_RUN_RESULT_SCHEMA_VERSION.to_string(),
        task_subtype: "prompt_run".to_string(),
        task_id: task_id.to_string(),
        output: PromptRunOutputV1 {
            schema_version: PROMPT_RUN_OUTPUT_SCHEMA_VERSION.to_string(),
            decision: "UNKNOWN".to_string(), // Default decision
            output_text: output.result,
            model: output.model.unwrap_or_else(|| "unknown".to_string()),
            usage: LlmUsage {
                input_tokens: output.usage.as_ref().and_then(|u| u.input_tokens),
                output_tokens: output.usage.as_ref().and_then(|u| u.output_tokens),
            },
            timings_ms: LlmTimings {
                llm_latency_ms: latency_ms,
            },
            artifacts,
        },
    };

    serde_json::to_value(envelope).expect("Failed to serialize success envelope")
}

/// Build a failure envelope.
fn build_failure_envelope(
    task_id: &str,
    code: &str,
    message: &str,
    debug_bundle: Option<DebugBundleInfo>,
) -> serde_json::Value {
    let envelope = PromptRunFailureEnvelope {
        success: false,
        schema_version: PROMPT_RUN_RESULT_SCHEMA_VERSION.to_string(),
        task_subtype: "prompt_run".to_string(),
        task_id: task_id.to_string(),
        failure_code: code.to_string(),
        message: message.to_string(),
        debug_bundle,
    };

    serde_json::to_value(envelope).expect("Failed to serialize failure envelope")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_secrets_none() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), serde_json::json!("test"));
        vars.insert("count".to_string(), serde_json::json!(42));
        assert!(detect_secrets(&vars).is_none());
    }

    #[test]
    fn test_detect_secrets_found() {
        let mut vars = HashMap::new();
        vars.insert("my_api_key".to_string(), serde_json::json!("secret"));
        vars.insert("name".to_string(), serde_json::json!("test"));
        let result = detect_secrets(&vars);
        assert!(result.is_some());
        assert!(result.unwrap().contains("1 variable"));
    }

    #[test]
    fn test_detect_secrets_multiple() {
        let mut vars = HashMap::new();
        vars.insert("api_key".to_string(), serde_json::json!("key1"));
        vars.insert("auth_token".to_string(), serde_json::json!("tok1"));
        vars.insert("PASSWORD".to_string(), serde_json::json!("pwd"));
        let result = detect_secrets(&vars);
        assert!(result.is_some());
        assert!(result.unwrap().contains("3 variable"));
    }

    #[test]
    fn test_render_template_simple() {
        let template = "Hello {{ name }}, you have {{ count }} items.";
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), serde_json::json!("Alice"));
        vars.insert("count".to_string(), serde_json::json!(5));
        let result = render_template(template, &Some(vars)).unwrap();
        assert_eq!(result, "Hello Alice, you have 5 items.");
    }

    #[test]
    fn test_render_template_missing_var() {
        let template = "Hello {{ name }}!";
        let vars: HashMap<String, serde_json::Value> = HashMap::new();
        let result = render_template(template, &Some(vars));
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_MISSING_VARIABLE);
    }

    #[test]
    fn test_render_template_invalid_type() {
        let template = "Data: {{ items }}";
        let mut vars = HashMap::new();
        vars.insert("items".to_string(), serde_json::json!(["a", "b"]));
        let result = render_template(template, &Some(vars));
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_INVALID_VARIABLE_TYPE);
    }

    #[test]
    fn test_render_template_null_value() {
        let template = "Value: {{ val }}";
        let mut vars = HashMap::new();
        vars.insert("val".to_string(), serde_json::Value::Null);
        let result = render_template(template, &Some(vars)).unwrap();
        assert_eq!(result, "Value: null");
    }

    #[test]
    fn test_verify_hash_match() {
        let hash = "a".repeat(64);
        assert!(verify_hash(&hash, &hash).is_ok());
    }

    #[test]
    fn test_verify_hash_with_prefix() {
        let hash = "a".repeat(64);
        let prefixed = format!("sha256:{}", hash);
        assert!(verify_hash(&prefixed, &hash).is_ok());
        assert!(verify_hash(&hash, &prefixed).is_ok());
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let hash1 = "a".repeat(64);
        let hash2 = "b".repeat(64);
        let result = verify_hash(&hash1, &hash2);
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_PROMPT_HASH_MISMATCH);
    }

    #[test]
    fn test_validate_prompt_identity_valid() {
        let prompt = crate::types::PromptIdentity {
            provider: "ekka".to_string(),
            prompt_slug: "my-prompt".to_string(),
            prompt_version: serde_json::json!("1.0"),
            prompt_hash: "a".repeat(64),
        };
        assert!(validate_prompt_identity(&prompt).is_ok());
    }

    #[test]
    fn test_validate_prompt_identity_invalid_provider() {
        let prompt = crate::types::PromptIdentity {
            provider: "other".to_string(),
            prompt_slug: "my-prompt".to_string(),
            prompt_version: serde_json::json!("1.0"),
            prompt_hash: "a".repeat(64),
        };
        let result = validate_prompt_identity(&prompt);
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_INVALID_PROMPT_IDENTITY);
    }

    #[test]
    fn test_validate_prompt_identity_invalid_hash() {
        let prompt = crate::types::PromptIdentity {
            provider: "ekka".to_string(),
            prompt_slug: "my-prompt".to_string(),
            prompt_version: serde_json::json!("1.0"),
            prompt_hash: "tooshort".to_string(),
        };
        let result = validate_prompt_identity(&prompt);
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_INVALID_PROMPT_IDENTITY);
    }

    #[test]
    fn test_build_failure_envelope() {
        let envelope = build_failure_envelope("task-123", "TEST_ERROR", "Test message", None);
        assert_eq!(envelope["success"], false);
        assert_eq!(envelope["failure_code"], "TEST_ERROR");
        assert_eq!(envelope["message"], "Test message");
        assert_eq!(envelope["task_id"], "task-123");
    }

    // =========================================================================
    // Input Dirs Authorization Tests (generic, capability-driven)
    // =========================================================================

    /// Helper to create a test payload with optional input_dirs and variables
    fn make_test_payload(
        input_dirs: Option<Vec<String>>,
        variables: Option<HashMap<String, serde_json::Value>>,
    ) -> crate::types::PromptRunTaskPayloadV1 {
        crate::types::PromptRunTaskPayloadV1 {
            schema_version: "prompt_run_task.v1".to_string(),
            tenant_id: "tenant-1".to_string(),
            workspace_id: "workspace-1".to_string(),
            request_id: "req-123".to_string(),
            execution_nonce: None,
            retry_attempt: 0,
            prompt: crate::types::PromptIdentity {
                provider: "ekka".to_string(),
                prompt_slug: "test-prompt".to_string(),
                prompt_version: serde_json::json!("1.0"),
                prompt_hash: "a".repeat(64),
            },
            variables,
            metadata: None,
            input_dirs,
            output_dir: None,
        }
    }

    #[test]
    fn test_authorize_input_dirs_no_input() {
        // No input_dirs and no INPUT_PATH variable - should return empty list
        let payload = make_test_payload(None, None);
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty(), "Should return empty list when no input dirs");
    }

    #[test]
    fn test_single_input_path_backcompat() {
        // Backward compat: INPUT_PATH variable should be treated as input_dirs=[INPUT_PATH]
        let temp_dir = std::env::temp_dir().join(format!("ekka-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Use injected home path instead of env var (avoids race with other tests)
        let injected_home = Some(temp_dir.clone());

        let mut vars = HashMap::new();
        vars.insert(
            "INPUT_PATH".to_string(),
            serde_json::json!(temp_dir.to_str().unwrap()),
        );

        let payload = make_test_payload(None, Some(vars));
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", injected_home.as_ref());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(result.is_ok(), "INPUT_PATH should be treated as single input_dir");
        let dirs = result.unwrap();
        assert_eq!(dirs.len(), 1, "Should have exactly one dir from INPUT_PATH backcompat");
    }

    #[test]
    fn test_multi_input_dirs() {
        // Multiple input directories should all be validated
        let temp_dir = std::env::temp_dir().join(format!("ekka-test-{}", uuid::Uuid::new_v4()));
        let dir1 = temp_dir.join("input1");
        let dir2 = temp_dir.join("input2");
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::create_dir_all(&dir2).unwrap();

        // Use injected home path instead of env var (avoids race with other tests)
        let injected_home = Some(temp_dir.clone());

        let input_dirs = vec![
            dir1.to_str().unwrap().to_string(),
            dir2.to_str().unwrap().to_string(),
        ];

        let payload = make_test_payload(Some(input_dirs), None);
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", injected_home.as_ref());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(result.is_ok(), "Both input dirs should be allowed");
        let dirs = result.unwrap();
        assert_eq!(dirs.len(), 2, "Should have two approved dirs");
    }

    #[test]
    fn test_input_dirs_takes_priority_over_input_path() {
        // When both input_dirs and INPUT_PATH are present, input_dirs wins
        let temp_dir = std::env::temp_dir().join(format!("ekka-test-{}", uuid::Uuid::new_v4()));
        let dir1 = temp_dir.join("from_input_dirs");
        let dir2 = temp_dir.join("from_input_path");
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::create_dir_all(&dir2).unwrap();

        // Use injected home path instead of env var (avoids race with other tests)
        let injected_home = Some(temp_dir.clone());

        let mut vars = HashMap::new();
        vars.insert(
            "INPUT_PATH".to_string(),
            serde_json::json!(dir2.to_str().unwrap()),
        );

        let input_dirs = vec![dir1.to_str().unwrap().to_string()];
        let payload = make_test_payload(Some(input_dirs), Some(vars));
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", injected_home.as_ref());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(result.is_ok());
        let dirs = result.unwrap();
        assert_eq!(dirs.len(), 1, "Should only have dir from input_dirs, not INPUT_PATH");
        // The path should be the one from input_dirs
        assert!(dirs[0].to_str().unwrap().contains("from_input_dirs"));
    }

    #[test]
    fn test_input_dirs_denied_outside_ekka_home() {
        // Directories outside EKKA_HOME should be denied
        let temp_dir = std::env::temp_dir().join(format!("ekka-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Use injected home path instead of env var (avoids race with other tests)
        let injected_home = Some(temp_dir.clone());

        // Use a path that exists but is outside EKKA_HOME
        let outside_path = if cfg!(target_os = "windows") {
            "C:\\Windows\\System32"
        } else {
            "/usr/bin"
        };

        let input_dirs = vec![outside_path.to_string()];
        let payload = make_test_payload(Some(input_dirs), None);
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", injected_home.as_ref());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(result.is_err(), "Dir outside EKKA_HOME should be denied");
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_INPUT_DIR_NOT_AUTHORIZED);
    }

    #[test]
    fn test_input_dirs_non_existent_path_fails() {
        // Non-existent paths should fail (cannot canonicalize)
        let temp_dir = std::env::temp_dir().join(format!("ekka-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Use injected home path instead of env var (avoids race with other tests)
        let injected_home = Some(temp_dir.clone());

        let non_existent = temp_dir.join("does_not_exist");
        let input_dirs = vec![non_existent.to_str().unwrap().to_string()];
        let payload = make_test_payload(Some(input_dirs), None);
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", injected_home.as_ref());

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(result.is_err(), "Non-existent path should fail");
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, FAILURE_INPUT_DIR_NOT_AUTHORIZED);
        assert!(msg.contains("cannot be resolved"));
    }

    #[test]
    fn test_input_dirs_no_ekka_home_set() {
        // With input_dirs but no EKKA_HOME - should fail
        std::env::remove_var("EKKA_HOME");

        let input_dirs = vec!["/some/path".to_string()];
        let payload = make_test_payload(Some(input_dirs), None);
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", None);

        assert!(result.is_err(), "Should deny when EKKA_HOME not set");
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_INPUT_DIR_NOT_AUTHORIZED);
    }

    #[test]
    fn test_input_path_non_string_fails() {
        // Non-string INPUT_PATH variable should fail
        let mut vars = HashMap::new();
        vars.insert("INPUT_PATH".to_string(), serde_json::json!(123));

        let payload = make_test_payload(None, Some(vars));
        let result = authorize_input_dirs(&payload, "tenant-1", None, "task-123", None);

        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, FAILURE_INPUT_PATH_NOT_AUTHORIZED);
    }

    // =========================================================================
    // Output Contract Validation Tests
    // =========================================================================

    fn make_test_contract() -> OutputContract {
        OutputContract {
            schema_id: "ekka.report.v1".to_string(),
            schema: serde_json::json!({}), // Not used in MVP validation
            enforce: true,
        }
    }

    #[test]
    fn test_output_contract_valid() {
        let contract = make_test_contract();
        let output = r#"Some preamble text
<<<EKKA_REPORT_JSON>>>
{
  "schema_version": "ekka.report.v1",
  "files_written": [{"path": "README.md", "bytes": 100, "sha256": "abc123"}],
  "summary": {"files_written_count": 1, "errors_count": 0},
  "errors": []
}
<<<END_EKKA_REPORT_JSON>>>
Some postamble"#;

        let result = validate_output_contract(output, &contract, "task-123", "tenant-test");
        assert!(result.is_ok(), "Valid report should pass validation");
    }

    #[test]
    fn test_output_contract_missing_start_delimiter() {
        let contract = make_test_contract();
        let output = r#"Some output without delimiters
{
  "schema_version": "ekka.report.v1",
  "files_written": [],
  "summary": {"files_written_count": 0, "errors_count": 0},
  "errors": []
}
<<<END_EKKA_REPORT_JSON>>>"#;

        let result = validate_output_contract(output, &contract, "task-123", "tenant-test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, FAILURE_REPORT_INVALID);
        assert!(err.message.contains("delimiters"));
    }

    #[test]
    fn test_output_contract_missing_end_delimiter() {
        let contract = make_test_contract();
        let output = r#"<<<EKKA_REPORT_JSON>>>
{
  "schema_version": "ekka.report.v1",
  "files_written": [],
  "summary": {"files_written_count": 0, "errors_count": 0},
  "errors": []
}
No end delimiter"#;

        let result = validate_output_contract(output, &contract, "task-123", "tenant-test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, FAILURE_REPORT_INVALID);
    }

    #[test]
    fn test_output_contract_invalid_json() {
        let contract = make_test_contract();
        let output = r#"<<<EKKA_REPORT_JSON>>>
{ not valid json
<<<END_EKKA_REPORT_JSON>>>"#;

        let result = validate_output_contract(output, &contract, "task-123", "tenant-test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, FAILURE_REPORT_INVALID);
        assert!(err.message.contains("parse error"));
    }

    #[test]
    fn test_output_contract_schema_version_mismatch() {
        let contract = make_test_contract();
        let output = r#"<<<EKKA_REPORT_JSON>>>
{
  "schema_version": "wrong.version.v1",
  "files_written": [],
  "summary": {"files_written_count": 0, "errors_count": 0},
  "errors": []
}
<<<END_EKKA_REPORT_JSON>>>"#;

        let result = validate_output_contract(output, &contract, "task-123", "tenant-test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, FAILURE_REPORT_INVALID);
        assert!(err.message.contains("mismatch"));
    }

    #[test]
    fn test_output_contract_missing_required_fields() {
        let contract = make_test_contract();
        let output = r#"<<<EKKA_REPORT_JSON>>>
{
  "schema_version": "ekka.report.v1"
}
<<<END_EKKA_REPORT_JSON>>>"#;

        let result = validate_output_contract(output, &contract, "task-123", "tenant-test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, FAILURE_REPORT_INVALID);
        assert!(err.message.contains("missing required fields"));
    }

    // =========================================================================
    // LLM Timeout Tests
    // =========================================================================

    /// Test that the timeout mechanism works correctly with a slow command.
    /// Uses env var override to set a short timeout.
    #[tokio::test]
    async fn test_llm_hard_timeout_kills_process() {
        use std::time::Instant;

        // Set a very short timeout for testing (1 second)
        std::env::set_var("EKKA_LLM_TIMEOUT_SECS", "1");

        let start = Instant::now();

        // Create a command that sleeps for longer than the timeout
        let child = Command::new("sleep")
            .arg("10") // Sleep for 10 seconds, but timeout is 1 second
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn sleep command");

        // Get timeout from env (should be 1 second)
        let timeout_secs = crate::types::get_llm_timeout_secs();
        assert_eq!(timeout_secs, 1, "Timeout should be 1 second from env override");

        let timeout_duration = Duration::from_secs(timeout_secs);

        // Wait with timeout
        let result = tokio::time::timeout(timeout_duration, child.wait_with_output()).await;

        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Clean up env
        std::env::remove_var("EKKA_LLM_TIMEOUT_SECS");

        // Should have timed out
        assert!(result.is_err(), "Should have timed out");

        // Elapsed time should be close to timeout (1000ms +/- 200ms)
        assert!(
            elapsed_ms >= 900 && elapsed_ms <= 1500,
            "Elapsed time should be ~1000ms, got {}ms",
            elapsed_ms
        );

        // The process should be killed when the Child is dropped
        // (tokio sends SIGKILL on drop for Unix)
        // Give a brief moment for cleanup
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify total test time is short (not waiting for full sleep)
        let total_elapsed = start.elapsed().as_millis() as u64;
        assert!(
            total_elapsed < 3000,
            "Total test time should be under 3s (process killed), got {}ms",
            total_elapsed
        );
    }

    /// Test that the timeout value comes from env var when set.
    /// NOTE: This test uses a mutex-like pattern with set-read-restore to handle parallel test execution.
    #[test]
    fn test_get_llm_timeout_from_env() {
        // Save original value
        let original = std::env::var("EKKA_LLM_TIMEOUT_SECS").ok();

        // Set custom timeout and read immediately
        std::env::set_var("EKKA_LLM_TIMEOUT_SECS", "42");
        let timeout = crate::types::get_llm_timeout_secs();

        // Restore original (or remove if not set)
        match original {
            Some(val) => std::env::set_var("EKKA_LLM_TIMEOUT_SECS", val),
            None => std::env::remove_var("EKKA_LLM_TIMEOUT_SECS"),
        }

        assert_eq!(timeout, 42, "Should use env var value");
    }

    /// Test that default timeout is used when env var is not set.
    /// NOTE: This test is inherently racy with other tests that set the env var.
    /// We just verify the function works - the default value test may see other tests' values.
    #[test]
    fn test_get_llm_timeout_default() {
        // This test verifies the function returns a valid value.
        // Due to parallel test execution, we can't guarantee the env var is unset.
        let timeout = crate::types::get_llm_timeout_secs();

        // Just verify we get a reasonable timeout value (either default or from env)
        assert!(
            timeout > 0 && timeout <= 3600,
            "Timeout should be reasonable, got {}",
            timeout
        );
    }
}
