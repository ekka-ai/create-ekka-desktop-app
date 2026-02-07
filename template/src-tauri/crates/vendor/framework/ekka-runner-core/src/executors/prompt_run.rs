//! prompt_run executor - fetches prompts from engine, renders, executes via Claude CLI

use ekka_artifact_store::ArtifactStore;
use ekka_ops::llm_result::ArtifactRef;
use ekka_path_guard::{AuthContext, PathGuard};
use regex::Regex;
use reqwest::Client;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};
use uuid::Uuid;

use super::artifact_capture::{
    capture_artifacts, CaptureConfig, CaptureContext, RawLlmOutput,
};
use crate::types::{
    ClaudeCliOutput, EngineContext, LlmTimings, LlmUsage, PromptFetchRequest,
    PromptFetchResponse, PromptRunFailureEnvelope, PromptRunOutputV1, PromptRunSuccessEnvelope,
    PromptRunTaskPayloadV1, TaskExecutionContext, HEARTBEAT_INTERVAL_SECS, LLM_TIMEOUT_SECS,
    PROMPT_RUN_OUTPUT_SCHEMA_VERSION, PROMPT_RUN_RESULT_SCHEMA_VERSION,
    PROMPT_RUN_TASK_SCHEMA_VERSION, PromptIdentity,
};

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

const SECRET_PATTERNS: &[&str] = &[
    "api_key", "apikey", "token", "secret", "password", "auth", "bearer", "private_key",
];

/// Execute a prompt_run task with optional artifact capture
///
/// If `artifact_store` is provided, raw LLM stdout/stderr will be captured as artifacts.
/// Artifact capture failures are logged but do NOT block completion.
pub async fn execute<S: ArtifactStore>(
    client: &Client,
    engine_ctx: &EngineContext,
    ctx: &TaskExecutionContext,
    heartbeat_fn: Option<Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>>,
    artifact_store: Option<&S>,
) -> Result<serde_json::Value, String> {
    info!(op = "prompt_run.execute.start", task_id = %ctx.task_id_short, "Starting prompt_run");

    let payload = match validate_payload(&ctx.input_json) {
        Ok(p) => p,
        Err((code, msg)) => return Ok(build_failure_envelope(&ctx.task_id, code, &msg, vec![])),
    };

    if let Some(ref vars) = payload.variables {
        if let Some(msg) = detect_secrets(vars) {
            return Ok(build_failure_envelope(&ctx.task_id, FAILURE_SECRETS_IN_PAYLOAD, &msg, vec![]));
        }
    }

    if let Some(ref vars) = payload.variables {
        if let Err((code, msg)) = authorize_input_path(vars, &payload.tenant_id, &ctx.task_id_short) {
            return Ok(build_failure_envelope(&ctx.task_id, code, &msg, vec![]));
        }
    }

    let fetch_result = match fetch_prompt(client, engine_ctx, &payload).await {
        Ok(r) => r,
        Err((code, msg)) => return Ok(build_failure_envelope(&ctx.task_id, code, &msg, vec![])),
    };

    if let Err((code, msg)) = verify_hash(&payload.prompt.prompt_hash, &fetch_result.prompt_hash) {
        return Ok(build_failure_envelope(&ctx.task_id, code, &msg, vec![]));
    }

    let rendered_prompt = match render_template(&fetch_result.prompt_text, &payload.variables) {
        Ok(r) => r,
        Err((code, msg)) => return Ok(build_failure_envelope(&ctx.task_id, code, &msg, vec![])),
    };

    // Execute LLM and get both parsed output and raw bytes
    let exec_result = execute_claude_with_raw(&rendered_prompt, heartbeat_fn).await;

    match exec_result {
        Ok((output, raw_output, latency_ms)) => {
            info!(op = "prompt_run.llm.completed", task_id = %ctx.task_id_short, latency_ms = %latency_ms, "LLM completed");

            // Capture artifacts (success case)
            let artifacts = capture_llm_artifacts(
                artifact_store,
                &payload.tenant_id,
                &ctx.task_id,
                false, // is_failure = false
                Some(&raw_output),
                None, // Don't capture prompt on success by default
            );

            Ok(build_success_envelope(&ctx.task_id, output, latency_ms, artifacts))
        }
        Err((code, msg, raw_output)) => {
            warn!(op = "prompt_run.llm.failed", task_id = %ctx.task_id_short, code = %code, "LLM failed");

            // Capture artifacts (failure case - includes rendered prompt)
            let artifacts = capture_llm_artifacts(
                artifact_store,
                &payload.tenant_id,
                &ctx.task_id,
                true, // is_failure = true
                raw_output.as_ref(),
                Some(&rendered_prompt), // Capture prompt on failure
            );

            Ok(build_failure_envelope(&ctx.task_id, code, &msg, artifacts))
        }
    }
}

/// Helper to capture LLM artifacts without blocking on errors
fn capture_llm_artifacts<S: ArtifactStore>(
    store: Option<&S>,
    tenant_id: &str,
    task_id: &str,
    is_failure: bool,
    raw_output: Option<&RawLlmOutput>,
    rendered_prompt: Option<&str>,
) -> Vec<ArtifactRef> {
    let Some(store) = store else {
        info!(
            op = "prompt_run.artifacts.capture.skipped",
            task_id = %&task_id[..8.min(task_id.len())],
            reason = "no_store",
            "Artifact store not configured"
        );
        return vec![];
    };

    let ctx = CaptureContext::new(tenant_id, task_id, is_failure);
    let config = CaptureConfig::default();

    let result = capture_artifacts(store, &ctx, &config, raw_output, rendered_prompt);
    result.artifacts
}

fn validate_payload(input_json: &serde_json::Value) -> Result<PromptRunTaskPayloadV1, (&'static str, String)> {
    let payload: PromptRunTaskPayloadV1 = serde_json::from_value(input_json.clone())
        .map_err(|e| (FAILURE_INVALID_PAYLOAD, format!("Failed to parse: {}", e)))?;

    if payload.schema_version != PROMPT_RUN_TASK_SCHEMA_VERSION {
        return Err((FAILURE_INVALID_SCHEMA_VERSION, format!("Invalid schema_version: {}", payload.schema_version)));
    }

    validate_prompt_identity(&payload.prompt)?;
    Ok(payload)
}

fn validate_prompt_identity(prompt: &PromptIdentity) -> Result<(), (&'static str, String)> {
    if prompt.provider != "ekka" {
        return Err((FAILURE_INVALID_PROMPT_IDENTITY, format!("Invalid provider: {}", prompt.provider)));
    }
    if prompt.prompt_slug.is_empty() {
        return Err((FAILURE_INVALID_PROMPT_IDENTITY, "Prompt slug empty".to_string()));
    }
    if !prompt.prompt_version.is_string() && !prompt.prompt_version.is_number() {
        return Err((FAILURE_INVALID_PROMPT_IDENTITY, "Version must be string or number".to_string()));
    }
    let hash = prompt.prompt_hash.strip_prefix("sha256:").unwrap_or(&prompt.prompt_hash);
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((FAILURE_INVALID_PROMPT_IDENTITY, "Invalid hash format".to_string()));
    }
    Ok(())
}

fn detect_secrets(variables: &HashMap<String, serde_json::Value>) -> Option<String> {
    let count = variables.keys().filter(|k| {
        let lower = k.to_lowercase();
        SECRET_PATTERNS.iter().any(|p| lower.contains(p))
    }).count();
    if count > 0 { Some(format!("Detected {} secret variable(s)", count)) } else { None }
}

fn authorize_input_path(variables: &HashMap<String, serde_json::Value>, tenant_id: &str, task_id_short: &str) -> Result<(), (&'static str, String)> {
    let input_path_str = match variables.get("input_path") {
        Some(v) => v.as_str().ok_or((FAILURE_INPUT_PATH_NOT_AUTHORIZED, "input_path must be string".to_string()))?,
        None => return Ok(()),
    };

    let ekka_home = std::env::var("EKKA_HOME").ok().filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or((FAILURE_INPUT_PATH_NOT_AUTHORIZED, "EKKA_HOME not set".to_string()))?;

    let auth_ctx = AuthContext::new(tenant_id, "runner");
    let guard = PathGuard::from_env(ekka_home.clone(), auth_ctx).unwrap_or_else(|_| PathGuard::home_only(ekka_home));

    if guard.is_allowed(&PathBuf::from(input_path_str), "read") {
        info!(op = "prompt_run.input_path.allowed", task_id = %task_id_short, "Authorized");
        Ok(())
    } else {
        warn!(op = "prompt_run.input_path.denied", task_id = %task_id_short, "Denied");
        Err((FAILURE_INPUT_PATH_NOT_AUTHORIZED, "input_path not authorized".to_string()))
    }
}

async fn fetch_prompt(client: &Client, engine_ctx: &EngineContext, payload: &PromptRunTaskPayloadV1) -> Result<PromptFetchResponse, (&'static str, String)> {
    let url = format!("{}/engine/runner/prompts/fetch", engine_ctx.engine_url);
    let version_str = match &payload.prompt.prompt_version {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return Err((FAILURE_INVALID_PROMPT_IDENTITY, "Invalid version type".to_string())),
    };

    let request_body = PromptFetchRequest {
        tenant_id: payload.tenant_id.clone(),
        workspace_id: payload.workspace_id.clone(),
        prompt_slug: payload.prompt.prompt_slug.clone(),
        prompt_version: version_str,
    };

    // Build request with node session auth
    let response = client.post(&url)
        .header("X-REQUEST-ID", Uuid::new_v4().to_string())
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", engine_ctx.session_token))
        .header("X-EKKA-PROOF-TYPE", "node_session")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| (FAILURE_PROMPT_FETCH_FAILED, format!("Request failed: {}", e.without_url())))?;

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err((FAILURE_PROMPT_NOT_FOUND, "Prompt not found".to_string()));
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return Err((FAILURE_PROMPT_NOT_AUTHORIZED, "Not authorized".to_string()));
    }
    if !status.is_success() {
        return Err((FAILURE_PROMPT_FETCH_FAILED, format!("Status {}", status)));
    }

    response.json().await.map_err(|e| (FAILURE_PROMPT_FETCH_FAILED, format!("Parse error: {}", e)))
}

fn verify_hash(expected: &str, fetched: &str) -> Result<(), (&'static str, String)> {
    let e = expected.strip_prefix("sha256:").unwrap_or(expected);
    let f = fetched.strip_prefix("sha256:").unwrap_or(fetched);
    if e.to_lowercase() != f.to_lowercase() {
        Err((FAILURE_PROMPT_HASH_MISMATCH, "Hash mismatch".to_string()))
    } else {
        Ok(())
    }
}

fn render_template(template: &str, variables: &Option<HashMap<String, serde_json::Value>>) -> Result<String, (&'static str, String)> {
    let re = Regex::new(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}").expect("Invalid regex");
    let empty = HashMap::new();
    let vars = variables.as_ref().unwrap_or(&empty);

    let placeholders: std::collections::HashSet<String> = re.captures_iter(template)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();

    let mut missing = 0;
    let mut invalid = 0;
    let mut result = template.to_string();

    for var_name in placeholders {
        match vars.get(&var_name) {
            Some(value) => {
                let replacement = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Null => "null".to_string(),
                    _ => { invalid += 1; continue; }
                };
                let pattern = format!(r"\{{\{{\s*{}\s*\}}\}}", regex::escape(&var_name));
                let var_re = Regex::new(&pattern).expect("Invalid var regex");
                result = var_re.replace_all(&result, replacement.as_str()).to_string();
            }
            None => missing += 1,
        }
    }

    if invalid > 0 { return Err((FAILURE_INVALID_VARIABLE_TYPE, format!("{} invalid type(s)", invalid))); }
    if missing > 0 { return Err((FAILURE_MISSING_VARIABLE, format!("{} missing variable(s)", missing))); }
    Ok(result)
}

/// Execute Claude CLI and return parsed output along with raw stdout/stderr for artifact capture.
///
/// On success: Returns (ClaudeCliOutput, RawLlmOutput, latency_ms)
/// On failure: Returns (error_code, message, Option<RawLlmOutput>)
async fn execute_claude_with_raw(
    prompt: &str,
    heartbeat_fn: Option<Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>>,
) -> Result<(ClaudeCliOutput, RawLlmOutput, u64), (&'static str, String, Option<RawLlmOutput>)> {
    let start = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));

    let hb_handle = heartbeat_fn.map(|hb| {
        let stop = stop.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)).await;
                if stop.load(Ordering::Relaxed) { break; }
                let _ = hb().await;
            }
        })
    });

    let mut child = Command::new("claude")
        .arg("--output-format").arg("json")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            stop.store(true, Ordering::Relaxed);
            (FAILURE_LLM_EXECUTION_FAILED, format!("Spawn failed: {}", e), None)
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        let bytes = prompt.as_bytes().to_vec();
        tokio::spawn(async move { let _ = stdin.write_all(&bytes).await; });
    }

    let wait = tokio::select! {
        r = child.wait_with_output() => Some(r),
        _ = tokio::time::sleep(Duration::from_secs(LLM_TIMEOUT_SECS)) => None,
    };

    stop.store(true, Ordering::Relaxed);
    if let Some(h) = hb_handle { let _ = h.await; }

    let latency = start.elapsed().as_millis() as u64;

    let output = match wait {
        Some(Ok(o)) => o,
        Some(Err(e)) => return Err((FAILURE_LLM_EXECUTION_FAILED, format!("Exec failed: {}", e), None)),
        None => {
            info!(op = "prompt_run.llm.timeout", timeout_secs = %LLM_TIMEOUT_SECS, "LLM timeout");
            return Err((FAILURE_LLM_TIMEOUT, format!("Timeout after {}s", LLM_TIMEOUT_SECS), None));
        }
    };

    // Create raw output for artifact capture
    let raw_output = RawLlmOutput::new(
        output.stdout.clone(),
        output.stderr.clone(),
        output.status.code(),
    );

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).chars().take(100).collect::<String>();
        info!(op = "prompt_run.llm.failed", exit_code = ?output.status.code(), "LLM non-zero exit");
        return Err((
            FAILURE_LLM_EXECUTION_FAILED,
            format!("Exit {}: {}", output.status, stderr),
            Some(raw_output),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let cli_output: ClaudeCliOutput = serde_json::from_str(&stdout)
        .map_err(|e| {
            info!(op = "prompt_run.llm.parse_error", error = %e, "Failed to parse LLM output");
            (FAILURE_LLM_EXECUTION_FAILED, format!("Parse error: {}", e), Some(raw_output.clone()))
        })?;

    Ok((cli_output, raw_output, latency))
}

fn build_success_envelope(
    task_id: &str,
    output: ClaudeCliOutput,
    latency_ms: u64,
    artifacts: Vec<ArtifactRef>,
) -> serde_json::Value {
    serde_json::to_value(PromptRunSuccessEnvelope {
        success: true,
        schema_version: PROMPT_RUN_RESULT_SCHEMA_VERSION.to_string(),
        task_subtype: "prompt_run".to_string(),
        task_id: task_id.to_string(),
        output: PromptRunOutputV1 {
            schema_version: PROMPT_RUN_OUTPUT_SCHEMA_VERSION.to_string(),
            decision: "UNKNOWN".to_string(),
            output_text: output.result,
            model: output.model.unwrap_or_else(|| "unknown".to_string()),
            usage: LlmUsage {
                input_tokens: output.usage.as_ref().and_then(|u| u.input_tokens),
                output_tokens: output.usage.as_ref().and_then(|u| u.output_tokens),
            },
            timings_ms: LlmTimings { llm_latency_ms: latency_ms },
            artifacts,
        },
    }).expect("serialize")
}

fn build_failure_envelope(
    task_id: &str,
    code: &str,
    message: &str,
    artifacts: Vec<ArtifactRef>,
) -> serde_json::Value {
    serde_json::to_value(PromptRunFailureEnvelope {
        success: false,
        schema_version: PROMPT_RUN_RESULT_SCHEMA_VERSION.to_string(),
        task_subtype: "prompt_run".to_string(),
        task_id: task_id.to_string(),
        failure_code: code.to_string(),
        message: message.to_string(),
        artifacts,
    }).expect("serialize")
}
