//! Task dispatch for ekka-runner-local
//!
//! Routes tasks to the appropriate executor based on task_subtype.
//! This is the single point where new executors should be added.

use reqwest::Client;
use std::sync::Arc;
use tracing::warn;

use crate::executors;
use crate::types::{EngineContext, TaskExecutionContext};

/// Dispatch a task to the appropriate executor based on task_subtype.
///
/// # Arguments
/// * `task_subtype` - The task subtype (e.g., "node_exec", "prompt_run")
/// * `client` - HTTP client for making requests
/// * `node_url` - Base URL of the local node (for node_exec)
/// * `session_id` - Session ID for node authentication (for node_exec)
/// * `engine_ctx` - Engine context for prompt_run (URL, internal key, tenant/workspace)
/// * `ctx` - Task execution context with input_json
/// * `heartbeat_fn` - Optional heartbeat callback for long-running tasks
///
/// # Returns
/// * `Ok(serde_json::Value)` - The output from task execution
/// * `Err(String)` - Error message if execution failed
pub async fn dispatch_task(
    task_subtype: Option<&str>,
    client: &Client,
    node_url: &str,
    session_id: &str,
    engine_ctx: Option<&EngineContext>,
    ctx: &TaskExecutionContext,
    heartbeat_fn: Option<Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>>,
) -> Result<serde_json::Value, String> {
    match task_subtype {
        Some("node_exec") => {
            executors::node_exec::execute(client, node_url, session_id, ctx).await
        }
        Some("prompt_run") => {
            // prompt_run requires engine context
            let engine_ctx = engine_ctx.ok_or_else(|| {
                "Engine context required for prompt_run executor".to_string()
            })?;
            executors::prompt_run::execute(client, engine_ctx, ctx, heartbeat_fn).await
        }
        _ => {
            // Unknown subtype
            warn!(
                op = "engine_runner.task.unsupported",
                task_id = %ctx.task_id_short,
                task_subtype = ?task_subtype,
                "Unsupported task subtype for engine runner"
            );
            Err("Unsupported task subtype".to_string())
        }
    }
}

/// Determine error code and retryability from an execution error.
///
/// This centralizes error classification for all executors.
pub fn classify_error(error: &str) -> (&'static str, bool) {
    if error.contains("CAPABILITY_DENIED") {
        ("CAPABILITY_DENIED", false)
    } else if error.contains("Unknown capability_code") {
        ("INVALID_CAPABILITY", false)
    } else if error.contains("Unsupported task subtype") {
        ("UNSUPPORTED_TASK", false)
    // prompt_run specific errors (non-retryable)
    } else if error.contains("INVALID_SCHEMA_VERSION")
        || error.contains("INVALID_PROMPT_IDENTITY")
        || error.contains("SECRETS_IN_PAYLOAD")
        || error.contains("PROMPT_HASH_MISMATCH")
        || error.contains("MISSING_VARIABLE")
        || error.contains("INVALID_VARIABLE_TYPE")
        || error.contains("PROMPT_NOT_FOUND")
        || error.contains("PROMPT_NOT_AUTHORIZED")
    {
        ("PROMPT_RUN_ERROR", false)
    // prompt_run retryable errors
    } else if error.contains("LLM_TIMEOUT") || error.contains("PROMPT_FETCH_FAILED") {
        ("PROMPT_RUN_ERROR", true)
    } else {
        ("RUNNER_ERROR", true)
    }
}
