//! Task dispatch - routes to appropriate executor based on task_subtype

use ekka_artifact_store::{ArtifactStore, FilesystemArtifactStore};
use reqwest::Client;
use std::sync::Arc;
use tracing::warn;

use crate::executors;
use crate::types::{EngineContext, TaskExecutionContext};

pub async fn dispatch_task(
    task_subtype: Option<&str>,
    client: &Client,
    node_url: &str,
    session_id: &str,
    engine_ctx: Option<&EngineContext>,
    ctx: &TaskExecutionContext,
    heartbeat_fn: Option<Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>>,
) -> Result<serde_json::Value, String> {
    // For backward compatibility, call with no artifact store
    dispatch_task_with_artifacts::<FilesystemArtifactStore>(
        task_subtype,
        client,
        node_url,
        session_id,
        engine_ctx,
        ctx,
        heartbeat_fn,
        None,
    ).await
}

/// Dispatch task with optional artifact store for capturing LLM outputs
pub async fn dispatch_task_with_artifacts<S: ArtifactStore>(
    task_subtype: Option<&str>,
    client: &Client,
    node_url: &str,
    session_id: &str,
    engine_ctx: Option<&EngineContext>,
    ctx: &TaskExecutionContext,
    heartbeat_fn: Option<Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync>>,
    artifact_store: Option<&S>,
) -> Result<serde_json::Value, String> {
    match task_subtype {
        Some("node_exec") => {
            executors::node_exec::execute(client, node_url, session_id, ctx).await
        }
        Some("prompt_run") => {
            let engine_ctx = engine_ctx.ok_or("Engine context required for prompt_run")?;
            executors::prompt_run::execute(client, engine_ctx, ctx, heartbeat_fn, artifact_store).await
        }
        _ => {
            warn!(op = "runner.task.unsupported", task_id = %ctx.task_id_short, task_subtype = ?task_subtype, "Unsupported");
            Err("Unsupported task subtype".to_string())
        }
    }
}

pub fn classify_error(error: &str) -> (&'static str, bool) {
    if error.contains("CAPABILITY_DENIED") { ("CAPABILITY_DENIED", false) }
    else if error.contains("Unknown capability_code") { ("INVALID_CAPABILITY", false) }
    else if error.contains("Unsupported task subtype") { ("UNSUPPORTED_TASK", false) }
    else if error.contains("INVALID_SCHEMA_VERSION") || error.contains("SECRETS_IN_PAYLOAD")
         || error.contains("PROMPT_HASH_MISMATCH") || error.contains("MISSING_VARIABLE")
         || error.contains("PROMPT_NOT_FOUND") { ("PROMPT_RUN_ERROR", false) }
    else if error.contains("LLM_TIMEOUT") || error.contains("PROMPT_FETCH_FAILED") { ("PROMPT_RUN_ERROR", true) }
    else { ("RUNNER_ERROR", true) }
}
