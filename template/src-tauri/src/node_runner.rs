//! Desktop Node Session Runner
//!
//! Runner loop using node_id + node_secret authentication (NOT Ed25519).
//!
//! ## Architecture
//!
//! - Uses node_credentials (vault) for authentication
//! - Runner uses JWT token for all engine calls
//! - Token refreshed automatically via node_secret auth when expired
//! - Tenant/workspace comes from token (EKKA decides scope)
//!
//! ## Security
//!
//! - NO Ed25519 keys required
//! - NO environment variable credentials
//! - Tokens held in memory only
//! - node_secret never logged

#![allow(dead_code)] // API types and fields may not all be used yet

use crate::config;
use crate::node_auth::{NodeSession, NodeSessionHolder, NodeSessionRunnerConfig};
use crate::node_credentials::authenticate_node;
use crate::state::RunnerState;
// Use ekka_runner_local for enhanced executor with debug bundle support
use ekka_runner_local::dispatch::{classify_error, dispatch_task};
use ekka_runner_local::types::{EngineContext, TaskExecutionContext};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;

const DEFAULT_NODE_URL: &str = "http://127.0.0.1:7777";
const POLL_INTERVAL_SECS: u64 = 5;
const MAX_POLL_LIMIT: u32 = 10;
const RUNNER_ID_PREFIX: &str = "ekka-node-runner";

// =============================================================================
// Types (duplicated from ekka-runner-core to avoid internal key dependency)
// =============================================================================

#[derive(Debug, Deserialize)]
struct EnginePollResponse {
    tasks: Vec<EngineTaskInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct EngineTaskInfo {
    id: String,
    task_type: String,
    task_subtype: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EngineClaimResponse {
    input_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct EngineCompleteRequest {
    runner_id: String,
    output: EngineCompleteOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct EngineCompleteOutput {
    decision: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposed_patch: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct EngineFailRequest {
    runner_id: String,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

// =============================================================================
// Callback Trait
// =============================================================================

pub trait NodeRunnerCallback: Send + Sync {
    fn on_start(&self, runner_id: &str);
    fn on_poll(&self);
    fn on_claim(&self, task_id: &str);
    fn on_complete(&self, task_id: &str);
    fn on_error(&self, error: &str);
    fn on_stop(&self);
}

/// Desktop callbacks that update RunnerState
pub struct DesktopNodeRunnerCallbacks {
    state: RunnerState,
}

impl DesktopNodeRunnerCallbacks {
    pub fn new(state: RunnerState) -> Self {
        Self { state }
    }
}

impl NodeRunnerCallback for DesktopNodeRunnerCallbacks {
    fn on_start(&self, runner_id: &str) {
        info!(op = "node_runner.start", runner_id = %runner_id, "Node runner started");
        self.state.start(runner_id);
    }

    fn on_poll(&self) {
        self.state.record_poll();
    }

    fn on_claim(&self, task_id: &str) {
        info!(op = "node_runner.claim", task_id = %&task_id[..8.min(task_id.len())], "Task claimed");
        self.state.record_claim(task_id);
    }

    fn on_complete(&self, task_id: &str) {
        info!(op = "node_runner.complete", task_id = %&task_id[..8.min(task_id.len())], "Task completed");
        self.state.record_complete(task_id);
    }

    fn on_error(&self, error: &str) {
        warn!(op = "node_runner.error", "Runner error occurred");
        self.state.record_error(error);
    }

    fn on_stop(&self) {
        info!(op = "node_runner.stop", "Node runner stopped");
        self.state.stop();
    }
}

// =============================================================================
// Node Session Runner
// =============================================================================

struct NodeSessionRunner {
    client: Client,
    engine_url: String,
    node_url: String,
    node_id: Uuid,
    runner_id: String,
    session_holder: Arc<NodeSessionHolder>,
    home_path: PathBuf,
    device_fingerprint: Option<String>,
    /// User subject (from JWT) for PathGuard grant validation
    user_sub: Option<String>,
}

impl NodeSessionRunner {
    fn new(
        config: &NodeSessionRunnerConfig,
        session_holder: Arc<NodeSessionHolder>,
        home_path: PathBuf,
        device_fingerprint: Option<String>,
        user_sub: Option<String>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        let runner_id = format!("{}-{}", RUNNER_ID_PREFIX, &Uuid::new_v4().to_string()[..8]);

        Self {
            client,
            engine_url: config.engine_url.clone(),
            node_url: config.node_url.clone(),
            node_id: config.node_id,
            runner_id,
            session_holder,
            home_path,
            device_fingerprint,
            user_sub,
        }
    }

    /// Get current valid session, refreshing if needed
    ///
    /// Uses node_id + node_secret authentication (NOT Ed25519 keys).
    /// IMPORTANT: Uses spawn_blocking to avoid Tokio runtime panic.
    async fn get_session(&self) -> Result<NodeSession, String> {
        // Check if we have a valid session
        if let Some(session) = self.session_holder.get_valid() {
            return Ok(session);
        }

        // Need to refresh - use spawn_blocking to avoid runtime panic
        info!(
            op = "node_runner.refresh_session.start",
            method = "node_secret",
            "Refreshing node session via node_secret auth"
        );

        let engine_url = self.engine_url.clone();

        let auth_token = tokio::task::spawn_blocking(move || {
            authenticate_node(&engine_url)
        })
        .await
        .map_err(|e| format!("Session refresh task failed: {}", e))?
        .map_err(|e| {
            error!(
                op = "node_runner.refresh_session.failed",
                method = "node_secret",
                error = %e,
                "Session refresh via node_secret failed"
            );
            format!("Session refresh failed: {}", e)
        })?;

        // Convert NodeAuthToken to NodeSession
        let session = NodeSession {
            token: auth_token.token,
            session_id: auth_token.session_id,
            tenant_id: auth_token.tenant_id,
            workspace_id: auth_token.workspace_id,
            expires_at: auth_token.expires_at,
        };

        info!(
            op = "node_runner.refresh_session.ok",
            method = "node_secret",
            session_id = %session.session_id,
            "Session refreshed successfully via node_secret"
        );
        self.session_holder.set(session.clone());
        Ok(session)
    }

    /// Get security headers using current session
    async fn security_headers(&self) -> Result<Vec<(&'static str, String)>, String> {
        let session = self.get_session().await?;

        Ok(vec![
            ("Authorization", format!("Bearer {}", session.token)),
            ("X-EKKA-PROOF-TYPE", "node_session".to_string()),
            ("X-REQUEST-ID", Uuid::new_v4().to_string()),
            ("X-EKKA-CORRELATION-ID", Uuid::new_v4().to_string()),
            ("X-EKKA-MODULE", "engine.runner_tasks".to_string()),
            ("X-EKKA-CLIENT", config::app_slug().to_string()),
            ("X-EKKA-CLIENT-VERSION", "0.2.0".to_string()),
            ("X-EKKA-NODE-ID", self.node_id.to_string()),
        ])
    }

    async fn poll_tasks(&self) -> Result<Vec<EngineTaskInfo>, String> {
        let session = self.get_session().await?;

        let url = format!(
            "{}/engine/runner-tasks?status=pending&limit={}&tenant_id={}&workspace_id={}",
            self.engine_url, MAX_POLL_LIMIT, session.tenant_id, session.workspace_id
        );

        let headers = self.security_headers().await?;
        let mut req = self.client.get(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        req = req.header("X-EKKA-ACTION", "list");

        let response = req
            .send()
            .await
            .map_err(|e| format!("Poll failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Poll failed ({}): {}",
                status,
                body.chars().take(100).collect::<String>()
            ));
        }

        let poll: EnginePollResponse = response
            .json()
            .await
            .map_err(|e| format!("Parse poll response: {}", e))?;

        Ok(poll.tasks)
    }

    async fn claim_task(&self, task_id: &str) -> Result<EngineClaimResponse, String> {
        let session = self.get_session().await?;

        let url = format!(
            "{}/engine/runner-tasks/{}/claim?tenant_id={}&workspace_id={}",
            self.engine_url, task_id, session.tenant_id, session.workspace_id
        );

        let headers = self.security_headers().await?;
        let mut req = self.client.post(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        req = req.header("X-EKKA-ACTION", "claim");

        let response = req
            .json(&serde_json::json!({ "runner_id": self.runner_id }))
            .send()
            .await
            .map_err(|e| format!("Claim failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Claim failed ({}): {}",
                status,
                body.chars().take(100).collect::<String>()
            ));
        }

        response
            .json()
            .await
            .map_err(|e| format!("Parse claim response: {}", e))
    }

    async fn complete_task(
        &self,
        task_id: &str,
        output: EngineCompleteOutput,
        duration_ms: Option<u64>,
    ) -> Result<(), String> {
        let session = self.get_session().await?;

        let url = format!(
            "{}/engine/runner-tasks/{}/complete?tenant_id={}&workspace_id={}",
            self.engine_url, task_id, session.tenant_id, session.workspace_id
        );

        let headers = self.security_headers().await?;
        let mut req = self.client.post(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        req = req.header("X-EKKA-ACTION", "complete");

        let body = EngineCompleteRequest {
            runner_id: self.runner_id.clone(),
            output,
            duration_ms,
        };

        // DEBUG: Log FULL request details before sending
        let body_json_str = serde_json::to_string(&body).unwrap_or_default();
        tracing::info!(
            op = "node_runner.complete.debug",
            url = %url,
            body_json = %body_json_str,
            "Complete request - FULL BODY"
        );

        let response = req
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Complete failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            tracing::error!(
                op = "node_runner.complete.response_error",
                status = %status,
                full_response = %body_text,
                "Complete failed - FULL RESPONSE"
            );
            return Err(format!(
                "Complete failed ({}): {}",
                status,
                body_text
            ));
        }

        Ok(())
    }

    async fn fail_task(
        &self,
        task_id: &str,
        error: &str,
        code: &str,
        retryable: bool,
    ) -> Result<(), String> {
        let session = self.get_session().await?;

        let url = format!(
            "{}/engine/runner-tasks/{}/fail?tenant_id={}&workspace_id={}",
            self.engine_url, task_id, session.tenant_id, session.workspace_id
        );

        let headers = self.security_headers().await?;
        let mut req = self.client.post(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        req = req.header("X-EKKA-ACTION", "fail");

        let body = EngineFailRequest {
            runner_id: self.runner_id.clone(),
            error: error.to_string(),
            error_code: Some(code.to_string()),
            retryable: Some(retryable),
            duration_ms: None,
        };

        let response = req
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Fail failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(format!("Fail failed ({})", status));
        }

        Ok(())
    }

    async fn heartbeat(&self, task_id: &str) -> Result<(), String> {
        let session = self.get_session().await?;

        let url = format!(
            "{}/engine/runner-tasks/{}/heartbeat?tenant_id={}&workspace_id={}",
            self.engine_url, task_id, session.tenant_id, session.workspace_id
        );

        let headers = self.security_headers().await?;
        let mut req = self.client.post(&url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        req = req.header("X-EKKA-ACTION", "heartbeat");

        let response = req
            .json(&serde_json::json!({ "runner_id": self.runner_id }))
            .send()
            .await
            .map_err(|e| format!("Heartbeat failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Heartbeat failed ({})", response.status()));
        }

        Ok(())
    }

    async fn process_task(&self, task: &EngineTaskInfo, cb: &Arc<dyn NodeRunnerCallback>) {
        let task_id = &task.id;
        let task_id_short = &task_id[..8.min(task_id.len())];

        info!(
            op = "node_runner.task.start",
            task_id = %task_id_short,
            task_type = %task.task_type,
            task_subtype = ?task.task_subtype,
            "Processing task"
        );

        // Claim
        let claim_result = match self.claim_task(task_id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    op = "node_runner.task.claim_failed",
                    task_id = %task_id_short,
                    error = %e,
                    "Claim failed"
                );
                cb.on_error(&e);
                return;
            }
        };

        cb.on_claim(task_id);
        info!(
            op = "node_runner.task.claimed",
            task_id = %task_id_short,
            "Task claimed"
        );

        // Build execution context
        let ctx = TaskExecutionContext::new(task_id.clone(), claim_result.input_json);

        // Get session for engine context
        let session = match self.get_session().await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    op = "node_runner.task.session_error",
                    task_id = %task_id_short,
                    error = %e,
                    "Failed to get session for execution"
                );
                let _ = self
                    .fail_task(task_id, &e, "SESSION_ERROR", true)
                    .await;
                cb.on_error(&e);
                return;
            }
        };

        // Build engine context for prompt_run executor with node session auth
        // Inject ekka_home_path so PathGuard doesn't need EKKA_HOME env var
        // Inject user_sub so PathGuard grant validation matches user's grants
        let mut engine_ctx = EngineContext::with_node_session(
            self.engine_url.clone(),
            session.token.clone(),
            session.tenant_id.to_string(),
            session.workspace_id.to_string(),
        )
        .set_ekka_home_path(self.home_path.clone());

        if let Some(ref sub) = self.user_sub {
            engine_ctx = engine_ctx.set_user_sub(sub.clone());
        }

        // Build heartbeat function
        let heartbeat_task_id = task_id.clone();
        let heartbeat_self = NodeSessionRunnerHeartbeat {
            client: self.client.clone(),
            engine_url: self.engine_url.clone(),
            runner_id: self.runner_id.clone(),
            session_holder: self.session_holder.clone(),
            node_id: self.node_id,
        };

        let heartbeat_fn: Arc<
            dyn Fn()
                    -> std::pin::Pin<
                        Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
                    > + Send
                + Sync,
        > = Arc::new(move || {
            let task_id = heartbeat_task_id.clone();
            let hb = heartbeat_self.clone();

            Box::pin(async move { hb.send_heartbeat(&task_id).await })
        });

        // Dispatch to actual executor
        let start = std::time::Instant::now();
        let result = dispatch_task(
            task.task_subtype.as_deref(),
            &self.client,
            &self.node_url,
            "", // session_id not used for prompt_run
            Some(&engine_ctx),
            &ctx,
            Some(heartbeat_fn),
        )
        .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        // Handle result
        match result {
            Ok(envelope) => {
                // Check if executor returned success or failure
                let success = envelope
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let (decision, reason) = if success {
                    ("ACCEPT".to_string(), "Task executed successfully".to_string())
                } else {
                    let failure_code = envelope
                        .get("failure_code")
                        .and_then(|v| v.as_str())
                        .unwrap_or("UNKNOWN");
                    (
                        "REJECT".to_string(),
                        format!("Task failed: {}", failure_code),
                    )
                };

                info!(
                    op = "node_runner.task.executed",
                    task_id = %task_id_short,
                    success = %success,
                    duration_ms = %duration_ms,
                    "Task execution completed"
                );

                let output = EngineCompleteOutput {
                    decision,
                    reason,
                    proposed_patch: Some(vec![envelope]),
                };

                if let Err(e) = self.complete_task(task_id, output, Some(duration_ms)).await {
                    error!(
                        op = "node_runner.task.complete_failed",
                        task_id = %task_id_short,
                        error = %e,
                        "Complete failed"
                    );
                    cb.on_error(&e);
                } else {
                    cb.on_complete(task_id);
                }
            }
            Err(e) => {
                warn!(
                    op = "node_runner.task.failed",
                    task_id = %task_id_short,
                    error = %e,
                    duration_ms = %duration_ms,
                    "Task execution failed"
                );

                let (code, retryable) = classify_error(&e);

                if let Err(fail_err) = self.fail_task(task_id, &e, code, retryable).await {
                    error!(
                        op = "node_runner.task.fail_failed",
                        task_id = %task_id_short,
                        error = %fail_err,
                        "Fail request failed"
                    );
                }
                cb.on_error(&e);
            }
        }
    }
}

// =============================================================================
// Heartbeat Helper
// =============================================================================

/// Helper struct to send heartbeats from the executor
#[derive(Clone)]
struct NodeSessionRunnerHeartbeat {
    client: Client,
    engine_url: String,
    runner_id: String,
    session_holder: Arc<NodeSessionHolder>,
    node_id: Uuid, // Kept for headers only
}

impl NodeSessionRunnerHeartbeat {
    async fn send_heartbeat(&self, task_id: &str) -> Result<(), String> {
        // Get current session (refresh if needed)
        let session = if let Some(s) = self.session_holder.get_valid() {
            s
        } else {
            // Try to refresh using node_secret auth (NOT Ed25519)
            info!(
                op = "node_runner.heartbeat.refresh_session.start",
                method = "node_secret",
                "Refreshing session for heartbeat via node_secret"
            );

            let engine_url = self.engine_url.clone();

            let auth_token = tokio::task::spawn_blocking(move || {
                authenticate_node(&engine_url)
            })
            .await
            .map_err(|e| format!("Session refresh task failed: {}", e))?
            .map_err(|e| {
                error!(
                    op = "node_runner.heartbeat.refresh_session.failed",
                    method = "node_secret",
                    error = %e,
                    "Session refresh for heartbeat failed"
                );
                format!("Session refresh failed: {}", e)
            })?;

            // Convert NodeAuthToken to NodeSession
            let session = NodeSession {
                token: auth_token.token,
                session_id: auth_token.session_id,
                tenant_id: auth_token.tenant_id,
                workspace_id: auth_token.workspace_id,
                expires_at: auth_token.expires_at,
            };

            info!(
                op = "node_runner.heartbeat.refresh_session.ok",
                method = "node_secret",
                session_id = %session.session_id,
                "Session refreshed for heartbeat via node_secret"
            );
            self.session_holder.set(session.clone());
            session
        };

        let url = format!(
            "{}/engine/runner-tasks/{}/heartbeat?tenant_id={}&workspace_id={}",
            self.engine_url, task_id, session.tenant_id, session.workspace_id
        );

        let task_id_short = &task_id[..8.min(task_id.len())];

        // CRITICAL: Include all security envelope headers (securityEnvelope middleware requires all)
        // Previously missing: X-REQUEST-ID, X-EKKA-CORRELATION-ID, X-EKKA-MODULE, X-EKKA-CLIENT, X-EKKA-CLIENT-VERSION
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", session.token))
            .header("X-EKKA-PROOF-TYPE", "node_session")
            .header("X-REQUEST-ID", Uuid::new_v4().to_string())
            .header("X-EKKA-CORRELATION-ID", Uuid::new_v4().to_string())
            .header("X-EKKA-MODULE", "engine.runner_tasks")
            .header("X-EKKA-ACTION", "heartbeat")
            .header("X-EKKA-CLIENT", config::app_slug())
            .header("X-EKKA-CLIENT-VERSION", "0.2.0")
            .header("X-EKKA-NODE-ID", self.node_id.to_string())
            .json(&serde_json::json!({ "runner_id": self.runner_id }))
            .send()
            .await
            .map_err(|e| format!("Heartbeat failed: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let body_trunc = if body.len() > 200 {
                format!("{}...", &body[..200])
            } else {
                body
            };
            warn!(
                op = "prompt_run.heartbeat.failed",
                task_id = %task_id_short,
                http_status = %status.as_u16(),
                response_body = %body_trunc,
                "Heartbeat request failed"
            );
            return Err(format!("Heartbeat failed ({}) {}", status, body_trunc));
        }

        info!(
            op = "prompt_run.heartbeat.ok",
            task_id = %task_id_short,
            http_status = %status.as_u16(),
            "Heartbeat succeeded"
        );

        Ok(())
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Max consecutive errors before entering backoff mode
const MAX_CONSECUTIVE_ERRORS: u32 = 3;
/// Max backoff delay in seconds
const MAX_BACKOFF_SECS: u64 = 60;

/// Start the node session runner loop
///
/// Uses node_id + node_secret auth for session refresh (NOT Ed25519).
/// Includes backoff on repeated failures to prevent poll spam.
pub async fn run_node_session_runner_loop(
    config: NodeSessionRunnerConfig,
    session_holder: Arc<NodeSessionHolder>,
    home_path: PathBuf,
    device_fingerprint: Option<String>,
    user_sub: Option<String>,
    state_cb: Option<Arc<dyn NodeRunnerCallback>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let runner = NodeSessionRunner::new(&config, session_holder, home_path, device_fingerprint, user_sub);
    let cb = state_cb.unwrap_or_else(|| Arc::new(NoOpCallback));

    cb.on_start(&runner.runner_id);

    info!(
        op = "node_runner.start",
        runner_id = %runner.runner_id,
        node_id = %runner.node_id,
        auth_method = "node_secret",
        "Node session runner starting (uses node_secret auth)"
    );

    let mut consecutive_errors: u32 = 0;

    loop {
        // Check for shutdown signal
        if *shutdown_rx.borrow() {
            info!(op = "node_runner.shutdown", "Shutdown signal received");
            cb.on_stop();
            break;
        }

        match runner.poll_tasks().await {
            Ok(tasks) => {
                // Reset error count on success
                consecutive_errors = 0;
                cb.on_poll();

                if tasks.is_empty() {
                    // Wait for next poll or shutdown
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)) => {}
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                info!(op = "node_runner.shutdown", "Shutdown during poll wait");
                                cb.on_stop();
                                break;
                            }
                        }
                    }
                    continue;
                }

                info!(
                    op = "node_runner.poll.found",
                    count = tasks.len(),
                    "Found pending tasks"
                );

                for task in tasks {
                    // Check shutdown before processing each task
                    if *shutdown_rx.borrow() {
                        info!(op = "node_runner.shutdown", "Shutdown before task processing");
                        cb.on_stop();
                        return Ok(());
                    }
                    runner.process_task(&task, &cb).await;
                }
            }
            Err(e) => {
                consecutive_errors += 1;

                // Calculate backoff: exponential up to MAX_BACKOFF_SECS
                let backoff_secs = if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    std::cmp::min(
                        POLL_INTERVAL_SECS * (1 << (consecutive_errors - MAX_CONSECUTIVE_ERRORS)),
                        MAX_BACKOFF_SECS,
                    )
                } else {
                    POLL_INTERVAL_SECS
                };

                error!(
                    op = "node_runner.poll.error",
                    error = %e,
                    consecutive_errors = consecutive_errors,
                    backoff_secs = backoff_secs,
                    "Poll failed"
                );
                cb.on_error(&e);

                // Wait with backoff
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

/// No-op callback for when no state tracking is needed
struct NoOpCallback;

impl NodeRunnerCallback for NoOpCallback {
    fn on_start(&self, _: &str) {}
    fn on_poll(&self) {}
    fn on_claim(&self, _: &str) {}
    fn on_complete(&self, _: &str) {}
    fn on_error(&self, _: &str) {}
    fn on_stop(&self) {}
}

/// Start the node runner after session is established
pub async fn start_node_runner(
    runner_state: RunnerState,
    session_holder: Arc<NodeSessionHolder>,
    config: NodeSessionRunnerConfig,
    home_path: PathBuf,
    device_fingerprint: Option<String>,
    user_sub: Option<String>,
) -> Option<tokio::sync::watch::Sender<bool>> {
    info!(
        op = "node_runner.init",
        node_id = %config.node_id,
        tenant_id = %config.tenant_id,
        workspace_id = %config.workspace_id,
        "Starting node session runner"
    );

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Create callbacks
    let callbacks = Arc::new(DesktopNodeRunnerCallbacks::new(runner_state));

    // Spawn the runner loop
    tokio::spawn(async move {
        if let Err(e) = run_node_session_runner_loop(
            config,
            session_holder,
            home_path,
            device_fingerprint,
            user_sub,
            Some(callbacks),
            shutdown_rx,
        )
        .await
        {
            warn!(
                op = "node_runner.error",
                error = %e,
                "Node runner loop exited with error"
            );
        }
    });

    Some(shutdown_tx)
}
