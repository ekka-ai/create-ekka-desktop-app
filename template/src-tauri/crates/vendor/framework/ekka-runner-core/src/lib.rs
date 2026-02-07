//! EKKA Runner Core - Library for embedding runner loop in applications
//!
//! Provides the engine runner loop that polls/claims/executes tasks.

pub mod dispatch;
pub mod executors;
pub mod types;

// Re-export artifact capture types for convenience
pub use executors::artifact_capture::{
    CaptureConfig, CaptureContext, CapturePolicy, CaptureResult,
    PromptCapturePolicy, RawLlmOutput, capture_artifacts,
};
pub use ekka_artifact_store::{ArtifactStore, FilesystemArtifactStore};
pub use ekka_ops::llm_result::ArtifactRef;

use dispatch::{classify_error, dispatch_task};
use reqwest::Client;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{error, info, warn};
use types::{
    EngineClaimResponse, EngineCompleteOutput, EngineCompleteRequest, EngineContext,
    EngineFailRequest, EnginePollResponse, EngineTaskInfo, TaskExecutionContext,
};
use uuid::Uuid;

const DEFAULT_ENGINE_URL: &str = "http://localhost:3200";
const DEFAULT_NODE_URL: &str = "http://127.0.0.1:7777";
const POLL_INTERVAL_SECS: u64 = 5;
const MAX_POLL_LIMIT: u32 = 10;
const RUNNER_ID_PREFIX: &str = "ekka-runner";

// =============================================================================
// Configuration
// =============================================================================

/// Node credentials for authentication
#[derive(Debug, Clone)]
pub struct NodeCredentials {
    pub node_id: String,
    pub node_secret: String,
}

/// Runner configuration
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub engine_url: String,
    pub node_url: String,
    pub credentials: NodeCredentials,
    pub session_id: String,
    /// Tenant ID - populated from node auth response
    pub tenant_id: Option<String>,
    /// Workspace ID - populated from node auth response
    pub workspace_id: Option<String>,
}

impl RunnerConfig {
    /// Create config from environment variables
    ///
    /// Required:
    /// - EKKA_NODE_ID: Node UUID (from node registration)
    /// - EKKA_NODE_SECRET: Node secret (from node registration)
    ///
    /// Optional:
    /// - ENGINE_URL / EKKA_ENGINE_URL: Engine base URL (default: http://localhost:3200)
    /// - NODE_URL: Local node URL (default: http://127.0.0.1:7777)
    pub fn from_env() -> Result<Self, String> {
        let engine_url = std::env::var("ENGINE_URL")
            .or_else(|_| std::env::var("EKKA_ENGINE_URL"))
            .unwrap_or_else(|_| DEFAULT_ENGINE_URL.to_string());
        let node_url = std::env::var("NODE_URL").unwrap_or_else(|_| DEFAULT_NODE_URL.to_string());
        let session_id = std::env::var("EKKA_RUNNER_SESSION_ID").unwrap_or_default();

        // Node credentials are required
        let node_id = std::env::var("EKKA_NODE_ID")
            .map_err(|_| "EKKA_NODE_ID is required. Register your node to obtain credentials.")?;
        let node_secret = std::env::var("EKKA_NODE_SECRET")
            .map_err(|_| "EKKA_NODE_SECRET is required. Register your node to obtain credentials.")?;

        // Validate node_id is a UUID
        Uuid::parse_str(&node_id).map_err(|_| "EKKA_NODE_ID must be a valid UUID")?;

        let credentials = NodeCredentials { node_id, node_secret };

        // Tenant/workspace are optional - they come from the node auth response
        let tenant_id = std::env::var("EKKA_TENANT_ID").ok();
        let workspace_id = std::env::var("EKKA_WORKSPACE_ID").ok();

        // Validate UUIDs if present
        if let Some(ref tid) = tenant_id {
            Uuid::parse_str(tid).map_err(|_| "EKKA_TENANT_ID must be valid UUID")?;
        }
        if let Some(ref wid) = workspace_id {
            Uuid::parse_str(wid).map_err(|_| "EKKA_WORKSPACE_ID must be valid UUID")?;
        }

        Ok(Self { engine_url, node_url, credentials, session_id, tenant_id, workspace_id })
    }
}

// =============================================================================
// State Callbacks
// =============================================================================

/// Callback trait for runner state updates
pub trait RunnerStateCallback: Send + Sync {
    fn on_start(&self, runner_id: &str);
    fn on_poll(&self);
    fn on_claim(&self, task_id: &str);
    fn on_complete(&self, task_id: &str);
    fn on_error(&self, error: &str);
    fn on_stop(&self);
}

/// No-op implementation for standalone binary
pub struct NoOpCallback;
impl RunnerStateCallback for NoOpCallback {
    fn on_start(&self, _: &str) {}
    fn on_poll(&self) {}
    fn on_claim(&self, _: &str) {}
    fn on_complete(&self, _: &str) {}
    fn on_error(&self, _: &str) {}
    fn on_stop(&self) {}
}

// =============================================================================
// Main Loop
// =============================================================================

/// Node session auth response
#[derive(Debug, serde::Deserialize)]
struct NodeAuthResponse {
    token: String,
    session_id: String,
    tenant_id: String,
    workspace_id: String,
    #[allow(dead_code)]
    expires_in_seconds: u64,
}

/// Authenticate with the engine using node_id + node_secret
async fn authenticate_node(
    client: &Client,
    engine_url: &str,
    node_id: &str,
    node_secret: &str,
) -> Result<NodeAuthResponse, String> {
    let url = format!("{}/engine/nodes/auth", engine_url);

    info!(
        op = "runner.auth.start",
        node_id_prefix = %&node_id[..8.min(node_id.len())],
        "Authenticating with engine"
    );

    // Security envelope headers required by all endpoints
    let request_id = Uuid::new_v4().to_string();
    let correlation_id = Uuid::new_v4().to_string();

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        // Security envelope headers (required)
        .header("X-EKKA-PROOF-TYPE", "node_secret")
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &correlation_id)
        .header("X-EKKA-MODULE", "runner")
        .header("X-EKKA-ACTION", "auth")
        .header("X-EKKA-CLIENT", "ekka-runner-core")
        .header("X-EKKA-CLIENT-VERSION", "1.0.0")
        .json(&serde_json::json!({
            "node_id": node_id,
            "node_secret": node_secret
        }))
        .send()
        .await
        .map_err(|e| format!("Auth request failed: {}", e.without_url()))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Auth failed ({}): {}", status, body.chars().take(200).collect::<String>()));
    }

    let auth: NodeAuthResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse auth response: {}", e))?;

    info!(
        op = "runner.auth.success",
        session_id = %auth.session_id,
        tenant_id_prefix = %&auth.tenant_id[..8.min(auth.tenant_id.len())],
        "Authentication successful"
    );

    Ok(auth)
}

/// Run the engine runner loop
///
/// This polls engine for pending tasks, claims them, executes, and reports results.
/// Call with a shutdown_rx to allow graceful shutdown.
pub async fn run_engine_runner_loop(
    config: RunnerConfig,
    state_cb: Option<Arc<dyn RunnerStateCallback>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let runner = EngineRunner::new(config).await?;
    let cb = state_cb.unwrap_or_else(|| Arc::new(NoOpCallback));

    cb.on_start(&runner.runner_id);

    info!(op = "runner.start", runner_id = %runner.runner_id, auth_mode = "node_session", "Engine runner starting");

    loop {
        // Check for shutdown signal
        if *shutdown_rx.borrow() {
            info!(op = "runner.shutdown", "Shutdown signal received");
            cb.on_stop();
            break;
        }

        match runner.poll_tasks().await {
            Ok(tasks) => {
                cb.on_poll();

                if tasks.is_empty() {
                    // Wait for next poll or shutdown
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)) => {}
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                info!(op = "runner.shutdown", "Shutdown during poll wait");
                                cb.on_stop();
                                break;
                            }
                        }
                    }
                    continue;
                }

                info!(op = "runner.poll.found", count = tasks.len(), "Found pending tasks");

                for task in tasks {
                    // Check shutdown before processing each task
                    if *shutdown_rx.borrow() {
                        info!(op = "runner.shutdown", "Shutdown before task processing");
                        cb.on_stop();
                        return Ok(());
                    }
                    runner.process_task(&task, &cb).await;
                }
            }
            Err(e) => {
                error!(op = "runner.poll.error", error = %e, "Poll failed");
                cb.on_error(&e);
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

// =============================================================================
// Engine Runner
// =============================================================================

/// Runtime auth state - holds the node session JWT token
#[derive(Clone)]
struct RuntimeAuth {
    token: String,
}

struct EngineRunner {
    client: Client,
    engine_url: String,
    node_url: String,
    auth: Arc<RwLock<RuntimeAuth>>,
    credentials: NodeCredentials,
    session_id: String,
    tenant_id: String,
    workspace_id: String,
    runner_id: String,
}

impl EngineRunner {
    async fn new(config: RunnerConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        let runner_id = format!("{}-{}", RUNNER_ID_PREFIX, &Uuid::new_v4().to_string()[..8]);

        // Authenticate with engine using node credentials to get JWT token
        let auth_response = authenticate_node(
            &client,
            &config.engine_url,
            &config.credentials.node_id,
            &config.credentials.node_secret,
        ).await?;

        let auth = Arc::new(RwLock::new(RuntimeAuth { token: auth_response.token }));

        Ok(Self {
            client,
            engine_url: config.engine_url,
            node_url: config.node_url,
            auth,
            credentials: config.credentials,
            session_id: config.session_id,
            tenant_id: auth_response.tenant_id,
            workspace_id: auth_response.workspace_id,
            runner_id,
        })
    }

    /// Re-authenticate using stored node credentials after a 401
    async fn refresh_auth(&self) -> Result<(), String> {
        info!(op = "runner.auth.refresh", "Refreshing token after 401");

        let auth_response = authenticate_node(
            &self.client,
            &self.engine_url,
            &self.credentials.node_id,
            &self.credentials.node_secret,
        ).await?;

        if let Ok(mut guard) = self.auth.write() {
            guard.token = auth_response.token;
        }

        info!(op = "runner.auth.refresh.ok", "Token refreshed successfully");
        Ok(())
    }

    /// Read current auth token from lock
    fn current_token(&self) -> String {
        self.auth.read().map(|a| a.token.clone()).unwrap_or_default()
    }

    fn security_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("X-REQUEST-ID", Uuid::new_v4().to_string()),
            ("X-EKKA-CORRELATION-ID", Uuid::new_v4().to_string()),
            ("X-EKKA-MODULE", "runner".to_string()),
            ("X-EKKA-CLIENT", "ekka-runner-core".to_string()),
            ("X-EKKA-CLIENT-VERSION", "1.0.0".to_string()),
            ("Authorization", format!("Bearer {}", self.current_token())),
            ("X-EKKA-PROOF-TYPE", "node_session".to_string()),
        ]
    }

    async fn poll_tasks(&self) -> Result<Vec<EngineTaskInfo>, String> {
        // Try up to 2 times (initial + 1 retry after 401)
        for attempt in 0..2 {
            let url = format!(
                "{}/engine/runner-tasks-v2?target_type=runner_desktop&status=pending&limit={}&tenant_id={}&workspace_id={}",
                self.engine_url, MAX_POLL_LIMIT, self.tenant_id, self.workspace_id
            );

            let mut req = self.client.get(&url);
            for (k, v) in self.security_headers() {
                req = req.header(k, v);
            }
            req = req.header("X-EKKA-ACTION", "poll");

            let response = req.send().await
                .map_err(|e| format!("Poll failed: {}", e.without_url()))?;

            if response.status().is_success() {
                let poll: EnginePollResponse = response.json().await
                    .map_err(|e| format!("Parse poll response: {}", e))?;
                return Ok(poll.tasks);
            }

            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Handle 401: refresh auth and retry once
            if attempt == 0 && status == reqwest::StatusCode::UNAUTHORIZED {
                warn!(
                    op = "runner.poll.401_recovery",
                    status = %status,
                    "Got 401 on poll, refreshing token and retrying"
                );
                self.refresh_auth().await?;
                continue;
            }

            return Err(format!("Poll failed ({}): {}", status, body.chars().take(100).collect::<String>()));
        }

        Err("Poll failed after retry".to_string())
    }

    async fn claim_task(&self, task_id: &str) -> Result<EngineClaimResponse, String> {
        // Try up to 2 times (initial + 1 retry after 401)
        for attempt in 0..2 {
            let url = format!(
                "{}/engine/runner-tasks-v2/{}/claim?tenant_id={}&workspace_id={}",
                self.engine_url, task_id, self.tenant_id, self.workspace_id
            );

            let mut req = self.client.post(&url);
            for (k, v) in self.security_headers() {
                req = req.header(k, v);
            }
            req = req.header("X-EKKA-ACTION", "claim");

            let response = req
                .json(&serde_json::json!({ "runner_id": self.runner_id }))
                .send()
                .await
                .map_err(|e| format!("Claim failed: {}", e.without_url()))?;

            if response.status().is_success() {
                return response.json().await.map_err(|e| format!("Parse claim response: {}", e));
            }

            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Handle 401: refresh auth and retry once
            if attempt == 0 && status == reqwest::StatusCode::UNAUTHORIZED {
                warn!(
                    op = "runner.claim.401_recovery",
                    status = %status,
                    "Got 401 on claim, refreshing token and retrying"
                );
                self.refresh_auth().await?;
                continue;
            }

            return Err(format!("Claim failed ({}): {}", status, body.chars().take(100).collect::<String>()));
        }

        Err("Claim failed after retry".to_string())
    }

    async fn complete_task(&self, task_id: &str, output: EngineCompleteOutput, _duration_ms: Option<u64>) -> Result<(), String> {
        // Serialize output once (shared across retries)
        let output_json = serde_json::to_value(&output)
            .map_err(|e| format!("Failed to serialize output: {}", e))?;

        // Try up to 2 times (initial + 1 retry after 401)
        for attempt in 0..2 {
            let url = format!(
                "{}/engine/runner-tasks-v2/{}/complete?tenant_id={}&workspace_id={}",
                self.engine_url, task_id, self.tenant_id, self.workspace_id
            );

            let mut req = self.client.post(&url);
            for (k, v) in self.security_headers() {
                req = req.header(k, v);
            }
            req = req.header("X-EKKA-ACTION", "complete");

            let body = EngineCompleteRequest {
                runner_id: self.runner_id.clone(),
                output: Some(output_json.clone()),
            };

            let response = req.json(&body).send().await
                .map_err(|e| format!("Complete failed: {}", e.without_url()))?;

            if response.status().is_success() {
                return Ok(());
            }

            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();

            // Handle 401: refresh auth and retry once
            if attempt == 0 && status == reqwest::StatusCode::UNAUTHORIZED {
                warn!(
                    op = "runner.complete.401_recovery",
                    status = %status,
                    "Got 401 on complete, refreshing token and retrying"
                );
                self.refresh_auth().await?;
                continue;
            }

            return Err(format!("Complete failed ({}): {}", status, body_text.chars().take(100).collect::<String>()));
        }

        Err("Complete failed after retry".to_string())
    }

    async fn fail_task(&self, task_id: &str, error: &str, code: &str, retryable: bool) -> Result<(), String> {
        // Try up to 2 times (initial + 1 retry after 401)
        for attempt in 0..2 {
            let url = format!(
                "{}/engine/runner-tasks-v2/{}/fail?tenant_id={}&workspace_id={}",
                self.engine_url, task_id, self.tenant_id, self.workspace_id
            );

            let mut req = self.client.post(&url);
            for (k, v) in self.security_headers() {
                req = req.header(k, v);
            }
            req = req.header("X-EKKA-ACTION", "fail");

            let body = EngineFailRequest {
                runner_id: self.runner_id.clone(),
                error_code: code.to_string(),
                error_message: Some(error.to_string()),
                error_details: None,
                retryable: Some(retryable),
            };

            let response = req.json(&body).send().await
                .map_err(|e| format!("Fail failed: {}", e.without_url()))?;

            if response.status().is_success() {
                return Ok(());
            }

            let status = response.status();

            // Handle 401: refresh auth and retry once
            if attempt == 0 && status == reqwest::StatusCode::UNAUTHORIZED {
                warn!(
                    op = "runner.fail.401_recovery",
                    status = %status,
                    "Got 401 on fail, refreshing token and retrying"
                );
                self.refresh_auth().await?;
                continue;
            }

            return Err(format!("Fail failed ({})", status));
        }

        Err("Fail failed after retry".to_string())
    }

    async fn process_task(&self, task: &EngineTaskInfo, cb: &Arc<dyn RunnerStateCallback>) {
        let task_id = &task.id;
        let task_id_short = &task_id[..8.min(task_id.len())];

        info!(op = "runner.task.start", task_id = %task_id_short, capability = %task.capability_identity, "Processing task");

        // Claim
        let claim_result = match self.claim_task(task_id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(op = "runner.task.claim_failed", task_id = %task_id_short, error = %e, "Claim failed");
                cb.on_error(&e);
                return;
            }
        };

        cb.on_claim(task_id);
        info!(op = "runner.task.claimed", task_id = %task_id_short, "Task claimed");

        // Build context
        let ctx = TaskExecutionContext::new(task_id.clone(), claim_result.input_json);

        // Build engine context with current token (read from lock)
        let engine_ctx = EngineContext::with_node_session(
            self.engine_url.clone(),
            self.current_token(),
            self.tenant_id.clone(),
            self.workspace_id.clone(),
        );

        // Build heartbeat function with shared auth for fresh token access
        let heartbeat_task_id = task_id.clone();
        let heartbeat_client = self.client.clone();
        let heartbeat_engine_url = self.engine_url.clone();
        let heartbeat_tenant_id = self.tenant_id.clone();
        let heartbeat_workspace_id = self.workspace_id.clone();
        let heartbeat_runner_id = self.runner_id.clone();
        let heartbeat_auth = self.auth.clone();

        let heartbeat_fn: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> + Send + Sync> = Arc::new(move || {
            let task_id = heartbeat_task_id.clone();
            let client = heartbeat_client.clone();
            let engine_url = heartbeat_engine_url.clone();
            let tenant_id = heartbeat_tenant_id.clone();
            let workspace_id = heartbeat_workspace_id.clone();
            let runner_id = heartbeat_runner_id.clone();
            let auth = heartbeat_auth.clone();

            Box::pin(async move {
                // Read fresh token from shared auth lock
                let token = auth.read().map(|a| a.token.clone()).unwrap_or_default();

                // V2 endpoint
                let url = format!(
                    "{}/engine/runner-tasks-v2/{}/heartbeat?tenant_id={}&workspace_id={}",
                    engine_url, task_id, tenant_id, workspace_id
                );

                let response = client.post(&url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("X-EKKA-PROOF-TYPE", "node_session")
                    .header("X-EKKA-ACTION", "heartbeat")
                    .header("X-REQUEST-ID", Uuid::new_v4().to_string())
                    .header("X-EKKA-CORRELATION-ID", Uuid::new_v4().to_string())
                    .header("X-EKKA-MODULE", "runner")
                    .header("X-EKKA-CLIENT", "ekka-runner-core")
                    .header("X-EKKA-CLIENT-VERSION", "1.0.0")
                    .json(&serde_json::json!({ "runner_id": runner_id }))
                    .send()
                    .await
                    .map_err(|e| format!("Heartbeat failed: {}", e.without_url()))?;

                if !response.status().is_success() {
                    return Err(format!("Heartbeat failed ({})", response.status()));
                }
                Ok(())
            })
        });

        // Dispatch - use task_subtype() to map capability_identity to legacy subtypes
        let result = dispatch_task(
            task.task_subtype(),
            &self.client,
            &self.node_url,
            &self.session_id,
            Some(&engine_ctx),
            &ctx,
            Some(heartbeat_fn),
        ).await;

        // Complete or fail
        match result {
            Ok(output) => {
                info!(op = "runner.task.succeeded", task_id = %task_id_short, "Task completed");

                let complete_output = EngineCompleteOutput {
                    decision: "ACCEPT".to_string(),
                    reason: "Task executed successfully".to_string(),
                    proposed_patch: Some(vec![output]),
                };

                if let Err(e) = self.complete_task(task_id, complete_output, None).await {
                    error!(op = "runner.task.complete_failed", task_id = %task_id_short, error = %e, "Complete failed");
                    cb.on_error(&e);
                } else {
                    cb.on_complete(task_id);
                }
            }
            Err(e) => {
                warn!(op = "runner.task.failed", task_id = %task_id_short, error = %e, "Task failed");
                let (code, retryable) = classify_error(&e);

                if let Err(fail_err) = self.fail_task(task_id, &e, code, retryable).await {
                    error!(op = "runner.task.fail_failed", task_id = %task_id_short, error = %fail_err, "Fail failed");
                }
                cb.on_error(&e);
            }
        }
    }
}
