//! EKKA Local Runner - Thin wrapper around ekka-runner-core
//!
//! Background runner process that polls/claims/executes jobs.
//!
//! ## MODES
//!
//! - **node** (DEPRECATED): Polls local node job queue
//! - **engine** (CANONICAL): Uses ekka-runner-core library
//!
//! ## Usage
//!
//! Engine mode (CANONICAL):
//! ```bash
//! EKKA_RUNNER_MODE=engine \
//!   EKKA_NODE_ID=<node-uuid> EKKA_NODE_SECRET=<node-secret> \
//!   EKKA_ENGINE_URL=http://localhost:3200 \
//!   cargo run -p ekka-runner-local
//! ```

// Node mode legacy code (DEPRECATED) - kept for backward compatibility
// These modules are no longer used since engine mode now uses ekka-runner-core
#[allow(dead_code)]
mod dispatch;
#[allow(dead_code)]
mod executors;
#[allow(dead_code)]
mod types;

use ekka_node_module_jobs::{JobPayload, JobPayloadParams, JobType};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// =============================================================================
// Health Server for Desktop Readiness Check
// =============================================================================

const HEALTH_PORT: u16 = 9473;

/// Shared health state for the runner
pub struct HealthState {
    auth_ok: AtomicBool,
    last_poll_at: RwLock<Option<Instant>>,
    last_error: RwLock<Option<String>>,
}

impl HealthState {
    fn new() -> Self {
        Self {
            auth_ok: AtomicBool::new(false),
            last_poll_at: RwLock::new(None),
            last_error: RwLock::new(None),
        }
    }

    fn set_auth_ok(&self) {
        self.auth_ok.store(true, Ordering::SeqCst);
    }

    fn is_auth_ok(&self) -> bool {
        self.auth_ok.load(Ordering::SeqCst)
    }

    async fn set_last_poll(&self) {
        *self.last_poll_at.write().await = Some(Instant::now());
    }

    async fn get_last_poll_ms_ago(&self) -> Option<u64> {
        self.last_poll_at.read().await.map(|t| t.elapsed().as_millis() as u64)
    }

    async fn set_last_error(&self, error: Option<String>) {
        *self.last_error.write().await = error;
    }

    async fn get_last_error(&self) -> Option<String> {
        self.last_error.read().await.clone()
    }
}

/// Start the health HTTP server on a separate task
async fn start_health_server(state: Arc<HealthState>) {
    let addr = format!("127.0.0.1:{}", HEALTH_PORT);

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!(op = "health.server.start", addr = %addr, "Health server listening");
            l
        }
        Err(e) => {
            error!(op = "health.server.bind_failed", addr = %addr, error = %e, "Failed to bind health server");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut socket, _)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];

                    // Read request (we only care about GET /health)
                    if socket.read(&mut buf).await.is_err() {
                        return;
                    }

                    let request = String::from_utf8_lossy(&buf);

                    // Only handle GET /health
                    if !request.starts_with("GET /health") {
                        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                        return;
                    }

                    // Build health response
                    let auth_ok = state.is_auth_ok();
                    let last_poll_ms_ago = state.get_last_poll_ms_ago().await;
                    let last_error = state.get_last_error().await;

                    let (status_code, status_text, body) = if auth_ok {
                        let body = serde_json::json!({
                            "status": "ok",
                            "mode": "engine",
                            "auth": "ok",
                            "last_poll_ms_ago": last_poll_ms_ago,
                            "last_error": last_error
                        });
                        (200, "OK", body)
                    } else {
                        let body = serde_json::json!({
                            "status": "starting",
                            "mode": "engine",
                            "auth": "pending",
                            "last_poll_ms_ago": serde_json::Value::Null,
                            "last_error": last_error
                        });
                        (503, "Service Unavailable", body)
                    };

                    let body_str = serde_json::to_string(&body).unwrap_or_default();
                    let response = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        status_code, status_text, body_str.len(), body_str
                    );

                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
            Err(e) => {
                warn!(op = "health.server.accept_failed", error = %e, "Failed to accept connection");
            }
        }
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Runner mode - determines which queue to poll
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerMode {
    /// Poll local node job queue (default)
    Node,
    /// Poll engine runner_tasks queue (RAPTOR-3 Step 4)
    Engine,
}

impl std::fmt::Display for RunnerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerMode::Node => write!(f, "node"),
            RunnerMode::Engine => write!(f, "engine"),
        }
    }
}

const DEFAULT_NODE_URL: &str = "http://127.0.0.1:7777";
const POLL_INTERVAL_SECS: u64 = 5;
const MAX_POLL_LIMIT: u32 = 10;

// =============================================================================
// Node Runner API Types (DEPRECATED - for node mode only)
// =============================================================================

#[derive(Debug, Deserialize)]
struct PollResponse {
    jobs: Vec<PollJobInfo>,
}

#[derive(Debug, Deserialize)]
struct PollJobInfo {
    job_id: String,
    workspace_id: String,
    job_type: JobType,
    #[allow(dead_code)]
    status: String,
    #[allow(dead_code)]
    created_at_utc: String,
    payload: Option<JobPayload>,
}

#[derive(Debug, Serialize)]
struct ClaimRequest {
    job_id: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ClaimResponse {
    job_id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct CompleteRequest {
    job_id: String,
    result: String,
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CompleteResponse {
    job_id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct CloneRequest {
    workspace_id: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CloneResponse {
    status: String,
    workspace_id: String,
}

#[derive(Debug, Serialize)]
struct CommitRequest {
    workspace_id: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CommitResponse {
    status: String,
    branch: String,
    #[allow(dead_code)]
    commit_id: String,
    #[allow(dead_code)]
    files_changed: u32,
}

#[derive(Debug, Serialize)]
struct PushRequest {
    workspace_id: String,
}

#[derive(Debug, Deserialize)]
struct PushResponse {
    status: String,
    branch: String,
}

#[derive(Debug, Serialize)]
struct PrRequest {
    workspace_id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrResponse {
    status: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    error: String,
    code: String,
}

#[derive(Debug, Serialize)]
struct AgentRunRequest {
    job_id: String,
    prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    inputs: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct AgentRunResponse {
    #[allow(dead_code)]
    job_id: String,
    artifact_text: Option<String>,
    artifact_json: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct CompleteRequestWithResult {
    job_id: String,
    result: String,
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_json: Option<serde_json::Value>,
}

// =============================================================================
// Node Runner Implementation (DEPRECATED)
// =============================================================================

struct Runner {
    client: Client,
    node_url: String,
    session_id: String,
}

impl Runner {
    fn new(node_url: String, session_id: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            node_url,
            session_id,
        }
    }

    fn idempotency_key(&self, job_id: &str, op: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(job_id.as_bytes());
        hasher.update(b":");
        hasher.update(op.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..16])
    }

    async fn poll_jobs(&self) -> Result<Vec<PollJobInfo>, String> {
        let url = format!("{}/v0/runner/poll?limit={}", self.node_url, MAX_POLL_LIMIT);

        let response = self
            .client
            .get(&url)
            .header("X-Session-Id", &self.session_id)
            .send()
            .await
            .map_err(|e| format!("Poll request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!(
                "Poll failed ({}): {} ({})",
                status, error.error, error.code
            ));
        }

        let poll: PollResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse poll response: {}", e))?;

        Ok(poll.jobs)
    }

    async fn claim_job(&self, job_id: &str) -> Result<ClaimResponse, String> {
        let url = format!("{}/v0/runner/claim", self.node_url);

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .json(&ClaimRequest {
                job_id: job_id.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("Claim request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!(
                "Claim failed ({}): {} ({})",
                status, error.error, error.code
            ));
        }

        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse claim response: {}", e))
    }

    async fn complete_job(
        &self,
        job_id: &str,
        result: &str,
        code: &str,
        message: &str,
    ) -> Result<(), String> {
        let url = format!("{}/v0/runner/complete", self.node_url);

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .json(&CompleteRequest {
                job_id: job_id.to_string(),
                result: result.to_string(),
                code: code.to_string(),
                message: message.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("Complete request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!(
                "Complete failed ({}): {} ({})",
                status, error.error, error.code
            ));
        }

        Ok(())
    }

    async fn complete_job_with_result(
        &self,
        job_id: &str,
        result: &str,
        code: &str,
        message: &str,
        artifact_text: Option<String>,
        artifact_json: Option<serde_json::Value>,
    ) -> Result<(), String> {
        let url = format!("{}/v0/runner/complete", self.node_url);

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .json(&CompleteRequestWithResult {
                job_id: job_id.to_string(),
                result: result.to_string(),
                code: code.to_string(),
                message: message.to_string(),
                artifact_text,
                artifact_json,
            })
            .send()
            .await
            .map_err(|e| format!("Complete request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!(
                "Complete failed ({}): {} ({})",
                status, error.error, error.code
            ));
        }

        Ok(())
    }

    async fn agent_run(
        &self,
        job_id: &str,
        prompt: &str,
        inputs: Option<&serde_json::Value>,
    ) -> Result<AgentRunResponse, String> {
        let url = format!("{}/v0/agent/run", self.node_url);
        let idem_key = self.idempotency_key(job_id, "agent_run");

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .header("x-idempotency-key", &idem_key)
            .json(&AgentRunRequest {
                job_id: job_id.to_string(),
                prompt: prompt.to_string(),
                inputs: inputs.cloned(),
            })
            .send()
            .await
            .map_err(|e| format!("Agent run request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!("Agent run failed ({}): {}", status, error.code));
        }

        let agent_response: AgentRunResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse agent response: {}", e))?;

        info!(
            op = "runner.agent.ok",
            prompt_len = %prompt.len(),
            has_text = %agent_response.artifact_text.is_some(),
            has_json = %agent_response.artifact_json.is_some(),
            "Agent run completed"
        );

        Ok(agent_response)
    }

    async fn git_clone(&self, workspace_id: &str, job_id: &str) -> Result<(), String> {
        let url = format!("{}/v0/git/clone", self.node_url);
        let idem_key = self.idempotency_key(job_id, "clone");

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .header("x-idempotency-key", &idem_key)
            .json(&CloneRequest {
                workspace_id: workspace_id.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("Clone request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!("Clone failed ({}): {}", status, error.code));
        }

        let _clone: CloneResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse clone response: {}", e))?;

        info!(op = "runner.clone.ok", "Clone completed");
        Ok(())
    }

    async fn git_commit(
        &self,
        workspace_id: &str,
        message: &str,
        job_id: &str,
    ) -> Result<String, String> {
        let url = format!("{}/v0/git/commit", self.node_url);
        let idem_key = self.idempotency_key(job_id, "commit");

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .header("x-idempotency-key", &idem_key)
            .json(&CommitRequest {
                workspace_id: workspace_id.to_string(),
                message: message.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("Commit request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!("Commit failed ({}): {}", status, error.code));
        }

        let commit: CommitResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse commit response: {}", e))?;

        info!(
            op = "runner.commit.ok",
            status = %commit.status,
            "Commit completed"
        );

        Ok(commit.branch)
    }

    async fn git_push(&self, workspace_id: &str, job_id: &str) -> Result<String, String> {
        let url = format!("{}/v0/git/push", self.node_url);
        let idem_key = self.idempotency_key(job_id, "push");

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .header("x-idempotency-key", &idem_key)
            .json(&PushRequest {
                workspace_id: workspace_id.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("Push request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!("Push failed ({}): {}", status, error.code));
        }

        let push: PushResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse push response: {}", e))?;

        info!(
            op = "runner.push.ok",
            status = %push.status,
            "Push completed"
        );

        Ok(push.branch)
    }

    async fn git_pr(
        &self,
        workspace_id: &str,
        title: &str,
        body: Option<&str>,
        _job_id: &str,
    ) -> Result<(), String> {
        let url = format!("{}/v0/git/pr", self.node_url);

        let response = self
            .client
            .post(&url)
            .header("X-Session-Id", &self.session_id)
            .json(&PrRequest {
                workspace_id: workspace_id.to_string(),
                title: title.to_string(),
                body: body.map(|s| s.to_string()),
            })
            .send()
            .await
            .map_err(|e| format!("PR request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Unknown error".to_string(),
                code: "UNKNOWN".to_string(),
            });
            return Err(format!("PR failed ({}): {}", status, error.code));
        }

        let pr: PrResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse PR response: {}", e))?;

        info!(
            op = "runner.pr.ok",
            status = %pr.status,
            code = %pr.code,
            "PR created"
        );

        Ok(())
    }

    async fn execute_repo_workflow(
        &self,
        job: &PollJobInfo,
        payload: &JobPayload,
    ) -> Result<(), String> {
        let (commit_message, pr_title, pr_body) = match &payload.params {
            JobPayloadParams::RepoWorkflow(p) => (
                p.commit_message
                    .clone()
                    .unwrap_or_else(|| "EKKA automated commit".to_string()),
                p.pr_title
                    .clone()
                    .unwrap_or_else(|| "EKKA automated PR".to_string()),
                p.pr_body.clone(),
            ),
            _ => {
                return Err("Payload type mismatch for repo_workflow job".to_string());
            }
        };

        let workspace_id = &job.workspace_id;
        let job_id = &job.job_id;

        info!(op = "runner.workflow.clone", "Starting clone");
        self.git_clone(workspace_id, job_id).await?;

        info!(op = "runner.workflow.commit", "Starting commit");
        let _branch = self.git_commit(workspace_id, &commit_message, job_id).await?;

        info!(op = "runner.workflow.push", "Starting push");
        let _branch = self.git_push(workspace_id, job_id).await?;

        info!(op = "runner.workflow.pr", "Creating PR");
        self.git_pr(workspace_id, &pr_title, pr_body.as_deref(), job_id)
            .await?;

        Ok(())
    }

    async fn execute_agent_run(
        &self,
        job: &PollJobInfo,
        payload: &JobPayload,
    ) -> Result<(Option<String>, Option<serde_json::Value>), String> {
        let (prompt, inputs) = match &payload.params {
            JobPayloadParams::AgentRun(p) => (
                p.prompt
                    .clone()
                    .unwrap_or_else(|| "Process the request".to_string()),
                p.inputs.clone(),
            ),
            _ => {
                return Err("Payload type mismatch for agent_run job".to_string());
            }
        };

        let job_id = &job.job_id;

        info!(
            op = "runner.agent.start",
            prompt_len = %prompt.len(),
            has_inputs = %inputs.is_some(),
            "Starting agent execution"
        );

        let response = self.agent_run(job_id, &prompt, inputs.as_ref()).await?;

        Ok((response.artifact_text, response.artifact_json))
    }

    async fn process_job(&self, job: PollJobInfo) {
        let job_id = job.job_id.clone();
        let job_id_short = &job_id[..8.min(job_id.len())];

        info!(
            op = "runner.job.start",
            job_id = %job_id_short,
            job_type = %job.job_type,
            "Processing job"
        );

        match self.claim_job(&job_id).await {
            Ok(_) => {
                info!(
                    op = "runner.job.claimed",
                    job_id = %job_id_short,
                    "Job claimed"
                );
            }
            Err(e) => {
                warn!(
                    op = "runner.job.claim_failed",
                    job_id = %job_id_short,
                    error = %e,
                    "Failed to claim job"
                );
                return;
            }
        }

        match job.job_type {
            JobType::RepoWorkflow => {
                let payload = match &job.payload {
                    Some(p) => p.clone(),
                    None => JobPayload::repo_workflow(None, None, None),
                };

                match self.execute_repo_workflow(&job, &payload).await {
                    Ok(()) => {
                        info!(
                            op = "runner.job.succeeded",
                            job_id = %job_id_short,
                            "Job completed successfully"
                        );
                        match self
                            .complete_job(&job_id, "succeeded", "OK", "Workflow completed")
                            .await
                        {
                            Ok(()) => {
                                info!(
                                    op = "runner.job.complete_posted",
                                    job_id = %job_id_short,
                                    http_status = 200,
                                    "Complete POST succeeded"
                                );
                            }
                            Err(e) => {
                                error!(
                                    op = "runner.job.complete_failed",
                                    job_id = %job_id_short,
                                    error = %e,
                                    "Failed to mark job as succeeded"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            op = "runner.job.failed",
                            job_id = %job_id_short,
                            error = %e,
                            "Job execution failed"
                        );
                        let code = if e.contains("REPO_NOT_BOUND") {
                            "REPO_NOT_BOUND"
                        } else if e.contains("REPO_NOT_ALLOWED") {
                            "REPO_NOT_ALLOWED"
                        } else if e.contains("GITHUB_NOT_CONNECTED") {
                            "GITHUB_NOT_CONNECTED"
                        } else if e.contains("CAPABILITY_DENIED") {
                            "CAPABILITY_DENIED"
                        } else if e.contains("NO_CHANGES") {
                            "NO_CHANGES"
                        } else {
                            "WORKFLOW_ERROR"
                        };

                        if let Err(complete_err) = self
                            .complete_job(&job_id, "failed", code, "Workflow failed")
                            .await
                        {
                            error!(
                                op = "runner.job.complete_failed",
                                job_id = %job_id_short,
                                error = %complete_err,
                                "Failed to mark job as failed"
                            );
                        }
                    }
                }
            }
            JobType::AgentRun => {
                let payload = match &job.payload {
                    Some(p) => p.clone(),
                    None => JobPayload::agent_run(None, None, None),
                };

                match self.execute_agent_run(&job, &payload).await {
                    Ok((artifact_text, artifact_json)) => {
                        info!(
                            op = "runner.job.succeeded",
                            job_id = %job_id_short,
                            "Agent job completed successfully"
                        );
                        match self
                            .complete_job_with_result(
                                &job_id,
                                "succeeded",
                                "OK",
                                "Agent execution completed",
                                artifact_text,
                                artifact_json,
                            )
                            .await
                        {
                            Ok(()) => {
                                info!(
                                    op = "runner.job.complete_posted",
                                    job_id = %job_id_short,
                                    http_status = 200,
                                    "Complete POST succeeded"
                                );
                            }
                            Err(e) => {
                                error!(
                                    op = "runner.job.complete_failed",
                                    job_id = %job_id_short,
                                    error = %e,
                                    "Failed to mark job as succeeded"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            op = "runner.job.failed",
                            job_id = %job_id_short,
                            error = %e,
                            "Agent execution failed"
                        );
                        let code = if e.contains("CAPABILITY_DENIED") {
                            "CAPABILITY_DENIED"
                        } else if e.contains("PROMPT_TOO_LARGE") {
                            "PROMPT_TOO_LARGE"
                        } else if e.contains("INPUTS_TOO_LARGE") {
                            "INPUTS_TOO_LARGE"
                        } else {
                            "AGENT_ERROR"
                        };

                        if let Err(complete_err) = self
                            .complete_job(&job_id, "failed", code, "Agent execution failed")
                            .await
                        {
                            error!(
                                op = "runner.job.complete_failed",
                                job_id = %job_id_short,
                                error = %complete_err,
                                "Failed to mark job as failed"
                            );
                        }
                    }
                }
            }
            _ => {
                warn!(
                    op = "runner.job.unsupported",
                    job_id = %job_id_short,
                    job_type = %job.job_type,
                    "Unsupported job type"
                );
                let _ = self
                    .complete_job(&job_id, "failed", "UNSUPPORTED_JOB", "Unsupported job type")
                    .await;
            }
        }
    }

    async fn run(&self) {
        info!(op = "runner.start", "Local runner starting");

        loop {
            match self.poll_jobs().await {
                Ok(jobs) => {
                    if jobs.is_empty() {
                        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                        continue;
                    }

                    info!(
                        op = "runner.poll.found",
                        count = jobs.len(),
                        "Found queued jobs"
                    );

                    for job in jobs {
                        self.process_job(job).await;
                    }
                }
                Err(e) => {
                    error!(op = "runner.poll.error", error = %e, "Poll failed");
                    tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

// =============================================================================
// Engine Runner Implementation moved to ekka-runner-core library
// =============================================================================

// =============================================================================
// Health State Callback for Engine Mode
// =============================================================================

/// Callback implementation that updates health state
struct HealthStateCallback {
    state: Arc<HealthState>,
}

impl ekka_runner_core::RunnerStateCallback for HealthStateCallback {
    fn on_start(&self, runner_id: &str) {
        // on_start is called after successful auth
        self.state.set_auth_ok();
        info!(op = "health.auth_ok", runner_id = %runner_id, "Health state: auth successful");
    }

    fn on_poll(&self) {
        // Update last poll timestamp
        let state = self.state.clone();
        tokio::spawn(async move {
            state.set_last_poll().await;
        });
    }

    fn on_claim(&self, _task_id: &str) {}

    fn on_complete(&self, _task_id: &str) {
        // Clear any previous error on success
        let state = self.state.clone();
        tokio::spawn(async move {
            state.set_last_error(None).await;
        });
    }

    fn on_error(&self, error: &str) {
        let state = self.state.clone();
        let error = error.to_string();
        tokio::spawn(async move {
            state.set_last_error(Some(error)).await;
        });
    }

    fn on_stop(&self) {}
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ekka_runner_local=info".parse().unwrap()),
        )
        .with_target(true)
        .init();

    let mode = match std::env::var("EKKA_RUNNER_MODE").as_deref() {
        Ok("node") => RunnerMode::Node,
        Ok("engine") | Err(_) => RunnerMode::Engine,
        Ok(other) => {
            error!(
                op = "runner.init.error",
                mode = %other,
                "Invalid EKKA_RUNNER_MODE (must be 'node' or 'engine')"
            );
            std::process::exit(1);
        }
    };

    info!(op = "runner.init", mode = %mode, "Runner mode selected");

    match mode {
        RunnerMode::Node => {
            warn!(
                op = "runner.init.deprecated",
                mode = "node",
                "Node runner mode is DEPRECATED - migrate to engine mode (EKKA_RUNNER_MODE=engine)"
            );

            let node_queue_mode = std::env::var("EKKA_NODE_JOB_QUEUE_MODE").unwrap_or_default();
            if node_queue_mode != "legacy" {
                error!(
                    op = "runner.init.error",
                    node_queue_mode = %node_queue_mode,
                    "Node runner requires EKKA_NODE_JOB_QUEUE_MODE=legacy"
                );
                std::process::exit(1);
            }

            let node_url =
                std::env::var("NODE_URL").unwrap_or_else(|_| DEFAULT_NODE_URL.to_string());

            let session_id = match std::env::var("EKKA_RUNNER_SESSION_ID") {
                Ok(id) if !id.is_empty() => id,
                _ => {
                    error!(
                        op = "runner.init.error",
                        "EKKA_RUNNER_SESSION_ID environment variable is required in node mode"
                    );
                    std::process::exit(1);
                }
            };

            info!(
                op = "runner.init",
                mode = "node",
                session_id_len = session_id.len(),
                "Node runner initialized (DEPRECATED - use engine mode)"
            );

            let runner = Runner::new(node_url, session_id);
            runner.run().await;
        }
        RunnerMode::Engine => {
            // Use ekka-runner-core library for engine mode
            let config = match ekka_runner_core::RunnerConfig::from_env() {
                Ok(c) => c,
                Err(e) => {
                    error!(op = "runner.init.error", error = %e, "Config error");
                    std::process::exit(1);
                }
            };

            // Cleanup old debug bundles on startup (dev mode only)
            executors::debug_bundle::cleanup_old_bundles();

            let node_queue_mode = std::env::var("EKKA_NODE_JOB_QUEUE_MODE").unwrap_or_default();
            if node_queue_mode == "legacy" {
                error!(op = "runner.init.error", "Engine mode requires EKKA_NODE_JOB_QUEUE_MODE=disabled");
                std::process::exit(1);
            }

            info!(
                op = "runner.init",
                mode = "engine",
                tenant_id_prefix = %config.tenant_id.as_ref().map(|s| s.chars().take(8).collect::<String>()).unwrap_or_else(|| "pending".to_string()),
                workspace_id_prefix = %config.workspace_id.as_ref().map(|s| s.chars().take(8).collect::<String>()).unwrap_or_else(|| "pending".to_string()),
                "Engine runner initialized (using ekka-runner-core)"
            );

            // Create shared health state
            let health_state = Arc::new(HealthState::new());

            // Start health server in background
            let health_state_clone = health_state.clone();
            tokio::spawn(async move {
                start_health_server(health_state_clone).await;
            });

            // Create health state callback
            let callback = Arc::new(HealthStateCallback {
                state: health_state,
            });

            // Create shutdown channel
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

            // Handle Ctrl+C for graceful shutdown
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                info!(op = "runner.shutdown.signal", "Ctrl+C received");
                let _ = shutdown_tx.send(true);
            });

            if let Err(e) = ekka_runner_core::run_engine_runner_loop(config, Some(callback), shutdown_rx).await {
                error!(op = "runner.error", error = %e, "Runner error");
                std::process::exit(1);
            }
        }
    }
}
