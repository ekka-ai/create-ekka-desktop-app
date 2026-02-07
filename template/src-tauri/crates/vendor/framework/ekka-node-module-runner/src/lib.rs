//! EKKA Node Runner Module - RAPTOR-2 Step 33 + RAPTOR-3 Step 1
//!
//! Provides the execution boundary between EKKA jobs and agent runners.
//! Runners can claim queued jobs, execute them, and report completion.
//!
//! ## Security Properties
//!
//! - No absolute paths in responses (only workspace_id and job_id)
//! - Session validation before capability checks (401 then 403)
//! - Capability-gated: runner.read, runner.claim, runner.complete
//! - Job state machine: queued -> running -> succeeded/failed
//! - Audit events for job lifecycle
//! - Structured logging with node.runner.* prefix
//!
//! ## Lease-Based Job Claiming (RAPTOR-3 Step 1)
//!
//! - Runners identify themselves via X-Runner-Id header
//! - Jobs are claimed with time-limited leases (default 5 min)
//! - Runners must heartbeat to extend leases for long-running jobs
//! - Stale jobs (expired lease) can be reclaimed by other runners
//! - Complete verifies lease ownership before marking job done
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - A RunnerModuleContext with job store and audit store
//!
//! When disabled via EKKA_ENABLE_RUNNER=0, routes are NOT mounted -> 404.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

pub use ekka_node_modules::{
    error_codes, ModuleConfig, ModuleError,
    SessionInfo, SessionValidationError, SessionValidator,
};

// Re-export job types from jobs module for convenience
pub use ekka_node_module_jobs::{Job, JobResult, JobStatus, JobStore, JobType};

// =============================================================================
// Module Configuration
// =============================================================================

/// Runner module configuration
pub const RUNNER_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Runner",
    env_var: "EKKA_ENABLE_RUNNER",
    default_enabled: false, // Disabled by default; privileged operation
};

/// Required capability for runner read operations (poll)
pub const RUNNER_READ_CAPABILITY: &str = "runner.read";

/// Required capability for claiming jobs
pub const RUNNER_CLAIM_CAPABILITY: &str = "runner.claim";

/// Required capability for completing jobs
pub const RUNNER_COMPLETE_CAPABILITY: &str = "runner.complete";

/// Maximum limit for poll query
pub const MAX_POLL_LIMIT: usize = 20;

/// Maximum audit events in ring buffer
const AUDIT_MAX_EVENTS: usize = 200;

/// Header name for runner ID (RAPTOR-3 Step 1)
pub const RUNNER_ID_HEADER: &str = "x-runner-id";

/// Default lease duration in seconds (RAPTOR-3 Step 1)
pub const DEFAULT_LEASE_DURATION_SECS: i64 = 300; // 5 minutes

/// Callback type for persisting job state changes (RAPTOR-3 Step 2)
pub type PersistCallback = Arc<dyn Fn() + Send + Sync>;

// =============================================================================
// Runner Audit Types
// =============================================================================

/// Runner audit event - safe fields only, no paths/URLs/tokens
#[derive(Debug, Clone, Serialize)]
pub struct RunnerAuditEvent {
    /// Timestamp in ISO 8601 UTC
    pub ts_utc: String,
    /// Job ID
    pub job_id: String,
    /// Workspace ID
    pub workspace_id: String,
    /// Operation: job.claimed, job.completed
    pub op: String,
    /// Result: ok or err
    pub result: String,
    /// Stable code: OK, SUCCEEDED, FAILED, or error code
    pub code: String,
    /// Session key (sha256 truncated of tenant:subject, not raw)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
}

impl RunnerAuditEvent {
    /// Create a new audit event
    pub fn new(
        job_id: &str,
        workspace_id: &str,
        op: &str,
        result: &str,
        code: &str,
        tenant_id: Option<&str>,
        subject: Option<&str>,
    ) -> Self {
        let session_key = match (tenant_id, subject) {
            (Some(t), Some(s)) => {
                let mut hasher = Sha256::new();
                hasher.update(t.as_bytes());
                hasher.update(b":");
                hasher.update(s.as_bytes());
                let hash = hasher.finalize();
                Some(hex::encode(&hash[..8])) // 16 hex chars, truncated
            }
            _ => None,
        };

        Self {
            ts_utc: Utc::now().to_rfc3339(),
            job_id: job_id.to_string(),
            workspace_id: workspace_id.to_string(),
            op: op.to_string(),
            result: result.to_string(),
            code: code.to_string(),
            session_key,
        }
    }
}

/// In-memory runner audit ring buffer
#[derive(Default)]
pub struct RunnerAuditStore {
    /// Events by job_id
    events: RwLock<HashMap<String, Vec<RunnerAuditEvent>>>,
}

impl RunnerAuditStore {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
        }
    }

    /// Record an audit event
    pub fn record(&self, event: RunnerAuditEvent) {
        if let Ok(mut events) = self.events.write() {
            let job_events = events.entry(event.job_id.clone()).or_insert_with(Vec::new);
            job_events.push(event);

            // Keep only last AUDIT_MAX_EVENTS per job
            if job_events.len() > AUDIT_MAX_EVENTS {
                let excess = job_events.len() - AUDIT_MAX_EVENTS;
                job_events.drain(0..excess);
            }
        }
    }

    /// Get events for a job (most recent first)
    #[allow(dead_code)]
    pub fn get(&self, job_id: &str, limit: usize) -> Vec<RunnerAuditEvent> {
        if let Ok(events) = self.events.read() {
            if let Some(job_events) = events.get(job_id) {
                let start = job_events.len().saturating_sub(limit);
                return job_events[start..].iter().rev().cloned().collect();
            }
        }
        Vec::new()
    }

    /// Get all events (for testing)
    #[allow(dead_code)]
    pub fn all_events(&self) -> Vec<RunnerAuditEvent> {
        if let Ok(events) = self.events.read() {
            events.values().flatten().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

// =============================================================================
// API Request/Response Types
// =============================================================================

/// Claim job request
#[derive(Debug, Deserialize)]
pub struct ClaimJobRequest {
    /// Job ID to claim
    pub job_id: String,
}

/// Claim job response
#[derive(Debug, Serialize)]
pub struct ClaimJobResponse {
    pub job_id: String,
    pub status: JobStatus,
}

/// Complete job request
#[derive(Debug, Deserialize)]
pub struct CompleteJobRequest {
    /// Job ID to complete
    pub job_id: String,
    /// Result: succeeded or failed
    pub result: String,
    /// Result code (e.g., "OK", "ERROR")
    #[serde(default)]
    pub code: Option<String>,
    /// Result message (safe string, no paths/URLs)
    #[serde(default)]
    pub message: Option<String>,
    /// Text artifact (for agent_run, RAPTOR-2 Step 35)
    #[serde(default)]
    pub artifact_text: Option<String>,
    /// JSON artifact (for agent_run, RAPTOR-2 Step 35)
    #[serde(default)]
    pub artifact_json: Option<serde_json::Value>,
}

/// Complete job response
#[derive(Debug, Serialize)]
pub struct CompleteJobResponse {
    pub job_id: String,
    pub status: JobStatus,
}

/// Heartbeat request (RAPTOR-3 Step 1)
#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    /// Job ID to heartbeat
    pub job_id: String,
    /// Lease duration in seconds (optional, defaults to DEFAULT_LEASE_DURATION_SECS)
    #[serde(default)]
    pub lease_duration_secs: Option<i64>,
}

/// Heartbeat response (RAPTOR-3 Step 1)
#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub job_id: String,
    pub lease_expires_at_utc: String,
}

/// Poll query parameters
#[derive(Debug, Deserialize)]
pub struct PollQuery {
    /// Maximum jobs to return (default 10, max 20)
    #[serde(default = "default_poll_limit")]
    pub limit: usize,
}

fn default_poll_limit() -> usize {
    10
}

/// Poll job info (subset of job fields)
#[derive(Debug, Serialize)]
pub struct PollJobInfo {
    pub job_id: String,
    pub workspace_id: String,
    pub job_type: JobType,
    pub status: JobStatus,
    pub created_at_utc: String,
    /// Job payload with execution parameters (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ekka_node_module_jobs::JobPayload>,
    // === Retry fields (RAPTOR-3 Step 3) ===
    /// Current attempt count (0 = first attempt, 1+ = retry)
    pub attempt_count: u32,
    /// Maximum attempts before terminal failure
    pub max_attempts: u32,
    /// Last error code from previous failed attempt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
}

/// Poll response
#[derive(Debug, Serialize)]
pub struct PollResponse {
    pub jobs: Vec<PollJobInfo>,
}

/// Runner error response
#[derive(Debug, Serialize)]
pub struct RunnerError {
    pub error: String,
    pub code: String,
}

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Context for the Runner module
#[derive(Clone)]
pub struct RunnerModuleContext {
    /// Job store (shared with jobs module)
    pub job_store: Arc<JobStore>,
    /// Audit store for runner events
    pub audit_store: Arc<RunnerAuditStore>,
    /// Session validator (provided by host for request-time auth)
    pub session_validator: SessionValidator,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
    /// Optional persist callback (RAPTOR-3 Step 2)
    /// Called after claim/complete to persist job state
    pub persist_callback: Option<PersistCallback>,
}

impl RunnerModuleContext {
    pub fn new(
        job_store: Arc<JobStore>,
        audit_store: Arc<RunnerAuditStore>,
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            job_store,
            audit_store,
            session_validator,
            log_prefix: log_prefix.into(),
            persist_callback: None,
        }
    }

    /// Create context with persistence callback (RAPTOR-3 Step 2)
    pub fn with_persist(
        job_store: Arc<JobStore>,
        audit_store: Arc<RunnerAuditStore>,
        session_validator: SessionValidator,
        log_prefix: impl Into<String>,
        persist_callback: PersistCallback,
    ) -> Self {
        Self {
            job_store,
            audit_store,
            session_validator,
            log_prefix: log_prefix.into(),
            persist_callback: Some(persist_callback),
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.runner.{}", self.log_prefix, op)
    }

    /// Call persist callback if configured (RAPTOR-3 Step 2)
    fn persist(&self) {
        if let Some(ref callback) = self.persist_callback {
            callback();
        }
    }
}

/// Mount the Runner module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: RunnerModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !RUNNER_MODULE_CONFIG.is_enabled() {
        info!(
            module = "runner",
            enabled = false,
            "Runner module disabled (set EKKA_ENABLE_RUNNER=1 to enable)"
        );
        return router;
    }

    info!(
        module = "runner",
        enabled = true,
        "Runner module enabled"
    );

    let state = Arc::new(ctx);

    // Create a sub-router with our state, then merge into main router
    let runner_router: Router<S> = Router::new()
        .route("/v0/runner/claim", post(runner_claim_handler))
        .route("/v0/runner/complete", post(runner_complete_handler))
        .route("/v0/runner/poll", get(runner_poll_handler))
        .route("/v0/runner/heartbeat", post(runner_heartbeat_handler))
        .with_state(state);

    router.merge(runner_router)
}

// =============================================================================
// Axum Handlers
// =============================================================================

/// Extract runner ID from X-Runner-Id header
fn extract_runner_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(RUNNER_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 100)
}

/// POST /v0/runner/claim - Claim a queued job
/// Requires: valid session + "runner.claim" capability + X-Runner-Id header
/// Transitions job from queued to running with lease
async fn runner_claim_handler(
    State(ctx): State<Arc<RunnerModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<ClaimJobRequest>,
) -> Result<Json<ClaimJobResponse>, (StatusCode, Json<RunnerError>)> {
    info!(
        op = %ctx.log_op("claim.request"),
        "Runner claim requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("claim.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(RunnerError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if session.require_capability(RUNNER_CLAIM_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("claim.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(RunnerError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Extract runner ID from header (RAPTOR-3 Step 1)
    let runner_id = extract_runner_id(&headers).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("claim.missing_runner_id"),
            "Missing or invalid X-Runner-Id header"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(RunnerError {
                error: "Missing or invalid X-Runner-Id header".to_string(),
                code: "MISSING_RUNNER_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Parse job_id
    let job_id = request.job_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("claim.invalid_job_id"),
            "Invalid job ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(RunnerError {
                error: "Invalid job ID".to_string(),
                code: "INVALID_JOB_ID".to_string(),
            }),
        )
    })?;

    // Step 5: Get job to check existence and get workspace_id for audit
    let job = ctx.job_store.get_job(job_id).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("claim.job_not_found"),
            "Job not found"
        );
        ctx.audit_store.record(RunnerAuditEvent::new(
            &request.job_id,
            "",
            "job.claimed",
            "err",
            "JOB_NOT_FOUND",
            Some(&session.tenant_id),
            Some(&session.user_id),
        ));
        (
            StatusCode::NOT_FOUND,
            Json(RunnerError {
                error: "Job not found".to_string(),
                code: "JOB_NOT_FOUND".to_string(),
            }),
        )
    })?;

    // Step 6: Claim job with lease (RAPTOR-3 Step 1)
    let claimed_job = ctx.job_store.claim_job(
        job_id,
        &runner_id,
        DEFAULT_LEASE_DURATION_SECS,
    ).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("claim.job_not_claimable"),
            job_status = %job.status,
            "Job not claimable"
        );
        ctx.audit_store.record(RunnerAuditEvent::new(
            &request.job_id,
            &job.workspace_id.to_string(),
            "job.claimed",
            "err",
            "JOB_NOT_CLAIMABLE",
            Some(&session.tenant_id),
            Some(&session.user_id),
        ));
        (
            StatusCode::CONFLICT,
            Json(RunnerError {
                error: "Job not claimable (not queued, already claimed, or max attempts reached)".to_string(),
                code: "JOB_NOT_CLAIMABLE".to_string(),
            }),
        )
    })?;

    // Step 7: Record audit event
    ctx.audit_store.record(RunnerAuditEvent::new(
        &request.job_id,
        &job.workspace_id.to_string(),
        "job.claimed",
        "ok",
        "OK",
        Some(&session.tenant_id),
        Some(&session.user_id),
    ));

    // Persist job state change (RAPTOR-3 Step 2)
    ctx.persist();

    info!(
        op = %ctx.log_op("claim.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        runner_id = %&runner_id[..8.min(runner_id.len())],
        job_id = %job_id,
        attempt = claimed_job.attempt_count,
        "Job claimed successfully"
    );

    Ok(Json(ClaimJobResponse {
        job_id: job_id.to_string(),
        status: JobStatus::Running,
    }))
}

/// POST /v0/runner/complete - Complete a running job
/// Requires: valid session + "runner.complete" capability + X-Runner-Id header
/// Transitions job from running to succeeded/failed with lease verification
async fn runner_complete_handler(
    State(ctx): State<Arc<RunnerModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<CompleteJobRequest>,
) -> Result<Json<CompleteJobResponse>, (StatusCode, Json<RunnerError>)> {
    info!(
        op = %ctx.log_op("complete.request"),
        "Runner complete requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("complete.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(RunnerError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if session.require_capability(RUNNER_COMPLETE_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("complete.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(RunnerError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Extract runner ID from header (RAPTOR-3 Step 1)
    let runner_id = extract_runner_id(&headers).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("complete.missing_runner_id"),
            "Missing or invalid X-Runner-Id header"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(RunnerError {
                error: "Missing or invalid X-Runner-Id header".to_string(),
                code: "MISSING_RUNNER_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Parse job_id
    let job_id = request.job_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("complete.invalid_job_id"),
            "Invalid job ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(RunnerError {
                error: "Invalid job ID".to_string(),
                code: "INVALID_JOB_ID".to_string(),
            }),
        )
    })?;

    // Step 5: Parse result status
    let result_status = match request.result.to_lowercase().as_str() {
        "succeeded" => JobStatus::Succeeded,
        "failed" => JobStatus::Failed,
        _ => {
            warn!(
                op = %ctx.log_op("complete.invalid_result"),
                "Invalid result value"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(RunnerError {
                    error: "Invalid result. Must be 'succeeded' or 'failed'".to_string(),
                    code: "INVALID_RESULT".to_string(),
                }),
            ));
        }
    };

    // Step 6: Get job to check existence and get workspace_id for audit
    let job = ctx.job_store.get_job(job_id).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("complete.job_not_found"),
            "Job not found"
        );
        ctx.audit_store.record(RunnerAuditEvent::new(
            &request.job_id,
            "",
            "job.completed",
            "err",
            "JOB_NOT_FOUND",
            Some(&session.tenant_id),
            Some(&session.user_id),
        ));
        (
            StatusCode::NOT_FOUND,
            Json(RunnerError {
                error: "Job not found".to_string(),
                code: "JOB_NOT_FOUND".to_string(),
            }),
        )
    })?;

    // Step 7: Sanitize code and message
    let code = request.code.map(|c| sanitize_string(&c, 50));
    let message = request.message.map(|m| sanitize_string(&m, 200));

    // Step 7b: Build JobResult with artifacts if provided (RAPTOR-2 Step 35)
    let job_result = if request.artifact_text.is_some() || request.artifact_json.is_some() {
        let mut result = JobResult {
            status: request.result.clone(),
            code: code.clone().unwrap_or_else(|| "OK".to_string()),
            message: message.clone(),
            artifact_text: request.artifact_text.map(|t| sanitize_string(&t, 64 * 1024)),
            artifact_json: request.artifact_json,
        };
        // Sanitize and validate result
        result.sanitize();
        if let Err(e) = result.validate() {
            warn!(
                op = %ctx.log_op("complete.invalid_result"),
                error = %e,
                "Result validation failed"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(RunnerError {
                    error: "Result contains forbidden patterns".to_string(),
                    code: "INVALID_RESULT_DATA".to_string(),
                }),
            ));
        }
        Some(result)
    } else {
        None
    };

    // Step 8: Complete job with lease verification (RAPTOR-3 Step 1)
    let _completed_job = ctx.job_store.complete_job_with_lease(
        job_id,
        &runner_id,
        result_status,
        code.clone(),
        message,
        job_result,
    ).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("complete.lease_not_owned"),
            "Lease not owned by this runner"
        );
        ctx.audit_store.record(RunnerAuditEvent::new(
            &request.job_id,
            &job.workspace_id.to_string(),
            "job.completed",
            "err",
            "LEASE_NOT_OWNED",
            Some(&session.tenant_id),
            Some(&session.user_id),
        ));
        (
            StatusCode::CONFLICT,
            Json(RunnerError {
                error: "Lease not owned by this runner (job may have been reclaimed)".to_string(),
                code: "LEASE_NOT_OWNED".to_string(),
            }),
        )
    })?;

    // Step 9: Record audit event
    let audit_code = match result_status {
        JobStatus::Succeeded => code.clone().unwrap_or_else(|| "SUCCEEDED".to_string()),
        JobStatus::Failed => code.clone().unwrap_or_else(|| "FAILED".to_string()),
        _ => "OK".to_string(),
    };

    ctx.audit_store.record(RunnerAuditEvent::new(
        &request.job_id,
        &job.workspace_id.to_string(),
        "job.completed",
        "ok",
        &audit_code,
        Some(&session.tenant_id),
        Some(&session.user_id),
    ));

    // Persist job state change (RAPTOR-3 Step 2)
    ctx.persist();

    info!(
        op = %ctx.log_op("complete.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        runner_id = %&runner_id[..8.min(runner_id.len())],
        job_id = %job_id,
        result = %result_status,
        "Job completed successfully"
    );

    Ok(Json(CompleteJobResponse {
        job_id: job_id.to_string(),
        status: result_status,
    }))
}

/// GET /v0/runner/poll?limit=<n> - Poll for queued jobs
/// Requires: valid session + "runner.read" capability
/// Returns queued jobs across all workspaces
async fn runner_poll_handler(
    State(ctx): State<Arc<RunnerModuleContext>>,
    headers: HeaderMap,
    Query(query): Query<PollQuery>,
) -> Result<Json<PollResponse>, (StatusCode, Json<RunnerError>)> {
    info!(
        op = %ctx.log_op("poll.request"),
        "Runner poll requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("poll.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(RunnerError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (request-time authorization)
    if session.require_capability(RUNNER_READ_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("poll.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(RunnerError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Enforce limit bounds (max 20)
    let limit = query.limit.min(MAX_POLL_LIMIT);

    // Step 4: Get claimable jobs from store (RAPTOR-3 Step 1)
    // This includes queued jobs AND running jobs with expired leases
    let claimable_jobs = ctx.job_store.list_claimable_jobs(limit);

    let poll_jobs: Vec<PollJobInfo> = claimable_jobs
        .iter()
        .map(|j| PollJobInfo {
            job_id: j.job_id.to_string(),
            workspace_id: j.workspace_id.to_string(),
            job_type: j.job_type,
            status: j.status,
            created_at_utc: j.created_at.to_rfc3339(),
            payload: j.payload.clone(),
            // Retry fields (RAPTOR-3 Step 3)
            attempt_count: j.attempt_count,
            max_attempts: j.max_attempts,
            last_error_code: j.last_error_code.clone(),
        })
        .collect();

    info!(
        op = %ctx.log_op("poll.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        count = %poll_jobs.len(),
        "Poll complete"
    );

    Ok(Json(PollResponse { jobs: poll_jobs }))
}

/// POST /v0/runner/heartbeat - Extend lease on a running job (RAPTOR-3 Step 1)
/// Requires: valid session + "runner.claim" capability + X-Runner-Id header
/// Extends the lease expiry time for a job the runner owns
async fn runner_heartbeat_handler(
    State(ctx): State<Arc<RunnerModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, Json<RunnerError>)> {
    info!(
        op = %ctx.log_op("heartbeat.request"),
        "Runner heartbeat requested"
    );

    // Step 1: Validate session via host-provided validator (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("heartbeat.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(RunnerError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability (uses claim capability for heartbeat)
    if session.require_capability(RUNNER_CLAIM_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("heartbeat.capability_denied"),
            session_id = %&session.session_id[..8.min(session.session_id.len())],
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(RunnerError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Extract runner ID from header
    let runner_id = extract_runner_id(&headers).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("heartbeat.missing_runner_id"),
            "Missing or invalid X-Runner-Id header"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(RunnerError {
                error: "Missing or invalid X-Runner-Id header".to_string(),
                code: "MISSING_RUNNER_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Parse job_id
    let job_id = request.job_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("heartbeat.invalid_job_id"),
            "Invalid job ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(RunnerError {
                error: "Invalid job ID".to_string(),
                code: "INVALID_JOB_ID".to_string(),
            }),
        )
    })?;

    // Step 5: Get lease duration (use default if not specified)
    let lease_duration_secs = request.lease_duration_secs.unwrap_or(DEFAULT_LEASE_DURATION_SECS);

    // Step 6: Heartbeat the job (extend lease)
    let updated_job = ctx.job_store.heartbeat_job(
        job_id,
        &runner_id,
        lease_duration_secs,
    ).ok_or_else(|| {
        warn!(
            op = %ctx.log_op("heartbeat.lease_not_owned"),
            "Lease not owned by this runner"
        );
        (
            StatusCode::CONFLICT,
            Json(RunnerError {
                error: "Lease not owned by this runner (job may have been reclaimed)".to_string(),
                code: "LEASE_NOT_OWNED".to_string(),
            }),
        )
    })?;

    let lease_expires_at_utc = updated_job.lease_expires_at
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();

    info!(
        op = %ctx.log_op("heartbeat.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        runner_id = %&runner_id[..8.min(runner_id.len())],
        job_id = %job_id,
        "Heartbeat successful"
    );

    Ok(Json(HeartbeatResponse {
        job_id: job_id.to_string(),
        lease_expires_at_utc,
    }))
}

/// Sanitize a string to remove control characters and limit length
fn sanitize_string(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
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
        assert!(!json.to_lowercase().contains("secret"), "Leaked sensitive word: {}", json);
        assert!(!json.to_lowercase().contains("token"), "Leaked token: {}", json);
        // No URLs
        assert!(!json.contains("github.com"), "Leaked URL: {}", json);
        assert!(!json.contains("https://"), "Leaked URL scheme: {}", json);
        // No env vars
        assert!(!json.contains("EKKA_"), "Leaked env var: {}", json);
    }

    // =========================================================================
    // Module Config Tests
    // =========================================================================

    #[test]
    fn test_module_config_default_disabled() {
        // Runner should be disabled by default (privileged operation)
        assert!(!RUNNER_MODULE_CONFIG.default_enabled);
    }

    #[test]
    fn test_capability_constants() {
        assert_eq!(RUNNER_READ_CAPABILITY, "runner.read");
        assert_eq!(RUNNER_CLAIM_CAPABILITY, "runner.claim");
        assert_eq!(RUNNER_COMPLETE_CAPABILITY, "runner.complete");
    }

    #[test]
    fn test_max_poll_limit() {
        assert_eq!(MAX_POLL_LIMIT, 20);
    }

    // =========================================================================
    // Audit Event Tests
    // =========================================================================

    #[test]
    fn test_audit_event_session_key_hashed() {
        let event = RunnerAuditEvent::new(
            "job-123",
            "ws-456",
            "job.claimed",
            "ok",
            "OK",
            Some("tenant-abc"),
            Some("subject-xyz"),
        );

        // Session key should be present and hashed (not raw tenant:subject)
        assert!(event.session_key.is_some());
        let key = event.session_key.unwrap();
        assert!(!key.contains("tenant-abc"));
        assert!(!key.contains("subject-xyz"));
        assert_eq!(key.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_audit_event_no_session_key_when_missing() {
        let event = RunnerAuditEvent::new(
            "job-123",
            "ws-456",
            "job.claimed",
            "err",
            "FAILED",
            None,
            None,
        );
        assert!(event.session_key.is_none());
    }

    #[test]
    fn test_audit_event_no_paths() {
        let event = RunnerAuditEvent::new(
            "job-123",
            "ws-456",
            "job.completed",
            "ok",
            "SUCCEEDED",
            Some("t"),
            Some("s"),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert_no_leak(&json);
    }

    // =========================================================================
    // Audit Store Tests
    // =========================================================================

    #[test]
    fn test_audit_store_record_and_get() {
        let store = RunnerAuditStore::new();

        let event = RunnerAuditEvent::new(
            "job-123",
            "ws-456",
            "job.claimed",
            "ok",
            "OK",
            Some("t"),
            Some("s"),
        );
        store.record(event);

        let events = store.get("job-123", 10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].op, "job.claimed");
    }

    #[test]
    fn test_audit_store_job_isolation() {
        let store = RunnerAuditStore::new();

        store.record(RunnerAuditEvent::new("job-1", "ws", "job.claimed", "ok", "OK", None, None));
        store.record(RunnerAuditEvent::new("job-2", "ws", "job.completed", "ok", "OK", None, None));

        assert_eq!(store.get("job-1", 10).len(), 1);
        assert_eq!(store.get("job-2", 10).len(), 1);
        assert_eq!(store.get("job-3", 10).len(), 0);
    }

    // =========================================================================
    // Response Leak Tests
    // =========================================================================

    #[test]
    fn test_claim_response_no_leak() {
        let response = ClaimJobResponse {
            job_id: Uuid::new_v4().to_string(),
            status: JobStatus::Running,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_complete_response_no_leak() {
        let response = CompleteJobResponse {
            job_id: Uuid::new_v4().to_string(),
            status: JobStatus::Succeeded,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_poll_response_no_leak() {
        let response = PollResponse {
            jobs: vec![
                PollJobInfo {
                    job_id: Uuid::new_v4().to_string(),
                    workspace_id: Uuid::new_v4().to_string(),
                    job_type: JobType::RepoWorkflow,
                    status: JobStatus::Queued,
                    created_at_utc: "2024-01-01T00:00:00Z".to_string(),
                    payload: None,
                    // Retry fields (RAPTOR-3 Step 3)
                    attempt_count: 1,
                    max_attempts: 3,
                    last_error_code: Some("GITHUB_NOT_CONNECTED".to_string()),
                },
            ],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_leak(&json);
    }

    #[test]
    fn test_error_response_no_leak() {
        let error = RunnerError {
            error: "Job not found".to_string(),
            code: "JOB_NOT_FOUND".to_string(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert_no_leak(&json);
    }

    // =========================================================================
    // Sanitize Tests
    // =========================================================================

    #[test]
    fn test_sanitize_string_removes_control_chars() {
        let input = "hello\x00world\x1f";
        let result = sanitize_string(input, 100);
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_sanitize_string_limits_length() {
        let input = "a".repeat(300);
        let result = sanitize_string(&input, 50);
        assert_eq!(result.len(), 50);
    }

    #[test]
    fn test_sanitize_string_trims() {
        let input = "  hello  ";
        let result = sanitize_string(input, 100);
        assert_eq!(result, "hello");
    }

    // =========================================================================
    // Request Deserialization Tests
    // =========================================================================

    #[test]
    fn test_claim_request_deserialization() {
        let json = r#"{"job_id":"550e8400-e29b-41d4-a716-446655440000"}"#;
        let request: ClaimJobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.job_id, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_complete_request_deserialization() {
        let json = r#"{"job_id":"550e8400-e29b-41d4-a716-446655440000","result":"succeeded","code":"OK","message":"Done"}"#;
        let request: CompleteJobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.job_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(request.result, "succeeded");
        assert_eq!(request.code, Some("OK".to_string()));
        assert_eq!(request.message, Some("Done".to_string()));
    }

    #[test]
    fn test_complete_request_minimal() {
        let json = r#"{"job_id":"550e8400-e29b-41d4-a716-446655440000","result":"failed"}"#;
        let request: CompleteJobRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.result, "failed");
        assert!(request.code.is_none());
        assert!(request.message.is_none());
    }

    // =========================================================================
    // Status Serialization Tests
    // =========================================================================

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

    // =========================================================================
    // Poll Limit Tests
    // =========================================================================

    #[test]
    fn test_poll_query_default_limit() {
        let json = r#"{}"#;
        let query: PollQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit, 10);
    }

    #[test]
    fn test_poll_query_custom_limit() {
        let json = r#"{"limit": 5}"#;
        let query: PollQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit, 5);
    }
}
