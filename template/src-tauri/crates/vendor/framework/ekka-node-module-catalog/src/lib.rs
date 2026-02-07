//! EKKA Node Catalog Module - RAPTOR-2 Step 39 + RAPTOR-3 Step 8 + Step 9
//!
//! Provides Agent Registry and Execution Plan Catalog for orchestrating
//! node capabilities via versioned execution plans.
//!
//! ## RAPTOR-3 Step 8: Engine-Owned Execution
//!
//! The `agent_run` plan type now routes through the engine's workflow-runs API
//! instead of creating node-local jobs. This ensures:
//! - All agent execution goes through engine's runner_tasks queue
//! - Temporal workflows manage task lifecycle
//! - Consistent with EKKA_NODE_JOB_QUEUE_MODE=disabled
//!
//! ## RAPTOR-3 Step 9: Engine-Only Demo Mode
//!
//! When `engine_required` is set (demo profile), the catalog MUST fail if
//! engine is unavailable. No legacy fallback is allowed. This ensures:
//! - Demo only executes via engine workflows
//! - No node-local job queue fallback in demo mode
//! - Error: ENGINE_REQUIRED (409) with generic message
//!
//! ## Security Properties
//!
//! - No absolute paths in responses (only IDs)
//! - Session validation before capability checks (401 then 403)
//! - Capability-gated: catalog.read, catalog.trigger
//! - Plans declare required modules/capabilities for UI consent flow
//! - Structured logging with node.catalog.* prefix
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - A CatalogModuleContext with job store and validators
//!
//! When disabled via EKKA_ENABLE_CATALOG=0, routes are NOT mounted -> 404.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

pub use ekka_node_modules::{
    error_codes, ModuleConfig, SessionInfo, SessionValidationError, SessionValidator,
};
use ekka_node_module_jobs::{JobPayload, JobStore, JobType};

// =============================================================================
// Module Configuration
// =============================================================================

/// Module configuration for the Catalog module
pub const CATALOG_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "Catalog",
    env_var: "EKKA_ENABLE_CATALOG",
    default_enabled: true, // Safe tier - catalog metadata only
};

/// Required capability for reading catalog
pub const CATALOG_READ_CAPABILITY: &str = "catalog.read";

/// Required capability for triggering plans
pub const CATALOG_TRIGGER_CAPABILITY: &str = "catalog.trigger";

// =============================================================================
// Agent Types
// =============================================================================

/// Agent source - where the agent comes from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSource {
    /// Built-in core agent
    Core,
    /// Tenant-specific custom agent
    Tenant,
    /// Marketplace-installed agent
    Marketplace,
}

/// Agent registration entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub agent_id: String,
    pub name: String,
    pub description: String,
    pub source: AgentSource,
    pub enabled: bool,
}

// =============================================================================
// Plan Types
// =============================================================================

/// Input field schema for plan inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFieldSchema {
    pub name: String,
    pub field_type: String, // "string", "number", "boolean", "json"
    pub required: bool,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
}

/// Input schema for a plan (v1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSchemaV1 {
    pub schema_version: String, // "v1"
    pub fields: Vec<InputFieldSchema>,
}

/// Execution plan entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub plan_id: String,
    pub agent_id: String,
    pub name: String,
    pub description: String,
    pub input_schema_v1: InputSchemaV1,
    pub required_modules: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub enabled: bool,
    /// Job type that this plan creates
    pub job_type: String, // "repo_workflow" | "agent_run"
}

// =============================================================================
// Proposal Types
// =============================================================================

/// Preview of a single step in the execution plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepPreview {
    pub step_kind: String,
    pub module: String,
    pub action: String,
}

/// Proposal response - what will happen if triggered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    pub plan_id: String,
    pub steps_preview: Vec<StepPreview>,
    pub requires_consent: bool,
    pub required_modules: Vec<String>,
    pub required_capabilities: Vec<String>,
    /// Validated inputs (sanitized)
    pub validated_inputs: HashMap<String, serde_json::Value>,
}

// =============================================================================
// API Request/Response Types
// =============================================================================

/// Response for GET /v0/catalog/agents
#[derive(Debug, Serialize)]
pub struct AgentsResponse {
    pub agents: Vec<Agent>,
}

/// Query params for GET /v0/catalog/plans
#[derive(Debug, Deserialize)]
pub struct PlansQuery {
    pub agent_id: String,
}

/// Response for GET /v0/catalog/plans
#[derive(Debug, Serialize)]
pub struct PlansResponse {
    pub plans: Vec<ExecutionPlan>,
}

/// Request for POST /v0/catalog/propose
#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    pub plan_id: String,
    pub inputs: HashMap<String, serde_json::Value>,
}

/// Response for POST /v0/catalog/propose
#[derive(Debug, Serialize)]
pub struct ProposeResponse {
    pub proposal_id: String,
    pub plan_id: String,
    pub steps_preview: Vec<StepPreview>,
    pub requires_consent: bool,
    pub required_modules: Vec<String>,
    pub required_capabilities: Vec<String>,
}

/// Request for POST /v0/catalog/trigger
#[derive(Debug, Deserialize)]
pub struct TriggerRequest {
    /// Trigger via proposal_id (preferred)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
    /// OR trigger directly with plan_id + inputs + confirm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub confirm: bool,
    /// Workspace ID for job creation
    pub workspace_id: String,
}

/// Response for POST /v0/catalog/trigger
#[derive(Debug, Serialize)]
pub struct TriggerResponse {
    pub job_ids: Vec<String>,
    pub status: String,
}

/// Catalog error response
#[derive(Debug, Serialize)]
pub struct CatalogError {
    pub error: String,
    pub code: String,
}

// =============================================================================
// Static Catalog Data (RAPTOR-2 Step 39)
// =============================================================================

/// Get the built-in core agents
fn get_core_agents() -> Vec<Agent> {
    vec![
        Agent {
            agent_id: "repo-agent".to_string(),
            name: "Repo Agent".to_string(),
            description: "Manages repository operations: clone, commit, push, PR creation".to_string(),
            source: AgentSource::Core,
            enabled: true,
        },
        Agent {
            agent_id: "agent-runner".to_string(),
            name: "Agent Runner".to_string(),
            description: "Executes AI agent analysis and generates structured outputs with intents".to_string(),
            source: AgentSource::Core,
            enabled: true,
        },
    ]
}

/// Get the built-in execution plans
fn get_core_plans() -> Vec<ExecutionPlan> {
    vec![
        // Repo Agent plan: setup_git_repo
        ExecutionPlan {
            plan_id: "setup-git-repo".to_string(),
            agent_id: "repo-agent".to_string(),
            name: "Setup Git Repository".to_string(),
            description: "Creates a repo_workflow job to clone, commit changes, push, and create a PR".to_string(),
            input_schema_v1: InputSchemaV1 {
                schema_version: "v1".to_string(),
                fields: vec![
                    InputFieldSchema {
                        name: "commit_message".to_string(),
                        field_type: "string".to_string(),
                        required: true,
                        description: "Commit message for the changes".to_string(),
                        default_value: None,
                        max_length: Some(200),
                    },
                    InputFieldSchema {
                        name: "pr_title".to_string(),
                        field_type: "string".to_string(),
                        required: true,
                        description: "Title for the pull request".to_string(),
                        default_value: None,
                        max_length: Some(200),
                    },
                    InputFieldSchema {
                        name: "pr_body".to_string(),
                        field_type: "string".to_string(),
                        required: false,
                        description: "Description for the pull request body".to_string(),
                        default_value: None,
                        max_length: Some(1000),
                    },
                ],
            },
            required_modules: vec!["jobs".to_string(), "git".to_string(), "github".to_string()],
            required_capabilities: vec!["jobs.create".to_string(), "git.clone".to_string(), "git.write".to_string()],
            enabled: true,
            job_type: "repo_workflow".to_string(),
        },
        // Agent Runner plan: analyze_and_propose_repo_change
        ExecutionPlan {
            plan_id: "analyze-and-propose".to_string(),
            agent_id: "agent-runner".to_string(),
            name: "Analyze and Propose Repo Change".to_string(),
            description: "Creates an agent_run job that analyzes inputs and produces a repo workflow intent".to_string(),
            input_schema_v1: InputSchemaV1 {
                schema_version: "v1".to_string(),
                fields: vec![
                    InputFieldSchema {
                        name: "prompt".to_string(),
                        field_type: "string".to_string(),
                        required: true,
                        description: "Analysis prompt for the agent".to_string(),
                        default_value: None,
                        max_length: Some(8192),
                    },
                    InputFieldSchema {
                        name: "context".to_string(),
                        field_type: "json".to_string(),
                        required: false,
                        description: "Additional context as JSON object".to_string(),
                        default_value: None,
                        max_length: None,
                    },
                ],
            },
            required_modules: vec!["jobs".to_string(), "agent".to_string()],
            required_capabilities: vec!["jobs.create".to_string(), "agent.run".to_string()],
            enabled: true,
            job_type: "agent_run".to_string(),
        },
    ]
}

// =============================================================================
// Proposal Store (In-Memory for RAPTOR-2)
// =============================================================================

/// In-memory proposal store for validation
#[derive(Debug, Default)]
pub struct ProposalStore {
    proposals: std::sync::RwLock<HashMap<String, Proposal>>,
}

impl ProposalStore {
    pub fn new() -> Self {
        Self {
            proposals: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn store(&self, proposal: Proposal) {
        let mut proposals = self.proposals.write().unwrap();
        proposals.insert(proposal.proposal_id.clone(), proposal);
    }

    pub fn get(&self, proposal_id: &str) -> Option<Proposal> {
        let proposals = self.proposals.read().unwrap();
        proposals.get(proposal_id).cloned()
    }
}

// =============================================================================
// Module Context
// =============================================================================

/// Type alias for capability checker
pub type CapabilityChecker = Arc<dyn Fn(&str) -> bool + Send + Sync>;

// =============================================================================
// Engine Task Creator (RAPTOR-3 Step 8)
// =============================================================================

/// Input for creating an engine workflow run (wf_node_exec)
#[derive(Debug, Clone, Serialize)]
pub struct EngineWorkflowRunInput {
    pub tenant_id: String,
    pub workspace_id: String,
    pub capability_code: String,
    pub inputs: HashMap<String, serde_json::Value>,
}

/// Result from creating an engine workflow run
#[derive(Debug, Clone, Deserialize)]
pub struct EngineWorkflowRunResult {
    pub workflow_run_id: String,
    pub status: String,
}

/// Error from engine workflow run creation
#[derive(Debug, Clone)]
pub struct EngineTaskError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for EngineTaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Type alias for async engine task creator callback
/// Returns Result<workflow_run_id, EngineTaskError>
pub type EngineTaskCreator = Arc<
    dyn Fn(EngineWorkflowRunInput) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<EngineWorkflowRunResult, EngineTaskError>> + Send>>
        + Send
        + Sync,
>;

/// Context for the Catalog module
#[derive(Clone)]
pub struct CatalogModuleContext {
    /// Job store for creating jobs (repo_workflow only, RAPTOR-3 Step 8)
    pub job_store: Arc<JobStore>,
    /// Proposal store for tracking proposals
    pub proposal_store: Arc<ProposalStore>,
    /// Session validator (provided by host for request-time auth)
    pub session_validator: SessionValidator,
    /// Capability checker (checks if a capability is available)
    pub capability_checker: CapabilityChecker,
    /// Module enabled checker
    pub module_enabled_checker: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// Workspace existence checker
    pub workspace_exists: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// Log operation prefix
    pub log_prefix: String,
    /// Engine task creator (RAPTOR-3 Step 8) - for agent_run via engine workflow
    /// If None and engine_required is false, falls back to local job creation (legacy mode)
    /// If None and engine_required is true, returns ENGINE_REQUIRED error
    pub engine_task_creator: Option<EngineTaskCreator>,
    /// Engine required flag (RAPTOR-3 Step 9) - when true, engine is mandatory
    /// Demo profile sets this to true to enforce engine-only execution
    pub engine_required: bool,
}

impl CatalogModuleContext {
    pub fn new(
        job_store: Arc<JobStore>,
        proposal_store: Arc<ProposalStore>,
        session_validator: SessionValidator,
        capability_checker: CapabilityChecker,
        module_enabled_checker: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        workspace_exists: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            job_store,
            proposal_store,
            session_validator,
            capability_checker,
            module_enabled_checker,
            workspace_exists,
            log_prefix: log_prefix.into(),
            engine_task_creator: None, // Legacy mode by default
            engine_required: false,    // Legacy mode allows no engine
        }
    }

    /// Create context with engine task creator (RAPTOR-3 Step 8)
    /// When engine_task_creator is Some, agent_run jobs go through engine workflow
    pub fn with_engine_task_creator(
        job_store: Arc<JobStore>,
        proposal_store: Arc<ProposalStore>,
        session_validator: SessionValidator,
        capability_checker: CapabilityChecker,
        module_enabled_checker: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        workspace_exists: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        log_prefix: impl Into<String>,
        engine_task_creator: EngineTaskCreator,
    ) -> Self {
        Self {
            job_store,
            proposal_store,
            session_validator,
            capability_checker,
            module_enabled_checker,
            workspace_exists,
            log_prefix: log_prefix.into(),
            engine_task_creator: Some(engine_task_creator),
            engine_required: false, // Set explicitly if needed
        }
    }

    /// Create context with engine task creator AND engine_required flag (RAPTOR-3 Step 9)
    /// When engine_required is true and engine is unavailable, returns ENGINE_REQUIRED error
    /// Use this for demo profile to enforce engine-only execution
    pub fn with_engine_required(
        job_store: Arc<JobStore>,
        proposal_store: Arc<ProposalStore>,
        session_validator: SessionValidator,
        capability_checker: CapabilityChecker,
        module_enabled_checker: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        workspace_exists: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        log_prefix: impl Into<String>,
        engine_task_creator: Option<EngineTaskCreator>,
        engine_required: bool,
    ) -> Self {
        Self {
            job_store,
            proposal_store,
            session_validator,
            capability_checker,
            module_enabled_checker,
            workspace_exists,
            log_prefix: log_prefix.into(),
            engine_task_creator,
            engine_required,
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.catalog.{}", self.log_prefix, op)
    }
}

// =============================================================================
// Mount Function
// =============================================================================

/// Mount the Catalog module routes onto a router.
/// Routes are only mounted if the module is enabled.
pub fn mount<S>(router: Router<S>, ctx: CatalogModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !CATALOG_MODULE_CONFIG.is_enabled() {
        info!(
            module = "catalog",
            enabled = false,
            "Catalog module disabled (set EKKA_ENABLE_CATALOG=1 to enable)"
        );
        return router;
    }

    info!(
        module = "catalog",
        enabled = true,
        "Catalog module enabled"
    );

    let state = Arc::new(ctx);

    let catalog_router: Router<S> = Router::new()
        .route("/v0/catalog/agents", get(agents_handler))
        .route("/v0/catalog/plans", get(plans_handler))
        .route("/v0/catalog/propose", post(propose_handler))
        .route("/v0/catalog/trigger", post(trigger_handler))
        .with_state(state);

    router.merge(catalog_router)
}

// =============================================================================
// Handlers
// =============================================================================

/// GET /v0/catalog/agents - List all registered agents
async fn agents_handler(
    State(ctx): State<Arc<CatalogModuleContext>>,
    headers: HeaderMap,
) -> Result<Json<AgentsResponse>, (StatusCode, Json<CatalogError>)> {
    info!(op = %ctx.log_op("agents.request"), "Agents list requested");

    // Step 1: Validate session (401 before 403)
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("agents.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(CatalogError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability
    if session.require_capability(CATALOG_READ_CAPABILITY).is_err() {
        warn!(
            op = %ctx.log_op("agents.capability_denied"),
            "Capability denied"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(CatalogError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Return core agents
    let agents = get_core_agents();

    info!(
        op = %ctx.log_op("agents.ok"),
        count = %agents.len(),
        "Agents listed"
    );

    Ok(Json(AgentsResponse { agents }))
}

/// GET /v0/catalog/plans?agent_id=<id> - List plans for an agent
async fn plans_handler(
    State(ctx): State<Arc<CatalogModuleContext>>,
    headers: HeaderMap,
    Query(query): Query<PlansQuery>,
) -> Result<Json<PlansResponse>, (StatusCode, Json<CatalogError>)> {
    info!(
        op = %ctx.log_op("plans.request"),
        agent_id = %query.agent_id,
        "Plans list requested"
    );

    // Step 1: Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("plans.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(CatalogError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability
    if session.require_capability(CATALOG_READ_CAPABILITY).is_err() {
        warn!(op = %ctx.log_op("plans.capability_denied"), "Capability denied");
        return Err((
            StatusCode::FORBIDDEN,
            Json(CatalogError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Filter plans by agent_id
    let all_plans = get_core_plans();
    let plans: Vec<ExecutionPlan> = all_plans
        .into_iter()
        .filter(|p| p.agent_id == query.agent_id)
        .collect();

    info!(
        op = %ctx.log_op("plans.ok"),
        agent_id = %query.agent_id,
        count = %plans.len(),
        "Plans listed"
    );

    Ok(Json(PlansResponse { plans }))
}

/// POST /v0/catalog/propose - Create a proposal for a plan
async fn propose_handler(
    State(ctx): State<Arc<CatalogModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<ProposeRequest>,
) -> Result<Json<ProposeResponse>, (StatusCode, Json<CatalogError>)> {
    info!(
        op = %ctx.log_op("propose.request"),
        plan_id = %request.plan_id,
        "Proposal requested"
    );

    // Step 1: Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("propose.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(CatalogError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check capability
    if session.require_capability(CATALOG_READ_CAPABILITY).is_err() {
        warn!(op = %ctx.log_op("propose.capability_denied"), "Capability denied");
        return Err((
            StatusCode::FORBIDDEN,
            Json(CatalogError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Find the plan
    let all_plans = get_core_plans();
    let plan = all_plans.iter().find(|p| p.plan_id == request.plan_id);
    let plan = match plan {
        Some(p) => p,
        None => {
            warn!(
                op = %ctx.log_op("propose.plan_not_found"),
                plan_id = %request.plan_id,
                "Plan not found"
            );
            return Err((
                StatusCode::NOT_FOUND,
                Json(CatalogError {
                    error: "Plan not found".to_string(),
                    code: "PLAN_NOT_FOUND".to_string(),
                }),
            ));
        }
    };

    // Step 4: Validate inputs against schema
    let validated_inputs = validate_inputs(&plan.input_schema_v1, &request.inputs)?;

    // Step 5: Build steps preview
    let steps_preview = build_steps_preview(plan);

    // Step 6: Create proposal
    let proposal_id = Uuid::new_v4().to_string();
    let proposal = Proposal {
        proposal_id: proposal_id.clone(),
        plan_id: plan.plan_id.clone(),
        steps_preview: steps_preview.clone(),
        requires_consent: true, // Always require consent for now
        required_modules: plan.required_modules.clone(),
        required_capabilities: plan.required_capabilities.clone(),
        validated_inputs,
    };

    // Store proposal for later retrieval
    ctx.proposal_store.store(proposal);

    info!(
        op = %ctx.log_op("propose.ok"),
        proposal_id = %proposal_id,
        plan_id = %plan.plan_id,
        "Proposal created"
    );

    Ok(Json(ProposeResponse {
        proposal_id,
        plan_id: plan.plan_id.clone(),
        steps_preview,
        requires_consent: true,
        required_modules: plan.required_modules.clone(),
        required_capabilities: plan.required_capabilities.clone(),
    }))
}

/// POST /v0/catalog/trigger - Trigger execution of a plan
async fn trigger_handler(
    State(ctx): State<Arc<CatalogModuleContext>>,
    headers: HeaderMap,
    Json(request): Json<TriggerRequest>,
) -> Result<Json<TriggerResponse>, (StatusCode, Json<CatalogError>)> {
    info!(
        op = %ctx.log_op("trigger.request"),
        proposal_id = ?request.proposal_id,
        plan_id = ?request.plan_id,
        "Trigger requested"
    );

    // Step 1: Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("trigger.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(CatalogError {
                error: e.error,
                code: e.code,
            }),
        )
    })?;

    // Step 2: Check catalog.trigger capability
    if session.require_capability(CATALOG_TRIGGER_CAPABILITY).is_err() {
        warn!(op = %ctx.log_op("trigger.capability_denied"), "Capability denied");
        return Err((
            StatusCode::FORBIDDEN,
            Json(CatalogError {
                error: "Not permitted".to_string(),
                code: error_codes::CAPABILITY_DENIED.to_string(),
            }),
        ));
    }

    // Step 3: Parse workspace_id
    let workspace_id = request.workspace_id.parse::<Uuid>().map_err(|_| {
        warn!(
            op = %ctx.log_op("trigger.invalid_workspace_id"),
            "Invalid workspace ID format"
        );
        (
            StatusCode::BAD_REQUEST,
            Json(CatalogError {
                error: "Invalid workspace ID".to_string(),
                code: "INVALID_WORKSPACE_ID".to_string(),
            }),
        )
    })?;

    // Step 4: Verify workspace exists
    if !(ctx.workspace_exists)(&request.workspace_id) {
        warn!(
            op = %ctx.log_op("trigger.workspace_not_found"),
            "Workspace not found"
        );
        return Err((
            StatusCode::NOT_FOUND,
            Json(CatalogError {
                error: "Workspace not found".to_string(),
                code: "WORKSPACE_NOT_FOUND".to_string(),
            }),
        ));
    }

    // Step 5: Resolve plan and inputs
    let (plan, inputs) = if let Some(proposal_id) = &request.proposal_id {
        // Trigger via proposal
        let proposal = ctx.proposal_store.get(proposal_id).ok_or_else(|| {
            warn!(
                op = %ctx.log_op("trigger.proposal_not_found"),
                proposal_id = %proposal_id,
                "Proposal not found"
            );
            (
                StatusCode::NOT_FOUND,
                Json(CatalogError {
                    error: "Proposal not found".to_string(),
                    code: "PROPOSAL_NOT_FOUND".to_string(),
                }),
            )
        })?;

        let all_plans = get_core_plans();
        let plan = all_plans
            .into_iter()
            .find(|p| p.plan_id == proposal.plan_id)
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(CatalogError {
                        error: "Plan not found".to_string(),
                        code: "PLAN_NOT_FOUND".to_string(),
                    }),
                )
            })?;

        (plan, proposal.validated_inputs)
    } else if let (Some(plan_id), Some(inputs)) = (&request.plan_id, &request.inputs) {
        // Trigger directly (requires confirm=true)
        if !request.confirm {
            warn!(
                op = %ctx.log_op("trigger.confirm_required"),
                "Confirm required for direct trigger"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(CatalogError {
                    error: "Direct trigger requires confirm=true".to_string(),
                    code: "CONFIRM_REQUIRED".to_string(),
                }),
            ));
        }

        let all_plans = get_core_plans();
        let plan = all_plans
            .into_iter()
            .find(|p| &p.plan_id == plan_id)
            .ok_or_else(|| {
                warn!(
                    op = %ctx.log_op("trigger.plan_not_found"),
                    plan_id = %plan_id,
                    "Plan not found"
                );
                (
                    StatusCode::NOT_FOUND,
                    Json(CatalogError {
                        error: "Plan not found".to_string(),
                        code: "PLAN_NOT_FOUND".to_string(),
                    }),
                )
            })?;

        let validated_inputs = validate_inputs(&plan.input_schema_v1, inputs)?;
        (plan, validated_inputs)
    } else {
        warn!(
            op = %ctx.log_op("trigger.invalid_request"),
            "Must provide proposal_id OR (plan_id + inputs + confirm)"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(CatalogError {
                error: "Must provide proposal_id OR (plan_id + inputs + confirm)".to_string(),
                code: "INVALID_REQUEST".to_string(),
            }),
        ));
    };

    // Step 6: Check required capabilities (defense-in-depth)
    for cap in &plan.required_capabilities {
        // Map plan capabilities to session capabilities
        let session_cap = map_plan_cap_to_session_cap(cap);
        if session.require_capability(&session_cap).is_err() {
            warn!(
                op = %ctx.log_op("trigger.required_capability_denied"),
                capability = %cap,
                "Required capability denied"
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(CatalogError {
                    error: format!("Required capability denied: {}", cap),
                    code: error_codes::CAPABILITY_DENIED.to_string(),
                }),
            ));
        }
    }

    // Step 7: Create the job based on plan type
    // RAPTOR-3 Step 8: agent_run routes through engine workflow when engine_task_creator is available
    let execution_id = match plan.job_type.as_str() {
        "repo_workflow" => {
            let commit_message = inputs
                .get("commit_message")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let pr_title = inputs
                .get("pr_title")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let pr_body = inputs
                .get("pr_body")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let payload = JobPayload::repo_workflow(commit_message, pr_title, pr_body);
            let label = Some(format!("Plan: {}", plan.name));
            let job = ctx.job_store.create_job(workspace_id, JobType::RepoWorkflow, label, Some(payload));
            job.job_id.to_string()
        }
        "agent_run" => {
            // RAPTOR-3 Step 8+9: Route through engine workflow
            // When engine_required is true, engine MUST be available
            if let Some(ref engine_creator) = ctx.engine_task_creator {
                let prompt = inputs
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Process the request")
                    .to_string();
                let context = inputs.get("context").cloned();

                // Build inputs for engine workflow (capability_code: agent.run)
                let mut engine_inputs = HashMap::new();
                engine_inputs.insert("prompt".to_string(), serde_json::Value::String(prompt));
                if let Some(ctx_val) = context {
                    engine_inputs.insert("context".to_string(), ctx_val);
                }

                let engine_input = EngineWorkflowRunInput {
                    tenant_id: session.tenant_id.clone(),
                    workspace_id: request.workspace_id.clone(),
                    capability_code: "agent.run".to_string(),
                    inputs: engine_inputs,
                };

                info!(
                    op = %ctx.log_op("trigger.engine_workflow"),
                    plan_id = %plan.plan_id,
                    capability = "agent.run",
                    "Creating engine workflow run for agent_run"
                );

                // Call engine asynchronously
                let future = engine_creator(engine_input);
                match future.await {
                    Ok(result) => {
                        info!(
                            op = %ctx.log_op("trigger.engine_workflow.ok"),
                            workflow_run_id = %result.workflow_run_id,
                            "Engine workflow run created"
                        );
                        result.workflow_run_id
                    }
                    Err(e) => {
                        warn!(
                            op = %ctx.log_op("trigger.engine_workflow.failed"),
                            error_code = %e.code,
                            "Engine workflow run creation failed"
                        );
                        return Err((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(CatalogError {
                                error: "Engine workflow creation failed".to_string(),
                                code: e.code,
                            }),
                        ));
                    }
                }
            } else if ctx.engine_required {
                // RAPTOR-3 Step 9: Engine required but not configured - hard fail
                warn!(
                    op = %ctx.log_op("trigger.engine_required"),
                    plan_id = %plan.plan_id,
                    "Engine required but not configured - execution blocked"
                );
                return Err((
                    StatusCode::CONFLICT,
                    Json(CatalogError {
                        // Generic error message - don't leak configuration details
                        error: "Execution service unavailable".to_string(),
                        code: "ENGINE_REQUIRED".to_string(),
                    }),
                ));
            } else {
                // Legacy fallback: create local job (DEPRECATED, only for non-demo profiles)
                warn!(
                    op = %ctx.log_op("trigger.legacy_job"),
                    plan_id = %plan.plan_id,
                    "Creating legacy local job (engine_task_creator not configured)"
                );

                let prompt = inputs
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let context = inputs.get("context").cloned();

                let payload = JobPayload::agent_run(prompt, context, None);
                let label = Some(format!("Plan: {}", plan.name));
                let job = ctx.job_store.create_job(workspace_id, JobType::AgentRun, label, Some(payload));
                job.job_id.to_string()
            }
        }
        _ => {
            warn!(
                op = %ctx.log_op("trigger.unsupported_job_type"),
                job_type = %plan.job_type,
                "Unsupported job type"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(CatalogError {
                    error: format!("Unsupported job type: {}", plan.job_type),
                    code: "UNSUPPORTED_JOB_TYPE".to_string(),
                }),
            ));
        }
    };

    info!(
        op = %ctx.log_op("trigger.ok"),
        execution_id = %execution_id,
        plan_id = %plan.plan_id,
        workspace_id = %workspace_id,
        "Plan triggered, execution created"
    );

    Ok(Json(TriggerResponse {
        job_ids: vec![execution_id],
        status: "queued".to_string(),
    }))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Validate inputs against the schema
fn validate_inputs(
    schema: &InputSchemaV1,
    inputs: &HashMap<String, serde_json::Value>,
) -> Result<HashMap<String, serde_json::Value>, (StatusCode, Json<CatalogError>)> {
    let mut validated = HashMap::new();

    for field in &schema.fields {
        let value = inputs.get(&field.name);

        // Check required fields
        if field.required {
            match value {
                None => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(CatalogError {
                            error: format!("Missing required field: {}", field.name),
                            code: "MISSING_REQUIRED_FIELD".to_string(),
                        }),
                    ));
                }
                Some(v) if v.is_null() => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(CatalogError {
                            error: format!("Required field cannot be null: {}", field.name),
                            code: "NULL_REQUIRED_FIELD".to_string(),
                        }),
                    ));
                }
                _ => {}
            }
        }

        // Validate and sanitize value
        if let Some(v) = value {
            // Type validation
            let valid = match field.field_type.as_str() {
                "string" => v.is_string(),
                "number" => v.is_number(),
                "boolean" => v.is_boolean(),
                "json" => v.is_object() || v.is_array(),
                _ => true,
            };

            if !valid && !v.is_null() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(CatalogError {
                        error: format!("Invalid type for field {}: expected {}", field.name, field.field_type),
                        code: "INVALID_FIELD_TYPE".to_string(),
                    }),
                ));
            }

            // Max length validation for strings
            if let (Some(max_len), Some(s)) = (field.max_length, v.as_str()) {
                if s.len() > max_len {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(CatalogError {
                            error: format!("Field {} exceeds max length {}", field.name, max_len),
                            code: "FIELD_TOO_LONG".to_string(),
                        }),
                    ));
                }

                // Security: Check for forbidden patterns
                if contains_forbidden_pattern(s) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(CatalogError {
                            error: format!("Field {} contains forbidden pattern", field.name),
                            code: "FORBIDDEN_PATTERN".to_string(),
                        }),
                    ));
                }
            }

            validated.insert(field.name.clone(), v.clone());
        } else if let Some(default) = &field.default_value {
            validated.insert(field.name.clone(), default.clone());
        }
    }

    Ok(validated)
}

/// Check for forbidden patterns (paths, URLs, env vars)
fn contains_forbidden_pattern(s: &str) -> bool {
    s.contains("/Users/")
        || s.contains("/home/")
        || s.contains("/var/")
        || s.contains("/tmp/")
        || s.contains("/private/")
        || s.contains("C:\\")
        || s.contains("D:\\")
        || s.contains("https://")
        || s.contains("http://")
        || s.contains("EKKA_")
}

/// Build steps preview for a plan
fn build_steps_preview(plan: &ExecutionPlan) -> Vec<StepPreview> {
    match plan.job_type.as_str() {
        "repo_workflow" => vec![
            StepPreview {
                step_kind: "clone".to_string(),
                module: "git".to_string(),
                action: "clone".to_string(),
            },
            StepPreview {
                step_kind: "commit".to_string(),
                module: "git".to_string(),
                action: "commit".to_string(),
            },
            StepPreview {
                step_kind: "push".to_string(),
                module: "git".to_string(),
                action: "push".to_string(),
            },
            StepPreview {
                step_kind: "pr".to_string(),
                module: "github".to_string(),
                action: "create_pr".to_string(),
            },
        ],
        "agent_run" => vec![
            StepPreview {
                step_kind: "analyze".to_string(),
                module: "agent".to_string(),
                action: "run".to_string(),
            },
            StepPreview {
                step_kind: "generate_intent".to_string(),
                module: "agent".to_string(),
                action: "output".to_string(),
            },
        ],
        _ => vec![],
    }
}

/// Map plan capability to session capability format
fn map_plan_cap_to_session_cap(cap: &str) -> String {
    // Plan capabilities like "jobs.create" map directly
    cap.to_string()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Agent Tests
    // =========================================================================

    #[test]
    fn test_get_core_agents() {
        let agents = get_core_agents();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].agent_id, "repo-agent");
        assert_eq!(agents[1].agent_id, "agent-runner");
    }

    #[test]
    fn test_agent_serialization_no_leak() {
        let agents = get_core_agents();
        let json = serde_json::to_string(&agents).unwrap();
        assert!(!json.contains("/Users/"), "Leaked path");
        assert!(!json.contains("/home/"), "Leaked path");
        assert!(!json.contains("https://"), "Leaked URL");
        assert!(!json.contains("EKKA_"), "Leaked env var");
    }

    // =========================================================================
    // Plan Tests
    // =========================================================================

    #[test]
    fn test_get_core_plans() {
        let plans = get_core_plans();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].plan_id, "setup-git-repo");
        assert_eq!(plans[1].plan_id, "analyze-and-propose");
    }

    #[test]
    fn test_plan_serialization_no_leak() {
        let plans = get_core_plans();
        let json = serde_json::to_string(&plans).unwrap();
        assert!(!json.contains("/Users/"), "Leaked path");
        assert!(!json.contains("/home/"), "Leaked path");
        assert!(!json.contains("https://"), "Leaked URL");
        assert!(!json.contains("EKKA_"), "Leaked env var");
    }

    #[test]
    fn test_plan_has_required_modules() {
        let plans = get_core_plans();
        for plan in plans {
            assert!(!plan.required_modules.is_empty(), "Plan {} has no required modules", plan.plan_id);
            assert!(!plan.required_capabilities.is_empty(), "Plan {} has no required capabilities", plan.plan_id);
        }
    }

    // =========================================================================
    // Input Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_inputs_required_field() {
        let schema = InputSchemaV1 {
            schema_version: "v1".to_string(),
            fields: vec![InputFieldSchema {
                name: "prompt".to_string(),
                field_type: "string".to_string(),
                required: true,
                description: "Test".to_string(),
                default_value: None,
                max_length: None,
            }],
        };

        // Missing required field
        let inputs = HashMap::new();
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_err());

        // With required field
        let mut inputs = HashMap::new();
        inputs.insert("prompt".to_string(), serde_json::json!("test"));
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inputs_max_length() {
        let schema = InputSchemaV1 {
            schema_version: "v1".to_string(),
            fields: vec![InputFieldSchema {
                name: "title".to_string(),
                field_type: "string".to_string(),
                required: true,
                description: "Test".to_string(),
                default_value: None,
                max_length: Some(10),
            }],
        };

        // Too long
        let mut inputs = HashMap::new();
        inputs.insert("title".to_string(), serde_json::json!("this is way too long"));
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_err());

        // Within limit
        let mut inputs = HashMap::new();
        inputs.insert("title".to_string(), serde_json::json!("short"));
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_inputs_forbidden_patterns() {
        let schema = InputSchemaV1 {
            schema_version: "v1".to_string(),
            fields: vec![InputFieldSchema {
                name: "message".to_string(),
                field_type: "string".to_string(),
                required: true,
                description: "Test".to_string(),
                default_value: None,
                max_length: Some(1000),
            }],
        };

        // Forbidden path
        let mut inputs = HashMap::new();
        inputs.insert("message".to_string(), serde_json::json!("See /Users/john/file"));
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_err());

        // Forbidden URL
        let mut inputs = HashMap::new();
        inputs.insert("message".to_string(), serde_json::json!("See https://example.com"));
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_err());

        // Forbidden env var
        let mut inputs = HashMap::new();
        inputs.insert("message".to_string(), serde_json::json!("Use EKKA_SECRET"));
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_err());

        // Valid input
        let mut inputs = HashMap::new();
        inputs.insert("message".to_string(), serde_json::json!("Add new feature"));
        let result = validate_inputs(&schema, &inputs);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Steps Preview Tests
    // =========================================================================

    #[test]
    fn test_build_steps_preview_repo_workflow() {
        let plan = ExecutionPlan {
            plan_id: "test".to_string(),
            agent_id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            input_schema_v1: InputSchemaV1 {
                schema_version: "v1".to_string(),
                fields: vec![],
            },
            required_modules: vec![],
            required_capabilities: vec![],
            enabled: true,
            job_type: "repo_workflow".to_string(),
        };

        let steps = build_steps_preview(&plan);
        assert_eq!(steps.len(), 4);
        assert_eq!(steps[0].step_kind, "clone");
        assert_eq!(steps[1].step_kind, "commit");
        assert_eq!(steps[2].step_kind, "push");
        assert_eq!(steps[3].step_kind, "pr");
    }

    #[test]
    fn test_build_steps_preview_agent_run() {
        let plan = ExecutionPlan {
            plan_id: "test".to_string(),
            agent_id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            input_schema_v1: InputSchemaV1 {
                schema_version: "v1".to_string(),
                fields: vec![],
            },
            required_modules: vec![],
            required_capabilities: vec![],
            enabled: true,
            job_type: "agent_run".to_string(),
        };

        let steps = build_steps_preview(&plan);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].step_kind, "analyze");
        assert_eq!(steps[1].step_kind, "generate_intent");
    }

    // =========================================================================
    // Proposal Store Tests
    // =========================================================================

    #[test]
    fn test_proposal_store() {
        let store = ProposalStore::new();

        let proposal = Proposal {
            proposal_id: "test-123".to_string(),
            plan_id: "plan-1".to_string(),
            steps_preview: vec![],
            requires_consent: true,
            required_modules: vec![],
            required_capabilities: vec![],
            validated_inputs: HashMap::new(),
        };

        store.store(proposal);

        let retrieved = store.get("test-123");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().plan_id, "plan-1");

        let not_found = store.get("nonexistent");
        assert!(not_found.is_none());
    }

    // =========================================================================
    // Response Serialization Tests
    // =========================================================================

    #[test]
    fn test_agents_response_no_leak() {
        let response = AgentsResponse {
            agents: get_core_agents(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("/Users/"));
        assert!(!json.contains("/home/"));
        assert!(!json.contains("EKKA_"));
    }

    #[test]
    fn test_plans_response_no_leak() {
        let response = PlansResponse {
            plans: get_core_plans(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("/Users/"));
        assert!(!json.contains("/home/"));
        assert!(!json.contains("EKKA_"));
    }

    #[test]
    fn test_trigger_response_no_leak() {
        let response = TriggerResponse {
            job_ids: vec!["550e8400-e29b-41d4-a716-446655440000".to_string()],
            status: "queued".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("/Users/"));
        assert!(!json.contains("/home/"));
        assert!(!json.contains("EKKA_"));
    }

    // =========================================================================
    // Engine Required Tests (RAPTOR-3 Step 9)
    // =========================================================================

    #[test]
    fn test_engine_required_flag_exists() {
        // Verify engine_required flag is properly set on context
        let ctx = CatalogModuleContext::with_engine_required(
            std::sync::Arc::new(ekka_node_module_jobs::JobStore::new()),
            std::sync::Arc::new(ProposalStore::new()),
            std::sync::Arc::new(|_| Ok(SessionInfo {
                session_id: "test".to_string(),
                tenant_id: "tenant".to_string(),
                user_id: "user".to_string(),
                capabilities: vec![],
            })),
            std::sync::Arc::new(|_| true),
            std::sync::Arc::new(|_| true),
            std::sync::Arc::new(|_| true),
            "test",
            None,  // No engine task creator
            true,  // engine_required = true
        );
        assert!(ctx.engine_required);
        assert!(ctx.engine_task_creator.is_none());
    }

    #[test]
    fn test_legacy_mode_when_engine_not_required() {
        // When engine_required is false, legacy mode should be allowed
        let ctx = CatalogModuleContext::new(
            std::sync::Arc::new(ekka_node_module_jobs::JobStore::new()),
            std::sync::Arc::new(ProposalStore::new()),
            std::sync::Arc::new(|_| Ok(SessionInfo {
                session_id: "test".to_string(),
                tenant_id: "tenant".to_string(),
                user_id: "user".to_string(),
                capabilities: vec![],
            })),
            std::sync::Arc::new(|_| true),
            std::sync::Arc::new(|_| true),
            std::sync::Arc::new(|_| true),
            "test",
        );
        assert!(!ctx.engine_required);
        assert!(ctx.engine_task_creator.is_none());
    }
}
