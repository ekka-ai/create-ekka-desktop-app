//! EKKA Operations
//!
//! SDK orchestration for home, paths, and grants.
//!
//! ## Architecture
//!
//! This crate contains ALL business logic for EKKA operations:
//! - **home**: Home directory status and grant management
//! - **paths**: Path access checking and grant requests
//! - **grants**: Grant listing, lookup, and revocation
//!
//! The desktop app (and other frontends) are thin shells that:
//! 1. Implement the `GrantIssuer` trait with HTTP calls to EKKA Engine
//! 2. Call these operations with a `RuntimeContext`
//! 3. Return results to TypeScript
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ekka_ops::{RuntimeContext, AuthContext, home, paths};
//! use ekka_ops::traits::GrantIssuer;
//!
//! // Create context
//! let mut ctx = RuntimeContext::new(home_path, node_id);
//! ctx.set_auth(AuthContext::new("tenant", "user", "jwt"));
//!
//! // Check home status
//! let status = home::status(&ctx);
//!
//! // Request home grant (issuer is your GrantIssuer impl)
//! let result = home::grant(&ctx, &issuer)?;
//!
//! // Check path access
//! let allowed = paths::check(&ctx, "/some/path", "read");
//! ```

pub mod context;
pub mod error;
pub mod grants;
pub mod home;
pub mod llm_result;
pub mod paths;
pub mod prompt_run_payload;
pub mod retention;
pub mod traits;
pub mod vault;

// Re-export main types for convenience
pub use context::{AuthContext, RuntimeContext};
pub use error::{codes, EkkaError, EkkaResult, ErrorResponse};
pub use traits::{GrantIssuer, GrantRequest, GrantResponse};

// Re-export ekka_path_guard types that are part of our API
pub use ekka_path_guard::{PathAccess, PathType};

// Re-export LLM result types
pub use llm_result::{
    ArtifactCategory, ArtifactRef, CompressionAlgorithm, LlmResultV1, LlmUsage,
    PromptRunRecord, RetentionMode, RetentionPolicy, SCHEMA_LLM_RESULT_V1,
    validate_artifact_ref, validate_llm_result_v1, validate_prompt_run_record,
    validate_retention_policy,
};

// Re-export retention helpers
pub use retention::{
    compute_expires_at, compute_expires_at_from_policy, should_capture_raw_llm, SweeperResult,
};

// Re-export prompt run payload types (engine-facing contracts)
pub use prompt_run_payload::{
    failure_codes, PromptRunFailureEnvelope, PromptRunOutputV1, PromptRunSuccessEnvelope,
    PromptRunTimings, PromptRunUsage, validate_prompt_run_failure_envelope,
    validate_prompt_run_output_v1, validate_prompt_run_success_envelope,
    PROMPT_RUN_OUTPUT_SCHEMA_VERSION, PROMPT_RUN_RESULT_SCHEMA_VERSION,
    PROMPT_RUN_TASK_SCHEMA_VERSION,
};
