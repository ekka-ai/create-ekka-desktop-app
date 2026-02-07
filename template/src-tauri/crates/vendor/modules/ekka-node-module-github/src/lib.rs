//! EKKA Node GitHub Module - RAPTOR-2 Step 20
//!
//! Provides GitHub OAuth and PR creation support for the PR-only Git workflow.
//! Extracted from ekka-node-desktop as a registry-driven module.
//!
//! ## Security Invariants
//!
//! - Tokens stored server-side only (via GitHubTokenStore), NEVER returned to client
//! - No paths, URLs, or secrets in error messages
//! - Repo binding via server-side config (RepoBindingResolver)
//! - PR-only: branches must have ekka/ prefix
//!
//! ## Module Pattern
//!
//! This module provides a `mount()` function that takes:
//! - An axum Router
//! - A GitHubModuleContext with dependencies from host
//!
//! When disabled, routes are NOT mounted -> 404.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tracing::{info, warn};

pub use ekka_node_modules::{
    error_codes, ModuleConfig, ModuleError,
    SessionInfo, SessionValidationError, SessionValidator,
};

// =============================================================================
// Module Configuration
// =============================================================================

/// GitHub module configuration
pub const GITHUB_MODULE_CONFIG: ModuleConfig = ModuleConfig {
    name: "GitHub",
    env_var: "EKKA_ENABLE_GITHUB",
    default_enabled: false, // Privileged - disabled by default
};

// =============================================================================
// Host-Provided Interfaces
// =============================================================================

/// Interface for storing/retrieving GitHub tokens (provided by host)
/// Tokens are stored server-side only, NEVER returned to client
pub trait GitHubTokenStore: Send + Sync {
    /// Store a GitHub token for a session
    /// Returns true if session found and token stored
    fn set_github_token(&self, session_id: &str, token: String) -> bool;

    /// Get GitHub token for a session (for server-side API calls only)
    /// Returns None if session not found or no token stored
    fn get_github_token(&self, session_id: &str) -> Option<String>;

    /// Check if session has GitHub token connected
    fn has_github_token(&self, session_id: &str) -> bool;

    /// Clear GitHub token for a session (e.g., on disconnect)
    fn clear_github_token(&self, session_id: &str) -> bool;
}

/// Result of repo binding resolution
#[derive(Debug, Clone)]
pub struct OwnerRepo {
    pub owner: String,
    pub repo: String,
}

impl OwnerRepo {
    pub fn new(owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
        }
    }

    /// Parse from "owner/repo" format
    pub fn from_slug(slug: &str) -> Option<Self> {
        let parts: Vec<&str> = slug.split('/').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return None;
        }
        Some(Self::new(parts[0], parts[1]))
    }
}

/// Error from repo binding resolution (safe, no secrets)
#[derive(Debug, Clone)]
pub enum RepoResolveError {
    /// Workspace not configured for GitHub
    NotConfigured,
    /// Invalid workspace ID
    InvalidWorkspace,
}

impl RepoResolveError {
    pub fn code(&self) -> &'static str {
        match self {
            RepoResolveError::NotConfigured => "GITHUB_REPO_NOT_CONFIGURED",
            RepoResolveError::InvalidWorkspace => "INVALID_WORKSPACE_ID",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            RepoResolveError::NotConfigured => "Repository not configured for this workspace",
            RepoResolveError::InvalidWorkspace => "Invalid workspace ID",
        }
    }
}

/// Interface for resolving workspace_id -> owner/repo (provided by host)
/// Browser never sends owner/repo directly - only workspace_id
pub trait RepoBindingResolver: Send + Sync {
    fn resolve_repo(&self, workspace_id: &str) -> Result<OwnerRepo, RepoResolveError>;
}

// =============================================================================
// GitHub Configuration
// =============================================================================

/// GitHub OAuth App configuration (from environment)
#[derive(Debug, Clone)]
pub struct GitHubConfig {
    /// OAuth App client ID
    pub client_id: String,
    /// OAuth App client secret (server-side only)
    pub client_secret: String,
    /// OAuth callback URL (must match GitHub App settings)
    pub callback_url: String,
}

impl GitHubConfig {
    /// Load GitHub config from environment
    /// Returns None if required env vars not set
    pub fn from_env() -> Option<Self> {
        let client_id = env::var("EKKA_GITHUB_CLIENT_ID").ok()?;
        let client_secret = env::var("EKKA_GITHUB_CLIENT_SECRET").ok()?;
        let callback_url = env::var("EKKA_GITHUB_CALLBACK_URL")
            .unwrap_or_else(|_| "http://localhost:7777/v0/github/oauth/callback".to_string());

        Some(Self {
            client_id,
            client_secret,
            callback_url,
        })
    }

    /// Check if GitHub integration is configured
    pub fn is_configured() -> bool {
        env::var("EKKA_GITHUB_CLIENT_ID").is_ok() && env::var("EKKA_GITHUB_CLIENT_SECRET").is_ok()
    }
}

// =============================================================================
// Demo Repo Resolver (env-based mapping)
// =============================================================================

/// Demo implementation of RepoBindingResolver using EKKA_GITHUB_REPO_MAP
/// Format: {"workspace-uuid-1":"owner/repo1","workspace-uuid-2":"owner/repo2"}
pub struct EnvRepoBindingResolver {
    repo_map: HashMap<String, String>,
}

impl EnvRepoBindingResolver {
    pub fn from_env() -> Self {
        Self {
            repo_map: parse_repo_map(),
        }
    }

    pub fn new(repo_map: HashMap<String, String>) -> Self {
        Self { repo_map }
    }
}

impl RepoBindingResolver for EnvRepoBindingResolver {
    fn resolve_repo(&self, workspace_id: &str) -> Result<OwnerRepo, RepoResolveError> {
        let slug = self.repo_map.get(workspace_id)
            .ok_or(RepoResolveError::NotConfigured)?;

        OwnerRepo::from_slug(slug)
            .ok_or(RepoResolveError::NotConfigured)
    }
}

/// Parse EKKA_GITHUB_REPO_MAP from JSON format
fn parse_repo_map() -> HashMap<String, String> {
    match env::var("EKKA_GITHUB_REPO_MAP") {
        Ok(json) => {
            match serde_json::from_str::<HashMap<String, String>>(&json) {
                Ok(map) => {
                    // Validate entries
                    map.into_iter()
                        .filter(|(_, repo)| is_valid_repo_slug(repo))
                        .collect()
                }
                Err(e) => {
                    warn!(error = %e, "Failed to parse EKKA_GITHUB_REPO_MAP");
                    HashMap::new()
                }
            }
        }
        Err(_) => HashMap::new(),
    }
}

/// Validate repo slug format: "owner/repo"
fn is_valid_repo_slug(slug: &str) -> bool {
    let parts: Vec<&str> = slug.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let owner = parts[0];
    let repo = parts[1];

    // Basic validation: non-empty, alphanumeric + dash/underscore
    !owner.is_empty()
        && !repo.is_empty()
        && owner.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        && repo.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// =============================================================================
// GitHub API Types
// =============================================================================

/// Response for GET /v0/github/status
#[derive(Debug, Clone, Serialize)]
pub struct GitHubStatusResponse {
    /// Whether GitHub OAuth is configured (app has client ID/secret)
    pub configured: bool,
    /// Whether current session has GitHub token connected
    pub connected: bool,
}

/// Response for GET /v0/github/oauth/start
#[derive(Debug, Clone, Serialize)]
pub struct OAuthStartResponse {
    /// URL to redirect user to for GitHub authorization
    pub authorize_url: String,
}

/// Query params for OAuth callback
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackParams {
    pub code: String,
    #[serde(default)]
    pub state: Option<String>,
}

/// Response from GitHub token exchange (internal, not returned to client)
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used when real OAuth is implemented
pub struct GitHubTokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub scope: Option<String>,
}

/// GitHub API error response
#[derive(Debug, Clone, Serialize)]
pub struct GitHubError {
    pub error: String,
    pub code: String,
}

impl GitHubError {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }

    /// OAuth not configured
    pub fn not_configured() -> Self {
        Self::new("GitHub OAuth not configured", "GITHUB_NOT_CONFIGURED")
    }

    /// Repo mapping not found for workspace
    pub fn repo_not_configured() -> Self {
        Self::new("Repository not configured", "GITHUB_REPO_NOT_CONFIGURED")
    }

    /// GitHub API access denied
    pub fn access_denied() -> Self {
        Self::new("GitHub access denied", "GITHUB_ACCESS_DENIED")
    }

    /// GitHub repo not found
    #[allow(dead_code)] // Part of API contract
    pub fn repo_not_found() -> Self {
        Self::new("GitHub repository not found", "GITHUB_REPO_NOT_FOUND")
    }

    /// OAuth failed
    pub fn oauth_failed() -> Self {
        Self::new("GitHub OAuth failed", "GITHUB_OAUTH_FAILED")
    }

    /// No GitHub token for session
    pub fn not_connected() -> Self {
        Self::new("GitHub not connected", "GITHUB_NOT_CONNECTED")
    }

    /// PR creation failed
    #[allow(dead_code)] // Part of API contract
    pub fn pr_creation_failed() -> Self {
        Self::new("PR creation failed", "GITHUB_PR_CREATION_FAILED")
    }
}

// =============================================================================
// PR Creation Types
// =============================================================================

/// Request to create a PR (internal, from git module via host closure)
#[derive(Debug, Clone)]
pub struct CreatePrRequest {
    pub owner: String,
    pub repo: String,
    pub title: String,
    pub body: Option<String>,
    pub head: String,  // Source branch (must be ekka/*)
    pub base: String,  // Target branch (usually "main")
}

/// Response from PR creation
#[derive(Debug, Clone, Serialize)]
pub struct CreatePrResponse {
    pub status: String,
    pub pr_number: u64,
    pub pr_url: String,
}

// =============================================================================
// GitHub Client Trait (for testing)
// =============================================================================

/// Trait for GitHub API operations (allows faking in tests)
pub trait GitHubClient: Send + Sync {
    /// Exchange OAuth code for access token
    fn exchange_code(&self, code: &str) -> Result<String, GitHubError>;

    /// Create a pull request
    fn create_pr(&self, token: &str, request: &CreatePrRequest) -> Result<CreatePrResponse, GitHubError>;

    /// Validate token has access to repo
    fn validate_repo_access(&self, token: &str, owner: &str, repo: &str) -> Result<bool, GitHubError>;
}

/// Real GitHub client implementation (stub for now - uses HTTP in production)
pub struct RealGitHubClient {
    #[allow(dead_code)] // Used when real OAuth is implemented
    pub config: GitHubConfig,
}

impl RealGitHubClient {
    pub fn new(config: GitHubConfig) -> Self {
        Self { config }
    }
}

impl GitHubClient for RealGitHubClient {
    fn exchange_code(&self, _code: &str) -> Result<String, GitHubError> {
        // In a real implementation, this would make an HTTP POST to GitHub
        // For now, this is a stub that would be implemented with reqwest
        info!(
            op = "github.oauth.exchange",
            "Exchanging OAuth code for token (stub)"
        );

        // Stub: In production, use reqwest to POST to https://github.com/login/oauth/access_token
        // with client_id, client_secret, and code

        // Return error for now - real implementation needed
        Err(GitHubError::not_configured())
    }

    fn create_pr(&self, _token: &str, request: &CreatePrRequest) -> Result<CreatePrResponse, GitHubError> {
        // Validate branch has ekka/ prefix
        if !request.head.starts_with("ekka/") {
            return Err(GitHubError::new("Branch must have ekka/ prefix", "GITHUB_INVALID_BRANCH"));
        }

        info!(
            op = "github.pr.create",
            repo = %format!("{}/{}", request.owner, request.repo),
            head = %request.head,
            base = %request.base,
            "Creating PR (stub)"
        );

        // Stub: In production, use reqwest to POST to GitHub API
        // https://api.github.com/repos/{owner}/{repo}/pulls

        // For demo purposes, return stub response
        // Real implementation would parse the GitHub API response
        Err(GitHubError::not_configured())
    }

    fn validate_repo_access(&self, _token: &str, owner: &str, repo: &str) -> Result<bool, GitHubError> {
        info!(
            op = "github.validate_access",
            repo = %format!("{}/{}", owner, repo),
            "Validating repo access (stub)"
        );

        // Stub: Check if token has access to repo
        Err(GitHubError::not_configured())
    }
}

/// Fake GitHub client for testing
#[cfg(test)]
pub struct FakeGitHubClient {
    pub should_fail_exchange: bool,
    pub should_fail_pr: bool,
    pub fake_token: String,
    pub fake_pr_number: u64,
}

#[cfg(test)]
impl Default for FakeGitHubClient {
    fn default() -> Self {
        Self {
            should_fail_exchange: false,
            should_fail_pr: false,
            fake_token: "gho_fake_test_token".to_string(),
            fake_pr_number: 123,
        }
    }
}

#[cfg(test)]
impl GitHubClient for FakeGitHubClient {
    fn exchange_code(&self, _code: &str) -> Result<String, GitHubError> {
        if self.should_fail_exchange {
            Err(GitHubError::oauth_failed())
        } else {
            Ok(self.fake_token.clone())
        }
    }

    fn create_pr(&self, _token: &str, request: &CreatePrRequest) -> Result<CreatePrResponse, GitHubError> {
        // Validate branch prefix
        if !request.head.starts_with("ekka/") {
            return Err(GitHubError::new("Branch must have ekka/ prefix", "GITHUB_INVALID_BRANCH"));
        }

        if self.should_fail_pr {
            Err(GitHubError::pr_creation_failed())
        } else {
            Ok(CreatePrResponse {
                status: "created".to_string(),
                pr_number: self.fake_pr_number,
                pr_url: format!(
                    "https://github.com/{}/{}/pull/{}",
                    request.owner, request.repo, self.fake_pr_number
                ),
            })
        }
    }

    fn validate_repo_access(&self, _token: &str, _owner: &str, _repo: &str) -> Result<bool, GitHubError> {
        Ok(true)
    }
}

// =============================================================================
// OAuth URL Generation
// =============================================================================

/// Generate GitHub OAuth authorization URL
pub fn generate_oauth_url(config: &GitHubConfig, state: &str) -> String {
    let scope = "repo"; // Need repo scope for PR creation
    format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope={}&state={}",
        config.client_id,
        urlencoding::encode(&config.callback_url),
        scope,
        urlencoding::encode(state)
    )
}

// =============================================================================
// Module Context and Mount
// =============================================================================

/// Context for the GitHub module
/// Provided by the host application when mounting
pub struct GitHubModuleContext {
    /// Session validator (provided by host)
    pub session_validator: SessionValidator,
    /// Token store (provided by host - stores tokens server-side)
    pub token_store: Arc<dyn GitHubTokenStore>,
    /// Repo binding resolver (provided by host)
    pub repo_resolver: Arc<dyn RepoBindingResolver>,
    /// GitHub config (from environment)
    pub config: Option<GitHubConfig>,
    /// Log operation prefix (e.g., "node")
    pub log_prefix: String,
}

impl GitHubModuleContext {
    pub fn new(
        session_validator: SessionValidator,
        token_store: Arc<dyn GitHubTokenStore>,
        repo_resolver: Arc<dyn RepoBindingResolver>,
        log_prefix: impl Into<String>,
    ) -> Self {
        Self {
            session_validator,
            token_store,
            repo_resolver,
            config: GitHubConfig::from_env(),
            log_prefix: log_prefix.into(),
        }
    }

    fn log_op(&self, op: &str) -> String {
        format!("{}.github.{}", self.log_prefix, op)
    }

    fn is_configured(&self) -> bool {
        self.config.is_some()
    }
}

/// Mount the GitHub module routes onto a router
/// Routes are only mounted if the module is enabled
pub fn mount<S>(router: Router<S>, ctx: GitHubModuleContext) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !GITHUB_MODULE_CONFIG.is_enabled() {
        info!(
            module = "github",
            enabled = false,
            "GitHub module disabled (set EKKA_ENABLE_GITHUB=1 to enable)"
        );
        return router;
    }

    info!(
        module = "github",
        enabled = true,
        configured = ctx.is_configured(),
        "GitHub module enabled"
    );

    let state = Arc::new(ctx);

    // Create a sub-router with our state, then merge into main router
    let github_router: Router<S> = Router::new()
        .route("/v0/github/status", get(github_status_handler))
        .route("/v0/github/oauth/start", get(github_oauth_start_handler))
        .route("/v0/github/oauth/callback", get(github_oauth_callback_handler))
        .with_state(state);

    router.merge(github_router)
}

// =============================================================================
// Axum Handlers
// =============================================================================

/// GET /v0/github/status - Get GitHub integration status
/// Returns whether OAuth is configured and whether current session has token
async fn github_status_handler(
    State(ctx): State<Arc<GitHubModuleContext>>,
    headers: HeaderMap,
) -> Result<Json<GitHubStatusResponse>, (StatusCode, Json<GitHubError>)> {
    info!(
        op = %ctx.log_op("status.request"),
        "GitHub status requested"
    );

    // Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("status.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(GitHubError::new(e.error, e.code)),
        )
    })?;

    let connected = ctx.token_store.has_github_token(&session.session_id);

    info!(
        op = %ctx.log_op("status.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        configured = ctx.is_configured(),
        connected = connected,
        "GitHub status complete"
    );

    Ok(Json(GitHubStatusResponse {
        configured: ctx.is_configured(),
        connected,
    }))
}

/// GET /v0/github/oauth/start - Start OAuth flow
/// Returns URL to redirect user to for GitHub authorization
async fn github_oauth_start_handler(
    State(ctx): State<Arc<GitHubModuleContext>>,
    headers: HeaderMap,
) -> Result<Json<OAuthStartResponse>, (StatusCode, Json<GitHubError>)> {
    info!(
        op = %ctx.log_op("oauth.start.request"),
        "GitHub OAuth start requested"
    );

    // Validate session
    let session = (ctx.session_validator)(&headers).map_err(|e| {
        warn!(
            op = %ctx.log_op("oauth.start.auth_error"),
            code = %e.code,
            "Session validation failed"
        );
        (
            e.status,
            Json(GitHubError::new(e.error, e.code)),
        )
    })?;

    // Check if GitHub is configured
    let config = ctx.config.as_ref().ok_or_else(|| {
        warn!(
            op = %ctx.log_op("oauth.start.not_configured"),
            "GitHub OAuth not configured"
        );
        (StatusCode::SERVICE_UNAVAILABLE, Json(GitHubError::not_configured()))
    })?;

    // Generate OAuth URL with session ID as state (for CSRF protection)
    // Note: In production, use a proper CSRF token, not the session ID
    let authorize_url = generate_oauth_url(config, &session.session_id);

    info!(
        op = %ctx.log_op("oauth.start.ok"),
        session_id = %&session.session_id[..8.min(session.session_id.len())],
        "GitHub OAuth URL generated"
    );

    Ok(Json(OAuthStartResponse { authorize_url }))
}

/// GET /v0/github/oauth/callback - OAuth callback handler
/// Exchanges code for token and stores it server-side
async fn github_oauth_callback_handler(
    State(ctx): State<Arc<GitHubModuleContext>>,
    Query(params): Query<OAuthCallbackParams>,
) -> Result<Json<GitHubStatusResponse>, (StatusCode, Json<GitHubError>)> {
    info!(
        op = %ctx.log_op("oauth.callback.request"),
        "GitHub OAuth callback received"
    );

    // Extract session ID from state parameter
    let session_id = params.state.as_deref().ok_or_else(|| {
        warn!(
            op = %ctx.log_op("oauth.callback.no_state"),
            "Missing state parameter in OAuth callback"
        );
        (StatusCode::BAD_REQUEST, Json(GitHubError::new("Missing state parameter", "MISSING_STATE")))
    })?;

    // Check if GitHub is configured
    let _config = ctx.config.as_ref().ok_or_else(|| {
        warn!(
            op = %ctx.log_op("oauth.callback.not_configured"),
            "GitHub OAuth not configured"
        );
        (StatusCode::SERVICE_UNAVAILABLE, Json(GitHubError::not_configured()))
    })?;

    // Stub: In production, exchange code for token using RealGitHubClient
    // For now, just log and return not_configured
    info!(
        op = %ctx.log_op("oauth.callback.stub"),
        session_id = %&session_id[..8.min(session_id.len())],
        code_len = params.code.len(),
        "OAuth callback received (stub - real token exchange not implemented)"
    );

    // Return status showing not connected (stub behavior)
    Ok(Json(GitHubStatusResponse {
        configured: true,
        connected: false,
    }))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_path_leak(s: &str) {
        assert!(!s.contains("/Users"), "Leaked /Users path: {}", s);
        assert!(!s.contains("/home"), "Leaked /home path: {}", s);
        assert!(!s.contains("/var"), "Leaked /var path: {}", s);
        assert!(!s.contains("C:\\"), "Leaked C:\\ path: {}", s);
    }

    fn assert_no_secret_leak(s: &str) {
        assert!(!s.contains("gho_"), "Leaked GitHub token: {}", s);
        assert!(!s.contains("ghp_"), "Leaked GitHub PAT: {}", s);
        assert!(!s.contains("secret"), "Leaked secret: {}", s);
    }

    // =========================================================================
    // OwnerRepo Tests
    // =========================================================================

    #[test]
    fn test_owner_repo_from_slug_valid() {
        let result = OwnerRepo::from_slug("owner/repo");
        assert!(result.is_some());
        let or = result.unwrap();
        assert_eq!(or.owner, "owner");
        assert_eq!(or.repo, "repo");
    }

    #[test]
    fn test_owner_repo_from_slug_invalid() {
        assert!(OwnerRepo::from_slug("").is_none());
        assert!(OwnerRepo::from_slug("noslash").is_none());
        assert!(OwnerRepo::from_slug("too/many/slashes").is_none());
        assert!(OwnerRepo::from_slug("/repo").is_none());
        assert!(OwnerRepo::from_slug("owner/").is_none());
    }

    // =========================================================================
    // Repo Slug Validation Tests
    // =========================================================================

    #[test]
    fn test_valid_repo_slug() {
        assert!(is_valid_repo_slug("owner/repo"));
        assert!(is_valid_repo_slug("my-org/my-repo"));
        assert!(is_valid_repo_slug("org_name/repo_name"));
        assert!(is_valid_repo_slug("org/repo.js"));
    }

    #[test]
    fn test_invalid_repo_slug() {
        assert!(!is_valid_repo_slug(""));
        assert!(!is_valid_repo_slug("noslash"));
        assert!(!is_valid_repo_slug("too/many/slashes"));
        assert!(!is_valid_repo_slug("/repo"));
        assert!(!is_valid_repo_slug("owner/"));
        assert!(!is_valid_repo_slug("owner/repo with spaces"));
    }

    // =========================================================================
    // Error Response Tests
    // =========================================================================

    #[test]
    fn test_github_error_no_paths() {
        let errors = [
            GitHubError::not_configured(),
            GitHubError::repo_not_configured(),
            GitHubError::access_denied(),
            GitHubError::repo_not_found(),
            GitHubError::oauth_failed(),
            GitHubError::not_connected(),
            GitHubError::pr_creation_failed(),
        ];

        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            assert_no_path_leak(&json);
            assert_no_secret_leak(&json);
        }
    }

    #[test]
    fn test_github_status_response_no_secrets() {
        let response = GitHubStatusResponse {
            configured: true,
            connected: true,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
        assert_no_secret_leak(&json);
        assert!(!json.contains("token"), "Status should not mention token");
    }

    #[test]
    fn test_create_pr_response_no_secrets() {
        let response = CreatePrResponse {
            status: "created".to_string(),
            pr_number: 123,
            pr_url: "https://github.com/owner/repo/pull/123".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_no_path_leak(&json);
        assert_no_secret_leak(&json);
    }

    // =========================================================================
    // RepoResolveError Tests
    // =========================================================================

    #[test]
    fn test_repo_resolve_error_no_paths() {
        let errors = [
            RepoResolveError::NotConfigured,
            RepoResolveError::InvalidWorkspace,
        ];

        for err in errors {
            let message = err.message();
            let code = err.code();
            assert_no_path_leak(message);
            assert_no_path_leak(code);
        }
    }

    // =========================================================================
    // Fake Client Tests
    // =========================================================================

    #[test]
    fn test_fake_client_exchange_success() {
        let client = FakeGitHubClient::default();
        let result = client.exchange_code("test_code");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "gho_fake_test_token");
    }

    #[test]
    fn test_fake_client_exchange_failure() {
        let client = FakeGitHubClient {
            should_fail_exchange: true,
            ..Default::default()
        };
        let result = client.exchange_code("test_code");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "GITHUB_OAUTH_FAILED");
    }

    #[test]
    fn test_fake_client_pr_success() {
        let client = FakeGitHubClient::default();
        let request = CreatePrRequest {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            title: "Test PR".to_string(),
            body: Some("Test body".to_string()),
            head: "ekka/test/branch".to_string(),
            base: "main".to_string(),
        };
        let result = client.create_pr("token", &request);
        assert!(result.is_ok());
        let pr = result.unwrap();
        assert_eq!(pr.status, "created");
        assert_eq!(pr.pr_number, 123);
    }

    #[test]
    fn test_fake_client_pr_rejects_non_ekka_branch() {
        let client = FakeGitHubClient::default();
        let request = CreatePrRequest {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            title: "Test PR".to_string(),
            body: None,
            head: "feature/not-ekka".to_string(), // Invalid - not ekka/ prefix
            base: "main".to_string(),
        };
        let result = client.create_pr("token", &request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "GITHUB_INVALID_BRANCH");
    }

    // =========================================================================
    // OAuth URL Tests
    // =========================================================================

    #[test]
    fn test_generate_oauth_url_structure() {
        let config = GitHubConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_secret".to_string(),
            callback_url: "http://localhost:7777/v0/github/oauth/callback".to_string(),
        };

        let url = generate_oauth_url(&config, "test_state");

        assert!(url.starts_with("https://github.com/login/oauth/authorize"));
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains("scope=repo"));
        assert!(url.contains("state=test_state"));
        // Should NOT contain secret
        assert!(!url.contains("test_secret"));
    }

    // =========================================================================
    // EnvRepoBindingResolver Tests
    // =========================================================================

    #[test]
    fn test_env_repo_resolver_found() {
        let mut map = HashMap::new();
        map.insert("ws-123".to_string(), "owner/repo".to_string());
        let resolver = EnvRepoBindingResolver::new(map);

        let result = resolver.resolve_repo("ws-123");
        assert!(result.is_ok());
        let or = result.unwrap();
        assert_eq!(or.owner, "owner");
        assert_eq!(or.repo, "repo");
    }

    #[test]
    fn test_env_repo_resolver_not_found() {
        let resolver = EnvRepoBindingResolver::new(HashMap::new());
        let result = resolver.resolve_repo("ws-unknown");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "GITHUB_REPO_NOT_CONFIGURED");
    }

    // =========================================================================
    // Module Config Tests
    // =========================================================================

    #[test]
    fn test_module_config_default_disabled() {
        // GitHub should be disabled by default (privileged)
        assert!(!GITHUB_MODULE_CONFIG.default_enabled);
    }
}
