//! Tauri commands
//!
//! Entry points for TypeScript → Rust communication.

use crate::bootstrap::initialize_home;
use crate::config;
use crate::engine_process;
use crate::grants::require_home_granted;
use crate::handlers;
use crate::node_auth;
use crate::node_credentials;
use crate::ops::{auth, runtime};
use crate::state::EngineState;
use crate::types::{EngineRequest, EngineResponse};
use serde_json::Value;
use tauri::State;

/// Initialize the SDK and store in state
#[tauri::command]
pub fn engine_connect(state: State<EngineState>) -> Result<(), String> {
    let mut connected = state.connected.lock().map_err(|e| e.to_string())?;

    if *connected {
        return Ok(());
    }

    // Initialize home directory structure
    let bootstrap = initialize_home()?;

    // Store home path
    if let Ok(mut hp) = state.home_path.lock() {
        *hp = Some(bootstrap.home_path().to_path_buf());
    }

    // Store instance_id from marker (used as node_id for grants)
    let marker_path = bootstrap.home_path().join(".ekka-marker.json");
    if let Ok(content) = std::fs::read_to_string(&marker_path) {
        if let Ok(marker) = serde_json::from_str::<Value>(&content) {
            if let Some(instance_id_str) = marker.get("instance_id").and_then(|v| v.as_str()) {
                if let Ok(instance_id) = uuid::Uuid::parse_str(instance_id_str) {
                    if let Ok(mut nid) = state.node_id.lock() {
                        *nid = Some(instance_id);
                    }
                }
            }
        }
    }

    *connected = true;
    Ok(())
}

/// Clean up
#[tauri::command]
pub fn engine_disconnect(state: State<EngineState>) {
    // Clear vault cache first (before clearing auth)
    state.clear_vault_cache();

    if let Ok(mut connected) = state.connected.lock() {
        *connected = false;
    }
    if let Ok(mut auth) = state.auth.lock() {
        *auth = None;
    }
}

/// Main RPC dispatcher - routes all operations to handlers
///
/// ═══════════════════════════════════════════════════════════════════════════════════════════
/// DRIFT GUARD - ARCHITECTURE FREEZE
/// ═══════════════════════════════════════════════════════════════════════════════════════════
/// DO NOT extend this without revisiting the Desktop–Engine architecture decision.
///
/// The routing switch below (engine vs stub) is FROZEN as of Phase 3G.
/// Engine routing is one-way: once disabled for a session, it stays disabled.
/// The stub path handles all operations locally via SDK handlers.
///
/// Any changes to routing logic require explicit architecture review.
/// ═══════════════════════════════════════════════════════════════════════════════════════════
#[tauri::command]
pub fn engine_request(req: EngineRequest, state: State<EngineState>) -> EngineResponse {
    // LOCAL-ONLY OPERATIONS: Never route to engine
    // These are desktop-specific operations that must be handled locally
    let local_only = matches!(
        req.op.as_str(),
        "setup.status" | "nodeCredentials.set" | "nodeCredentials.status" | "nodeCredentials.clear"
    );

    // ROUTING SWITCH: If real engine is available and not local-only, route to it
    if !local_only && state.is_engine_available() {
        if let Some(response) = engine_process::route_to_engine(&req) {
            return response;
        }
        // Engine failed - permanently disable for this session
        state.disable_engine();
        tracing::warn!(op = "engine.disabled.session", "Engine routing disabled for session, using stub");
    }

    // STUB PATH: Handle locally via SDK handlers

    // Check connected (except for status operations and setup)
    if !matches!(req.op.as_str(), "runtime.info" | "home.status" | "vault.status" | "setup.status" | "nodeCredentials.set" | "nodeCredentials.status" | "nodeCredentials.clear") {
        let connected = match state.connected.lock() {
            Ok(guard) => *guard,
            Err(e) => return EngineResponse::err("INTERNAL_ERROR", &e.to_string()),
        };

        if !connected {
            return EngineResponse::err(
                "NOT_CONNECTED",
                "Engine not connected. Call engine_connect first.",
            );
        }
    }

    // Dispatch based on operation
    match req.op.as_str() {
        // Setup Status (pre-login, no connection required)
        "setup.status" => handle_setup_status(&state),

        // Auth
        "auth.set" => auth::handle_set(&req.payload, &state),

        // Node Credentials (keychain-stored node_id + node_secret)
        "nodeCredentials.set" => handle_node_credentials_set(&req.payload),
        "nodeCredentials.status" => handle_node_credentials_status(&state),
        "nodeCredentials.clear" => handle_node_credentials_clear(),

        // Node Session Authentication
        "nodeSession.ensureIdentity" => handle_ensure_node_identity(&state),
        "nodeSession.bootstrap" => handle_bootstrap_node_session(&req.payload, &state),
        "nodeSession.status" => handle_node_session_status(&state),

        // Home (use new SDK handlers)
        "home.status" => handlers::home::handle_status(&state),
        "home.grant" => handlers::home::handle_grant(&state),

        // Paths (new SDK operations)
        "paths.check" => handlers::paths::handle_check(&req.payload, &state),
        "paths.list" => handlers::paths::handle_list(&req.payload, &state),
        "paths.get" => handlers::paths::handle_get(&req.payload, &state),
        "paths.request" => handlers::paths::handle_request(&req.payload, &state),
        "paths.remove" => handlers::paths::handle_remove(&req.payload, &state),

        // Runtime
        "runtime.info" => runtime::handle_info(&state),

        // Runner status (local runner loop status)
        "runner.status" => {
            let status = state.runner_state.get();
            EngineResponse::ok(serde_json::json!(status))
        }

        // Runner task stats (proxied from engine API)
        "runner.taskStats" => handle_runner_task_stats(&state),

        // Workflow Runs (proxied from engine API)
        "workflowRuns.create" => handle_workflow_runs_create(&req.payload),
        "workflowRuns.get" => handle_workflow_runs_get(&req.payload),

        // Auth (proxied from API)
        "auth.login" => handle_auth_login(&req.payload),
        "auth.refresh" => handle_auth_refresh(&req.payload),
        "auth.logout" => handle_auth_logout(&req.payload),

        // Engine status (read-only diagnostics)
        "engine.status" => {
            let status = state.get_engine_status();
            EngineResponse::ok(serde_json::json!(status))
        }

        // Database (require HOME_GRANTED)
        "db.get" | "db.put" | "db.delete" => {
            if let Err(e) = require_home_granted(&state) {
                return e;
            }
            EngineResponse::err("NOT_IMPLEMENTED", &format!("{} not yet implemented", req.op))
        }

        // Queue (require HOME_GRANTED)
        "queue.enqueue" | "queue.claim" | "queue.ack" | "queue.nack" | "queue.heartbeat" => {
            if let Err(e) = require_home_granted(&state) {
                return e;
            }
            EngineResponse::err("NOT_IMPLEMENTED", &format!("{} not yet implemented", req.op))
        }

        // Pipeline (require HOME_GRANTED)
        "pipeline.submit" | "pipeline.events" => {
            if let Err(e) = require_home_granted(&state) {
                return e;
            }
            EngineResponse::err("NOT_IMPLEMENTED", &format!("{} not yet implemented", req.op))
        }

        // Vault - Status/Capabilities (require HOME_GRANTED)
        "vault.status" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_status(&state)
        }
        "vault.capabilities" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_capabilities(&state)
        }

        // Vault - Secrets (require HOME_GRANTED)
        "vault.secrets.list" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_secrets_list(&req.payload, &state)
        }
        "vault.secrets.get" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_secrets_get(&req.payload, &state)
        }
        "vault.secrets.create" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_secrets_create(&req.payload, &state)
        }
        "vault.secrets.update" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_secrets_update(&req.payload, &state)
        }
        "vault.secrets.delete" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_secrets_delete(&req.payload, &state)
        }
        "vault.secrets.upsert" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_secrets_upsert(&req.payload, &state)
        }

        // Vault - Bundles (require HOME_GRANTED)
        "vault.bundles.list" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_list(&req.payload, &state)
        }
        "vault.bundles.get" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_get(&req.payload, &state)
        }
        "vault.bundles.create" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_create(&req.payload, &state)
        }
        "vault.bundles.rename" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_rename(&req.payload, &state)
        }
        "vault.bundles.delete" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_delete(&req.payload, &state)
        }
        "vault.bundles.listSecrets" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_list_secrets(&req.payload, &state)
        }
        "vault.bundles.addSecret" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_add_secret(&req.payload, &state)
        }
        "vault.bundles.removeSecret" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_bundles_remove_secret(&req.payload, &state)
        }

        // Vault - Files (require HOME_GRANTED)
        "vault.files.writeText" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_write_text(&req.payload, &state)
        }
        "vault.files.writeBytes" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_write_bytes(&req.payload, &state)
        }
        "vault.files.readText" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_read_text(&req.payload, &state)
        }
        "vault.files.readBytes" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_read_bytes(&req.payload, &state)
        }
        "vault.files.list" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_list(&req.payload, &state)
        }
        "vault.files.exists" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_exists(&req.payload, &state)
        }
        "vault.files.delete" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_delete(&req.payload, &state)
        }
        "vault.files.mkdir" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_mkdir(&req.payload, &state)
        }
        "vault.files.move" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_files_move(&req.payload, &state)
        }

        // Vault - Injection (require HOME_GRANTED) - DEFERRED
        "vault.attachSecretsToConnector" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_attach_secrets_to_connector(&req.payload, &state)
        }
        "vault.injectSecretsIntoRun" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_inject_secrets_into_run(&req.payload, &state)
        }

        // Vault - Audit (require HOME_GRANTED)
        "vault.audit.list" => {
            if let Err(e) = require_home_granted(&state) { return e; }
            handlers::vault::handle_audit_list(&req.payload, &state)
        }

        // Legacy vault operations (deprecated)
        "vault.init" | "vault.isInitialized" | "vault.install" | "vault.listBundles"
        | "vault.showPolicy" | "vault.folders.list" | "vault.folders.get"
        | "vault.folders.create" | "vault.folders.rename" | "vault.folders.delete" => {
            if let Err(e) = require_home_granted(&state) {
                return e;
            }
            EngineResponse::err("DEPRECATED", &format!("{} is deprecated, use vault.* API instead", req.op))
        }

        // Debug utilities (dev mode only)
        "debug.isDevMode" => handle_is_dev_mode(),
        "debug.openFolder" => handle_open_folder(&req.payload, &state),
        "debug.resolveVaultPath" => handle_resolve_vault_path(&req.payload, &state),

        // Unknown
        _ => EngineResponse::err("INVALID_OP", &format!("Unknown operation: {}", req.op)),
    }
}

// =============================================================================
// Setup Status Handler
// =============================================================================

/// Get setup status for pre-login wizard
///
/// Returns status of:
/// - nodeIdentity: configured | not_configured
/// - setupComplete: true if node credentials are configured
///
/// This is called before login to determine if setup wizard is needed.
/// Home folder grant is handled post-login via HomeSetupPage.
fn handle_setup_status(_state: &EngineState) -> EngineResponse {
    tracing::info!(op = "rust.local.op", opName = "setup.status", "Handling setup.status locally");

    // Check node identity status (credentials in vault)
    let node_configured = node_credentials::has_credentials();

    // Setup is complete when node credentials are configured
    // Home folder grant is handled post-login, not here
    let setup_complete = node_configured;

    tracing::info!(
        op = "desktop.setup.status",
        node_configured = node_configured,
        setup_complete = setup_complete,
        "Setup status checked"
    );

    EngineResponse::ok(serde_json::json!({
        "nodeIdentity": if node_configured { "configured" } else { "not_configured" },
        "setupComplete": setup_complete
    }))
}

// =============================================================================
// Node Credentials Handlers
// =============================================================================

/// Set node credentials (store in OS keychain)
///
/// Accepts node_id (UUID) and node_secret (string).
/// Validates both before storing.
fn handle_node_credentials_set(payload: &Value) -> EngineResponse {
    tracing::info!(op = "rust.local.op", opName = "nodeCredentials.set", "Handling nodeCredentials.set locally");

    // Extract node_id
    let node_id_str = match payload.get("nodeId").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return EngineResponse::err("INVALID_PAYLOAD", "nodeId is required"),
    };

    // Validate node_id format
    let node_id = match node_credentials::validate_node_id(node_id_str) {
        Ok(id) => id,
        Err(e) => return EngineResponse::err("INVALID_NODE_ID", &e.to_string()),
    };

    // Extract node_secret
    let node_secret = match payload.get("nodeSecret").and_then(|v| v.as_str()) {
        Some(secret) => secret,
        None => return EngineResponse::err("INVALID_PAYLOAD", "nodeSecret is required"),
    };

    // Validate node_secret
    if let Err(e) = node_credentials::validate_node_secret(node_secret) {
        return EngineResponse::err("INVALID_NODE_SECRET", &e.to_string());
    }

    // Store credentials
    match node_credentials::store_credentials(&node_id, node_secret) {
        Ok(()) => EngineResponse::ok(serde_json::json!({
            "ok": true,
            "nodeId": node_id.to_string()
        })),
        Err(e) => EngineResponse::err("CREDENTIALS_STORE_ERROR", &e.to_string()),
    }
}

/// Get node credentials status (has credentials + node_id + auth status)
fn handle_node_credentials_status(state: &EngineState) -> EngineResponse {
    tracing::info!(op = "rust.local.op", opName = "nodeCredentials.status", "Handling nodeCredentials.status locally");
    let status = node_credentials::get_status();
    let auth_token = state.get_node_auth_token();

    EngineResponse::ok(serde_json::json!({
        "hasCredentials": status.has_credentials,
        "nodeId": status.node_id,
        "isAuthenticated": auth_token.is_some(),
        "authSession": auth_token.map(|t| serde_json::json!({
            "sessionId": t.session_id.to_string(),
            "tenantId": t.tenant_id.to_string(),
            "workspaceId": t.workspace_id.to_string(),
            "expiresAt": t.expires_at.to_rfc3339()
        }))
    }))
}

/// Clear node credentials from OS keychain
fn handle_node_credentials_clear() -> EngineResponse {
    tracing::info!(op = "rust.local.op", opName = "nodeCredentials.clear", "Handling nodeCredentials.clear locally");
    match node_credentials::clear_credentials() {
        Ok(()) => EngineResponse::ok(serde_json::json!({
            "ok": true
        })),
        Err(e) => EngineResponse::err("CREDENTIALS_CLEAR_ERROR", &e.to_string()),
    }
}

// =============================================================================
// Runner Task Stats (Proxied HTTP)
// =============================================================================

/// Fetch runner task stats from engine API.
/// Proxies GET /engine/runner-tasks/stats through Rust to avoid CORS.
/// Auto-authenticates from keychain if token is missing (single-flight, no retry on failure).
fn handle_runner_task_stats(state: &EngineState) -> EngineResponse {
    use crate::state::NodeAuthState;

    // Get engine URL (baked at build time)
    let engine_url = option_env!("EKKA_ENGINE_URL")
        .unwrap_or("https://api.ekka.ai")
        .to_string();

    // Get node auth token for Authorization header
    let node_token = match state.get_node_auth_token() {
        Some(token) => token,
        None => {
            // Check auth state - don't retry if already failed
            let auth_state = state.node_auth_state.get();
            if auth_state == NodeAuthState::Failed {
                let error = state.node_auth_state.get_last_error()
                    .unwrap_or_else(|| "Authentication previously failed".to_string());
                return EngineResponse::err("NOT_AUTHENTICATED", &error);
            }
            if auth_state == NodeAuthState::Authenticating {
                return EngineResponse::err("NOT_AUTHENTICATED", "Authentication in progress");
            }
            if auth_state == NodeAuthState::Authenticated {
                // Token should exist but doesn't - inconsistent state
                return EngineResponse::err("NOT_AUTHENTICATED", "Token expired, restart app");
            }

            // Token missing - try auto-auth from keychain (single-flight)
            if !node_credentials::has_credentials() {
                return EngineResponse::err(
                    "NOT_AUTHENTICATED",
                    "Node not authenticated. Complete setup first.",
                );
            }

            // Try to acquire single-flight lock
            if !state.node_auth_state.try_start() {
                return EngineResponse::err("NOT_AUTHENTICATED", "Authentication in progress");
            }

            // Attempt auto-auth (single attempt, no retry)
            tracing::info!(
                op = "desktop.node.auth.attempt",
                reason = "runner.taskStats",
                "Authenticating node from keychain"
            );

            match node_credentials::authenticate_node(&engine_url) {
                Ok(token) => {
                    // Store token and mark authenticated
                    state.node_auth_token.set(token.clone());
                    state.node_auth_state.set_authenticated();
                    token
                }
                Err(e) => {
                    let error_msg = format!("Node authentication failed: {}", e);
                    tracing::warn!(
                        op = "desktop.node.auth.failed",
                        error = %e,
                        "Node authentication failed - will not retry"
                    );
                    state.node_auth_state.set_failed(error_msg.clone());
                    return EngineResponse::err("NOT_AUTHENTICATED", &error_msg);
                }
            }
        }
    };

    // Build HTTP client
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResponse::err("HTTP_CLIENT_ERROR", &e.to_string()),
    };

    let request_id = uuid::Uuid::new_v4().to_string();

    // Make request with security envelope headers
    let response = client
        .get(format!("{}/engine/runner-tasks/stats", engine_url))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", node_token.token))
        .header("X-EKKA-PROOF-TYPE", "jwt")
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &request_id)
        .header("X-EKKA-MODULE", "engine.runner_tasks")
        .header("X-EKKA-ACTION", "stats")
        .header("X-EKKA-CLIENT", config::app_slug())
        .header("X-EKKA-CLIENT-VERSION", "0.2.0")
        .send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => EngineResponse::ok(data),
                    Err(e) => EngineResponse::err("PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body = resp.text().unwrap_or_default();
                EngineResponse::err(
                    "HTTP_ERROR",
                    &format!("HTTP {}: {}", status_code, body),
                )
            }
        }
        Err(e) => EngineResponse::err("REQUEST_FAILED", &e.to_string()),
    }
}

// =============================================================================
// Debug Handlers
// =============================================================================

/// Check if running in development mode (EKKA_ENV=development)
fn handle_is_dev_mode() -> EngineResponse {
    let is_dev = std::env::var("EKKA_ENV")
        .map(|v| v == "development")
        .unwrap_or(false);

    EngineResponse::ok(serde_json::json!({ "isDevMode": is_dev }))
}

/// Open a folder in the system file browser
fn handle_open_folder(payload: &Value, state: &EngineState) -> EngineResponse {
    // Only allow in dev mode
    let is_dev = std::env::var("EKKA_ENV")
        .map(|v| v == "development")
        .unwrap_or(false);

    if !is_dev {
        return EngineResponse::err("DEV_MODE_ONLY", "debug.openFolder is only available in development mode");
    }

    let path = match payload.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return EngineResponse::err("INVALID_PAYLOAD", "path is required"),
    };

    // If path starts with vault://, resolve it to filesystem path
    let resolved_path = if path.starts_with("vault://") {
        // Get home path
        let home_path = match state.home_path.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(p) => p.clone(),
                None => return EngineResponse::err("NOT_CONNECTED", "Home path not initialized"),
            },
            Err(e) => return EngineResponse::err("INTERNAL_ERROR", &e.to_string()),
        };

        // vault://tmp/... -> {EKKA_HOME}/vault/tmp/...
        let vault_path = path.strip_prefix("vault://").unwrap_or(path);
        home_path.join("vault").join(vault_path)
    } else {
        std::path::PathBuf::from(path)
    };

    // Check if path exists
    if !resolved_path.exists() {
        return EngineResponse::err("PATH_NOT_FOUND", &format!("Path does not exist: {}", resolved_path.display()));
    }

    // Open folder using system default
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&resolved_path)
            .spawn()
            .map_err(|e| e.to_string())
            .ok();
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&resolved_path)
            .spawn()
            .map_err(|e| e.to_string())
            .ok();
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&resolved_path)
            .spawn()
            .map_err(|e| e.to_string())
            .ok();
    }

    EngineResponse::ok(serde_json::json!({
        "ok": true,
        "path": resolved_path.display().to_string()
    }))
}

/// Resolve a vault:// path to filesystem path (dev mode only)
fn handle_resolve_vault_path(payload: &Value, state: &EngineState) -> EngineResponse {
    // Only allow in dev mode
    let is_dev = std::env::var("EKKA_ENV")
        .map(|v| v == "development")
        .unwrap_or(false);

    if !is_dev {
        return EngineResponse::err("DEV_MODE_ONLY", "debug.resolveVaultPath is only available in development mode");
    }

    let vault_uri = match payload.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return EngineResponse::err("INVALID_PAYLOAD", "path is required"),
    };

    if !vault_uri.starts_with("vault://") {
        return EngineResponse::err("INVALID_PATH", "Path must start with vault://");
    }

    // Get home path
    let home_path = match state.home_path.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(p) => p.clone(),
            None => return EngineResponse::err("NOT_CONNECTED", "Home path not initialized"),
        },
        Err(e) => return EngineResponse::err("INTERNAL_ERROR", &e.to_string()),
    };

    // vault://tmp/... -> {EKKA_HOME}/vault/tmp/...
    let vault_path = vault_uri.strip_prefix("vault://").unwrap_or(vault_uri);
    let resolved_path = home_path.join("vault").join(vault_path);

    EngineResponse::ok(serde_json::json!({
        "vaultUri": vault_uri,
        "filesystemPath": resolved_path.display().to_string(),
        "exists": resolved_path.exists()
    }))
}

// =============================================================================
// Node Session Handlers
// =============================================================================

/// Ensure node identity exists
///
/// Returns node identity from node auth token (obtained at startup via node_secret auth).
/// Does NOT use Ed25519 keypair generation.
fn handle_ensure_node_identity(state: &EngineState) -> EngineResponse {
    // Use node auth token if available (from startup auth)
    if let Some(node_token) = state.get_node_auth_token() {
        tracing::info!(
            op = "node_identity.from_token",
            node_id = %node_token.node_id,
            "Node identity from auth token"
        );
        return EngineResponse::ok(serde_json::json!({
            "ok": true,
            "node_id": node_token.node_id.to_string(),
            "tenant_id": node_token.tenant_id.to_string(),
            "workspace_id": node_token.workspace_id.to_string(),
            "auth_method": "node_secret"
        }));
    }

    // No node auth token - check for credentials
    let creds_status = node_credentials::get_status();
    if creds_status.has_credentials {
        // Credentials exist but auth failed or not attempted
        return EngineResponse::err(
            "NODE_NOT_AUTHENTICATED",
            "Node credentials exist but not authenticated. Restart app to authenticate.",
        );
    }

    // No credentials configured
    EngineResponse::err(
        "NODE_CREDENTIALS_MISSING",
        "Node credentials not configured. Use nodeCredentials.set to configure.",
    )
}

/// Bootstrap node session using node_id + node_secret auth
///
/// Uses node auth token (role=node) obtained at startup.
/// Requires local engine to be available (strict local engine mode).
/// Does NOT use Ed25519 register/challenge/session flow.
fn handle_bootstrap_node_session(payload: &Value, state: &EngineState) -> EngineResponse {
    // NodeSessionRunner is an in-process runner that uses node session auth (Authorization: Bearer).
    // It does NOT require the local engine-bootstrap binary - it makes direct HTTP calls to the engine API.
    // The engine_available check was overly restrictive and has been removed.

    // Get home_path
    let home_path = match state.home_path.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(p) => p.clone(),
            None => return EngineResponse::err("NOT_CONNECTED", "Home path not initialized"),
        },
        Err(e) => return EngineResponse::err("INTERNAL_ERROR", &e.to_string()),
    };

    // Get node_id from state
    let node_id = match state.node_id.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(id) => *id,
            None => return EngineResponse::err("NOT_CONNECTED", "Node ID not initialized"),
        },
        Err(e) => return EngineResponse::err("INTERNAL_ERROR", &e.to_string()),
    };

    // REQUIRE node auth token (from startup auth via node_id + node_secret)
    // Do NOT fall back to user auth or Ed25519 flow
    let node_token = match state.get_node_auth_token() {
        Some(token) => {
            tracing::info!(
                op = "node_session.using_node_token",
                node_id = %token.node_id,
                session_id = %token.session_id,
                "Using node auth token for session"
            );
            token
        }
        None => {
            tracing::error!(
                op = "node_session.no_token",
                "Node auth token not available - authenticate node at startup first"
            );
            return EngineResponse::err(
                "NODE_NOT_AUTHENTICATED",
                "Node not authenticated. Restart app with valid node credentials.",
            );
        }
    };

    // Get device fingerprint from marker
    let marker_path = home_path.join(".ekka-marker.json");
    let device_fingerprint = std::fs::read_to_string(&marker_path)
        .ok()
        .and_then(|content| serde_json::from_str::<Value>(&content).ok())
        .and_then(|marker| marker.get("device_id_fingerprint").and_then(|v| v.as_str()).map(|s| s.to_string()));

    // Create NodeSession from node auth token (no Ed25519 flow)
    let node_session = node_auth::NodeSession {
        token: node_token.token.clone(),
        session_id: node_token.session_id,
        tenant_id: node_token.tenant_id,
        workspace_id: node_token.workspace_id,
        expires_at: node_token.expires_at,
    };

    // Store session in state
    state.node_session.set(node_session.clone());

    // Check if we should start the runner
    let start_runner = payload.get("startRunner").and_then(|v| v.as_bool()).unwrap_or(false);

    if start_runner {
        // Build runner config from node auth token
        let runner_config = node_auth::NodeSessionRunnerConfig {
            engine_url: option_env!("EKKA_ENGINE_URL")
                .map(|s| s.to_string())
                .or_else(|| std::env::var("ENGINE_URL").ok())
                .unwrap_or_default(),
            node_url: std::env::var("NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:7777".to_string()),
            session_token: node_token.token.clone(),
            tenant_id: node_token.tenant_id,
            workspace_id: node_token.workspace_id,
            node_id,
        };

        let runner_state = state.runner_state.clone();
        let session_holder = state.node_session.clone();
        let home_path_clone = home_path.clone();
        let device_fp = device_fingerprint.clone();

        // Spawn runner in background
        tauri::async_runtime::spawn(async move {
            let _ = crate::node_runner::start_node_runner(
                runner_state,
                session_holder,
                runner_config,
                home_path_clone,
                device_fp,
                None, // No user_sub with node auth
            ).await;
        });
    }

    let session_info = serde_json::json!({
        "session_id": node_session.session_id.to_string(),
        "tenant_id": node_session.tenant_id.to_string(),
        "workspace_id": node_session.workspace_id.to_string(),
        "expires_at": node_session.expires_at.to_rfc3339()
    });

    EngineResponse::ok(serde_json::json!({
        "ok": true,
        "node_id": node_id.to_string(),
        "auth_method": "node_secret",
        "session": session_info
    }))
}

/// Get current node session status
fn handle_node_session_status(state: &EngineState) -> EngineResponse {
    let identity = state.node_identity.lock().ok().and_then(|g| g.clone());
    let session = state.node_session.get();

    EngineResponse::ok(serde_json::json!({
        "hasIdentity": identity.is_some(),
        "hasSession": session.is_some(),
        "sessionValid": state.node_session.get_valid().is_some(),
        "identity": identity.map(|i| serde_json::json!({
            "node_id": i.node_id.to_string(),
            "public_key_b64": i.public_key_b64,
            "created_at": i.created_at_iso_utc
        })),
        "session": session.map(|s| serde_json::json!({
            "session_id": s.session_id.to_string(),
            "tenant_id": s.tenant_id.to_string(),
            "workspace_id": s.workspace_id.to_string(),
            "expires_at": s.expires_at.to_rfc3339(),
            "is_expired": s.is_expired()
        }))
    }))
}

// =============================================================================
// Workflow Runs Handlers (Proxied HTTP)
// =============================================================================

/// Build security envelope headers for proxied requests
fn build_security_headers(jwt: Option<&str>, module: &str, action: &str) -> Vec<(String, String)> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("X-REQUEST-ID".to_string(), request_id.clone()),
        ("X-EKKA-CORRELATION-ID".to_string(), request_id),
        ("X-EKKA-PROOF-TYPE".to_string(), if jwt.is_some() { "jwt" } else { "none" }.to_string()),
        ("X-EKKA-MODULE".to_string(), module.to_string()),
        ("X-EKKA-ACTION".to_string(), action.to_string()),
        ("X-EKKA-CLIENT".to_string(), config::app_slug().to_string()),
        ("X-EKKA-CLIENT-VERSION".to_string(), "0.2.0".to_string()),
    ];

    if let Some(token) = jwt {
        headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
    }

    headers
}

/// Create a workflow run (POST /engine/workflow-runs)
fn handle_workflow_runs_create(payload: &Value) -> EngineResponse {
    let engine_url = option_env!("EKKA_ENGINE_URL")
        .unwrap_or("http://localhost:3200")
        .to_string();

    // Extract request body
    let request = match payload.get("request") {
        Some(r) => r.clone(),
        None => return EngineResponse::err("INVALID_PAYLOAD", "request is required"),
    };

    // Extract optional JWT
    let jwt = payload.get("jwt").and_then(|v| v.as_str());

    // Build client
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResponse::err("HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Build request
    let headers = build_security_headers(jwt, "desktop.docgen", "workflow.create");
    let mut req_builder = client.post(format!("{}/engine/workflow-runs", engine_url));

    for (key, value) in headers {
        req_builder = req_builder.header(&key, &value);
    }

    let response = req_builder.json(&request).send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => EngineResponse::ok(data),
                    Err(e) => EngineResponse::err("PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|v| v.get("message").or(v.get("error")).and_then(|m| m.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                EngineResponse::err_with_status("HTTP_ERROR", &error_msg, status_code)
            }
        }
        Err(e) => {
            if e.is_connect() {
                EngineResponse::err("ENGINE_UNAVAILABLE", &format!("Cannot connect to engine at {}. Is the engine running?", engine_url))
            } else {
                EngineResponse::err("REQUEST_FAILED", &e.to_string())
            }
        }
    }
}

/// Get a workflow run (GET /engine/workflow-runs/{id})
fn handle_workflow_runs_get(payload: &Value) -> EngineResponse {
    let engine_url = option_env!("EKKA_ENGINE_URL")
        .unwrap_or("http://localhost:3200")
        .to_string();

    // Extract workflow run ID
    let id = match payload.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return EngineResponse::err("INVALID_PAYLOAD", "id is required"),
    };

    // Extract optional JWT
    let jwt = payload.get("jwt").and_then(|v| v.as_str());

    // Build client
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResponse::err("HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Build request
    let headers = build_security_headers(jwt, "desktop.docgen", "workflow.get");
    let mut req_builder = client.get(format!("{}/engine/workflow-runs/{}", engine_url, id));

    for (key, value) in headers {
        req_builder = req_builder.header(&key, &value);
    }

    let response = req_builder.send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => EngineResponse::ok(data),
                    Err(e) => EngineResponse::err("PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|v| v.get("message").or(v.get("error")).and_then(|m| m.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                EngineResponse::err_with_status("HTTP_ERROR", &error_msg, status_code)
            }
        }
        Err(e) => {
            if e.is_connect() {
                EngineResponse::err("ENGINE_UNAVAILABLE", &format!("Cannot connect to engine at {}. Is the engine running?", engine_url))
            } else {
                EngineResponse::err("REQUEST_FAILED", &e.to_string())
            }
        }
    }
}

// =============================================================================
// Auth Handlers (Proxied HTTP)
// =============================================================================

/// Login (POST /auth/login)
fn handle_auth_login(payload: &Value) -> EngineResponse {
    let api_url = std::env::var("EKKA_API_URL")
        .unwrap_or_else(|_| "https://api.ekka.ai".to_string());

    // Extract credentials
    let identifier = match payload.get("identifier").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return EngineResponse::err("INVALID_PAYLOAD", "identifier is required"),
    };
    let password = match payload.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return EngineResponse::err("INVALID_PAYLOAD", "password is required"),
    };

    // Build client
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResponse::err("HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Build request
    let headers = build_security_headers(None, "auth", "login");
    let mut req_builder = client.post(format!("{}/auth/login", api_url));

    for (key, value) in headers {
        req_builder = req_builder.header(&key, &value);
    }

    let body = serde_json::json!({
        "identifier": identifier,
        "password": password
    });

    let response = req_builder.json(&body).send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => EngineResponse::ok(data),
                    Err(e) => EngineResponse::err("PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|v| v.get("message").or(v.get("error")).and_then(|m| m.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                EngineResponse::err_with_status("AUTH_ERROR", &error_msg, status_code)
            }
        }
        Err(e) => EngineResponse::err("REQUEST_FAILED", &e.to_string()),
    }
}

/// Refresh token (POST /auth/refresh)
fn handle_auth_refresh(payload: &Value) -> EngineResponse {
    let api_url = std::env::var("EKKA_API_URL")
        .unwrap_or_else(|_| "https://api.ekka.ai".to_string());

    // Extract refresh token
    let refresh_token = match payload.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return EngineResponse::err("INVALID_PAYLOAD", "refresh_token is required"),
    };

    // Extract optional current JWT
    let jwt = payload.get("jwt").and_then(|v| v.as_str());

    // Build client
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResponse::err("HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Build request
    let headers = build_security_headers(jwt, "auth", "refresh_token");
    let mut req_builder = client.post(format!("{}/auth/refresh", api_url));

    for (key, value) in headers {
        req_builder = req_builder.header(&key, &value);
    }

    let body = serde_json::json!({
        "refresh_token": refresh_token
    });

    let response = req_builder.json(&body).send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => EngineResponse::ok(data),
                    Err(e) => EngineResponse::err("PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|v| v.get("message").or(v.get("error")).and_then(|m| m.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                EngineResponse::err_with_status("AUTH_ERROR", &error_msg, status_code)
            }
        }
        Err(e) => EngineResponse::err("REQUEST_FAILED", &e.to_string()),
    }
}

/// Logout (POST /auth/logout)
fn handle_auth_logout(payload: &Value) -> EngineResponse {
    let api_url = std::env::var("EKKA_API_URL")
        .unwrap_or_else(|_| "https://api.ekka.ai".to_string());

    // Extract refresh token
    let refresh_token = match payload.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return EngineResponse::err("INVALID_PAYLOAD", "refresh_token is required"),
    };

    // Build client
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return EngineResponse::err("HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Build request
    let headers = build_security_headers(None, "auth", "logout");
    let mut req_builder = client.post(format!("{}/auth/logout", api_url));

    for (key, value) in headers {
        req_builder = req_builder.header(&key, &value);
    }

    let body = serde_json::json!({
        "refresh_token": refresh_token
    });

    let response = req_builder.json(&body).send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => EngineResponse::ok(data),
                    Err(e) => EngineResponse::err("PARSE_ERROR", &e.to_string()),
                }
            } else {
                // Logout errors are typically ignored, but still return properly
                let status_code = status.as_u16();
                let body = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|v| v.get("message").or(v.get("error")).and_then(|m| m.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                EngineResponse::err_with_status("AUTH_ERROR", &error_msg, status_code)
            }
        }
        Err(e) => EngineResponse::err("REQUEST_FAILED", &e.to_string()),
    }
}
