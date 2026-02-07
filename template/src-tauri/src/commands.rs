//! Bridge commands
//!
//! Entry points for TypeScript → Rust communication.

use crate::bootstrap::initialize_home;
use crate::grants::require_home_granted;
use crate::handlers;
use crate::node_auth;
use crate::node_credentials;
use crate::ops::auth;
use crate::state::EngineState;
use crate::types::{EngineRequest, EngineResponse};
use serde_json::Value;
use tauri::{AppHandle, State};

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

    // Store real node_id from vault credentials (NOT instance_id from marker)
    if let Ok((vault_node_id, _)) = node_credentials::load_credentials() {
        if let Ok(mut nid) = state.node_id.lock() {
            *nid = Some(vault_node_id);
        }
    }

    *connected = true;

    // Ensure grant verification key is loaded (Phase 6 equivalent).
    // On normal startup this is a no-op (key already fetched by main.rs Phase 6).
    // After first-time onboarding, Phase 6 was skipped so we fetch it here.
    if state.get_grant_verify_key().is_none() {
        let response = state.core_process.request(
            "wellKnown.fetch",
            &serde_json::json!({}),
        );
        if response.ok {
            if let Some(ref result) = response.result {
                if let Some(key) = result
                    .get("grant_verify_key_b64")
                    .and_then(|v| v.as_str())
                {
                    state.set_grant_verify_key(key.to_string());
                    std::env::set_var("ENGINE_GRANT_VERIFY_KEY_B64", key);
                    tracing::info!(
                        op = "desktop.well_known.loaded",
                        source = "engine_connect",
                        "Grant verification key loaded post-onboarding"
                    );
                }
            }
        } else {
            let err_msg = response.error.as_ref()
                .map(|e| e.message.as_str())
                .unwrap_or("Unknown error");
            tracing::warn!(
                op = "desktop.well_known.failed",
                source = "engine_connect",
                error = %err_msg,
                "Failed to fetch grant verification key"
            );
        }
    }

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

/// Main RPC dispatcher - routes all operations to local handlers
///
/// All commands require node identity (resolved at startup).
/// Operations go to local handlers + cloud API.
/// The spawned engine is a runner runtime (for task execution), NOT a request router.
#[tauri::command]
pub fn engine_request(req: EngineRequest, state: State<EngineState>, app_handle: AppHandle) -> EngineResponse {
    // HANDLER DISPATCH: Handle operations locally or proxy to remote API

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

        // Node Credentials (routed to Desktop Core process via JSON-RPC)
        // After successful set, TS calls engine_connect and proceeds to login
        "nodeCredentials.set" => handle_node_credentials_set_via_core(&req.payload, &state, app_handle),
        "nodeCredentials.status" => state.core_process.request("nodeCredentials.status", &req.payload),
        "nodeCredentials.clear" => state.core_process.request("nodeCredentials.clear", &req.payload),

        // Node Session Authentication
        "nodeSession.ensureIdentity" => handle_ensure_node_identity(&state),
        "nodeSession.bootstrap" => handle_bootstrap_node_session(&req.payload, &state),
        "nodeSession.status" => handle_node_session_status(&state),

        // Home status (host probes via SDK, core formats response)
        "home.status" => {
            use ekka_sdk_core::ekka_ops::home;
            let payload = match state.to_runtime_context() {
                Some(ctx) => {
                    let status = home::status(&ctx);
                    serde_json::json!({
                        "state": status.state,
                        "homePath": status.home_path,
                        "grantPresent": status.grant_present,
                        "reason": status.reason,
                    })
                }
                None => {
                    let home_path = state.home_path.lock().ok()
                        .and_then(|p| p.clone())
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    serde_json::json!({
                        "state": "BOOTSTRAP_PRE_LOGIN",
                        "homePath": home_path,
                        "grantPresent": false,
                        "reason": null,
                    })
                }
            };
            state.core_process.request("home.status", &payload)
        }
        "home.grant" => handlers::home::handle_grant(&state),

        // Paths (new SDK operations)
        "paths.check" => handlers::paths::handle_check(&req.payload, &state),
        "paths.list" => handlers::paths::handle_list(&req.payload, &state),
        "paths.get" => handlers::paths::handle_get(&req.payload, &state),
        "paths.request" => handlers::paths::handle_request(&req.payload, &state),
        "paths.remove" => handlers::paths::handle_remove(&req.payload, &state),

        // Runtime (host probes home state, core formats response)
        "runtime.info" => {
            let (home_state, home_path, _, _) = crate::grants::get_home_status(&state);
            state.core_process.request("runtime.info", &serde_json::json!({
                "homeState": home_state,
                "homePath": home_path.to_string_lossy(),
            }))
        }

        // Runner status (local runner loop status, formatted by Desktop Core)
        "runner.status" => {
            let status = state.runner_state.get();
            state.core_process.request("runner.status", &serde_json::json!(status))
        }

        // Runner task stats (routed to Desktop Core → engine API)
        "runner.taskStats" => state.core_process.request("runner.taskStats", &req.payload),

        // Auth (proxied from API)
        "auth.login" => state.core_process.request("auth.login", &req.payload),
        "auth.refresh" => state.core_process.request("auth.refresh", &req.payload),
        "auth.logout" => state.core_process.request("auth.logout", &req.payload),

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
fn handle_setup_status(state: &EngineState) -> EngineResponse {
    state.core_process.request("setup.status", &serde_json::json!({}))
}

// =============================================================================
// Node Credentials Handlers
// =============================================================================

/// Set node credentials via Desktop Core process
///
/// Core handles validation and encrypted storage.
/// TS handles the post-onboarding transition: handleSetupComplete() → ekka.connect() → login.
fn handle_node_credentials_set_via_core(payload: &Value, state: &EngineState, _app_handle: AppHandle) -> EngineResponse {
    tracing::info!(op = "rust.local.op", opName = "nodeCredentials.set", "Routing nodeCredentials.set to Desktop Core");

    let resp = state.core_process.request("nodeCredentials.set", payload);

    if resp.ok {
        tracing::info!(
            op = "desktop.onboarding.complete",
            "Credentials stored via Core - TS will call engine_connect and proceed"
        );
    }

    resp
}

// =============================================================================
// Node Session Handlers
// =============================================================================

/// Ensure node identity exists (host probes token state, core formats response + checks credentials)
fn handle_ensure_node_identity(state: &EngineState) -> EngineResponse {
    let node_token = state.get_node_auth_token();
    let has_token = node_token.is_some();

    let payload = serde_json::json!({
        "hasToken": has_token,
        "nodeId": node_token.as_ref().map(|t| t.node_id.to_string()),
        "tenantId": node_token.as_ref().map(|t| t.tenant_id.to_string()),
        "workspaceId": node_token.as_ref().map(|t| t.workspace_id.to_string()),
    });

    state.core_process.request("nodeSession.ensureIdentity", &payload)
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

    // Get node auth token - try auto-auth if not available
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
            // Token missing - auto-auth via Desktop Core (single-flight)
            if !state.node_auth_state.try_start() {
                return EngineResponse::err("NODE_AUTH_IN_PROGRESS", "Authentication in progress, please wait");
            }

            // From here, ALL paths must call set_authenticated() or set_failed()
            tracing::info!(
                op = "node_session.auto_auth",
                "Auto-authenticating node via Desktop Core"
            );

            let response = state.core_process.request(
                "node.auth.authenticate",
                &serde_json::json!({}),
            );

            if response.ok {
                if let Some(ref result) = response.result {
                    let token = node_credentials::NodeAuthToken {
                        token: result.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        node_id: result.get("nodeId").and_then(|v| v.as_str())
                            .and_then(|s| uuid::Uuid::parse_str(s).ok())
                            .unwrap_or(node_id),
                        tenant_id: result.get("tenantId").and_then(|v| v.as_str())
                            .and_then(|s| uuid::Uuid::parse_str(s).ok())
                            .unwrap_or_default(),
                        workspace_id: result.get("workspaceId").and_then(|v| v.as_str())
                            .and_then(|s| uuid::Uuid::parse_str(s).ok())
                            .unwrap_or_default(),
                        session_id: result.get("sessionId").and_then(|v| v.as_str())
                            .and_then(|s| uuid::Uuid::parse_str(s).ok())
                            .unwrap_or_default(),
                        expires_at: result.get("expiresAt").and_then(|v| v.as_str())
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .unwrap_or_else(chrono::Utc::now),
                    };

                    state.node_auth_token.set(token.clone());
                    state.node_auth_state.set_authenticated();
                    tracing::info!(
                        op = "node_session.auto_auth_success",
                        node_id = %token.node_id,
                        "Node auto-authenticated via Desktop Core"
                    );
                    token
                } else {
                    let error_msg = "Auth response missing result".to_string();
                    state.node_auth_state.set_failed(error_msg.clone());
                    return EngineResponse::err("NODE_NOT_AUTHENTICATED", &error_msg);
                }
            } else {
                let err_msg = response.error.as_ref()
                    .map(|e| e.message.as_str())
                    .unwrap_or("Unknown error");
                let error_msg = format!("Node authentication failed: {}", err_msg);
                tracing::error!(
                    op = "node_session.auto_auth_failed",
                    error = %err_msg,
                    "Node auto-authentication failed"
                );
                state.node_auth_state.set_failed(error_msg.clone());
                return EngineResponse::err("NODE_NOT_AUTHENTICATED", &error_msg);
            }
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

/// Get current node session status (host probes state, core formats response)
fn handle_node_session_status(state: &EngineState) -> EngineResponse {
    let session = state.node_session.get();

    let payload = serde_json::json!({
        "hasIdentity": false,
        "hasSession": session.is_some(),
        "sessionValid": state.node_session.get_valid().is_some(),
        "identity": null,
        "session": session.map(|s| serde_json::json!({
            "session_id": s.session_id.to_string(),
            "tenant_id": s.tenant_id.to_string(),
            "workspace_id": s.workspace_id.to_string(),
            "expires_at": s.expires_at.to_rfc3339(),
            "is_expired": s.is_expired()
        }))
    });

    state.core_process.request("nodeSession.status", &payload)
}
