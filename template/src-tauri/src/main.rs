//! EKKA Desktop Core - Entry Point
//!
//! # Startup Order
//!
//! 1. Initialize tracing
//! 2. Check if node credentials exist
//! 3. If NO credentials → UI loads in onboarding mode (no engine/updater/runner)
//! 4. If credentials exist:
//!    a. Run node-gated updater → FATAL if fails
//!    b. Authenticate node → FATAL if fails
//!    c. Spawn engine → FATAL if fails
//! 5. After onboarding stores credentials → TS calls engine_connect → login
//!
//! # Design Constraints
//!
//! - Node ID is REQUIRED before updater/engine/runner
//! - Fresh install loads UI for onboarding only
//! - After onboarding → engine_connect loads key via wellKnown.fetch → login

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bootstrap;
mod commands;
mod config;
mod core_process;
mod device_secret;
mod engine_process;
mod grants;
mod handlers;
mod node_auth;
mod node_credentials;
mod node_runner;
mod node_vault_crypto;
mod node_vault_store;
mod ops;
mod security_epoch;
mod state;
mod types;
mod updater;

use commands::{engine_connect, engine_disconnect, engine_request};
use engine_process::EngineProcess;
use node_credentials::{has_credentials, load_credentials};
use state::EngineState;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;

fn main() {
    // ==========================================================================
    // PHASE 1: TRACING INITIALIZATION
    // ==========================================================================
    if let Err(_) = dotenvy::from_filename(".env.local") {
        let _ = dotenvy::from_filename("../.env.local");
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ekka_runner_core=info".parse().unwrap())
                .add_directive("ekka_runner_local=info".parse().unwrap())
                .add_directive("ekka_desktop_app=info".parse().unwrap())
                .add_directive("ekka_node_auth=info".parse().unwrap()),
        )
        .with_target(true)
        .init();

    tracing::info!(op = "desktop.startup", "EKKA Desktop Core starting");

    // ==========================================================================
    // PHASE 2: CHECK NODE CREDENTIALS (DO NOT EXIT IF MISSING)
    // ==========================================================================
    let has_node_credentials = has_credentials();

    if has_node_credentials {
        tracing::info!(
            op = "desktop.credentials.found",
            "Node credentials found - full startup"
        );
    } else {
        tracing::info!(
            op = "desktop.credentials.missing",
            "Node credentials not found - onboarding mode (UI only)"
        );
    }

    // ==========================================================================
    // PHASE 3: BRIDGE INITIALIZATION
    // ==========================================================================
    let engine_process = Arc::new(EngineProcess::new());
    let engine_for_setup = engine_process.clone();
    let engine_for_shutdown = engine_process;

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(EngineState::default())
        .setup(move |app| {
            // ==================================================================
            // ONBOARDING MODE: No credentials → skip engine/updater, show UI
            // ==================================================================
            if !has_node_credentials {
                tracing::info!(
                    op = "desktop.onboarding.mode",
                    "Onboarding mode - UI will load, engine/updater/runner blocked"
                );
                // UI loads, user completes onboarding, TS calls engine_connect (loads key)
                return Ok(());
            }

            // ==================================================================
            // FULL STARTUP: Credentials exist → updater, auth, engine
            // ==================================================================
            let node_id = match load_credentials() {
                Ok((id, _)) => id,
                Err(e) => {
                    tracing::error!(
                        op = "desktop.credentials.load.fatal",
                        error = %e,
                        "FATAL: Credentials exist but failed to load"
                    );
                    std::process::exit(1);
                }
            };

            tracing::info!(
                op = "desktop.node.identity.confirmed",
                node_id = %node_id,
                "Node identity confirmed - proceeding with full startup"
            );

            // ==================================================================
            // PHASE 4: NODE-GATED UPDATER CHECK (FATAL IF FAILS)
            // ==================================================================
            let app_handle = app.app_handle().clone();
            let updater_node_id = node_id;

            tauri::async_runtime::spawn(async move {
                tracing::info!(
                    op = "desktop.updater.start",
                    node_id = %updater_node_id,
                    "Starting node-gated update check"
                );

                match updater::check_and_apply_update(&app_handle, updater_node_id).await {
                    Ok(()) => {
                        tracing::info!(
                            op = "desktop.updater.complete",
                            node_id = %updater_node_id,
                            "Update check complete"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            op = "desktop.updater.fatal",
                            node_id = %updater_node_id,
                            error = %e,
                            "FATAL: Desktop updater failed"
                        );
                        std::process::exit(1);
                    }
                }
            });

            // ==================================================================
            // PHASE 5: ENGINE URL VALIDATION
            // ==================================================================
            // Validate engine URL is baked (FATAL if missing).
            // Core uses its own baked config for auth; this is a startup sanity check.
            let _engine_url = match option_env!("EKKA_ENGINE_URL") {
                Some(url) => url.to_string(),
                None => {
                    tracing::error!(
                        op = "desktop.engine.fatal",
                        "FATAL: EKKA_ENGINE_URL not baked at build time"
                    );
                    std::process::exit(1);
                }
            };

            // ==================================================================
            // PHASE 6: FETCH GRANT VERIFICATION KEY (via Desktop Core)
            // ==================================================================
            let app_handle_for_well_known = app.app_handle().clone();
            std::thread::spawn(move || {
                let state = app_handle_for_well_known.state::<EngineState>();
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
                                "Grant verification key loaded"
                            );
                        } else {
                            tracing::warn!(
                                op = "desktop.well_known.failed",
                                "Well-known response missing grant_verify_key_b64 field"
                            );
                        }
                    }
                } else {
                    let err_msg = response
                        .error
                        .as_ref()
                        .map(|e| e.message.as_str())
                        .unwrap_or("Unknown error");
                    tracing::warn!(
                        op = "desktop.well_known.failed",
                        error = %err_msg,
                        "Failed to fetch grant verification key"
                    );
                }
            });

            // ==================================================================
            // PHASE 7: NODE AUTH AND ENGINE SPAWN (FATAL IF FAILS)
            // ==================================================================
            let resource_path: Option<PathBuf> = app
                .path()
                .resource_dir()
                .ok()
                .map(|dir: PathBuf| dir.join("resources").join("ekka-engine-bootstrap"));

            let state_handle = app.state::<EngineState>();
            let node_auth_holder = state_handle.node_auth_token.clone();
            let node_auth_state = state_handle.node_auth_state.clone();
            let core_for_auth = state_handle.core_process.clone();
            let engine = engine_for_setup.clone();
            let node_id_for_engine = node_id;

            std::thread::spawn(move || {
                if !node_auth_state.try_start() {
                    tracing::info!(
                        op = "desktop.node.auth.skipped",
                        reason = "already_in_progress_or_completed",
                        "Skipping auth"
                    );
                    return;
                }

                tracing::info!(
                    op = "desktop.node.auth.attempt",
                    node_id = %node_id_for_engine,
                    "Authenticating node via Desktop Core"
                );

                let response = core_for_auth.request(
                    "node.auth.authenticate",
                    &serde_json::json!({}),
                );

                if response.ok {
                    if let Some(ref result) = response.result {
                        // Parse token fields from Core response
                        let token = node_credentials::NodeAuthToken {
                            token: result.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            node_id: result.get("nodeId").and_then(|v| v.as_str())
                                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                                .unwrap_or(node_id_for_engine),
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

                        node_auth_holder.set(token);
                        node_auth_state.set_authenticated();
                        tracing::info!(
                            op = "desktop.node.auth.complete",
                            node_id = %node_id_for_engine,
                            "Node authenticated via Desktop Core"
                        );
                    } else {
                        node_auth_state.set_failed("Auth response missing result".to_string());
                        tracing::error!(
                            op = "desktop.node.auth.fatal",
                            node_id = %node_id_for_engine,
                            "FATAL: Node auth response missing result"
                        );
                        std::process::exit(1);
                    }
                } else {
                    let err = response.error.as_ref();
                    let code = err.map(|e| e.code.as_str()).unwrap_or("UNKNOWN");
                    let message = err.map(|e| e.message.as_str()).unwrap_or("Unknown error");

                    node_auth_state.set_failed(format!("Auth failed: {}", message));

                    if code == "NODE_SECRET_INVALID" {
                        tracing::error!(
                            op = "desktop.node.auth.fatal",
                            node_id = %node_id_for_engine,
                            "FATAL: Node secret invalid or revoked"
                        );
                    } else {
                        tracing::error!(
                            op = "desktop.node.auth.fatal",
                            node_id = %node_id_for_engine,
                            error = %message,
                            "FATAL: Node authentication failed"
                        );
                    }
                    std::process::exit(1);
                }

                if let Err(e) =
                    engine_process::ensure_bootstrap_installed_from_resources(resource_path)
                {
                    tracing::debug!(
                        op = "engine.bootstrap.skip",
                        error = %e,
                        "Bootstrap install skipped"
                    );
                }

                tracing::info!(
                    op = "desktop.setup.complete",
                    node_id = %node_id_for_engine,
                    "Spawning engine"
                );

                let engine_started = engine_process::spawn_and_wait(&engine);
                let status = engine.get_status();

                tracing::info!(
                    op = "desktop.engine_status",
                    node_id = %node_id_for_engine,
                    installed = status.installed,
                    running = status.running,
                    available = status.available,
                    pid = ?status.pid,
                    "Engine status"
                );

                if !engine_started {
                    tracing::error!(
                        op = "desktop.engine.fatal",
                        node_id = %node_id_for_engine,
                        "FATAL: Engine failed to start"
                    );
                    std::process::exit(1);
                }

                if status.available {
                    tracing::info!(
                        op = "desktop.engine.ready",
                        node_id = %node_id_for_engine,
                        "Engine ready"
                    );
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            engine_connect,
            engine_disconnect,
            engine_request,
        ])
        .build(tauri::generate_context!())
        .expect("error while building EKKA Desktop application")
        .run(move |_app, event| {
            if let tauri::RunEvent::Exit = event {
                tracing::debug!(op = "desktop.shutdown", "Shutting down");
                engine_process::shutdown(&engine_for_shutdown);
            }
        });
}
