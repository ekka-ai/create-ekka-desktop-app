//! EKKA Desktop - Entry Point
//!
//! Minimal main.rs that sets up Tauri with the engine commands.
//! Starts embedded runner loop on app startup.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bootstrap;
mod commands;
mod config;
mod device_secret;
mod engine_process;
mod grants;
mod well_known;
mod handlers;
mod node_auth;
mod node_credentials;
mod node_runner;
mod node_vault_crypto;
mod node_vault_store;
mod ops;
mod state;
mod types;

use commands::{engine_connect, engine_disconnect, engine_request};
use engine_process::EngineProcess;
use state::EngineState;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;

fn main() {
    // Load .env.local for development (before anything else)
    // This provides EKKA_SECURITY_EPOCH and other dev-time overrides.
    // Note: ENGINE_GRANT_VERIFY_KEY_B64 is now fetched from /.well-known/ekka-configuration
    if let Err(_) = dotenvy::from_filename(".env.local") {
        // Also try parent directory (when running from src-tauri)
        let _ = dotenvy::from_filename("../.env.local");
    }

    // Initialize tracing for runner logs
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

    // Create engine process holder
    let engine_process = Arc::new(EngineProcess::new());
    let engine_for_state = engine_process.clone();
    let engine_for_setup = engine_process.clone();
    let engine_for_shutdown = engine_process;

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(EngineState::with_engine(engine_for_state))
        .setup(move |app| {
            // Attempt to spawn engine process
            tracing::info!(op = "desktop.startup", "EKKA Desktop starting");

            // Log security epoch status (still needed for home bootstrap)
            let security_epoch_set = std::env::var("EKKA_SECURITY_EPOCH").is_ok();
            tracing::info!(
                op = "desktop.required_env.loaded",
                EKKA_SECURITY_EPOCH = security_epoch_set,
                "Security epoch env var status"
            );

            // Log build-time baked engine URL presence (not the URL itself)
            let engine_url_baked = option_env!("EKKA_ENGINE_URL").is_some();
            tracing::info!(
                op = "desktop.engine_url.baked",
                present = engine_url_baked,
                "EKKA_ENGINE_URL baked at build time"
            );

            // Check for stored node credentials (vault-backed)
            let has_creds = node_credentials::has_credentials();

            if !has_creds {
                tracing::warn!(
                    op = "desktop.node.credentials.missing",
                    "Node credentials not configured - onboarding required, engine start blocked"
                );
                // Engine will not be spawned - available will remain false
                // UI should show onboarding flow
            }

            // Resolve resource path for bootstrap binary
            let resource_path: Option<PathBuf> = app
                .path()
                .resource_dir()
                .ok()
                .map(|dir: PathBuf| dir.join("resources").join("ekka-engine-bootstrap"));

            // Get node auth token holder and auth state to pass to spawn thread
            let state_handle = app.state::<EngineState>();
            let node_auth_holder = state_handle.node_auth_token.clone();
            let node_auth_state = state_handle.node_auth_state.clone();

            // Fetch grant verification key from engine's well-known endpoint
            // This runs async and caches the key in state for grant verification
            let app_handle = app.app_handle().clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<EngineState>();
                match well_known::fetch_and_cache_verify_key(&state).await {
                    Ok(()) => {
                        tracing::info!(
                            op = "desktop.well_known.loaded",
                            "Grant verification key loaded from engine"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            op = "desktop.well_known.failed",
                            error = %e,
                            "Failed to fetch grant verification key - grants will not be verified"
                        );
                    }
                }
            });

            // Spawn engine in background thread to not block UI
            let engine = engine_for_setup.clone();
            std::thread::spawn(move || {
                // Gate: Skip engine spawn if no credentials
                if !has_creds {
                    tracing::info!(
                        op = "desktop.engine.start.blocked",
                        reason = "missing_credentials",
                        "Engine start blocked - node credentials required"
                    );
                    return;
                }

                // Authenticate node with server before spawning engine
                // EKKA_ENGINE_URL is baked at build time via build.rs
                let engine_url = match option_env!("EKKA_ENGINE_URL") {
                    Some(url) => url.to_string(),
                    None => {
                        tracing::warn!(
                            op = "desktop.engine.start.blocked",
                            reason = "missing_engine_url",
                            "Engine start blocked - EKKA_ENGINE_URL not baked at build time"
                        );
                        return;
                    }
                };

                // Single-flight: try to acquire auth lock
                if !node_auth_state.try_start() {
                    tracing::info!(
                        op = "desktop.node.auth.skipped",
                        reason = "already_in_progress_or_completed",
                        "Skipping auth - already attempted"
                    );
                    return;
                }

                tracing::info!(
                    op = "desktop.node.auth.attempt",
                    reason = "startup",
                    "Authenticating node from vault"
                );

                match node_credentials::authenticate_node(&engine_url) {
                    Ok(token) => {
                        // Store token in state (in-memory only)
                        node_auth_holder.set(token);
                        node_auth_state.set_authenticated();
                        tracing::info!(
                            op = "desktop.node.auth.complete",
                            "Node authenticated, proceeding to engine spawn"
                        );
                    }
                    Err(node_credentials::CredentialsError::AuthFailed(status, ref body)) => {
                        let error_msg = format!("Auth failed: HTTP {}", status);
                        node_auth_state.set_failed(error_msg);

                        // Check if this is a secret error (invalid or revoked)
                        if node_credentials::is_secret_error(status, body) {
                            tracing::warn!(
                                op = "desktop.node.auth.failed",
                                status = status,
                                "Node secret is invalid or revoked - clearing credentials"
                            );
                            // Clear invalid credentials from keychain
                            let _ = node_credentials::clear_credentials();
                        } else {
                            tracing::warn!(
                                op = "desktop.node.auth.failed",
                                status = status,
                                "Node authentication failed - will not retry"
                            );
                        }
                        return;
                    }
                    Err(e) => {
                        let error_msg = format!("Auth failed: {}", e);
                        node_auth_state.set_failed(error_msg);
                        tracing::warn!(
                            op = "desktop.node.auth.failed",
                            error = %e,
                            "Node authentication failed - will not retry"
                        );
                        return;
                    }
                }

                // Install bootstrap binary from resources if not present
                if let Err(e) = engine_process::ensure_bootstrap_installed_from_resources(resource_path) {
                    tracing::debug!(op = "engine.bootstrap.skip", error = %e, "Bootstrap install skipped");
                }

                // Log setup complete
                tracing::info!(
                    op = "desktop.setup.complete",
                    "Device setup complete - credentials valid, proceeding to engine"
                );

                engine_process::spawn_and_wait(&engine);
                let status = engine.get_status();
                tracing::info!(
                    op = "desktop.engine_status",
                    installed = status.installed,
                    running = status.running,
                    available = status.available,
                    pid = ?status.pid,
                    version = ?status.version,
                    build = ?status.build,
                    "Engine status"
                );

                if status.available {
                    tracing::info!(
                        op = "desktop.engine.ready",
                        "Engine is ready"
                    );
                }
            });

            // Node runner is started via nodeSession.bootstrap operation.
            // Node auth happens at app startup (above) using node_id + node_secret.
            // This ensures:
            // 1. Node credentials loaded from vault (encrypted at rest)
            // 2. Node authenticated via POST /engine/nodes/auth
            // 3. Node JWT (role=node) stored in memory
            // 4. Runner uses node JWT (NOT user JWT or internal service key)

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            engine_connect,
            engine_disconnect,
            engine_request,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app, event| {
            if let tauri::RunEvent::Exit = event {
                // Shutdown engine process on app exit
                tracing::debug!(op = "desktop.shutdown", "Shutting down engine process");
                engine_process::shutdown(&engine_for_shutdown);
            }
        });
}
