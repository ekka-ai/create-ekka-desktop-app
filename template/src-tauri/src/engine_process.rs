//! Engine Process Management
//!
//! Handles spawning, readiness checking, and routing for the external ekka-engine binary.
//!
//! ═══════════════════════════════════════════════════════════════════════════════════════════
//! DRIFT GUARD - ARCHITECTURE FREEZE
//! ═══════════════════════════════════════════════════════════════════════════════════════════
//! DO NOT extend this without revisiting the Desktop–Engine architecture decision.
//!
//! This module is FROZEN as of Phase 3G. Responsibilities are:
//! - Spawn ekka-engine binary on startup
//! - Check readiness via health endpoint
//! - Route requests to engine (or fallback to stub)
//! - One-way disable on failure
//! - Clean shutdown on Desktop exit
//! - Read-only status visibility (installed, running, available, pid, version, build)
//! - Log streaming (stdout/stderr forwarding)
//!
//! Any changes require explicit architecture review.
//! ═══════════════════════════════════════════════════════════════════════════════════════════

use crate::bootstrap::resolve_home_path;
use crate::node_credentials;
use crate::types::{EngineRequest, EngineResponse};
use serde::Serialize;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// =============================================================================
// Engine Environment Builder
// =============================================================================

/// Build environment variables for engine process spawn.
/// Returns Err with missing key name if a required var is missing/invalid.
///
/// Order of precedence for node credentials:
/// 1. OS Keychain (stored via nodeCredentials.set)
/// 2. Environment variables (EKKA_NODE_ID, EKKA_NODE_SECRET)
fn build_engine_env() -> Result<Vec<(&'static str, String)>, &'static str> {
    let mut env = Vec::new();

    // EKKA_RUNNER_MODE=engine (always set)
    env.push(("EKKA_RUNNER_MODE", "engine".to_string()));

    // EKKA_ENGINE_URL - baked at build time
    if let Some(url) = option_env!("EKKA_ENGINE_URL") {
        env.push(("EKKA_ENGINE_URL", url.to_string()));
    }

    // EKKA_INTERNAL_SERVICE_KEY - optional for desktop (only needed for engine-bootstrap binary)
    // Desktop runner uses node session auth, not internal key
    let internal_key = std::env::var("EKKA_INTERNAL_SERVICE_KEY")
        .or_else(|_| std::env::var("INTERNAL_SERVICE_KEY"))
        .ok();

    if let Some(ref key) = internal_key {
        env.push(("EKKA_INTERNAL_SERVICE_KEY", key.clone()));
        tracing::info!(
            op = "desktop.internal_key.optional",
            present = true,
            "Internal service key configured (for engine-bootstrap)"
        );
    } else {
        tracing::info!(
            op = "desktop.internal_key.optional",
            present = false,
            "Internal service key not set (desktop runner uses node session auth)"
        );
    }

    // EKKA_TENANT_ID - optional for desktop (only needed for engine-bootstrap binary)
    // Desktop runner gets tenant_id from node session
    if let Ok(tenant_id) = std::env::var("EKKA_TENANT_ID") {
        if uuid::Uuid::parse_str(&tenant_id).is_ok() {
            env.push(("EKKA_TENANT_ID", tenant_id));
        }
    }

    // EKKA_WORKSPACE_ID - optional for desktop (only needed for engine-bootstrap binary)
    // Desktop runner gets workspace_id from node session
    if let Ok(workspace_id) = std::env::var("EKKA_WORKSPACE_ID") {
        if uuid::Uuid::parse_str(&workspace_id).is_ok() {
            env.push(("EKKA_WORKSPACE_ID", workspace_id));
        }
    }

    // Node credentials: Try keychain first, fall back to env vars
    // This enables headless engine startup without manual env exports
    if let Ok((node_id, node_secret)) = node_credentials::load_credentials() {
        env.push(("EKKA_NODE_ID", node_id.to_string()));
        env.push(("EKKA_NODE_SECRET", node_secret));

        tracing::info!(
            op = "desktop.node.identity.loaded",
            keys = ?["node_id", "node_secret"],
            node_id = %node_id,
            "Node credentials loaded from keychain for engine spawn"
        );
    } else {
        // Fallback to environment variables
        if let Ok(node_id) = std::env::var("EKKA_NODE_ID") {
            env.push(("EKKA_NODE_ID", node_id));
        }
        if let Ok(node_secret) = std::env::var("EKKA_NODE_SECRET") {
            env.push(("EKKA_NODE_SECRET", node_secret));
        }
    }

    Ok(env)
}

/// Engine status for diagnostics (read-only)
#[derive(Debug, Clone, Serialize)]
pub struct EngineStatus {
    pub installed: bool,
    pub running: bool,
    pub available: bool,
    pub pid: Option<u32>,
    pub version: Option<String>,
    pub build: Option<String>,
}

/// Engine process holder
pub struct EngineProcess {
    child: Mutex<Option<Child>>,
    available: Mutex<bool>,
    installed: Mutex<bool>,
}

impl EngineProcess {
    pub fn new() -> Self {
        Self {
            child: Mutex::new(None),
            available: Mutex::new(false),
            installed: Mutex::new(false),
        }
    }

    /// Check if engine is available
    pub fn is_available(&self) -> bool {
        self.available.lock().map(|g| *g).unwrap_or(false)
    }

    /// Check if engine binary is installed
    pub fn is_installed(&self) -> bool {
        self.installed.lock().map(|g| *g).unwrap_or(false)
    }

    /// Check if engine process is running (has child and not exited)
    pub fn is_running(&self) -> bool {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(ref mut child) = *guard {
                // try_wait returns Ok(Some(_)) if exited, Ok(None) if still running
                return child.try_wait().ok().flatten().is_none();
            }
        }
        false
    }

    /// Get engine process ID (if running)
    pub fn get_pid(&self) -> Option<u32> {
        if let Ok(guard) = self.child.lock() {
            if let Some(ref child) = *guard {
                return Some(child.id());
            }
        }
        None
    }

    /// Get engine status (read-only diagnostics)
    pub fn get_status(&self) -> EngineStatus {
        EngineStatus {
            installed: self.is_installed(),
            running: self.is_running(),
            available: self.is_available(),
            pid: self.get_pid(),
            // Version/build require engine info endpoint (not yet available)
            version: None,
            build: None,
        }
    }

    /// Set availability
    fn set_available(&self, available: bool) {
        if let Ok(mut guard) = self.available.lock() {
            *guard = available;
        }
    }

    /// Set installed flag
    fn set_installed(&self, installed: bool) {
        if let Ok(mut guard) = self.installed.lock() {
            *guard = installed;
        }
    }

    /// Permanently disable engine for this session (one-way switch)
    pub fn disable(&self) {
        self.set_available(false);
    }
}

impl Default for EngineProcess {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute engine binary path using ekka_home_folder
fn compute_engine_path() -> Result<PathBuf, String> {
    let home = resolve_home_path()?;
    Ok(home.join("engine").join("ekka-engine"))
}

/// Ensure bootstrap engine is installed from embedded resources
///
/// Extracts the bundled ekka-engine-bootstrap binary to ekka_home_folder/engine/ekka-engine
/// if it doesn't already exist.
///
/// Returns Ok(true) if installed, Ok(false) if already present.
pub fn ensure_bootstrap_installed_from_resources(resource_path: Option<PathBuf>) -> Result<bool, String> {
    let engine_path = compute_engine_path()?;

    // Already installed - return silently
    if engine_path.exists() {
        return Ok(false);
    }

    // Get resource bytes - try packaged path first, fall back to dev path
    let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("ekka-engine-bootstrap");

    let effective_path = match &resource_path {
        Some(path) if path.exists() => path.clone(),
        _ => dev_path.clone(),
    };

    if !effective_path.exists() {
        tracing::warn!(
            op = "engine.bootstrap.resource_missing",
            resource = %effective_path.display(),
            "Bootstrap resource not found"
        );
        return Err("Bootstrap resource not found".to_string());
    }

    let resource_bytes = fs::read(&effective_path).map_err(|e| {
        tracing::warn!(
            op = "engine.bootstrap.resource_missing",
            resource = %effective_path.display(),
            error = %e,
            "Bootstrap resource not readable"
        );
        format!("Failed to read resource: {}", e)
    })?;

    // Create engine directory
    let engine_dir = engine_path.parent().ok_or("Invalid engine path")?;
    fs::create_dir_all(engine_dir)
        .map_err(|e| format!("Failed to create engine directory: {}", e))?;

    // Write atomically: tmp file -> chmod +x -> rename
    let tmp_path = engine_path.with_extension("tmp");

    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    file.write_all(&resource_bytes)
        .map_err(|e| format!("Failed to write bootstrap binary: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync file: {}", e))?;
    drop(file);

    // Set executable permission (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp_path)
            .map_err(|e| format!("Failed to get permissions: {}", e))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_path, perms)
            .map_err(|e| format!("Failed to set executable: {}", e))?;
    }

    // Atomic rename
    fs::rename(&tmp_path, &engine_path)
        .map_err(|e| format!("Failed to rename to final path: {}", e))?;

    tracing::info!(
        op = "engine.bootstrap.install",
        path = %engine_path.display(),
        "Bootstrap engine installed from resources"
    );

    Ok(true)
}

/// Spawn and wait for engine readiness
///
/// Returns true if engine is ready, false otherwise.
/// Stores result in EngineProcess.available.
pub fn spawn_and_wait(engine: &EngineProcess) -> bool {
    let engine_path = match compute_engine_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                op = "engine.path.error",
                error = %e,
                "Failed to compute engine path"
            );
            engine.set_available(false);
            return false;
        }
    };

    // Check if binary exists
    let installed = engine_path.exists();
    engine.set_installed(installed);

    if !installed {
        tracing::info!(
            op = "engine.spawn.missing",
            path = %engine_path.display(),
            "Engine binary not found, using stub backend"
        );
        engine.set_available(false);
        return false;
    }

    tracing::info!(
        op = "engine.spawn.start",
        path = %engine_path.display(),
        "Spawning engine process"
    );

    // Build engine environment from process env
    let engine_env = match build_engine_env() {
        Ok(env) => env,
        Err(missing_key) => {
            tracing::error!(
                op = "engine.spawn.missing_required_env",
                key = %missing_key,
                "Required environment variable missing or invalid"
            );
            engine.set_available(false);
            return false;
        }
    };

    tracing::info!(
        op = "engine.spawn.env",
        keys = ?engine_env.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        "Setting engine environment"
    );

    // Spawn the engine process with piped stdout/stderr
    let mut child = match Command::new(&engine_path)
        .envs(engine_env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                op = "engine.spawn.failed",
                error = %e,
                "Failed to spawn engine process"
            );
            engine.set_available(false);
            return false;
        }
    };

    // Spawn log reader threads (best-effort, ignore errors)
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => tracing::info!(op = "engine.stdout", "{}", l),
                    Err(_) => break,
                }
            }
            tracing::debug!(op = "engine.stdout.closed", "Engine stdout stream closed");
        });
    }

    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                match line {
                    Ok(l) => tracing::info!(op = "engine.stderr", "{}", l),
                    Err(_) => break,
                }
            }
            tracing::debug!(op = "engine.stderr.closed", "Engine stderr stream closed");
        });
    }

    // Get pid for logging
    let pid = child.id();

    // Store child process
    if let Ok(mut guard) = engine.child.lock() {
        *guard = Some(child);
    }

    tracing::info!(op = "engine.spawn.success", pid = pid, "Engine process spawned");

    // Allow bootstrap time to exec into real engine or fail
    // Bootstrap either: execs real engine (same PID), or exits with error code
    std::thread::sleep(Duration::from_secs(2));

    // Check if bootstrap exited early (indicates failure)
    let bootstrap_failed = if let Ok(mut guard) = engine.child.lock() {
        if let Some(ref mut c) = *guard {
            match c.try_wait() {
                Ok(Some(status)) => {
                    let code = status.code();
                    tracing::warn!(
                        op = "engine.bootstrap.failed",
                        pid = pid,
                        exit_code = ?code,
                        "Bootstrap exited early - real engine not started"
                    );
                    true
                }
                Ok(None) => false, // Still running = bootstrap exec'd into real engine
                Err(_) => true,
            }
        } else {
            true
        }
    } else {
        true
    };

    if bootstrap_failed {
        engine.set_available(false);
        return false;
    }

    tracing::debug!(op = "engine.bootstrap.exec", pid = pid, "Bootstrap exec'd into real engine, starting readiness check");

    // Wait for readiness (real engine should now be running)
    let ready = wait_for_ready(15);
    engine.set_available(ready);

    if ready {
        tracing::info!(op = "engine.ready", "Engine is ready");
    } else {
        tracing::warn!(op = "engine.ready.timeout", "Engine readiness timeout");
    }

    ready
}

/// Wait for engine to become ready by checking health endpoint
fn wait_for_ready(timeout_secs: u64) -> bool {
    // Default port for engine health check
    let port: u16 = std::env::var("EKKA_ENGINE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9473);

    let url = format!("http://127.0.0.1:{}/health", port);

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        if let Ok(resp) = client.get(&url).send() {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    false
}

/// Shutdown engine process (called on app exit)
pub fn shutdown(engine: &EngineProcess) {
    if let Ok(mut guard) = engine.child.lock() {
        if let Some(mut child) = guard.take() {
            tracing::info!(op = "engine.shutdown", "Shutting down engine process");
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    engine.set_available(false);
}

/// Route a request to the real engine
///
/// Returns Some(response) if engine handled the request, None on failure.
/// On failure, caller should fall back to stub.
pub fn route_to_engine(req: &EngineRequest) -> Option<EngineResponse> {
    let port: u16 = std::env::var("EKKA_ENGINE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9473);

    let url = format!("http://127.0.0.1:{}/request", port);

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(op = "engine.route.client_error", error = %e, "Failed to create HTTP client");
            return None;
        }
    };

    match client.post(&url).json(req).send() {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<EngineResponse>() {
                Ok(engine_resp) => {
                    tracing::debug!(op = "engine.route.success", op_name = %req.op, "Routed to engine");
                    Some(engine_resp)
                }
                Err(e) => {
                    tracing::warn!(op = "engine.route.parse_error", error = %e, "Failed to parse engine response");
                    None
                }
            }
        }
        Ok(resp) => {
            tracing::warn!(op = "engine.route.error", status = %resp.status(), "Engine returned error");
            None
        }
        Err(e) => {
            tracing::warn!(op = "engine.route.failed", error = %e, "Failed to route to engine");
            None
        }
    }
}
