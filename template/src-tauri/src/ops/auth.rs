//! Auth operations
//!
//! Handles: auth.set + dev token export to ~/.ekka/<app-id>/

use crate::config;
use crate::state::{AuthContext, EngineState};
use crate::types::EngineResponse;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Handle auth.set operation
pub fn handle_set(payload: &Value, state: &EngineState) -> EngineResponse {
    let tenant_id = match payload.get("tenantId").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => return EngineResponse::err("INVALID_PAYLOAD", "Missing or empty 'tenantId'"),
    };

    let sub = match payload.get("sub").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return EngineResponse::err("INVALID_PAYLOAD", "Missing or empty 'sub'"),
    };

    let jwt = match payload.get("jwt").and_then(|v| v.as_str()) {
        Some(j) if !j.is_empty() => j.to_string(),
        _ => return EngineResponse::err("INVALID_PAYLOAD", "Missing or empty 'jwt'"),
    };

    // Workspace ID is optional - defaults to tenant_id if not provided
    let workspace_id = payload
        .get("workspaceId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let auth_context = AuthContext {
        tenant_id,
        sub,
        jwt,
        workspace_id,
    };

    // Clear vault cache when auth changes (new tenant/user means new encryption key)
    state.clear_vault_cache();

    match state.auth.lock() {
        Ok(mut guard) => {
            // Export dev token file before moving auth_context
            export_dev_token(&auth_context);
            *guard = Some(auth_context);
            EngineResponse::ok(json!({ "ok": true }))
        }
        Err(e) => EngineResponse::err("INTERNAL_ERROR", &e.to_string()),
    }
}

// =============================================================================
// Dev tooling token export — writes to ~/.ekka/<app-id>/, NOT ~/.ekka-desktop/
// =============================================================================

/// Resolve ~/.ekka/ root directory.
fn ekka_root() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".ekka"))
}

/// Resolve ~/.ekka/<app-id>/ directory using baked app_slug from config.
fn dev_tooling_dir() -> Option<PathBuf> {
    ekka_root().map(|root| root.join(config::app_slug()))
}

/// Pointer file: ~/.ekka/dev-token.path
fn pointer_path() -> Option<PathBuf> {
    ekka_root().map(|root| root.join("dev-token.path"))
}

/// Export current JWT to ~/.ekka/<app-id>/dev-token.json for dev tooling.
///
/// Also writes a pointer file at ~/.ekka/dev-token.path so that
/// engine_curl.sh can locate the token without knowing the app-id.
///
/// Security controls:
/// - Directory permissions: 0700 (owner only)
/// - File permissions: 0600 (owner read/write only)
/// - Token is NEVER logged
/// - File is deleted on logout/disconnect (see commands.rs)
/// - Local filesystem only — no network exposure
fn export_dev_token(auth: &AuthContext) {
    let tooling_dir = match dev_tooling_dir() {
        Some(d) => d,
        None => return,
    };

    // Ensure ~/.ekka/<app-id>/ exists with 0700
    if let Err(e) = std::fs::create_dir_all(&tooling_dir) {
        tracing::warn!(op = "auth.exportToken.failed", error = %e, "Failed to create dev tooling dir");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tooling_dir, std::fs::Permissions::from_mode(0o700));
        // Also ensure ~/.ekka/ parent is 0700
        if let Some(root) = ekka_root() {
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
    }

    let token_path = tooling_dir.join("dev-token.json");
    let now = chrono::Utc::now().to_rfc3339();

    let token_data = json!({
        "access_token": auth.jwt,
        "tenant_id": auth.tenant_id,
        "user_id": auth.sub,
        "workspace_id": auth.workspace_id,
        "exported_at": now,
        "source": config::app_slug()
    });

    let json_str = match serde_json::to_string_pretty(&token_data) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(op = "auth.exportToken.failed", error = %e, "Failed to serialize dev token");
            return;
        }
    };

    if let Err(e) = std::fs::write(&token_path, &json_str) {
        tracing::warn!(op = "auth.exportToken.failed", error = %e, "Failed to write dev token file");
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
    }

    // Write pointer file: ~/.ekka/dev-token.path
    if let Some(ptr) = pointer_path() {
        let abs_path = format!("{}\n", token_path.display());
        if let Err(e) = std::fs::write(&ptr, &abs_path) {
            tracing::warn!(op = "auth.exportToken.pointer.failed", error = %e, "Failed to write pointer file");
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&ptr, std::fs::Permissions::from_mode(0o600));
            }
        }
    }

    tracing::info!(
        op = "auth.exportToken",
        user_id = %auth.sub,
        tenant_id = %auth.tenant_id,
        app_id = config::app_slug(),
        "Dev token exported to ~/.ekka/<app-id>/ (token not logged)"
    );
}

/// Remove dev token + pointer files (called on logout/disconnect).
pub fn clear_dev_token() {
    // Remove token file at ~/.ekka/<app-id>/dev-token.json
    if let Some(tooling_dir) = dev_tooling_dir() {
        let token_path = tooling_dir.join("dev-token.json");
        if token_path.exists() {
            let _ = std::fs::remove_file(&token_path);
        }
    }

    // Remove pointer file at ~/.ekka/dev-token.path
    if let Some(ptr) = pointer_path() {
        if ptr.exists() {
            let _ = std::fs::remove_file(&ptr);
        }
    }

    tracing::info!(op = "auth.clearDevToken", "Dev token + pointer file removed");
}
