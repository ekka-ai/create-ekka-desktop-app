//! Grant validation
//!
//! Handles verification of HOME grants and home status checks.

use crate::bootstrap::resolve_home_path;
use crate::state::{AuthContext, EngineState, HomeState};
use crate::types::EngineResponse;
use ekka_sdk_core::ekka_path_guard::GrantStore;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Check if a valid HOME grant exists for the given auth context
pub fn check_home_grant(home_path: &PathBuf, auth: &AuthContext, verify_key: &str) -> Result<bool, String> {
    let grants_path = home_path.join("grants.json");

    // No grants file = no grant
    if !grants_path.exists() {
        return Ok(false);
    }

    let key_b64 = verify_key;

    // Load and verify grants
    let store = GrantStore::new(grants_path, &key_b64).map_err(|e| e.to_string())?;
    let grants = store.grants();

    // Check for valid HOME grant matching auth context
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for grant in grants {
        // Check if this is a HOME grant (covers home_path)
        let home_str = home_path.to_string_lossy();
        if !home_str.starts_with(grant.path_prefix()) && grant.path_prefix() != home_str {
            continue;
        }

        // Check tenant_id matches
        if grant.tenant_id() != auth.tenant_id {
            continue;
        }

        // Check sub matches
        if grant.subject() != auth.sub {
            continue;
        }

        // Check not expired
        if grant.expires_at() < now {
            continue;
        }

        // Valid HOME grant found
        return Ok(true);
    }

    Ok(false)
}

/// Get current home status including state, path, and grant presence
pub fn get_home_status(state: &EngineState) -> (HomeState, PathBuf, bool, Option<String>) {
    // Resolve home path
    let home_path = match resolve_home_path() {
        Ok(p) => p,
        Err(e) => {
            return (
                HomeState::BootstrapPreLogin,
                PathBuf::new(),
                false,
                Some(format!("Failed to resolve home path: {}", e)),
            );
        }
    };

    // Store home path
    if let Ok(mut hp) = state.home_path.lock() {
        *hp = Some(home_path.clone());
    }

    // Check auth
    let auth = match state.auth.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            return (
                HomeState::BootstrapPreLogin,
                home_path,
                false,
                Some("Lock error".to_string()),
            )
        }
    };

    let auth = match auth {
        Some(a) => a,
        None => return (HomeState::BootstrapPreLogin, home_path, false, None),
    };

    // Get verify key from state (fetched from well-known endpoint)
    let verify_key = match state.get_grant_verify_key() {
        Some(k) => k,
        None => {
            return (
                HomeState::AuthenticatedNoHomeGrant,
                home_path,
                false,
                Some("Grant verification key not loaded. Waiting for engine configuration.".to_string()),
            );
        }
    };

    // Check for valid HOME grant
    match check_home_grant(&home_path, &auth, &verify_key) {
        Ok(true) => (HomeState::HomeGranted, home_path, true, None),
        Ok(false) => (
            HomeState::AuthenticatedNoHomeGrant,
            home_path,
            false,
            Some("No valid HOME grant found".to_string()),
        ),
        Err(e) => (HomeState::AuthenticatedNoHomeGrant, home_path, false, Some(e)),
    }
}

/// Guard function: returns error response if HOME grant is not present
pub fn require_home_granted(state: &EngineState) -> Result<(), EngineResponse> {
    let (home_state, _, _, reason) = get_home_status(state);

    if home_state != HomeState::HomeGranted {
        return Err(EngineResponse::err(
            "HOME_GRANT_REQUIRED",
            &reason.unwrap_or_else(|| "HOME grant required before this operation".to_string()),
        ));
    }

    Ok(())
}
