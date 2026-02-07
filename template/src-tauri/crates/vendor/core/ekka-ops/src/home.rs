//! Home Operations
//!
//! Manages EKKA home directory status and grants.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};
use crate::traits::{GrantIssuer, GrantRequest};
use ekka_path_guard::{GrantStore, GrantsFile, PathAccess, PathGrant, PathType};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// Types
// =============================================================================

/// Home directory state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HomeState {
    /// Not authenticated yet
    BootstrapPreLogin,
    /// Authenticated but no HOME grant
    AuthenticatedNoHomeGrant,
    /// Ready to use
    HomeGranted,
}

/// Home status information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeStatus {
    /// Current state
    pub state: HomeState,
    /// Home directory path
    pub home_path: String,
    /// Whether a valid grant is present
    pub grant_present: bool,
    /// Reason if not ready (None if ready)
    pub reason: Option<String>,
}

/// Result of grant request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantResult {
    /// Whether grant was successful
    pub success: bool,
    /// Grant ID
    pub grant_id: String,
    /// Expiration timestamp (RFC3339)
    pub expires_at: Option<String>,
}

// =============================================================================
// Constants
// =============================================================================

/// Default HOME grant expiration: 1 year
const HOME_GRANT_EXPIRES_SECONDS: u64 = 31536000;

// =============================================================================
// Operations
// =============================================================================

/// Get home directory status
///
/// Checks authentication and grant presence.
pub fn status(ctx: &RuntimeContext) -> HomeStatus {
    // Check auth first
    let auth = match &ctx.auth {
        Some(a) => a,
        None => {
            return HomeStatus {
                state: HomeState::BootstrapPreLogin,
                home_path: ctx.home_path.to_string_lossy().to_string(),
                grant_present: false,
                reason: None,
            };
        }
    };

    // Check for valid HOME grant
    match check_home_grant(ctx, auth) {
        Ok(true) => HomeStatus {
            state: HomeState::HomeGranted,
            home_path: ctx.home_path.to_string_lossy().to_string(),
            grant_present: true,
            reason: None,
        },
        Ok(false) => HomeStatus {
            state: HomeState::AuthenticatedNoHomeGrant,
            home_path: ctx.home_path.to_string_lossy().to_string(),
            grant_present: false,
            reason: Some("No valid HOME grant found".to_string()),
        },
        Err(e) => HomeStatus {
            state: HomeState::AuthenticatedNoHomeGrant,
            home_path: ctx.home_path.to_string_lossy().to_string(),
            grant_present: false,
            reason: Some(e.message),
        },
    }
}

/// Request HOME grant from engine
///
/// # Arguments
/// * `ctx` - Runtime context (must be authenticated)
/// * `issuer` - Grant issuer implementation
///
/// # Returns
/// Grant result with ID and expiration
pub fn grant<I: GrantIssuer>(ctx: &RuntimeContext, issuer: &I) -> EkkaResult<GrantResult> {
    // Must be authenticated
    let _auth = ctx.auth.as_ref().ok_or_else(|| {
        EkkaError::new(codes::NOT_AUTHENTICATED, "Must login before requesting HOME grant")
    })?;

    // Create HOME grant request
    let req = GrantRequest::home(&ctx.home_path, HOME_GRANT_EXPIRES_SECONDS);

    // Issue grant via injected issuer
    let response = issuer.issue(ctx, req)?;

    // Save grant to grants.json
    save_grant(ctx, &response.signed_grant)?;

    // Extract grant ID
    let grant_id = response.signed_grant.grant.grant_id.clone();

    Ok(GrantResult {
        success: true,
        grant_id,
        expires_at: Some(response.expires_at),
    })
}

/// Check if a valid HOME grant exists
fn check_home_grant(ctx: &RuntimeContext, auth: &crate::context::AuthContext) -> EkkaResult<bool> {
    let grants_path = ctx.grants_path();

    // No grants file = no grant
    if !grants_path.exists() {
        return Ok(false);
    }

    // Load engine verify key
    let key_b64 = std::env::var("ENGINE_GRANT_VERIFY_KEY_B64").map_err(|_| {
        EkkaError::new(
            codes::INTERNAL_ERROR,
            "ENGINE_GRANT_VERIFY_KEY_B64 not set",
        )
    })?;

    // Load and verify grants
    let store = GrantStore::new(grants_path, &key_b64).map_err(|e| {
        EkkaError::from_source(codes::IO_ERROR, "Failed to load grants", e)
    })?;

    let grants = store.grants();

    // Check for valid HOME grant matching auth context
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let home_str = ctx.home_path.to_string_lossy();

    for grant in grants {
        // Check if this is a HOME grant (covers home_path)
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

/// Save a grant to grants.json
fn save_grant(ctx: &RuntimeContext, signed_grant: &ekka_path_guard::SignedGrant) -> EkkaResult<()> {
    let grants_path = ctx.grants_path();

    // Load existing or create new grants file
    let mut grants_file: GrantsFile = if grants_path.exists() {
        let content = std::fs::read_to_string(&grants_path).map_err(|e| {
            EkkaError::from_source(codes::IO_ERROR, "Failed to read grants.json", e)
        })?;
        serde_json::from_str(&content).unwrap_or(GrantsFile {
            schema_version: "1.0".to_string(),
            grants: vec![],
        })
    } else {
        GrantsFile {
            schema_version: "1.0".to_string(),
            grants: vec![],
        }
    };

    // Determine path_type and path_access from grant
    let path_type = match &signed_grant.grant.resource {
        ekka_path_guard::GrantResource::Path { attrs, .. } => {
            attrs
                .as_ref()
                .and_then(|a| a.path_type)
                .unwrap_or(PathType::General)
        }
        _ => PathType::General,
    };
    let path_access = signed_grant
        .grant
        .permissions
        .access
        .unwrap_or(PathAccess::ReadOnly);

    // Create PathGrant
    let path_grant = PathGrant {
        signed_grant: signed_grant.clone(),
        path_type,
        path_access,
    };

    // Add to grants array
    grants_file.grants.push(path_grant);

    // Write atomically (temp file + rename)
    let grants_json = serde_json::to_string_pretty(&grants_file).map_err(|e| {
        EkkaError::from_source(codes::INTERNAL_ERROR, "Failed to serialize grants", e)
    })?;

    let temp_path = grants_path.with_extension("json.tmp");
    std::fs::write(&temp_path, &grants_json).map_err(|e| {
        EkkaError::from_source(codes::IO_ERROR, "Failed to write grants", e)
    })?;
    std::fs::rename(&temp_path, &grants_path).map_err(|e| {
        EkkaError::from_source(codes::IO_ERROR, "Failed to rename grants file", e)
    })?;

    Ok(())
}

/// Check if home is ready (authenticated + grant present)
pub fn is_ready(ctx: &RuntimeContext) -> bool {
    status(ctx).state == HomeState::HomeGranted
}

/// Require home to be ready, returning error if not
pub fn require_ready(ctx: &RuntimeContext) -> EkkaResult<()> {
    let s = status(ctx);
    if s.state != HomeState::HomeGranted {
        return Err(EkkaError::new(
            codes::HOME_GRANT_REQUIRED,
            s.reason.unwrap_or_else(|| "HOME grant required".to_string()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AuthContext;

    #[test]
    fn test_status_no_auth() {
        let ctx = RuntimeContext::new(
            std::path::PathBuf::from("/tmp/test-home"),
            uuid::Uuid::new_v4(),
        );

        let s = status(&ctx);
        assert_eq!(s.state, HomeState::BootstrapPreLogin);
        assert!(!s.grant_present);
    }

    #[test]
    fn test_status_with_auth_no_grant() {
        let auth = AuthContext::new("tenant", "user", "jwt");
        let ctx = RuntimeContext::with_auth(
            std::path::PathBuf::from("/tmp/nonexistent-test-home"),
            uuid::Uuid::new_v4(),
            auth,
        );

        let s = status(&ctx);
        // Will be AuthenticatedNoHomeGrant since grants.json doesn't exist
        assert_eq!(s.state, HomeState::AuthenticatedNoHomeGrant);
        assert!(!s.grant_present);
    }
}
