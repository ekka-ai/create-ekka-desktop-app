//! Path Operations
//!
//! Manages path access checking, listing, and grant requests.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};
use crate::traits::{GrantIssuer, GrantRequest};
use ekka_path_guard::{
    GrantStore, GrantsFile, PathAccess, PathGrant, PathGuard, PathType,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// Types
// =============================================================================

/// Information about a path grant
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathInfo {
    /// Path prefix
    pub path: String,
    /// Path type (Home, Workspace, Data, etc.)
    pub path_type: PathType,
    /// Access level (ReadOnly, ReadWrite)
    pub access: PathAccess,
    /// Grant ID
    pub grant_id: String,
    /// Expiration timestamp (RFC3339)
    pub expires_at: Option<String>,
    /// Whether the grant is currently valid
    pub is_valid: bool,
    /// Who issued the grant (e.g., "ekka-engine")
    pub issuer: String,
    /// When the grant was issued (RFC3339)
    pub issued_at: String,
    /// User/subject who owns the grant
    pub subject: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Purpose of the grant
    pub purpose: String,
}

/// Result of a path access request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathGrantResult {
    /// Whether the request was successful
    pub success: bool,
    /// Grant ID if successful
    pub grant_id: Option<String>,
    /// Expiration timestamp (RFC3339) if successful
    pub expires_at: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Path check result with details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathCheckResult {
    /// Whether the operation is allowed
    pub allowed: bool,
    /// Reason for the decision
    pub reason: String,
    /// Path type if a grant covers this path
    pub path_type: Option<PathType>,
    /// Access level if a grant covers this path
    pub access: Option<PathAccess>,
    /// The path prefix that granted access (for revoking)
    pub granted_by: Option<String>,
}

// =============================================================================
// Constants
// =============================================================================

/// Default path grant expiration: 90 days
const PATH_GRANT_EXPIRES_SECONDS: u64 = 7776000;

// =============================================================================
// Operations
// =============================================================================

/// Check if an operation is allowed on a path
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `path` - Path to check
/// * `operation` - Operation to check ("read", "write", "delete")
///
/// # Returns
/// true if the operation is allowed
pub fn check(ctx: &RuntimeContext, path: &Path, operation: &str) -> bool {
    check_detailed(ctx, path, operation).allowed
}

/// Check if an operation is allowed on a path with detailed result
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `path` - Path to check
/// * `operation` - Operation to check ("read", "write", "delete")
///
/// # Returns
/// Detailed check result
pub fn check_detailed(ctx: &RuntimeContext, path: &Path, operation: &str) -> PathCheckResult {
    // Create path guard
    let guard = match create_path_guard(ctx) {
        Ok(g) => g,
        Err(e) => {
            return PathCheckResult {
                allowed: false,
                reason: e.message,
                path_type: None,
                access: None,
                granted_by: None,
            };
        }
    };

    let decision = guard.evaluate(path, operation);

    PathCheckResult {
        allowed: decision.allowed,
        reason: decision.reason,
        path_type: if decision.allowed {
            Some(decision.path_type)
        } else {
            None
        },
        access: if decision.allowed {
            Some(decision.path_access)
        } else {
            None
        },
        granted_by: decision.path_prefix,
    }
}

/// List all path grants
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `path_type` - Optional filter by path type
///
/// # Returns
/// List of path info for all grants
pub fn list(ctx: &RuntimeContext, path_type: Option<PathType>) -> EkkaResult<Vec<PathInfo>> {
    let grants_path = ctx.grants_path();

    // No grants file = empty list
    if !grants_path.exists() {
        return Ok(vec![]);
    }

    // Load grants
    let key_b64 = std::env::var("ENGINE_GRANT_VERIFY_KEY_B64").map_err(|_| {
        EkkaError::new(codes::INTERNAL_ERROR, "ENGINE_GRANT_VERIFY_KEY_B64 not set")
    })?;

    let store = GrantStore::new(grants_path, &key_b64)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to load grants", e))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut result = Vec::new();
    for grant in store.grants() {
        // Filter by path type if specified
        if let Some(filter_type) = path_type {
            if grant.path_type != filter_type {
                continue;
            }
        }

        let g = &grant.signed_grant.grant;
        let expires_at = g.expires_at.clone();
        let is_valid = grant.expires_at() > now;

        result.push(PathInfo {
            path: grant.path_prefix().to_string(),
            path_type: grant.path_type,
            access: grant.access(),
            grant_id: g.grant_id.clone(),
            expires_at,
            is_valid,
            issuer: g.issuer.clone(),
            issued_at: g.issued_at.clone(),
            subject: g.sub.clone(),
            tenant_id: g.tenant_id.clone(),
            purpose: g.purpose.clone(),
        });
    }

    Ok(result)
}

/// Get information about a specific path
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `path` - Path to look up
///
/// # Returns
/// Path info if a grant covers this path
pub fn get(ctx: &RuntimeContext, path: &Path) -> EkkaResult<Option<PathInfo>> {
    let grants = list(ctx, None)?;

    // Find most specific grant that covers this path
    let path_str = path.to_string_lossy();
    let mut best_match: Option<&PathInfo> = None;
    let mut best_specificity = 0;

    for grant in &grants {
        if path_str.starts_with(&grant.path) {
            let specificity = grant.path.len();
            if specificity > best_specificity {
                best_specificity = specificity;
                best_match = Some(grant);
            }
        }
    }

    Ok(best_match.cloned())
}

/// Request access to a path
///
/// # Arguments
/// * `ctx` - Runtime context (must be authenticated)
/// * `issuer` - Grant issuer implementation
/// * `path` - Path to request access to
/// * `path_type` - Type of path
/// * `access` - Access level requested
///
/// # Returns
/// Grant result
pub fn request<I: GrantIssuer>(
    ctx: &RuntimeContext,
    issuer: &I,
    path: &Path,
    path_type: PathType,
    access: PathAccess,
) -> EkkaResult<PathGrantResult> {
    // Must be authenticated
    let _auth = ctx.auth.as_ref().ok_or_else(|| {
        EkkaError::new(codes::NOT_AUTHENTICATED, "Must login before requesting path access")
    })?;

    // Enforce HOME path_type policy
    if path_type == PathType::Home {
        let home_str = ctx.home_path.to_string_lossy();
        let path_str = path.to_string_lossy();
        if !path_str.starts_with(&*home_str) {
            return Err(EkkaError::new(
                codes::INVALID_PATH,
                "HOME path_type can only be used for paths under EKKA home directory",
            ));
        }
    }

    // Create grant request
    let req = GrantRequest {
        path_prefix: path.to_string_lossy().to_string(),
        path_type,
        access,
        purpose: format!("{:?}_access", path_type).to_lowercase(),
        expires_in_seconds: PATH_GRANT_EXPIRES_SECONDS,
    };

    // Issue grant via injected issuer
    let response = match issuer.issue(ctx, req) {
        Ok(r) => r,
        Err(e) => {
            return Ok(PathGrantResult {
                success: false,
                grant_id: None,
                expires_at: None,
                error: Some(e.message),
            });
        }
    };

    // Save grant to grants.json
    save_grant(ctx, &response.signed_grant, path_type, access)?;

    Ok(PathGrantResult {
        success: true,
        grant_id: Some(response.signed_grant.grant.grant_id.clone()),
        expires_at: Some(response.expires_at),
        error: None,
    })
}

/// Remove a path grant
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `path` - Path to remove grant for (exact match or path covered by a grant)
///
/// # Returns
/// true if a grant was removed
pub fn remove(ctx: &RuntimeContext, path: &Path) -> EkkaResult<bool> {
    let grants_path = ctx.grants_path();

    if !grants_path.exists() {
        return Ok(false);
    }

    // Load grants file
    let content = std::fs::read_to_string(&grants_path)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to read grants.json", e))?;

    let mut grants_file: GrantsFile = serde_json::from_str(&content)
        .map_err(|e| EkkaError::from_source(codes::INTERNAL_ERROR, "Failed to parse grants.json", e))?;

    let path_str = path.to_string_lossy();
    let original_len = grants_file.grants.len();

    // Remove grants that match this path exactly
    grants_file.grants.retain(|g| g.path_prefix() != path_str);

    let removed = original_len != grants_file.grants.len();

    if removed {
        // Write back atomically
        let grants_json = serde_json::to_string_pretty(&grants_file)
            .map_err(|e| EkkaError::from_source(codes::INTERNAL_ERROR, "Failed to serialize grants", e))?;

        let temp_path = grants_path.with_extension("json.tmp");
        std::fs::write(&temp_path, &grants_json)
            .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to write grants", e))?;
        std::fs::rename(&temp_path, &grants_path)
            .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to rename grants file", e))?;
    }

    Ok(removed)
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Create a PathGuard for access checks
fn create_path_guard(ctx: &RuntimeContext) -> EkkaResult<PathGuard> {
    match &ctx.auth {
        Some(auth) => {
            let pg_auth = ekka_path_guard::AuthContext::new(&auth.tenant_id, &auth.sub);
            PathGuard::from_env(ctx.home_path.clone(), pg_auth).map_err(|e| {
                EkkaError::from_source(codes::INTERNAL_ERROR, "Failed to create path guard", e)
            })
        }
        None => {
            // Without auth, use home-only mode
            Ok(PathGuard::home_only(ctx.home_path.clone()))
        }
    }
}

/// Save a grant to grants.json
fn save_grant(
    ctx: &RuntimeContext,
    signed_grant: &ekka_path_guard::SignedGrant,
    path_type: PathType,
    path_access: PathAccess,
) -> EkkaResult<()> {
    let grants_path = ctx.grants_path();

    // Load existing or create new grants file
    let mut grants_file: GrantsFile = if grants_path.exists() {
        let content = std::fs::read_to_string(&grants_path)
            .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to read grants.json", e))?;
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

    // Create PathGrant
    let path_grant = PathGrant {
        signed_grant: signed_grant.clone(),
        path_type,
        path_access,
    };

    // Add to grants array
    grants_file.grants.push(path_grant);

    // Write atomically
    let grants_json = serde_json::to_string_pretty(&grants_file)
        .map_err(|e| EkkaError::from_source(codes::INTERNAL_ERROR, "Failed to serialize grants", e))?;

    let temp_path = grants_path.with_extension("json.tmp");
    std::fs::write(&temp_path, &grants_json)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to write grants", e))?;
    std::fs::rename(&temp_path, &grants_path)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to rename grants file", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AuthContext;
    use tempfile::TempDir;

    fn test_context() -> (RuntimeContext, TempDir) {
        let temp = TempDir::new().unwrap();
        let ctx = RuntimeContext::new(temp.path().to_path_buf(), uuid::Uuid::new_v4());
        (ctx, temp)
    }

    #[test]
    fn test_check_home_path() {
        let (ctx, temp) = test_context();
        let home_file = temp.path().join("test.txt");

        // Home paths are always allowed in home-only mode
        assert!(check(&ctx, &home_file, "read"));
        assert!(check(&ctx, &home_file, "write"));
    }

    #[test]
    fn test_check_outside_home() {
        let (ctx, _temp) = test_context();
        let outside = Path::new("/etc/passwd");

        // Paths outside home are denied without grants
        assert!(!check(&ctx, outside, "read"));
    }

    #[test]
    fn test_list_empty() {
        let (ctx, _temp) = test_context();

        let paths = list(&ctx, None).unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_home_path_type_enforcement() {
        let (mut ctx, _temp) = test_context();
        ctx.auth = Some(AuthContext::new("tenant", "user", "jwt"));

        // This should fail because the path is outside EKKA home
        use crate::traits::mock::MockGrantIssuer;
        let issuer = MockGrantIssuer::new();

        let result = request(
            &ctx,
            &issuer,
            Path::new("/some/other/path"),
            PathType::Home,
            PathAccess::ReadWrite,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, codes::INVALID_PATH);
    }
}
