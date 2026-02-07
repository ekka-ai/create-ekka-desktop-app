//! Grant Operations
//!
//! Manages grant listing, lookup, and revocation.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};
use crate::traits::GrantIssuer;
use ekka_path_guard::{GrantStore, GrantsFile, PathAccess, PathType};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// Types
// =============================================================================

/// Grant information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantInfo {
    /// Grant ID
    pub grant_id: String,
    /// Resource path or connector ID
    pub resource: String,
    /// Path type (for path grants)
    pub path_type: Option<PathType>,
    /// Access level (for path grants)
    pub access: Option<PathAccess>,
    /// Issuer
    pub issuer: String,
    /// Issue timestamp (RFC3339)
    pub issued_at: String,
    /// Expiration timestamp (RFC3339)
    pub expires_at: Option<String>,
    /// Whether the grant is currently valid
    pub is_valid: bool,
    /// Purpose/reason
    pub purpose: String,
}

/// Grant expiry information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantExpiry {
    /// Grant ID
    pub grant_id: String,
    /// Whether the grant has expired
    pub expired: bool,
    /// Expiration timestamp (RFC3339)
    pub expires_at: Option<String>,
    /// Seconds until expiration (negative if expired)
    pub seconds_remaining: i64,
}

// =============================================================================
// Operations
// =============================================================================

/// List all grants
///
/// # Arguments
/// * `ctx` - Runtime context
///
/// # Returns
/// List of grant information
pub fn list(ctx: &RuntimeContext) -> EkkaResult<Vec<GrantInfo>> {
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
        let signed = &grant.signed_grant;
        let inner = &signed.grant;

        let resource = match &inner.resource {
            ekka_path_guard::GrantResource::Path { path_prefix, .. } => path_prefix.clone(),
            ekka_path_guard::GrantResource::Connector { id } => id.clone(),
        };

        let is_valid = grant.expires_at() > now;

        result.push(GrantInfo {
            grant_id: inner.grant_id.clone(),
            resource,
            path_type: Some(grant.path_type),
            access: Some(grant.access()),
            issuer: inner.issuer.clone(),
            issued_at: inner.issued_at.clone(),
            expires_at: inner.expires_at.clone(),
            is_valid,
            purpose: inner.purpose.clone(),
        });
    }

    Ok(result)
}

/// Get a specific grant by ID
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `grant_id` - Grant ID to look up
///
/// # Returns
/// Grant info if found
pub fn get(ctx: &RuntimeContext, grant_id: &str) -> EkkaResult<Option<GrantInfo>> {
    let grants = list(ctx)?;
    Ok(grants.into_iter().find(|g| g.grant_id == grant_id))
}

/// Get grant expiry information
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `grant_id` - Grant ID to check
///
/// # Returns
/// Expiry information
pub fn expiry(ctx: &RuntimeContext, grant_id: &str) -> EkkaResult<Option<GrantExpiry>> {
    let grants_path = ctx.grants_path();

    if !grants_path.exists() {
        return Ok(None);
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

    for grant in store.grants() {
        if grant.grant_id() == grant_id {
            let expires_at_ts = grant.expires_at();
            let seconds_remaining = expires_at_ts - now;

            return Ok(Some(GrantExpiry {
                grant_id: grant_id.to_string(),
                expired: seconds_remaining < 0,
                expires_at: grant.signed_grant.grant.expires_at.clone(),
                seconds_remaining,
            }));
        }
    }

    Ok(None)
}

/// Revoke a grant
///
/// This removes the grant locally and optionally notifies the engine.
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `issuer` - Grant issuer (for engine notification)
/// * `grant_id` - Grant ID to revoke
///
/// # Returns
/// true if the grant was found and removed
pub fn revoke<I: GrantIssuer>(
    ctx: &RuntimeContext,
    issuer: &I,
    grant_id: &str,
) -> EkkaResult<bool> {
    let grants_path = ctx.grants_path();

    if !grants_path.exists() {
        return Ok(false);
    }

    // Load grants file
    let content = std::fs::read_to_string(&grants_path)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to read grants.json", e))?;

    let mut grants_file: GrantsFile = serde_json::from_str(&content)
        .map_err(|e| EkkaError::from_source(codes::INTERNAL_ERROR, "Failed to parse grants.json", e))?;

    let original_len = grants_file.grants.len();

    // Remove grant with matching ID
    grants_file.grants.retain(|g| g.grant_id() != grant_id);

    let removed = original_len != grants_file.grants.len();

    if removed {
        // Notify engine (best effort - don't fail if this fails)
        let _ = issuer.revoke(ctx, grant_id);

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

/// Remove a grant locally without notifying the engine
///
/// # Arguments
/// * `ctx` - Runtime context
/// * `grant_id` - Grant ID to remove
///
/// # Returns
/// true if the grant was found and removed
pub fn remove_local(ctx: &RuntimeContext, grant_id: &str) -> EkkaResult<bool> {
    let grants_path = ctx.grants_path();

    if !grants_path.exists() {
        return Ok(false);
    }

    // Load grants file
    let content = std::fs::read_to_string(&grants_path)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to read grants.json", e))?;

    let mut grants_file: GrantsFile = serde_json::from_str(&content)
        .map_err(|e| EkkaError::from_source(codes::INTERNAL_ERROR, "Failed to parse grants.json", e))?;

    let original_len = grants_file.grants.len();

    // Remove grant with matching ID
    grants_file.grants.retain(|g| g.grant_id() != grant_id);

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_context() -> (RuntimeContext, TempDir) {
        let temp = TempDir::new().unwrap();
        let ctx = RuntimeContext::new(temp.path().to_path_buf(), uuid::Uuid::new_v4());
        (ctx, temp)
    }

    #[test]
    fn test_list_empty() {
        let (ctx, _temp) = test_context();

        let grants = list(&ctx).unwrap();
        assert!(grants.is_empty());
    }

    #[test]
    fn test_get_not_found() {
        let (ctx, _temp) = test_context();

        let grant = get(&ctx, "nonexistent").unwrap();
        assert!(grant.is_none());
    }

    #[test]
    fn test_expiry_not_found() {
        let (ctx, _temp) = test_context();

        let exp = expiry(&ctx, "nonexistent").unwrap();
        assert!(exp.is_none());
    }
}
