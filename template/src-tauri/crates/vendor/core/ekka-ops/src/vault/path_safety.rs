//! Path Safety
//!
//! Path validation utilities for chroot enforcement.
//! User paths CANNOT access internal vault directories.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};
use std::path::PathBuf;

/// Reserved directory names that users cannot access
const RESERVED_DIRS: &[&str] = &["__meta__", "secrets", "bundles", "audit"];

/// Maximum path depth allowed
const MAX_PATH_DEPTH: usize = 20;

/// Validate a user-provided path for safety
///
/// Rules:
/// 1. Strip leading slash (treat as relative to workspace root)
/// 2. Reject .. segments (path traversal)
/// 3. Reject null bytes
/// 4. Reject empty segments (//foo)
/// 5. Reject reserved directory names at root level
/// 6. Normalize path separators (\ -> /)
/// 7. Limit path depth
pub fn validate_user_path(path: &str) -> EkkaResult<String> {
    // Reject null bytes
    if path.contains('\0') {
        return Err(EkkaError::new(
            codes::INVALID_PATH,
            "Path contains null bytes",
        ));
    }

    // Normalize path separators
    let normalized = path.replace('\\', "/");

    // Strip leading slash (treat as relative to workspace root)
    let normalized = normalized.trim_start_matches('/');

    // Split into segments and validate each
    let segments: Vec<&str> = normalized.split('/').collect();

    // Check path depth
    if segments.len() > MAX_PATH_DEPTH {
        return Err(EkkaError::new(
            codes::INVALID_PATH,
            format!("Path exceeds maximum depth of {}", MAX_PATH_DEPTH),
        ));
    }

    for (i, segment) in segments.iter().enumerate() {
        // Reject empty segments (except trailing)
        if segment.is_empty() && i < segments.len() - 1 {
            return Err(EkkaError::new(
                codes::INVALID_PATH,
                "Path contains empty segments",
            ));
        }

        // Reject path traversal
        if *segment == ".." {
            return Err(EkkaError::new(
                codes::PATH_TRAVERSAL_DENIED,
                "Path traversal (..) is not allowed",
            ));
        }

        // Reject reserved directories at root level
        if i == 0 && RESERVED_DIRS.contains(segment) {
            return Err(EkkaError::new(
                codes::PATH_TRAVERSAL_DENIED,
                format!("Access to '{}' directory is not allowed", segment),
            ));
        }
    }

    // Remove trailing slash if present
    let result = normalized.trim_end_matches('/').to_string();

    // Reject empty path
    if result.is_empty() {
        return Err(EkkaError::new(codes::INVALID_PATH, "Path cannot be empty"));
    }

    Ok(result)
}

/// Resolve a user path to an absolute filesystem path under the tenant/workspace chroot
///
/// Returns: {home}/vault/files/t_{tenant}/w_{workspace}/{user_path}
pub fn resolve_user_path(
    ctx: &RuntimeContext,
    workspace_id: Option<&str>,
    user_path: &str,
) -> EkkaResult<PathBuf> {
    // Validate the user path first
    let validated_path = validate_user_path(user_path)?;

    // Get tenant ID from auth context
    let auth = ctx.auth.as_ref().ok_or_else(|| {
        EkkaError::new(
            codes::NOT_AUTHENTICATED,
            "Must be authenticated to access vault files",
        )
    })?;

    let tenant_id = &auth.tenant_id;

    // Use provided workspace_id or default
    let workspace = workspace_id
        .map(String::from)
        .unwrap_or_else(|| "default".to_string());

    // Build the chrooted path
    let base_path = ctx
        .home_path
        .join("vault")
        .join("files")
        .join(format!("t_{}", tenant_id))
        .join(format!("w_{}", workspace));

    Ok(base_path.join(validated_path))
}

/// Resolve the base directory for a tenant/workspace (for listing at root)
pub fn resolve_workspace_root(
    ctx: &RuntimeContext,
    workspace_id: Option<&str>,
) -> EkkaResult<PathBuf> {
    // Get tenant ID from auth context
    let auth = ctx.auth.as_ref().ok_or_else(|| {
        EkkaError::new(
            codes::NOT_AUTHENTICATED,
            "Must be authenticated to access vault files",
        )
    })?;

    let tenant_id = &auth.tenant_id;

    // Use provided workspace_id or default
    let workspace = workspace_id
        .map(String::from)
        .unwrap_or_else(|| "default".to_string());

    Ok(ctx
        .home_path
        .join("vault")
        .join("files")
        .join(format!("t_{}", tenant_id))
        .join(format!("w_{}", workspace)))
}

/// Get the tenant-scoped path for secrets/bundles storage
#[allow(dead_code)]
pub fn resolve_tenant_path(ctx: &RuntimeContext, subdir: &str) -> EkkaResult<PathBuf> {
    let auth = ctx.auth.as_ref().ok_or_else(|| {
        EkkaError::new(
            codes::NOT_AUTHENTICATED,
            "Must be authenticated to access vault",
        )
    })?;

    let tenant_id = &auth.tenant_id;

    Ok(ctx
        .home_path
        .join("vault")
        .join(subdir)
        .join(format!("t_{}", tenant_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_paths() {
        assert!(validate_user_path("foo").is_ok());
        assert!(validate_user_path("foo/bar").is_ok());
        assert!(validate_user_path("foo/bar/baz.txt").is_ok());
        assert!(validate_user_path("reports/2026/january.json").is_ok());
    }

    #[test]
    fn test_validate_strips_leading_slash() {
        // Leading slashes are stripped, not rejected
        assert_eq!(validate_user_path("/foo").unwrap(), "foo");
        assert_eq!(validate_user_path("/foo/bar").unwrap(), "foo/bar");
        // Multiple leading slashes are all stripped
        assert_eq!(validate_user_path("//foo").unwrap(), "foo");
    }

    #[test]
    fn test_validate_rejects_path_traversal() {
        assert!(validate_user_path("..").is_err());
        assert!(validate_user_path("../foo").is_err());
        assert!(validate_user_path("foo/../bar").is_err());
        assert!(validate_user_path("foo/bar/../../baz").is_err());
    }

    #[test]
    fn test_validate_rejects_reserved_dirs() {
        assert!(validate_user_path("__meta__").is_err());
        assert!(validate_user_path("__meta__/secrets.json").is_err());
        assert!(validate_user_path("secrets").is_err());
        assert!(validate_user_path("bundles").is_err());
        assert!(validate_user_path("audit").is_err());

        // But nested is OK
        assert!(validate_user_path("my_data/__meta__").is_ok());
    }

    #[test]
    fn test_validate_rejects_null_bytes() {
        assert!(validate_user_path("foo\0bar").is_err());
    }

    #[test]
    fn test_validate_rejects_empty_segments() {
        assert!(validate_user_path("foo//bar").is_err());
    }

    #[test]
    fn test_validate_normalizes_separators() {
        let result = validate_user_path("foo\\bar\\baz").unwrap();
        assert_eq!(result, "foo/bar/baz");
    }

    #[test]
    fn test_validate_removes_trailing_slash() {
        let result = validate_user_path("foo/bar/").unwrap();
        assert_eq!(result, "foo/bar");
    }
}
