//! Vault Status Operations
//!
//! Status and capabilities information.

use crate::context::RuntimeContext;
use crate::error::EkkaResult;
use std::fs;

use super::types::{VaultCapabilities, VaultStatus};

/// Get vault status
pub fn status(ctx: &RuntimeContext) -> EkkaResult<VaultStatus> {
    let vault_path = ctx.home_path.join("vault");

    // Check if vault directory exists
    let initialized = vault_path.exists();

    // Get tenant ID if authenticated
    let tenant_id = ctx.auth.as_ref().map(|a| a.tenant_id.clone());

    // List available workspaces for the tenant
    let workspaces = if let Some(ref tid) = tenant_id {
        let files_path = vault_path.join("files").join(format!("t_{}", tid));
        if files_path.exists() {
            fs::read_dir(&files_path)
                .ok()
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().is_dir())
                        .filter_map(|e| {
                            e.file_name()
                                .to_string_lossy()
                                .strip_prefix("w_")
                                .map(|s| s.to_string())
                        })
                        .collect()
                })
                .unwrap_or_else(Vec::new)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(VaultStatus {
        initialized,
        tenant_id,
        workspaces,
    })
}

/// Get vault capabilities
pub fn capabilities(_ctx: &RuntimeContext) -> EkkaResult<VaultCapabilities> {
    Ok(VaultCapabilities {
        features: vec![
            "secrets".to_string(),
            "bundles".to_string(),
            "files".to_string(),
            "audit".to_string(),
        ],
        max_secret_size: 1024 * 1024,     // 1 MB
        max_file_size: 100 * 1024 * 1024, // 100 MB
        max_path_depth: 20,
    })
}
