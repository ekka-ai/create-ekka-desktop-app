//! Vault Operations
//!
//! High-level API for vault secrets, bundles, files, and audit.
//!
//! ## Security Invariant
//!
//! Secret values are NEVER returned to the caller. The API returns metadata only.
//! Values are only used internally for injection operations.
//!
//! ## Architecture
//!
//! This module owns ALL vault business logic. The desktop app handlers are thin
//! wrappers that call these functions and map errors.
//!
//! ## Performance
//!
//! All vault operations require a `VaultManagerCache` to avoid repeated PBKDF2
//! key derivation (100k iterations). The cache stores derived keys per session.
//! First call pays derivation cost (~500-900ms), subsequent calls are fast.
//!
//! ## Storage Layout
//!
//! ```text
//! {EKKA_HOME}/vault/
//! ├── secrets/
//! │   └── t_{tenant_id}/
//! │       ├── index.json.enc        # Encrypted SecretMeta index
//! │       └── values/
//! │           └── {secret_id}.enc   # Encrypted secret values
//! ├── bundles/
//! │   └── t_{tenant_id}/
//! │       └── index.json.enc        # Encrypted BundleMeta index
//! ├── files/                        # USER FILES (chrooted)
//! │   └── t_{tenant_id}/
//! │       └── w_{workspace_id}/
//! │           └── {user_paths}      # Encrypted file contents
//! └── audit/
//!     └── t_{tenant_id}/
//!         └── {year}-{month}.json.enc  # Monthly audit logs
//! ```
//!
//! ## Scoping Rules
//!
//! - `tenant_id` = `ctx.auth.tenant_id` (REQUIRED - error if not authenticated)
//! - `workspace_id` = `ctx.auth.workspace_id` OR payload.workspaceId OR `"default"`
//! - Secrets/Bundles: tenant-scoped only (shared across workspaces)
//! - Files: tenant + workspace scoped

mod audit_impl;
mod bundles_impl;
pub mod cache;
mod files_impl;
pub mod manager;
mod path_safety;
mod secrets_impl;
mod status_impl;
pub mod types;

use std::collections::HashMap;

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};

// Re-export cache types
pub use cache::{get_or_init_vault_manager, VaultCacheKey, VaultManagerCache};
pub use manager::VaultManager;

// Re-export public types
pub use types::{
    // Audit
    AuditAction,
    AuditEvent,
    AuditListOptions,
    AuditListResult,
    // Bundle
    BundleCreateInput,
    BundleListOptions,
    BundleMeta,
    // File
    FileDeleteOptions,
    FileEntry,
    FileKind,
    FileListOptions,
    FileOptions,
    // Secret
    SecretCreateInput,
    SecretInjection,
    SecretListOptions,
    SecretMeta,
    SecretRef,
    SecretType,
    SecretUpdateInput,
    // Status
    VaultCapabilities,
    VaultStatus,
};

// =============================================================================
// Deferred Operations (NOT_IMPLEMENTED)
// =============================================================================

/// Attach secrets to a connector configuration (DEFERRED - NOT_IMPLEMENTED)
///
/// Tech Debt: TD-VAULT-020
pub fn attach_secrets_to_connector(
    _ctx: &RuntimeContext,
    _connector_id: &str,
    _mappings: Vec<SecretRef>,
) -> EkkaResult<()> {
    Err(EkkaError::new(
        codes::NOT_IMPLEMENTED,
        "attachSecretsToConnector is not yet implemented. See TD-VAULT-020.",
    ))
}

/// Inject secrets into a run (DEFERRED - NOT_IMPLEMENTED)
///
/// Tech Debt: TD-VAULT-021
pub fn inject_secrets_into_run(
    _ctx: &RuntimeContext,
    _run_id: &str,
    _mappings: Vec<SecretRef>,
) -> EkkaResult<HashMap<String, String>> {
    Err(EkkaError::new(
        codes::NOT_IMPLEMENTED,
        "injectSecretsIntoRun is not yet implemented. See TD-VAULT-021.",
    ))
}

// =============================================================================
// Public API modules
// =============================================================================

/// Secrets operations
pub mod secrets {
    use super::*;

    pub fn list(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        opts: Option<SecretListOptions>,
    ) -> EkkaResult<Vec<SecretMeta>> {
        secrets_impl::list(ctx, cache, opts)
    }

    pub fn get(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        id: &str,
    ) -> EkkaResult<SecretMeta> {
        secrets_impl::get(ctx, cache, id)
    }

    pub fn create(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        input: SecretCreateInput,
    ) -> EkkaResult<SecretMeta> {
        secrets_impl::create(ctx, cache, input)
    }

    pub fn update(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        id: &str,
        input: SecretUpdateInput,
    ) -> EkkaResult<SecretMeta> {
        secrets_impl::update(ctx, cache, id, input)
    }

    pub fn delete(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        id: &str,
    ) -> EkkaResult<bool> {
        secrets_impl::delete(ctx, cache, id)
    }

    pub fn upsert(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        input: SecretCreateInput,
    ) -> EkkaResult<SecretMeta> {
        secrets_impl::upsert(ctx, cache, input)
    }
}

/// Bundles operations
pub mod bundles {
    use super::*;

    pub fn list(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        opts: Option<BundleListOptions>,
    ) -> EkkaResult<Vec<BundleMeta>> {
        bundles_impl::list(ctx, cache, opts)
    }

    pub fn get(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        id: &str,
    ) -> EkkaResult<BundleMeta> {
        bundles_impl::get(ctx, cache, id)
    }

    pub fn create(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        input: BundleCreateInput,
    ) -> EkkaResult<BundleMeta> {
        bundles_impl::create(ctx, cache, input)
    }

    pub fn rename(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        id: &str,
        new_name: &str,
    ) -> EkkaResult<BundleMeta> {
        bundles_impl::rename(ctx, cache, id, new_name)
    }

    pub fn delete(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        id: &str,
    ) -> EkkaResult<bool> {
        bundles_impl::delete(ctx, cache, id)
    }

    pub fn list_secrets(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        bundle_id: &str,
        opts: Option<SecretListOptions>,
    ) -> EkkaResult<Vec<SecretMeta>> {
        bundles_impl::list_secrets(ctx, cache, bundle_id, opts)
    }

    pub fn add_secret(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        bundle_id: &str,
        secret_id: &str,
    ) -> EkkaResult<BundleMeta> {
        bundles_impl::add_secret(ctx, cache, bundle_id, secret_id)
    }

    pub fn remove_secret(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        bundle_id: &str,
        secret_id: &str,
    ) -> EkkaResult<BundleMeta> {
        bundles_impl::remove_secret(ctx, cache, bundle_id, secret_id)
    }
}

/// Files operations
pub mod files {
    use super::*;

    pub fn write_text(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        path: &str,
        content: &str,
        opts: Option<FileOptions>,
    ) -> EkkaResult<()> {
        files_impl::write_text(ctx, cache, path, content, opts)
    }

    pub fn write_bytes(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        path: &str,
        content: &[u8],
        opts: Option<FileOptions>,
    ) -> EkkaResult<()> {
        files_impl::write_bytes(ctx, cache, path, content, opts)
    }

    pub fn read_text(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        path: &str,
        opts: Option<FileOptions>,
    ) -> EkkaResult<String> {
        files_impl::read_text(ctx, cache, path, opts)
    }

    pub fn read_bytes(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        path: &str,
        opts: Option<FileOptions>,
    ) -> EkkaResult<Vec<u8>> {
        files_impl::read_bytes(ctx, cache, path, opts)
    }

    pub fn list(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        dir_path: &str,
        opts: Option<FileListOptions>,
    ) -> EkkaResult<Vec<FileEntry>> {
        files_impl::list(ctx, cache, dir_path, opts)
    }

    pub fn exists(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        path: &str,
        opts: Option<FileOptions>,
    ) -> EkkaResult<bool> {
        files_impl::exists(ctx, cache, path, opts)
    }

    pub fn delete(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        path: &str,
        opts: Option<FileDeleteOptions>,
    ) -> EkkaResult<bool> {
        files_impl::delete(ctx, cache, path, opts)
    }

    pub fn mkdir(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        path: &str,
        opts: Option<FileOptions>,
    ) -> EkkaResult<()> {
        files_impl::mkdir(ctx, cache, path, opts)
    }

    pub fn move_file(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        from: &str,
        to: &str,
        opts: Option<FileOptions>,
    ) -> EkkaResult<()> {
        files_impl::move_file(ctx, cache, from, to, opts)
    }
}

/// Audit operations
pub mod audit {
    use super::*;

    pub fn list(
        ctx: &RuntimeContext,
        cache: &dyn VaultManagerCache,
        opts: Option<AuditListOptions>,
    ) -> EkkaResult<AuditListResult> {
        audit_impl::list(ctx, cache, opts)
    }
}

/// Status operations
pub fn status(ctx: &RuntimeContext) -> EkkaResult<VaultStatus> {
    status_impl::status(ctx)
}

/// Capabilities operations
pub fn capabilities(ctx: &RuntimeContext) -> EkkaResult<VaultCapabilities> {
    status_impl::capabilities(ctx)
}
