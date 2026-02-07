//! Bundles Operations
//!
//! Tenant-scoped bundle management. Bundles are groups of related secrets.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};

use super::cache::{get_or_init_vault_manager, VaultManagerCache};
use super::manager::{generate_id, new_audit_event, now_iso};
use super::types::{
    AuditAction, BundleCreateInput, BundleListOptions, BundleMeta, BundlesIndex, SecretListOptions,
    SecretMeta, SecretsIndex,
};

/// List all bundles
pub fn list(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    _opts: Option<BundleListOptions>,
) -> EkkaResult<Vec<BundleMeta>> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
    Ok(index.bundles)
}

/// Get a bundle by ID
pub fn get(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    id: &str,
) -> EkkaResult<BundleMeta> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;

    index
        .bundles
        .into_iter()
        .find(|b| b.id == id)
        .ok_or_else(|| EkkaError::new(codes::BUNDLE_NOT_FOUND, format!("Bundle not found: {}", id)))
}

/// Create a new bundle
pub fn create(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    input: BundleCreateInput,
) -> EkkaResult<BundleMeta> {
    // Validate name
    if input.name.trim().is_empty() {
        return Err(EkkaError::new(
            codes::INVALID_SECRET_NAME,
            "Bundle name cannot be empty",
        ));
    }

    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;

    // Check for duplicate name
    if index.bundles.iter().any(|b| b.name == input.name) {
        return Err(EkkaError::new(
            codes::BUNDLE_ALREADY_EXISTS,
            format!("Bundle already exists: {}", input.name),
        ));
    }

    let now = now_iso();
    let bundle = BundleMeta {
        id: generate_id("bnd"),
        name: input.name,
        description: input.description,
        secret_ids: Vec::new(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    index.bundles.push(bundle.clone());
    mgr.write_json("bundles/index.json", &index)?;

    // Audit
    let mut event = new_audit_event(AuditAction::BundleCreated, mgr.actor_id());
    event.bundle_id = Some(bundle.id.clone());
    mgr.record_audit_event(event)?;

    Ok(bundle)
}

/// Rename a bundle
pub fn rename(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    id: &str,
    new_name: &str,
) -> EkkaResult<BundleMeta> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;

    // Check for duplicate name
    if index.bundles.iter().any(|b| b.name == new_name && b.id != id) {
        return Err(EkkaError::new(
            codes::BUNDLE_ALREADY_EXISTS,
            format!("Bundle already exists: {}", new_name),
        ));
    }

    let bundle = index
        .bundles
        .iter_mut()
        .find(|b| b.id == id)
        .ok_or_else(|| EkkaError::new(codes::BUNDLE_NOT_FOUND, format!("Bundle not found: {}", id)))?;

    let now = now_iso();
    bundle.name = new_name.to_string();
    bundle.updated_at = now.clone();

    let bundle = bundle.clone();
    mgr.write_json("bundles/index.json", &index)?;

    // Audit
    let mut event = new_audit_event(AuditAction::BundleUpdated, mgr.actor_id());
    event.bundle_id = Some(bundle.id.clone());
    mgr.record_audit_event(event)?;

    Ok(bundle)
}

/// Delete a bundle
pub fn delete(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    id: &str,
) -> EkkaResult<bool> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;

    let original_len = index.bundles.len();
    index.bundles.retain(|b| b.id != id);

    if index.bundles.len() == original_len {
        return Err(EkkaError::new(
            codes::BUNDLE_NOT_FOUND,
            format!("Bundle not found: {}", id),
        ));
    }

    // Clear bundle_id from secrets
    let mut secrets_index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;
    for secret in &mut secrets_index.secrets {
        if secret.bundle_id.as_deref() == Some(id) {
            secret.bundle_id = None;
            secret.updated_at = now_iso();
        }
    }
    mgr.write_json("secrets/index.json", &secrets_index)?;

    mgr.write_json("bundles/index.json", &index)?;

    // Audit
    let mut event = new_audit_event(AuditAction::BundleDeleted, mgr.actor_id());
    event.bundle_id = Some(id.to_string());
    mgr.record_audit_event(event)?;

    Ok(true)
}

/// List secrets in a bundle
pub fn list_secrets(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    bundle_id: &str,
    _opts: Option<SecretListOptions>,
) -> EkkaResult<Vec<SecretMeta>> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;

    // Verify bundle exists
    let bundles_index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
    if !bundles_index.bundles.iter().any(|b| b.id == bundle_id) {
        return Err(EkkaError::new(
            codes::BUNDLE_NOT_FOUND,
            format!("Bundle not found: {}", bundle_id),
        ));
    }

    // Get all secrets with this bundle_id
    let secrets_index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;
    let secrets: Vec<SecretMeta> = secrets_index
        .secrets
        .into_iter()
        .filter(|s| s.bundle_id.as_deref() == Some(bundle_id))
        .collect();

    Ok(secrets)
}

/// Add a secret to a bundle
pub fn add_secret(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    bundle_id: &str,
    secret_id: &str,
) -> EkkaResult<BundleMeta> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;

    // Validate secret exists
    let mut secrets_index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;
    let secret = secrets_index
        .secrets
        .iter_mut()
        .find(|s| s.id == secret_id)
        .ok_or_else(|| {
            EkkaError::new(
                codes::SECRET_NOT_FOUND,
                format!("Secret not found: {}", secret_id),
            )
        })?;

    // Validate bundle exists
    let mut index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
    let bundle = index
        .bundles
        .iter_mut()
        .find(|b| b.id == bundle_id)
        .ok_or_else(|| {
            EkkaError::new(
                codes::BUNDLE_NOT_FOUND,
                format!("Bundle not found: {}", bundle_id),
            )
        })?;

    let now = now_iso();

    // Add to bundle's secret_ids if not already there
    if !bundle.secret_ids.contains(&secret_id.to_string()) {
        bundle.secret_ids.push(secret_id.to_string());
        bundle.updated_at = now.clone();
    }

    // Update secret's bundle_id
    secret.bundle_id = Some(bundle_id.to_string());
    secret.updated_at = now.clone();

    let bundle = bundle.clone();

    mgr.write_json("bundles/index.json", &index)?;
    mgr.write_json("secrets/index.json", &secrets_index)?;

    // Audit
    let mut event = new_audit_event(AuditAction::BundleSecretAdded, mgr.actor_id());
    event.bundle_id = Some(bundle.id.clone());
    event.secret_id = Some(secret_id.to_string());
    mgr.record_audit_event(event)?;

    Ok(bundle)
}

/// Remove a secret from a bundle
pub fn remove_secret(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    bundle_id: &str,
    secret_id: &str,
) -> EkkaResult<BundleMeta> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;

    let mut index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
    let bundle = index
        .bundles
        .iter_mut()
        .find(|b| b.id == bundle_id)
        .ok_or_else(|| {
            EkkaError::new(
                codes::BUNDLE_NOT_FOUND,
                format!("Bundle not found: {}", bundle_id),
            )
        })?;

    bundle.secret_ids.retain(|sid| sid != secret_id);
    bundle.updated_at = now_iso();

    let bundle = bundle.clone();
    mgr.write_json("bundles/index.json", &index)?;

    // Clear bundle_id from secret
    let mut secrets_index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;
    if let Some(secret) = secrets_index.secrets.iter_mut().find(|s| s.id == secret_id) {
        if secret.bundle_id.as_deref() == Some(bundle_id) {
            secret.bundle_id = None;
            secret.updated_at = now_iso();
        }
    }
    mgr.write_json("secrets/index.json", &secrets_index)?;

    // Audit
    let mut event = new_audit_event(AuditAction::BundleSecretRemoved, mgr.actor_id());
    event.bundle_id = Some(bundle.id.clone());
    event.secret_id = Some(secret_id.to_string());
    mgr.record_audit_event(event)?;

    Ok(bundle)
}
