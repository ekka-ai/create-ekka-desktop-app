//! Secrets Operations
//!
//! Tenant-scoped secret management. Secret values are NEVER returned to the caller.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};

use super::cache::{get_or_init_vault_manager, VaultManagerCache};
use super::manager::{generate_id, new_audit_event, now_iso};
use super::types::{
    AuditAction, BundlesIndex, SecretCreateInput, SecretListOptions, SecretMeta, SecretUpdateInput,
    SecretsIndex,
};

/// List all secrets (metadata only, NO values)
pub fn list(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    opts: Option<SecretListOptions>,
) -> EkkaResult<Vec<SecretMeta>> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;

    let opts = opts.unwrap_or_default();
    let secrets: Vec<SecretMeta> = index
        .secrets
        .into_iter()
        .filter(|s| {
            let type_match = opts
                .secret_type
                .as_ref()
                .map(|st| &s.secret_type == st)
                .unwrap_or(true);

            let tag_match = opts.tag.as_ref().map(|t| s.tags.contains(t)).unwrap_or(true);

            let bundle_match = opts
                .bundle_id
                .as_ref()
                .map(|bid| s.bundle_id.as_ref() == Some(bid))
                .unwrap_or(true);

            type_match && tag_match && bundle_match
        })
        .collect();

    Ok(secrets)
}

/// Get a secret by ID (metadata only, NO value)
pub fn get(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    id: &str,
) -> EkkaResult<SecretMeta> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;

    index
        .secrets
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| EkkaError::new(codes::SECRET_NOT_FOUND, format!("Secret not found: {}", id)))
}

/// Create a new secret
pub fn create(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    input: SecretCreateInput,
) -> EkkaResult<SecretMeta> {
    // Validate name
    if input.name.trim().is_empty() {
        return Err(EkkaError::new(
            codes::INVALID_SECRET_NAME,
            "Secret name cannot be empty",
        ));
    }

    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;

    // Check for duplicate name
    if index.secrets.iter().any(|s| s.name == input.name) {
        return Err(EkkaError::new(
            codes::SECRET_ALREADY_EXISTS,
            format!("Secret already exists: {}", input.name),
        ));
    }

    // Validate bundle exists if specified
    if let Some(ref bid) = input.bundle_id {
        let bundles_index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
        if !bundles_index.bundles.iter().any(|b| &b.id == bid) {
            return Err(EkkaError::new(
                codes::BUNDLE_NOT_FOUND,
                format!("Bundle not found: {}", bid),
            ));
        }
    }

    let now = now_iso();
    let secret = SecretMeta {
        id: generate_id("sec"),
        name: input.name,
        secret_type: input.secret_type,
        tags: input.tags,
        bundle_id: input.bundle_id.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    // Store the value (encrypted)
    mgr.write_secret_value(&secret.id, &input.value)?;

    // Update index
    index.secrets.push(secret.clone());
    mgr.write_json("secrets/index.json", &index)?;

    // If bundle specified, add to bundle's secret_ids
    if let Some(ref bid) = input.bundle_id {
        let mut bundles_index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
        if let Some(bundle) = bundles_index.bundles.iter_mut().find(|b| &b.id == bid) {
            if !bundle.secret_ids.contains(&secret.id) {
                bundle.secret_ids.push(secret.id.clone());
                bundle.updated_at = now.clone();
            }
        }
        mgr.write_json("bundles/index.json", &bundles_index)?;
    }

    // Audit
    let mut event = new_audit_event(AuditAction::SecretCreated, mgr.actor_id());
    event.secret_id = Some(secret.id.clone());
    event.secret_name = Some(secret.name.clone());
    event.bundle_id = secret.bundle_id.clone();
    mgr.record_audit_event(event)?;

    Ok(secret)
}

/// Update a secret
pub fn update(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    id: &str,
    input: SecretUpdateInput,
) -> EkkaResult<SecretMeta> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;

    // Find the index of the secret
    let secret_idx = index
        .secrets
        .iter()
        .position(|s| s.id == id)
        .ok_or_else(|| EkkaError::new(codes::SECRET_NOT_FOUND, format!("Secret not found: {}", id)))?;

    // Check for duplicate name
    if let Some(ref new_name) = input.name {
        if index
            .secrets
            .iter()
            .any(|s| &s.name == new_name && s.id != id)
        {
            return Err(EkkaError::new(
                codes::SECRET_ALREADY_EXISTS,
                format!("Secret already exists: {}", new_name),
            ));
        }
    }

    // Validate bundle if changing
    if let Some(ref bid) = input.bundle_id {
        let bundles_index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
        if !bundles_index.bundles.iter().any(|b| &b.id == bid) {
            return Err(EkkaError::new(
                codes::BUNDLE_NOT_FOUND,
                format!("Bundle not found: {}", bid),
            ));
        }
    }

    let now = now_iso();
    let old_bundle_id = index.secrets[secret_idx].bundle_id.clone();

    // Update fields
    let secret = &mut index.secrets[secret_idx];
    if let Some(name) = input.name {
        secret.name = name;
    }
    if let Some(secret_type) = input.secret_type {
        secret.secret_type = secret_type;
    }
    if let Some(tags) = input.tags {
        secret.tags = tags;
    }
    if let Some(bundle_id) = input.bundle_id.clone() {
        secret.bundle_id = Some(bundle_id);
    }
    secret.updated_at = now.clone();

    // Update value if provided
    if let Some(ref value) = input.value {
        mgr.write_secret_value(id, value)?;
    }

    let secret = secret.clone();
    mgr.write_json("secrets/index.json", &index)?;

    // Update bundle references if changed
    if old_bundle_id != secret.bundle_id {
        let mut bundles_index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;

        // Remove from old bundle
        if let Some(ref old_bid) = old_bundle_id {
            if let Some(old_bundle) = bundles_index.bundles.iter_mut().find(|b| &b.id == old_bid) {
                old_bundle.secret_ids.retain(|sid| sid != id);
                old_bundle.updated_at = now.clone();
            }
        }

        // Add to new bundle
        if let Some(ref new_bid) = secret.bundle_id {
            if let Some(new_bundle) = bundles_index.bundles.iter_mut().find(|b| &b.id == new_bid) {
                if !new_bundle.secret_ids.contains(&secret.id) {
                    new_bundle.secret_ids.push(secret.id.clone());
                    new_bundle.updated_at = now.clone();
                }
            }
        }

        mgr.write_json("bundles/index.json", &bundles_index)?;
    }

    // Audit
    let mut event = new_audit_event(AuditAction::SecretUpdated, mgr.actor_id());
    event.secret_id = Some(secret.id.clone());
    event.secret_name = Some(secret.name.clone());
    event.bundle_id = secret.bundle_id.clone();
    mgr.record_audit_event(event)?;

    Ok(secret)
}

/// Delete a secret
pub fn delete(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    id: &str,
) -> EkkaResult<bool> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;

    let original_len = index.secrets.len();
    let secret = index.secrets.iter().find(|s| s.id == id).cloned();
    index.secrets.retain(|s| s.id != id);

    if index.secrets.len() == original_len {
        return Err(EkkaError::new(
            codes::SECRET_NOT_FOUND,
            format!("Secret not found: {}", id),
        ));
    }

    // Delete the encrypted value
    let _ = mgr.delete_secret_value(id); // Ignore if already deleted

    // Remove from bundles
    let mut bundles_index: BundlesIndex = mgr.read_json_or_default("bundles/index.json")?;
    for bundle in &mut bundles_index.bundles {
        bundle.secret_ids.retain(|sid| sid != id);
    }
    mgr.write_json("bundles/index.json", &bundles_index)?;

    mgr.write_json("secrets/index.json", &index)?;

    // Audit
    let mut event = new_audit_event(AuditAction::SecretDeleted, mgr.actor_id());
    event.secret_id = Some(id.to_string());
    event.secret_name = secret.map(|s| s.name);
    mgr.record_audit_event(event)?;

    Ok(true)
}

/// Upsert a secret (create or update)
pub fn upsert(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    input: SecretCreateInput,
) -> EkkaResult<SecretMeta> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let index: SecretsIndex = mgr.read_json_or_default("secrets/index.json")?;

    // Find existing secret by name
    let existing = index.secrets.iter().find(|s| s.name == input.name);

    if let Some(secret) = existing {
        let update_input = SecretUpdateInput {
            name: None,
            value: Some(input.value),
            secret_type: Some(input.secret_type),
            tags: Some(input.tags),
            bundle_id: input.bundle_id,
        };
        update(ctx, cache, &secret.id, update_input)
    } else {
        create(ctx, cache, input)
    }
}
