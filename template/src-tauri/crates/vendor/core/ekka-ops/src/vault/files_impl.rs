//! Files Operations
//!
//! Tenant + workspace scoped encrypted file storage.
//! All user paths are chrooted under vault/files/t_{tenant}/w_{workspace}/.

use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};
use std::fs;
use std::path::Path;

use super::cache::{get_or_init_vault_manager, VaultManagerCache};
use super::manager::new_audit_event;
use super::path_safety::{resolve_user_path, resolve_workspace_root, validate_user_path};
use super::types::{AuditAction, FileDeleteOptions, FileEntry, FileKind, FileListOptions, FileOptions};

/// Write text content to a file
pub fn write_text(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    path: &str,
    content: &str,
    opts: Option<FileOptions>,
) -> EkkaResult<()> {
    let workspace_id = opts.as_ref().and_then(|o| o.workspace_id.as_deref());
    let resolved = resolve_user_path(ctx, workspace_id, path)?;

    // Ensure parent directory exists
    if let Some(parent) = resolved.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            EkkaError::from_source(codes::IO_ERROR, "Failed to create parent directory", e)
        })?;
    }

    // Write the file (encrypted via vault)
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let relative_path = build_files_path(ctx, workspace_id, path)?;
    mgr.vault
        .write_string(&relative_path, content)
        .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to write file", e))?;

    // Audit
    let mut event = new_audit_event(AuditAction::FileWritten, mgr.actor_id());
    event.path = Some(path.to_string());
    mgr.record_audit_event(event)?;

    Ok(())
}

/// Write binary content to a file
pub fn write_bytes(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    path: &str,
    content: &[u8],
    opts: Option<FileOptions>,
) -> EkkaResult<()> {
    let workspace_id = opts.as_ref().and_then(|o| o.workspace_id.as_deref());
    let resolved = resolve_user_path(ctx, workspace_id, path)?;

    // Ensure parent directory exists
    if let Some(parent) = resolved.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            EkkaError::from_source(codes::IO_ERROR, "Failed to create parent directory", e)
        })?;
    }

    // Write the file (encrypted via vault)
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let relative_path = build_files_path(ctx, workspace_id, path)?;
    mgr.vault
        .write(&relative_path, content)
        .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to write file", e))?;

    // Audit
    let mut event = new_audit_event(AuditAction::FileWritten, mgr.actor_id());
    event.path = Some(path.to_string());
    mgr.record_audit_event(event)?;

    Ok(())
}

/// Read text content from a file
pub fn read_text(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    path: &str,
    opts: Option<FileOptions>,
) -> EkkaResult<String> {
    let workspace_id = opts.as_ref().and_then(|o| o.workspace_id.as_deref());

    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let relative_path = build_files_path(ctx, workspace_id, path)?;

    if !mgr.vault.exists(&relative_path) {
        return Err(EkkaError::new(
            codes::FILE_NOT_FOUND,
            format!("File not found: {}", path),
        ));
    }

    let content = mgr
        .vault
        .read_string(&relative_path)
        .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to read file", e))?;

    // Audit
    let mut event = new_audit_event(AuditAction::FileRead, mgr.actor_id());
    event.path = Some(path.to_string());
    mgr.record_audit_event(event)?;

    Ok(content)
}

/// Read binary content from a file
pub fn read_bytes(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    path: &str,
    opts: Option<FileOptions>,
) -> EkkaResult<Vec<u8>> {
    let workspace_id = opts.as_ref().and_then(|o| o.workspace_id.as_deref());

    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let relative_path = build_files_path(ctx, workspace_id, path)?;

    if !mgr.vault.exists(&relative_path) {
        return Err(EkkaError::new(
            codes::FILE_NOT_FOUND,
            format!("File not found: {}", path),
        ));
    }

    let content = mgr
        .vault
        .read(&relative_path)
        .map_err(|e| EkkaError::from_source(codes::VAULT_ERROR, "Failed to read file", e))?;

    // Audit
    let mut event = new_audit_event(AuditAction::FileRead, mgr.actor_id());
    event.path = Some(path.to_string());
    mgr.record_audit_event(event)?;

    Ok(content)
}

/// List files and directories
pub fn list(
    ctx: &RuntimeContext,
    _cache: &dyn VaultManagerCache,
    dir_path: &str,
    opts: Option<FileListOptions>,
) -> EkkaResult<Vec<FileEntry>> {
    let opts = opts.unwrap_or_default();
    let workspace_id = opts.workspace_id.as_deref();

    // Validate the path (empty string or "/" means root)
    let validated_dir = if dir_path.is_empty() || dir_path == "/" {
        String::new()
    } else {
        validate_user_path(dir_path)?
    };

    let workspace_root = resolve_workspace_root(ctx, workspace_id)?;
    let search_dir = if validated_dir.is_empty() {
        workspace_root.clone()
    } else {
        workspace_root.join(&validated_dir)
    };

    // If directory doesn't exist, return empty list
    if !search_dir.exists() {
        return Ok(Vec::new());
    }

    if !search_dir.is_dir() {
        return Err(EkkaError::new(
            codes::INVALID_PATH,
            format!("Not a directory: {}", dir_path),
        ));
    }

    let mut entries = Vec::new();
    collect_entries(
        &search_dir,
        &workspace_root,
        &validated_dir,
        opts.recursive,
        &mut entries,
    )?;

    Ok(entries)
}

/// Check if a file or directory exists
pub fn exists(
    ctx: &RuntimeContext,
    _cache: &dyn VaultManagerCache,
    path: &str,
    opts: Option<FileOptions>,
) -> EkkaResult<bool> {
    let workspace_id = opts.as_ref().and_then(|o| o.workspace_id.as_deref());

    // Handle "/" as workspace root
    if path.is_empty() || path == "/" {
        let workspace_root = resolve_workspace_root(ctx, workspace_id)?;
        return Ok(workspace_root.exists());
    }

    let resolved = resolve_user_path(ctx, workspace_id, path)?;
    Ok(resolved.exists())
}

/// Delete a file or directory
pub fn delete(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    path: &str,
    opts: Option<FileDeleteOptions>,
) -> EkkaResult<bool> {
    let opts = opts.unwrap_or_default();
    let workspace_id = opts.workspace_id.as_deref();
    let resolved = resolve_user_path(ctx, workspace_id, path)?;

    if !resolved.exists() {
        return Err(EkkaError::new(
            codes::FILE_NOT_FOUND,
            format!("File not found: {}", path),
        ));
    }

    let mgr = get_or_init_vault_manager(ctx, cache)?;

    if resolved.is_dir() {
        if opts.recursive {
            fs::remove_dir_all(&resolved).map_err(|e| {
                EkkaError::from_source(codes::IO_ERROR, "Failed to delete directory", e)
            })?;
        } else {
            // Check if directory is empty
            let entries: Vec<_> = fs::read_dir(&resolved)
                .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to read directory", e))?
                .collect();

            if !entries.is_empty() {
                return Err(EkkaError::new(
                    codes::DIRECTORY_NOT_EMPTY,
                    "Directory is not empty. Use recursive: true to delete.",
                ));
            }

            fs::remove_dir(&resolved)
                .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to delete directory", e))?;
        }
    } else {
        fs::remove_file(&resolved)
            .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to delete file", e))?;
    }

    // Audit
    let mut event = new_audit_event(AuditAction::FileDeleted, mgr.actor_id());
    event.path = Some(path.to_string());
    mgr.record_audit_event(event)?;

    Ok(true)
}

/// Create a directory
pub fn mkdir(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    path: &str,
    opts: Option<FileOptions>,
) -> EkkaResult<()> {
    let workspace_id = opts.as_ref().and_then(|o| o.workspace_id.as_deref());
    let resolved = resolve_user_path(ctx, workspace_id, path)?;

    fs::create_dir_all(&resolved)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to create directory", e))?;

    // Audit
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut event = new_audit_event(AuditAction::FileMkdir, mgr.actor_id());
    event.path = Some(path.to_string());
    mgr.record_audit_event(event)?;

    Ok(())
}

/// Move a file or directory
pub fn move_file(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    from: &str,
    to: &str,
    opts: Option<FileOptions>,
) -> EkkaResult<()> {
    let workspace_id = opts.as_ref().and_then(|o| o.workspace_id.as_deref());
    let from_resolved = resolve_user_path(ctx, workspace_id, from)?;
    let to_resolved = resolve_user_path(ctx, workspace_id, to)?;

    if !from_resolved.exists() {
        return Err(EkkaError::new(
            codes::FILE_NOT_FOUND,
            format!("Source not found: {}", from),
        ));
    }

    if to_resolved.exists() {
        return Err(EkkaError::new(
            codes::FILE_ALREADY_EXISTS,
            format!("Destination already exists: {}", to),
        ));
    }

    // Ensure parent directory exists
    if let Some(parent) = to_resolved.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            EkkaError::from_source(codes::IO_ERROR, "Failed to create parent directory", e)
        })?;
    }

    fs::rename(&from_resolved, &to_resolved)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to move file", e))?;

    // Audit
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let mut event = new_audit_event(AuditAction::FileMoved, mgr.actor_id());
    event.path = Some(format!("{} -> {}", from, to));
    mgr.record_audit_event(event)?;

    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Build the vault-relative path for files
fn build_files_path(
    ctx: &RuntimeContext,
    workspace_id: Option<&str>,
    user_path: &str,
) -> EkkaResult<String> {
    let validated = validate_user_path(user_path)?;

    let auth = ctx.auth.as_ref().ok_or_else(|| {
        EkkaError::new(
            codes::NOT_AUTHENTICATED,
            "Must be authenticated to access vault files",
        )
    })?;

    let tenant_id = &auth.tenant_id;
    let workspace = workspace_id
        .map(String::from)
        .unwrap_or_else(|| "default".to_string());

    Ok(format!(
        "files/t_{}/w_{}/{}",
        tenant_id, workspace, validated
    ))
}

/// Recursively collect file entries
fn collect_entries(
    dir: &Path,
    workspace_root: &Path,
    prefix: &str,
    recursive: bool,
    entries: &mut Vec<FileEntry>,
) -> EkkaResult<()> {
    let read_dir = fs::read_dir(dir)
        .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to read directory", e))?;

    for entry_result in read_dir {
        let entry = entry_result
            .map_err(|e| EkkaError::from_source(codes::IO_ERROR, "Failed to read directory entry", e))?;

        let file_name = entry.file_name().to_string_lossy().to_string();
        let file_path = entry.path();
        let metadata = entry.metadata().map_err(|e| {
            EkkaError::from_source(codes::IO_ERROR, "Failed to get file metadata", e)
        })?;

        // Build relative path
        let relative_path = if prefix.is_empty() {
            file_name.clone()
        } else {
            format!("{}/{}", prefix, file_name)
        };

        let kind = if metadata.is_dir() {
            FileKind::Dir
        } else {
            FileKind::File
        };

        let size_bytes = if metadata.is_file() {
            Some(metadata.len())
        } else {
            None
        };

        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| {
                        chrono::DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                            .map(|dt| dt.to_rfc3339())
                    })
            })
            .flatten();

        entries.push(FileEntry {
            path: relative_path.clone(),
            name: file_name,
            kind: kind.clone(),
            size_bytes,
            modified_at,
        });

        // Recurse into subdirectories
        if recursive && kind == FileKind::Dir {
            collect_entries(&file_path, workspace_root, &relative_path, true, entries)?;
        }
    }

    Ok(())
}
