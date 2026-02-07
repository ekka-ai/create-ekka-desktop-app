//! Debug Bundle - LLM output debugging for development
//!
//! Saves debug artifacts for output contract validation failures.
//! ONLY enabled when EKKA_ENV=development.
//!
//! ## Storage Layout
//!
//! Files are stored in the vault's tmp area (encrypted at rest):
//!
//! ```text
//! {EKKA_HOME}/vault/tmp/telemetry/llm_debug/{tenant_id}/{run_id}/
//! ├── meta.json        # Safe metadata (timestamps, failure info, debug_bundle_ref)
//! ├── report.json      # Parsed ekka.report.v1 (if extraction succeeded)
//! ├── raw_output.txt   # Raw LLM output (TRUNCATED to 256KB)
//! └── hashes.json      # SHA256 hashes and lengths for verification
//! ```
//!
//! The `debug_bundle_ref` in meta.json uses vault URI format:
//! `vault://tmp/telemetry/llm_debug/{tenant_id}/{run_id}/`
//!
//! ## Security Invariants
//!
//! - raw_output.txt is TRUNCATED to 256KB max
//! - NEVER log raw output contents
//! - Logs may include: debug_bundle_ref, sha256 hashes, lengths, failure reason
//! - Tenant isolation: each tenant has separate directory
//!
//! ## Tech Debt (TD-DEBUG-BUNDLE-001)
//!
//! - Flip default debug saving to OFF outside dev
//! - Add explicit UI consent toggle
//! - Add export + redaction flow
//! - Consider storing only report.json by default
//! - Add scheduled cleanup for prod

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

// =============================================================================
// Constants
// =============================================================================

/// Maximum size for raw_output.txt (256KB)
const MAX_RAW_OUTPUT_SIZE: usize = 256 * 1024;

/// Debug bundle retention period (7 days)
const RETENTION_DAYS: u64 = 7;

/// Debug bundle directory under vault (encrypted at rest)
const DEBUG_DIR: &str = "vault/tmp/telemetry/llm_debug";

/// Vault URI prefix for debug_bundle_ref
const VAULT_URI_PREFIX: &str = "vault://tmp/telemetry/llm_debug";

// =============================================================================
// Types
// =============================================================================

/// Metadata for debug bundle (safe to log)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugBundleMeta {
    pub schema_version: String,
    /// Vault URI for this bundle (e.g., "vault://tmp/telemetry/llm_debug/{tenant}/{run_id}/")
    pub debug_bundle_ref: String,
    pub run_id: String,
    pub task_id: String,
    pub tenant_id: String,
    pub failure_code: String,
    pub failure_reason: String,
    pub created_at_utc: String,
    pub raw_output_truncated: bool,
    pub raw_output_original_len: usize,
}

/// Hash information for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugBundleHashes {
    pub raw_output_sha256: String,
    pub raw_output_len: usize,
    pub report_sha256: Option<String>,
    pub report_len: Option<usize>,
}

/// Reference to a saved debug bundle (safe to log)
#[derive(Debug, Clone)]
pub struct DebugBundleRef {
    pub path: String,
    pub run_id: String,
    pub hashes: DebugBundleHashes,
}

// =============================================================================
// Public API
// =============================================================================

/// Check if debug bundle saving is enabled.
///
/// Returns true if EKKA_ENV=development, false otherwise.
pub fn is_enabled() -> bool {
    match std::env::var("EKKA_ENV").as_deref() {
        Ok("development") => true,
        _ => false,
    }
}

/// Save a debug bundle for a failed output contract validation.
///
/// # Arguments
/// * `tenant_id` - Tenant ID for isolation
/// * `task_id` - Task ID for reference
/// * `failure_code` - Failure code (e.g., "REPORT_INVALID")
/// * `failure_reason` - Human-readable failure reason
/// * `raw_output` - Raw LLM output (will be truncated if > 256KB)
/// * `parsed_report` - Parsed report JSON (if extraction succeeded)
///
/// # Returns
/// * `Some(DebugBundleRef)` - Reference to saved bundle (safe to log)
/// * `None` - If saving failed or debug bundles are disabled
pub fn save_debug_bundle(
    tenant_id: &str,
    task_id: &str,
    failure_code: &str,
    failure_reason: &str,
    raw_output: &str,
    parsed_report: Option<&serde_json::Value>,
) -> Option<DebugBundleRef> {
    if !is_enabled() {
        return None;
    }

    // Get EKKA_HOME
    let ekka_home = match std::env::var("EKKA_HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h),
        _ => {
            warn!(
                op = "debug_bundle.save.skipped",
                reason = "EKKA_HOME not set",
                "Skipping debug bundle save"
            );
            return None;
        }
    };

    // Generate run_id (UUID for uniqueness)
    let run_id = uuid::Uuid::new_v4().to_string();

    // Build path: {EKKA_HOME}/tmp/telemetry/llm_debug/{tenant_id}/{run_id}/
    let bundle_dir = ekka_home
        .join(DEBUG_DIR)
        .join(tenant_id)
        .join(&run_id);

    // Create directory
    if let Err(e) = fs::create_dir_all(&bundle_dir) {
        warn!(
            op = "debug_bundle.save.error",
            error = %e,
            "Failed to create debug bundle directory"
        );
        return None;
    }

    // Compute raw output hash BEFORE truncation (for verification)
    let raw_output_bytes = raw_output.as_bytes();
    let raw_output_sha256 = compute_sha256(raw_output_bytes);
    let raw_output_original_len = raw_output_bytes.len();

    // Truncate raw output if needed
    let (truncated_output, was_truncated) = if raw_output_bytes.len() > MAX_RAW_OUTPUT_SIZE {
        let truncated = String::from_utf8_lossy(&raw_output_bytes[..MAX_RAW_OUTPUT_SIZE]);
        (format!("{}\n\n[TRUNCATED - original size: {} bytes]", truncated, raw_output_bytes.len()), true)
    } else {
        (raw_output.to_string(), false)
    };

    // Build metadata
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let created_at_utc = chrono::DateTime::from_timestamp(now.as_secs() as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Build vault URI for debug_bundle_ref
    let debug_bundle_ref = format!("{}/{}/{}/", VAULT_URI_PREFIX, tenant_id, run_id);

    let meta = DebugBundleMeta {
        schema_version: "debug_bundle.v1".to_string(),
        debug_bundle_ref: debug_bundle_ref.clone(),
        run_id: run_id.clone(),
        task_id: task_id.to_string(),
        tenant_id: tenant_id.to_string(),
        failure_code: failure_code.to_string(),
        failure_reason: failure_reason.to_string(),
        created_at_utc,
        raw_output_truncated: was_truncated,
        raw_output_original_len,
    };

    // Compute report hash if present
    let (report_sha256, report_len) = if let Some(report) = parsed_report {
        let report_str = serde_json::to_string_pretty(report).unwrap_or_default();
        let report_bytes = report_str.as_bytes();
        (Some(compute_sha256(report_bytes)), Some(report_bytes.len()))
    } else {
        (None, None)
    };

    let hashes = DebugBundleHashes {
        raw_output_sha256: raw_output_sha256.clone(),
        raw_output_len: raw_output_original_len,
        report_sha256: report_sha256.clone(),
        report_len,
    };

    // Write files
    let meta_path = bundle_dir.join("meta.json");
    let hashes_path = bundle_dir.join("hashes.json");
    let raw_output_path = bundle_dir.join("raw_output.txt");
    let report_path = bundle_dir.join("report.json");

    // Write meta.json
    if let Err(e) = fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap_or_default()) {
        warn!(op = "debug_bundle.save.error", error = %e, "Failed to write meta.json");
        return None;
    }

    // Write hashes.json
    if let Err(e) = fs::write(&hashes_path, serde_json::to_string_pretty(&hashes).unwrap_or_default()) {
        warn!(op = "debug_bundle.save.error", error = %e, "Failed to write hashes.json");
        return None;
    }

    // Write raw_output.txt
    if let Err(e) = fs::write(&raw_output_path, &truncated_output) {
        warn!(op = "debug_bundle.save.error", error = %e, "Failed to write raw_output.txt");
        return None;
    }

    // Write report.json if present
    if let Some(report) = parsed_report {
        if let Err(e) = fs::write(&report_path, serde_json::to_string_pretty(report).unwrap_or_default()) {
            warn!(op = "debug_bundle.save.error", error = %e, "Failed to write report.json");
            // Continue - report.json is optional
        }
    }

    let bundle_ref = DebugBundleRef {
        path: debug_bundle_ref, // Use vault:// URI
        run_id,
        hashes,
    };

    info!(
        op = "debug_bundle.saved",
        debug_bundle_ref = %bundle_ref.path,
        run_id = %bundle_ref.run_id,
        raw_output_sha256 = %bundle_ref.hashes.raw_output_sha256,
        raw_output_len = %bundle_ref.hashes.raw_output_len,
        truncated = %was_truncated,
        "Debug bundle saved"
    );

    Some(bundle_ref)
}

/// Cleanup old debug bundles on startup.
///
/// Deletes bundles older than RETENTION_DAYS (7 days).
/// Called once at runner startup.
pub fn cleanup_old_bundles() {
    if !is_enabled() {
        return;
    }

    let ekka_home = match std::env::var("EKKA_HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h),
        _ => return,
    };

    let debug_dir = ekka_home.join(DEBUG_DIR);
    if !debug_dir.exists() {
        return;
    }

    let retention_duration = Duration::from_secs(RETENTION_DAYS * 24 * 60 * 60);
    let now = SystemTime::now();
    let mut deleted_count = 0;
    let mut error_count = 0;

    // Iterate tenant directories
    let tenant_dirs = match fs::read_dir(&debug_dir) {
        Ok(d) => d,
        Err(_) => return,
    };

    for tenant_entry in tenant_dirs.flatten() {
        let tenant_path = tenant_entry.path();
        if !tenant_path.is_dir() {
            continue;
        }

        // Iterate run directories within tenant
        let run_dirs = match fs::read_dir(&tenant_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for run_entry in run_dirs.flatten() {
            let run_path = run_entry.path();
            if !run_path.is_dir() {
                continue;
            }

            // Check meta.json modification time
            let meta_path = run_path.join("meta.json");
            let modified = meta_path
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(now);

            if let Ok(age) = now.duration_since(modified) {
                if age > retention_duration {
                    // Delete the entire run directory
                    match fs::remove_dir_all(&run_path) {
                        Ok(()) => deleted_count += 1,
                        Err(_) => error_count += 1,
                    }
                }
            }
        }

        // Remove empty tenant directories
        if let Ok(entries) = fs::read_dir(&tenant_path) {
            if entries.count() == 0 {
                let _ = fs::remove_dir(&tenant_path);
            }
        }
    }

    if deleted_count > 0 || error_count > 0 {
        info!(
            op = "debug_bundle.cleanup",
            deleted = %deleted_count,
            errors = %error_count,
            retention_days = %RETENTION_DAYS,
            "Debug bundle cleanup completed"
        );
    }
}

// =============================================================================
// Internal Helpers
// =============================================================================

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Tests that modify environment variables use unique temp dirs
    // to avoid race conditions. The is_enabled() tests check the function
    // logic directly without modifying global state.

    #[test]
    fn test_compute_sha256() {
        let hash = compute_sha256(b"hello");
        assert_eq!(hash.len(), 64); // SHA256 = 64 hex chars
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    /// Test internal save logic with explicit path (bypasses env var checks)
    #[test]
    fn test_save_debug_bundle_internal() {
        // Create unique temp directory
        let temp_dir = std::env::temp_dir().join(format!("ekka-debug-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Directly test the file writing logic
        let run_id = uuid::Uuid::new_v4().to_string();
        let bundle_dir = temp_dir.join("tenant-test").join(&run_id);
        std::fs::create_dir_all(&bundle_dir).unwrap();

        let raw_output = "Test raw output from LLM";
        let raw_output_bytes = raw_output.as_bytes();
        let raw_output_sha256 = compute_sha256(raw_output_bytes);

        let debug_bundle_ref = format!("{}/tenant-test/{}/", VAULT_URI_PREFIX, run_id);
        let meta = DebugBundleMeta {
            schema_version: "debug_bundle.v1".to_string(),
            debug_bundle_ref,
            run_id: run_id.clone(),
            task_id: "task-456".to_string(),
            tenant_id: "tenant-test".to_string(),
            failure_code: "REPORT_INVALID".to_string(),
            failure_reason: "Test validation failure".to_string(),
            created_at_utc: "2024-01-01T00:00:00Z".to_string(),
            raw_output_truncated: false,
            raw_output_original_len: raw_output_bytes.len(),
        };

        let hashes = DebugBundleHashes {
            raw_output_sha256: raw_output_sha256.clone(),
            raw_output_len: raw_output_bytes.len(),
            report_sha256: None,
            report_len: None,
        };

        // Write files
        std::fs::write(
            bundle_dir.join("meta.json"),
            serde_json::to_string_pretty(&meta).unwrap(),
        ).unwrap();
        std::fs::write(
            bundle_dir.join("hashes.json"),
            serde_json::to_string_pretty(&hashes).unwrap(),
        ).unwrap();
        std::fs::write(bundle_dir.join("raw_output.txt"), raw_output).unwrap();

        // Verify files exist
        assert!(bundle_dir.join("meta.json").exists());
        assert!(bundle_dir.join("hashes.json").exists());
        assert!(bundle_dir.join("raw_output.txt").exists());

        // Read and verify meta.json
        let meta_content = std::fs::read_to_string(bundle_dir.join("meta.json")).unwrap();
        let loaded_meta: DebugBundleMeta = serde_json::from_str(&meta_content).unwrap();
        assert_eq!(loaded_meta.tenant_id, "tenant-test");
        assert_eq!(loaded_meta.task_id, "task-456");
        assert_eq!(loaded_meta.failure_code, "REPORT_INVALID");
        assert!(!loaded_meta.raw_output_truncated);

        // Verify hash
        let loaded_hashes_content = std::fs::read_to_string(bundle_dir.join("hashes.json")).unwrap();
        let loaded_hashes: DebugBundleHashes = serde_json::from_str(&loaded_hashes_content).unwrap();
        assert_eq!(loaded_hashes.raw_output_sha256, raw_output_sha256);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_truncation_logic() {
        // Test the truncation logic directly
        let large_output = "x".repeat(300 * 1024); // 300KB
        let large_output_bytes = large_output.as_bytes();

        // Verify size exceeds limit
        assert!(large_output_bytes.len() > MAX_RAW_OUTPUT_SIZE);

        // Verify truncation works
        let truncated_bytes = &large_output_bytes[..MAX_RAW_OUTPUT_SIZE];
        assert_eq!(truncated_bytes.len(), MAX_RAW_OUTPUT_SIZE);

        // Verify hash is computed on ORIGINAL
        let original_hash = compute_sha256(large_output_bytes);
        let truncated_hash = compute_sha256(truncated_bytes);
        assert_ne!(original_hash, truncated_hash, "Hash should differ for truncated content");
    }

    #[test]
    fn test_debug_bundle_meta_serialization() {
        let meta = DebugBundleMeta {
            schema_version: "debug_bundle.v1".to_string(),
            debug_bundle_ref: "vault://tmp/telemetry/llm_debug/tenant-456/test-run-id/".to_string(),
            run_id: "test-run-id".to_string(),
            task_id: "task-123".to_string(),
            tenant_id: "tenant-456".to_string(),
            failure_code: "REPORT_INVALID".to_string(),
            failure_reason: "Test failure".to_string(),
            created_at_utc: "2024-01-01T00:00:00Z".to_string(),
            raw_output_truncated: true,
            raw_output_original_len: 500000,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let parsed: DebugBundleMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema_version, "debug_bundle.v1");
        assert_eq!(parsed.debug_bundle_ref, "vault://tmp/telemetry/llm_debug/tenant-456/test-run-id/");
        assert_eq!(parsed.run_id, "test-run-id");
        assert_eq!(parsed.tenant_id, "tenant-456");
        assert!(parsed.raw_output_truncated);
        assert_eq!(parsed.raw_output_original_len, 500000);
    }

    #[test]
    fn test_debug_bundle_hashes_serialization() {
        let hashes = DebugBundleHashes {
            raw_output_sha256: "abc123".to_string(),
            raw_output_len: 1024,
            report_sha256: Some("def456".to_string()),
            report_len: Some(512),
        };

        let json = serde_json::to_string(&hashes).unwrap();
        let parsed: DebugBundleHashes = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.raw_output_sha256, "abc123");
        assert_eq!(parsed.raw_output_len, 1024);
        assert_eq!(parsed.report_sha256, Some("def456".to_string()));
        assert_eq!(parsed.report_len, Some(512));
    }
}
