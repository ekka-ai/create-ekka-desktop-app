//! Artifact capture for prompt_run executor
//!
//! Captures raw LLM stdout/stderr and optionally rendered prompts as artifacts.
//! Handles compression, truncation, and error-resilient storage.

use chrono::{Duration, Utc};
use ekka_artifact_store::{gzip_compress, ArtifactStore};
use ekka_ops::llm_result::{ArtifactCategory, ArtifactRef, CompressionAlgorithm};
use tracing::{info, warn};

// =============================================================================
// Constants
// =============================================================================

/// Maximum bytes per run (stdout + stderr combined)
const MAX_BYTES_PER_RUN: usize = 1024 * 1024; // 1MB

/// Truncation threshold - if exceeds cap, store first/last 2KB only
const TRUNCATION_HEAD_BYTES: usize = 2 * 1024; // 2KB
const TRUNCATION_TAIL_BYTES: usize = 2 * 1024; // 2KB

/// Content types
const CONTENT_TYPE_TEXT_PLAIN_GZ: &str = "text/plain+gzip";

/// Artifact expiration (30 days by default for debug artifacts)
const ARTIFACT_EXPIRY_DAYS: i64 = 30;

// =============================================================================
// Capture Policy
// =============================================================================

/// Policy for when to capture artifacts
#[derive(Debug, Clone, Default)]
pub enum CapturePolicy {
    /// Always capture stdout/stderr
    #[default]
    Always,
    /// Only capture on failure
    OnFailure,
    /// Never capture
    Never,
}

/// Policy for when to capture rendered prompt
#[derive(Debug, Clone, Default)]
pub enum PromptCapturePolicy {
    /// Only capture rendered prompt on failure
    #[default]
    OnFailure,
    /// Always capture rendered prompt
    Always,
    /// Never capture rendered prompt
    Never,
}

/// Capture configuration
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub capture_policy: CapturePolicy,
    pub prompt_policy: PromptCapturePolicy,
    pub max_bytes_per_run: usize,
    pub expiry_days: i64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            capture_policy: CapturePolicy::Always,
            prompt_policy: PromptCapturePolicy::OnFailure,
            max_bytes_per_run: MAX_BYTES_PER_RUN,
            expiry_days: ARTIFACT_EXPIRY_DAYS,
        }
    }
}

// =============================================================================
// Raw LLM Output
// =============================================================================

/// Raw output from Claude CLI execution
#[derive(Debug, Clone)]
pub struct RawLlmOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

impl RawLlmOutput {
    pub fn new(stdout: Vec<u8>, stderr: Vec<u8>, exit_code: Option<i32>) -> Self {
        Self { stdout, stderr, exit_code }
    }

    pub fn total_bytes(&self) -> usize {
        self.stdout.len() + self.stderr.len()
    }
}

// =============================================================================
// Capture Result
// =============================================================================

/// Result of artifact capture operation
#[derive(Debug, Clone, Default)]
pub struct CaptureResult {
    /// Captured artifact references
    pub artifacts: Vec<ArtifactRef>,
    /// Total bytes stored (after compression)
    pub bytes_stored: u64,
    /// Whether any content was truncated
    pub truncated: bool,
    /// Error message if capture partially failed
    pub error: Option<String>,
}

impl CaptureResult {
    pub fn skipped(reason: &str) -> Self {
        Self {
            artifacts: vec![],
            bytes_stored: 0,
            truncated: false,
            error: Some(format!("skipped: {}", reason)),
        }
    }

    pub fn failed(error: &str) -> Self {
        Self {
            artifacts: vec![],
            bytes_stored: 0,
            truncated: false,
            error: Some(error.to_string()),
        }
    }
}

// =============================================================================
// Capture Context
// =============================================================================

/// Context for artifact capture
#[derive(Debug, Clone)]
pub struct CaptureContext {
    pub tenant_id: String,
    pub task_id: String,
    pub task_id_short: String,
    pub is_failure: bool,
}

impl CaptureContext {
    pub fn new(tenant_id: &str, task_id: &str, is_failure: bool) -> Self {
        let task_id_short = task_id.chars().take(8).collect();
        Self {
            tenant_id: tenant_id.to_string(),
            task_id: task_id.to_string(),
            task_id_short,
            is_failure,
        }
    }
}

// =============================================================================
// Main Capture Function
// =============================================================================

/// Capture artifacts from LLM execution
///
/// This function:
/// 1. Logs capture start
/// 2. Checks policy to determine what to capture
/// 3. Applies truncation if content exceeds limits
/// 4. Compresses and stores artifacts
/// 5. Logs success/failure
/// 6. Returns artifact refs for inclusion in completion payload
///
/// IMPORTANT: Capture failures are logged but do NOT block completion.
pub fn capture_artifacts<S: ArtifactStore>(
    store: &S,
    ctx: &CaptureContext,
    config: &CaptureConfig,
    raw_output: Option<&RawLlmOutput>,
    rendered_prompt: Option<&str>,
) -> CaptureResult {
    info!(
        op = "prompt_run.artifacts.capture.started",
        task_id = %ctx.task_id_short,
        is_failure = %ctx.is_failure,
        "Starting artifact capture"
    );

    // Check capture policy
    let should_capture_output = match config.capture_policy {
        CapturePolicy::Always => true,
        CapturePolicy::OnFailure => ctx.is_failure,
        CapturePolicy::Never => false,
    };

    let should_capture_prompt = match config.prompt_policy {
        PromptCapturePolicy::Always => true,
        PromptCapturePolicy::OnFailure => ctx.is_failure,
        PromptCapturePolicy::Never => false,
    };

    if !should_capture_output && !should_capture_prompt {
        info!(
            op = "prompt_run.artifacts.capture.skipped",
            task_id = %ctx.task_id_short,
            reason = "policy",
            "Artifact capture skipped due to policy"
        );
        return CaptureResult::skipped("policy");
    }

    if raw_output.is_none() && rendered_prompt.is_none() {
        info!(
            op = "prompt_run.artifacts.capture.skipped",
            task_id = %ctx.task_id_short,
            reason = "no_content",
            "Artifact capture skipped - no content"
        );
        return CaptureResult::skipped("no_content");
    }

    let mut result = CaptureResult::default();
    let expires_at = Utc::now() + Duration::days(config.expiry_days);

    // Capture stdout
    if should_capture_output {
        if let Some(output) = raw_output {
            // Check if truncation needed
            let total = output.total_bytes();
            let needs_truncation = total > config.max_bytes_per_run;
            result.truncated = needs_truncation;

            if needs_truncation {
                warn!(
                    op = "prompt_run.artifacts.truncation",
                    task_id = %ctx.task_id_short,
                    total_bytes = %total,
                    max_bytes = %config.max_bytes_per_run,
                    "Content exceeds limit, storing truncated tails"
                );
            }

            // Capture stdout
            if !output.stdout.is_empty() {
                match capture_single_artifact(
                    store,
                    &ctx.tenant_id,
                    &ctx.task_id,
                    "stdout.txt.gz",
                    &output.stdout,
                    needs_truncation,
                    ArtifactCategory::RawLlm,
                    "LLM stdout",
                    Some(expires_at),
                ) {
                    Ok(artifact) => {
                        result.bytes_stored += artifact.bytes;
                        result.artifacts.push(artifact);
                    }
                    Err(e) => {
                        warn!(
                            op = "prompt_run.artifacts.capture.partial_failure",
                            task_id = %ctx.task_id_short,
                            artifact = "stdout",
                            error = %e,
                            "Failed to capture stdout"
                        );
                        if result.error.is_none() {
                            result.error = Some(format!("stdout: {}", e));
                        }
                    }
                }
            }

            // Capture stderr
            if !output.stderr.is_empty() {
                match capture_single_artifact(
                    store,
                    &ctx.tenant_id,
                    &ctx.task_id,
                    "stderr.txt.gz",
                    &output.stderr,
                    needs_truncation,
                    ArtifactCategory::RawLlm,
                    "LLM stderr",
                    Some(expires_at),
                ) {
                    Ok(artifact) => {
                        result.bytes_stored += artifact.bytes;
                        result.artifacts.push(artifact);
                    }
                    Err(e) => {
                        warn!(
                            op = "prompt_run.artifacts.capture.partial_failure",
                            task_id = %ctx.task_id_short,
                            artifact = "stderr",
                            error = %e,
                            "Failed to capture stderr"
                        );
                        if result.error.is_none() {
                            result.error = Some(format!("stderr: {}", e));
                        }
                    }
                }
            }
        }
    }

    // Capture rendered prompt (TECH_DEBT: prompt redaction v1 not implemented - hook available)
    if should_capture_prompt {
        if let Some(prompt) = rendered_prompt {
            // TODO: Apply redaction before storing (TECH_DEBT - prompt redaction v1)
            // For now, store as-is with category marking
            match capture_single_artifact(
                store,
                &ctx.tenant_id,
                &ctx.task_id,
                "rendered_prompt.txt.gz",
                prompt.as_bytes(),
                false, // Don't truncate prompts
                ArtifactCategory::Intermediate,
                "Rendered prompt (UNREDACTED)",
                Some(expires_at),
            ) {
                Ok(artifact) => {
                    result.bytes_stored += artifact.bytes;
                    result.artifacts.push(artifact);
                }
                Err(e) => {
                    warn!(
                        op = "prompt_run.artifacts.capture.partial_failure",
                        task_id = %ctx.task_id_short,
                        artifact = "prompt",
                        error = %e,
                        "Failed to capture prompt"
                    );
                    if result.error.is_none() {
                        result.error = Some(format!("prompt: {}", e));
                    }
                }
            }
        }
    }

    // Log final result
    if result.error.is_some() {
        warn!(
            op = "prompt_run.artifacts.capture.failed",
            task_id = %ctx.task_id_short,
            error = ?result.error,
            count = %result.artifacts.len(),
            "Artifact capture completed with errors"
        );
    } else if result.artifacts.is_empty() {
        info!(
            op = "prompt_run.artifacts.capture.skipped",
            task_id = %ctx.task_id_short,
            reason = "empty_content",
            "No artifacts to capture"
        );
    } else {
        info!(
            op = "prompt_run.artifacts.capture.success",
            task_id = %ctx.task_id_short,
            count = %result.artifacts.len(),
            total_bytes_stored = %result.bytes_stored,
            truncated = %result.truncated,
            "Artifact capture succeeded"
        );
    }

    result
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Capture a single artifact with compression
fn capture_single_artifact<S: ArtifactStore>(
    store: &S,
    tenant_id: &str,
    task_id: &str,
    filename: &str,
    content: &[u8],
    truncate: bool,
    category: ArtifactCategory,
    label: &str,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Result<ArtifactRef, String> {
    // Apply truncation if needed
    let content_to_store = if truncate && content.len() > TRUNCATION_HEAD_BYTES + TRUNCATION_TAIL_BYTES {
        let mut truncated = Vec::with_capacity(TRUNCATION_HEAD_BYTES + TRUNCATION_TAIL_BYTES + 100);
        truncated.extend_from_slice(&content[..TRUNCATION_HEAD_BYTES]);
        truncated.extend_from_slice(b"\n\n... [TRUNCATED] ...\n\n");
        truncated.extend_from_slice(&content[content.len() - TRUNCATION_TAIL_BYTES..]);
        truncated
    } else {
        content.to_vec()
    };

    let original_size = content_to_store.len();

    // Compress with gzip
    let compressed = gzip_compress(&content_to_store)
        .map_err(|e| format!("Compression failed: {}", e))?;

    // Build filename with task_id prefix for uniqueness
    let prefixed_filename = format!("{}_{}", &task_id[..8.min(task_id.len())], filename);

    // Store artifact
    let store_ref = store
        .put_bytes(
            tenant_id,
            &prefixed_filename,
            CONTENT_TYPE_TEXT_PLAIN_GZ,
            &compressed,
            expires_at,
        )
        .map_err(|e| format!("Store failed: {}", e))?;

    // Convert ekka_artifact_store::ArtifactRef to ekka_ops::llm_result::ArtifactRef
    let artifact = ArtifactRef::new(
        &store_ref.uri,
        &store_ref.sha256,
        store_ref.bytes_stored as u64,
        CONTENT_TYPE_TEXT_PLAIN_GZ,
    )
    .with_compression(CompressionAlgorithm::Gzip, original_size as u64)
    .with_label(label)
    .with_category(category);

    let artifact = if let Some(exp) = expires_at {
        artifact.with_expires_at(exp)
    } else {
        artifact
    };

    Ok(artifact)
}

/// Get artifacts as JSON for envelope inclusion
pub fn artifacts_to_json(artifacts: &[ArtifactRef]) -> Vec<serde_json::Value> {
    artifacts
        .iter()
        .filter_map(|a| serde_json::to_value(a).ok())
        .collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ekka_artifact_store::FilesystemArtifactStore;
    use tempfile::TempDir;

    fn create_test_store() -> (FilesystemArtifactStore, TempDir) {
        let temp = TempDir::new().unwrap();
        let store = FilesystemArtifactStore::new(temp.path().to_path_buf());
        (store, temp)
    }

    #[test]
    fn test_capture_success() {
        let (store, _temp) = create_test_store();
        let ctx = CaptureContext::new("tenant-abc", "task-12345678", false);
        let config = CaptureConfig::default();
        let raw = RawLlmOutput::new(
            b"Hello stdout".to_vec(),
            b"Hello stderr".to_vec(),
            Some(0),
        );

        let result = capture_artifacts(&store, &ctx, &config, Some(&raw), None);

        assert!(result.error.is_none(), "Error: {:?}", result.error);
        assert_eq!(result.artifacts.len(), 2);
        assert!(result.bytes_stored > 0);
        assert!(!result.truncated);

        // Verify URIs
        for artifact in &result.artifacts {
            assert!(artifact.uri.starts_with("ekka://artifacts/"));
            println!("Artifact URI: {}", artifact.uri);
        }
    }

    #[test]
    fn test_capture_with_truncation() {
        let (store, _temp) = create_test_store();
        let ctx = CaptureContext::new("tenant-abc", "task-12345678", false);
        let config = CaptureConfig {
            max_bytes_per_run: 1000, // Very small limit
            ..Default::default()
        };

        // Create large content (exceeds 1000 bytes)
        let large_stdout: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        let raw = RawLlmOutput::new(large_stdout, vec![], Some(0));

        let result = capture_artifacts(&store, &ctx, &config, Some(&raw), None);

        assert!(result.truncated);
        assert_eq!(result.artifacts.len(), 1);
    }

    #[test]
    fn test_capture_policy_on_failure_only() {
        let (store, _temp) = create_test_store();
        let config = CaptureConfig {
            capture_policy: CapturePolicy::OnFailure,
            ..Default::default()
        };

        // Success case - should skip
        let ctx_success = CaptureContext::new("tenant-abc", "task-12345678", false);
        let raw = RawLlmOutput::new(b"output".to_vec(), vec![], Some(0));
        let result = capture_artifacts(&store, &ctx_success, &config, Some(&raw), None);
        assert!(result.artifacts.is_empty());

        // Failure case - should capture
        let ctx_failure = CaptureContext::new("tenant-abc", "task-12345678", true);
        let result = capture_artifacts(&store, &ctx_failure, &config, Some(&raw), None);
        assert!(!result.artifacts.is_empty());
    }

    #[test]
    fn test_capture_prompt_on_failure() {
        let (store, _temp) = create_test_store();
        let ctx = CaptureContext::new("tenant-abc", "task-12345678", true); // Failure
        let config = CaptureConfig::default(); // Default: prompt on failure only

        let prompt = "This is the rendered prompt";
        let raw = RawLlmOutput::new(b"output".to_vec(), vec![], Some(1));

        let result = capture_artifacts(&store, &ctx, &config, Some(&raw), Some(prompt));

        // Should have stdout (raw has no stderr content) and prompt
        assert_eq!(result.artifacts.len(), 2);

        // Verify we have both types
        let labels: Vec<_> = result.artifacts.iter().filter_map(|a| a.label.as_ref()).collect();
        assert!(labels.iter().any(|l| l.contains("stdout")));
        assert!(labels.iter().any(|l| l.contains("prompt")));
    }

    #[test]
    fn test_artifact_ref_format() {
        let (store, _temp) = create_test_store();
        let ctx = CaptureContext::new("tenant-abc", "task-12345678", false);
        let config = CaptureConfig::default();
        let raw = RawLlmOutput::new(b"test output".to_vec(), vec![], Some(0));

        let result = capture_artifacts(&store, &ctx, &config, Some(&raw), None);
        let artifact = &result.artifacts[0];

        // Verify ArtifactRef structure
        assert!(artifact.uri.starts_with("ekka://artifacts/"));
        assert_eq!(artifact.sha256.len(), 64);
        assert!(artifact.bytes > 0);
        assert_eq!(artifact.content_type, "text/plain+gzip");
        assert_eq!(artifact.compression, CompressionAlgorithm::Gzip);
        assert!(artifact.original_bytes.is_some());
        assert!(artifact.label.is_some());
        assert_eq!(artifact.category, Some(ArtifactCategory::RawLlm));
    }
}
