//! Retention Policy Helpers
//!
//! Pure functions for evaluating retention policies and computing expiration timestamps.
//!
//! ## Usage
//!
//! ```rust
//! use ekka_ops::retention::{should_capture_raw_llm, compute_expires_at};
//! use ekka_ops::RetentionPolicy;
//! use chrono::Utc;
//!
//! let policy = RetentionPolicy::sampled(0.1, 30);
//! let now = Utc::now();
//!
//! // Deterministic sampling decision (pass a random value 0.0..1.0)
//! let capture = should_capture_raw_llm(&policy, true, 0.05);
//!
//! // Compute expiration timestamp
//! let expires = compute_expires_at(now, 30);
//! ```

use chrono::{DateTime, Duration, Utc};

use crate::llm_result::{RetentionMode, RetentionPolicy};

/// Determine whether to capture raw LLM input/output based on retention policy.
///
/// # Arguments
///
/// * `policy` - The retention policy to evaluate
/// * `is_success` - Whether the LLM call succeeded (for failure-biased capture)
/// * `random_sample` - A random value in [0.0, 1.0) for sampling decisions
///
/// # Returns
///
/// `true` if raw LLM data should be captured, `false` otherwise.
///
/// # Sampling Logic
///
/// - `Full` mode: Always capture if `capture_raw_llm` is true
/// - `Sampled` mode: Capture based on `sample_rate` (random_sample < sample_rate)
/// - `TransientOnly` mode: Never capture (transient data only)
/// - `MetadataOnly` mode: Never capture (metadata only)
/// - `StructuredOnly` mode: Never capture (structured output only)
///
/// Additionally, failures are always captured if `capture_raw_llm` is enabled,
/// regardless of sampling rate (failure-biased sampling for debugging).
///
/// # Example
///
/// ```rust
/// use ekka_ops::retention::should_capture_raw_llm;
/// use ekka_ops::RetentionPolicy;
///
/// let policy = RetentionPolicy::sampled(0.1, 30); // 10% sample rate
///
/// // With random value 0.05 (< 0.1), should capture
/// assert!(should_capture_raw_llm(&policy, true, 0.05));
///
/// // With random value 0.5 (> 0.1), should not capture success
/// assert!(!should_capture_raw_llm(&policy, true, 0.5));
///
/// // Failures always captured when capture_raw_llm is enabled
/// assert!(should_capture_raw_llm(&policy, false, 0.99));
/// ```
pub fn should_capture_raw_llm(policy: &RetentionPolicy, is_success: bool, random_sample: f64) -> bool {
    // Modes that never capture raw LLM
    match policy.mode {
        RetentionMode::TransientOnly | RetentionMode::MetadataOnly | RetentionMode::StructuredOnly => {
            return false;
        }
        _ => {}
    }

    // Must have capture_raw_llm enabled
    if !policy.capture_raw_llm {
        return false;
    }

    // Failure-biased: always capture failures
    if !is_success {
        return true;
    }

    // For successes, apply sampling
    match policy.mode {
        RetentionMode::Full => true,
        RetentionMode::Sampled => random_sample < policy.sample_rate,
        _ => false,
    }
}

/// Compute the expiration timestamp based on retention days.
///
/// # Arguments
///
/// * `now` - Current timestamp
/// * `retention_days` - Number of days to retain (0 = never expires)
///
/// # Returns
///
/// `Some(DateTime)` with the expiration time, or `None` if retention_days is 0 (indefinite).
///
/// # Example
///
/// ```rust
/// use ekka_ops::retention::compute_expires_at;
/// use chrono::{Utc, Duration};
///
/// let now = Utc::now();
///
/// // 30-day retention
/// let expires = compute_expires_at(now, 30);
/// assert!(expires.is_some());
/// let exp = expires.unwrap();
/// assert!(exp > now);
/// assert!(exp <= now + Duration::days(31)); // Roughly 30 days
///
/// // Indefinite retention
/// let no_expire = compute_expires_at(now, 0);
/// assert!(no_expire.is_none());
/// ```
pub fn compute_expires_at(now: DateTime<Utc>, retention_days: u32) -> Option<DateTime<Utc>> {
    if retention_days == 0 {
        None // Indefinite retention
    } else {
        Some(now + Duration::days(i64::from(retention_days)))
    }
}

/// Compute expiration from a retention policy.
///
/// Convenience wrapper that extracts `days` from the policy.
pub fn compute_expires_at_from_policy(now: DateTime<Utc>, policy: &RetentionPolicy) -> Option<DateTime<Utc>> {
    compute_expires_at(now, policy.days)
}

// =============================================================================
// Sweeper Result (for reporting)
// =============================================================================

/// Result of a sweeper run.
///
/// Contains counts and error samples for deterministic logging.
#[derive(Debug, Clone)]
pub struct SweeperResult {
    /// Number of artifacts deleted
    pub deleted: usize,
    /// Number of errors encountered
    pub errors: usize,
    /// Sample of error messages (up to 5)
    pub error_samples: Vec<String>,
}

impl SweeperResult {
    /// Create a successful result with deletion count.
    pub fn success(deleted: usize) -> Self {
        Self {
            deleted,
            errors: 0,
            error_samples: vec![],
        }
    }

    /// Create a result with errors.
    pub fn with_errors(deleted: usize, errors: usize, samples: Vec<String>) -> Self {
        Self {
            deleted,
            errors,
            error_samples: samples,
        }
    }
}

impl Default for SweeperResult {
    fn default() -> Self {
        Self {
            deleted: 0,
            errors: 0,
            error_samples: vec![],
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_capture_raw_llm_full_mode() {
        let policy = RetentionPolicy::full();

        // Full mode with capture_raw_llm=true: always capture
        assert!(should_capture_raw_llm(&policy, true, 0.0));
        assert!(should_capture_raw_llm(&policy, true, 0.5));
        assert!(should_capture_raw_llm(&policy, true, 0.99));
        assert!(should_capture_raw_llm(&policy, false, 0.99));
    }

    #[test]
    fn test_should_capture_raw_llm_sampled_mode() {
        let policy = RetentionPolicy::sampled(0.1, 30); // 10% sample rate

        // Below sample rate: capture
        assert!(should_capture_raw_llm(&policy, true, 0.05));
        assert!(should_capture_raw_llm(&policy, true, 0.09));

        // At or above sample rate: don't capture successes
        assert!(!should_capture_raw_llm(&policy, true, 0.1));
        assert!(!should_capture_raw_llm(&policy, true, 0.5));
        assert!(!should_capture_raw_llm(&policy, true, 0.99));

        // Failures always captured
        assert!(should_capture_raw_llm(&policy, false, 0.99));
    }

    #[test]
    fn test_should_capture_raw_llm_disabled() {
        let mut policy = RetentionPolicy::default();
        policy.capture_raw_llm = false;

        // Never capture when disabled
        assert!(!should_capture_raw_llm(&policy, true, 0.0));
        assert!(!should_capture_raw_llm(&policy, false, 0.0));
    }

    #[test]
    fn test_should_capture_raw_llm_transient_mode() {
        let policy = RetentionPolicy {
            mode: RetentionMode::TransientOnly,
            capture_raw_llm: true,
            ..Default::default()
        };

        // TransientOnly never captures
        assert!(!should_capture_raw_llm(&policy, true, 0.0));
        assert!(!should_capture_raw_llm(&policy, false, 0.0));
    }

    #[test]
    fn test_should_capture_raw_llm_metadata_only() {
        let policy = RetentionPolicy {
            mode: RetentionMode::MetadataOnly,
            capture_raw_llm: true,
            ..Default::default()
        };

        // MetadataOnly never captures raw
        assert!(!should_capture_raw_llm(&policy, true, 0.0));
        assert!(!should_capture_raw_llm(&policy, false, 0.0));
    }

    #[test]
    fn test_should_capture_raw_llm_structured_only() {
        let policy = RetentionPolicy {
            mode: RetentionMode::StructuredOnly,
            capture_raw_llm: true,
            ..Default::default()
        };

        // StructuredOnly never captures raw
        assert!(!should_capture_raw_llm(&policy, true, 0.0));
        assert!(!should_capture_raw_llm(&policy, false, 0.0));
    }

    #[test]
    fn test_compute_expires_at_with_days() {
        let now = Utc::now();

        // 30-day retention
        let expires = compute_expires_at(now, 30);
        assert!(expires.is_some());
        let exp = expires.unwrap();

        // Should be ~30 days in the future
        let diff = exp - now;
        assert_eq!(diff.num_days(), 30);
    }

    #[test]
    fn test_compute_expires_at_indefinite() {
        let now = Utc::now();

        // 0 days = indefinite
        let expires = compute_expires_at(now, 0);
        assert!(expires.is_none());
    }

    #[test]
    fn test_compute_expires_at_one_day() {
        let now = Utc::now();

        let expires = compute_expires_at(now, 1);
        assert!(expires.is_some());
        let exp = expires.unwrap();

        let diff = exp - now;
        assert_eq!(diff.num_days(), 1);
    }

    #[test]
    fn test_compute_expires_at_from_policy() {
        let now = Utc::now();
        let policy = RetentionPolicy::debug(); // 30 days

        let expires = compute_expires_at_from_policy(now, &policy);
        assert!(expires.is_some());
        assert_eq!((expires.unwrap() - now).num_days(), 30);
    }

    #[test]
    fn test_sweeper_result_success() {
        let result = SweeperResult::success(10);
        assert_eq!(result.deleted, 10);
        assert_eq!(result.errors, 0);
        assert!(result.error_samples.is_empty());
    }

    #[test]
    fn test_sweeper_result_with_errors() {
        let result = SweeperResult::with_errors(5, 2, vec!["err1".into(), "err2".into()]);
        assert_eq!(result.deleted, 5);
        assert_eq!(result.errors, 2);
        assert_eq!(result.error_samples.len(), 2);
    }
}
