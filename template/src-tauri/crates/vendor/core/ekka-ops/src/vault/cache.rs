//! Vault Manager Cache
//!
//! Provides caching infrastructure for VaultManager to avoid repeated PBKDF2 key derivation.
//!
//! ## Performance Issue Solved
//!
//! Without caching, each vault operation calls VaultManager::new() which triggers
//! PBKDF2 key derivation with 100,000 iterations (~500-900ms per call).
//! This cache allows deriving the key once per session and reusing it.
//!
//! ## Cache Key Semantics
//!
//! The cache is keyed by:
//! - `tenant_id`: Tenant isolation
//! - `user_sub`: User isolation
//! - `security_epoch`: Allows key rotation (cache miss on epoch change)
//! - `node_id`: Device isolation
//!
//! ## Thread Safety
//!
//! The trait requires Send + Sync. Implementations should use appropriate
//! synchronization primitives (e.g., RwLock).

use std::sync::Arc;
use uuid::Uuid;

use super::manager::VaultManager;
use crate::context::RuntimeContext;
use crate::error::{codes, EkkaError, EkkaResult};

/// Cache key for VaultManager instances
///
/// The key captures all factors that affect key derivation:
/// - tenant_id: Different tenants have different encryption contexts
/// - user_sub: Different users have different encryption contexts
/// - security_epoch: When epoch changes, keys must be re-derived
/// - node_id: Different devices have different device secrets
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultCacheKey {
    pub tenant_id: String,
    pub user_sub: String,
    pub security_epoch: u32,
    pub node_id: Uuid,
}

impl VaultCacheKey {
    /// Create a new cache key from components
    pub fn new(tenant_id: String, user_sub: String, security_epoch: u32, node_id: Uuid) -> Self {
        Self {
            tenant_id,
            user_sub,
            security_epoch,
            node_id,
        }
    }

    /// Create a cache key from RuntimeContext
    ///
    /// Returns None if auth is not set (user not logged in)
    pub fn from_context(ctx: &RuntimeContext) -> Option<Self> {
        let auth = ctx.auth.as_ref()?;
        Some(Self {
            tenant_id: auth.tenant_id.clone(),
            user_sub: auth.sub.clone(),
            // TODO: Get actual security_epoch from context when available
            security_epoch: 1,
            node_id: ctx.node_id,
        })
    }
}

/// Trait for caching VaultManager instances
///
/// This trait allows ekka-ops to use a cache without depending on
/// specific cache implementations (like Tauri's EngineState).
///
/// ## Implementation Requirements
///
/// - Thread-safe (Send + Sync required)
/// - Concurrent reads allowed
/// - Writes should be synchronized
pub trait VaultManagerCache: Send + Sync {
    /// Get a cached VaultManager by key
    ///
    /// Returns None if not cached
    fn get(&self, key: &VaultCacheKey) -> Option<Arc<VaultManager>>;

    /// Insert a VaultManager into the cache
    ///
    /// If a value already exists for the key, it should be replaced
    fn insert(&self, key: VaultCacheKey, vm: Arc<VaultManager>);

    /// Remove a VaultManager from the cache
    ///
    /// Returns true if a value was removed
    fn remove(&self, key: &VaultCacheKey) -> bool;

    /// Clear all cached VaultManagers
    ///
    /// Should be called on logout or auth context changes
    fn clear(&self);
}

/// Get or initialize a VaultManager from cache
///
/// This is the main entry point for vault operations. It:
/// 1. Checks if user is authenticated (required)
/// 2. Builds cache key from context
/// 3. Returns cached VaultManager if available
/// 4. Otherwise creates new VaultManager, caches it, and returns it
///
/// ## Performance
///
/// First call pays PBKDF2 cost (~500-900ms).
/// Subsequent calls return cached instance (< 1ms).
///
/// ## Example
///
/// ```rust,ignore
/// let vm = get_or_init_vault_manager(&ctx, &cache)?;
/// // Use vm for operations...
/// ```
pub fn get_or_init_vault_manager(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
) -> EkkaResult<Arc<VaultManager>> {
    // Build cache key (requires auth)
    let key = VaultCacheKey::from_context(ctx).ok_or_else(|| {
        EkkaError::new(
            codes::NOT_AUTHENTICATED,
            "Must be authenticated to access vault",
        )
    })?;

    // Check cache first
    if let Some(vm) = cache.get(&key) {
        tracing::debug!(
            tenant_id = %key.tenant_id,
            user_sub = %key.user_sub,
            "vault cache hit"
        );
        return Ok(vm);
    }

    // Cache miss - create new VaultManager
    tracing::info!(
        tenant_id = %key.tenant_id,
        user_sub = %key.user_sub,
        "vault cache miss, deriving key (this will take a moment)"
    );

    let start = std::time::Instant::now();
    let vm = Arc::new(VaultManager::new(ctx)?);
    let elapsed = start.elapsed();

    tracing::info!(
        tenant_id = %key.tenant_id,
        user_sub = %key.user_sub,
        elapsed_ms = elapsed.as_millis(),
        "vault key derivation complete"
    );

    // Cache and return
    cache.insert(key, vm.clone());

    Ok(vm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// Test implementation of VaultManagerCache (reserved for future use)
    #[allow(dead_code)]
    struct TestCache {
        inner: RwLock<HashMap<VaultCacheKey, Arc<VaultManager>>>,
    }

    #[allow(dead_code)]
    impl TestCache {
        fn new() -> Self {
            Self {
                inner: RwLock::new(HashMap::new()),
            }
        }
    }

    impl VaultManagerCache for TestCache {
        fn get(&self, key: &VaultCacheKey) -> Option<Arc<VaultManager>> {
            self.inner.read().unwrap().get(key).cloned()
        }

        fn insert(&self, key: VaultCacheKey, vm: Arc<VaultManager>) {
            self.inner.write().unwrap().insert(key, vm);
        }

        fn remove(&self, key: &VaultCacheKey) -> bool {
            self.inner.write().unwrap().remove(key).is_some()
        }

        fn clear(&self) {
            self.inner.write().unwrap().clear();
        }
    }

    #[test]
    fn test_cache_key_equality() {
        let key1 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );
        let key2 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );
        let key3 = VaultCacheKey::new(
            "tenant2".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_key_hash() {
        use std::collections::HashSet;

        let key1 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );
        let key2 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );

        let mut set = HashSet::new();
        set.insert(key1);
        assert!(set.contains(&key2));
    }

    #[test]
    fn test_epoch_change_causes_miss() {
        let key1 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );
        let key2 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            2, // Different epoch
            Uuid::nil(),
        );

        assert_ne!(key1, key2, "Different epochs should produce different keys");
    }

    #[test]
    fn test_tenant_change_causes_miss() {
        let key1 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );
        let key2 = VaultCacheKey::new(
            "tenant2".to_string(), // Different tenant
            "user1".to_string(),
            1,
            Uuid::nil(),
        );

        assert_ne!(key1, key2, "Different tenants should produce different keys");
    }

    #[test]
    fn test_user_change_causes_miss() {
        let key1 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user1".to_string(),
            1,
            Uuid::nil(),
        );
        let key2 = VaultCacheKey::new(
            "tenant1".to_string(),
            "user2".to_string(), // Different user
            1,
            Uuid::nil(),
        );

        assert_ne!(key1, key2, "Different users should produce different keys");
    }
}
