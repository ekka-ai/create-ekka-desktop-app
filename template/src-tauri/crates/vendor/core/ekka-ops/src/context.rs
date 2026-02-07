//! Runtime Context
//!
//! Contains all state needed for SDK operations.

use std::path::PathBuf;
use uuid::Uuid;

/// Authentication context from JWT
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Tenant identifier
    pub tenant_id: String,
    /// Subject (user ID)
    pub sub: String,
    /// JWT token for engine requests
    pub jwt: String,
}

impl AuthContext {
    /// Create new auth context
    pub fn new(tenant_id: impl Into<String>, sub: impl Into<String>, jwt: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            sub: sub.into(),
            jwt: jwt.into(),
        }
    }
}

/// Runtime context for SDK operations
///
/// Contains all state needed to execute operations.
/// Passed to all operation functions.
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    /// EKKA home directory path
    pub home_path: PathBuf,
    /// Optional authentication (None before login)
    pub auth: Option<AuthContext>,
    /// Node identifier from marker file
    pub node_id: Uuid,
}

impl RuntimeContext {
    /// Create a new runtime context
    pub fn new(home_path: PathBuf, node_id: Uuid) -> Self {
        Self {
            home_path,
            auth: None,
            node_id,
        }
    }

    /// Create context with authentication
    pub fn with_auth(home_path: PathBuf, node_id: Uuid, auth: AuthContext) -> Self {
        Self {
            home_path,
            auth: Some(auth),
            node_id,
        }
    }

    /// Set authentication context
    pub fn set_auth(&mut self, auth: AuthContext) {
        self.auth = Some(auth);
    }

    /// Clear authentication context
    pub fn clear_auth(&mut self) {
        self.auth = None;
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_some()
    }

    /// Get grants.json path
    pub fn grants_path(&self) -> PathBuf {
        self.home_path.join("grants.json")
    }

    /// Get marker file path
    pub fn marker_path(&self) -> PathBuf {
        self.home_path.join(".ekka-marker.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = RuntimeContext::new(
            PathBuf::from("/tmp/test"),
            Uuid::new_v4(),
        );

        assert!(!ctx.is_authenticated());
        assert_eq!(ctx.home_path, PathBuf::from("/tmp/test"));
    }

    #[test]
    fn test_context_with_auth() {
        let auth = AuthContext::new("tenant-1", "user-1", "jwt-token");
        let ctx = RuntimeContext::with_auth(
            PathBuf::from("/tmp/test"),
            Uuid::new_v4(),
            auth,
        );

        assert!(ctx.is_authenticated());
        assert_eq!(ctx.auth.as_ref().unwrap().tenant_id, "tenant-1");
    }
}
