//! Traits for Dependency Injection
//!
//! Defines interfaces that desktop/runner apps implement.
//! This allows the SDK to be tested without real engine calls.

use crate::context::RuntimeContext;
use crate::error::EkkaResult;
use ekka_path_guard::{PathAccess, PathType, SignedGrant};
use serde::{Deserialize, Serialize};

/// Grant request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest {
    /// Path prefix to grant access to
    pub path_prefix: String,
    /// Type of path (Home, Workspace, Data, etc.)
    pub path_type: PathType,
    /// Access level (ReadOnly, ReadWrite)
    pub access: PathAccess,
    /// Purpose/reason for the grant
    pub purpose: String,
    /// Expiration in seconds from now
    pub expires_in_seconds: u64,
}

impl GrantRequest {
    /// Create a HOME grant request
    pub fn home(home_path: &std::path::Path, expires_in_seconds: u64) -> Self {
        Self {
            path_prefix: home_path.to_string_lossy().to_string(),
            path_type: PathType::Home,
            access: PathAccess::ReadWrite,
            purpose: "home_bootstrap".to_string(),
            expires_in_seconds,
        }
    }

    /// Create a workspace grant request
    pub fn workspace(path: &std::path::Path, access: PathAccess, expires_in_seconds: u64) -> Self {
        Self {
            path_prefix: path.to_string_lossy().to_string(),
            path_type: PathType::Workspace,
            access,
            purpose: "workspace_access".to_string(),
            expires_in_seconds,
        }
    }
}

/// Grant issuance response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantResponse {
    /// The signed grant from the engine
    pub signed_grant: SignedGrant,
    /// Grant expiration timestamp (RFC3339)
    pub expires_at: String,
}

/// Trait for grant issuance
///
/// Implemented by desktop app with HTTP calls to EKKA Engine.
/// Can be mocked for testing.
pub trait GrantIssuer: Send + Sync {
    /// Issue a new grant from the EKKA Engine
    ///
    /// # Arguments
    /// * `ctx` - Runtime context with auth
    /// * `req` - Grant request parameters
    ///
    /// # Returns
    /// Signed grant from engine
    fn issue(&self, ctx: &RuntimeContext, req: GrantRequest) -> EkkaResult<GrantResponse>;

    /// Revoke an existing grant
    ///
    /// # Arguments
    /// * `ctx` - Runtime context with auth
    /// * `grant_id` - ID of grant to revoke
    fn revoke(&self, ctx: &RuntimeContext, grant_id: &str) -> EkkaResult<()>;
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use crate::error::{codes, EkkaError};
    use ekka_path_guard::{Grant, GrantConsent, GrantPermissions, GrantResource, PathResourceAttrs};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Mock grant issuer for testing
    pub struct MockGrantIssuer {
        should_fail: AtomicBool,
        fail_message: String,
    }

    impl MockGrantIssuer {
        pub fn new() -> Self {
            Self {
                should_fail: AtomicBool::new(false),
                fail_message: "Mock failure".to_string(),
            }
        }

        pub fn set_should_fail(&self, fail: bool) {
            self.should_fail.store(fail, Ordering::SeqCst);
        }
    }

    impl Default for MockGrantIssuer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl GrantIssuer for MockGrantIssuer {
        fn issue(&self, ctx: &RuntimeContext, req: GrantRequest) -> EkkaResult<GrantResponse> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(EkkaError::new(codes::ENGINE_ERROR, &self.fail_message));
            }

            let auth = ctx.auth.as_ref().ok_or_else(|| {
                EkkaError::new(codes::NOT_AUTHENTICATED, "No auth context")
            })?;

            let now = chrono::Utc::now();
            let expires_at = now + chrono::Duration::seconds(req.expires_in_seconds as i64);

            let grant = Grant {
                sub: auth.sub.clone(),
                tenant_id: auth.tenant_id.clone(),
                node_id: ctx.node_id,
                grant_id: uuid::Uuid::new_v4().to_string(),
                issuer: "ekka-engine-mock".to_string(),
                issued_at: now.to_rfc3339(),
                expires_at: Some(expires_at.to_rfc3339()),
                resource: GrantResource::Path {
                    path_prefix: req.path_prefix,
                    attrs: Some(PathResourceAttrs {
                        path_type: Some(req.path_type),
                    }),
                },
                permissions: GrantPermissions {
                    ops: vec!["read".to_string(), "write".to_string(), "delete".to_string()],
                    access: Some(req.access),
                },
                purpose: req.purpose,
                consent: GrantConsent {
                    mode: "user_click".to_string(),
                    approved_at: now.to_rfc3339(),
                    approved_by: auth.sub.clone(),
                },
            };

            let signed_grant = SignedGrant {
                schema: "GRANT".to_string(),
                canon_alg: "SECURITY.CANONICALIZE.V1".to_string(),
                signing_alg: "ed25519".to_string(),
                grant,
                grant_canonical_b64: "mock-canonical".to_string(),
                signature_b64: "mock-signature".to_string(),
            };

            Ok(GrantResponse {
                signed_grant,
                expires_at: expires_at.to_rfc3339(),
            })
        }

        fn revoke(&self, _ctx: &RuntimeContext, _grant_id: &str) -> EkkaResult<()> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(EkkaError::new(codes::ENGINE_ERROR, &self.fail_message));
            }
            Ok(())
        }
    }
}
