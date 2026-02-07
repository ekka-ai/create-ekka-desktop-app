//! EKKA SDK Core - Facade Crate
//!
//! Single import point for desktop and runner apps.
//! Re-exports crates only - no new abstractions.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ekka_sdk_core::ekka_path_guard::PathGuard;
//! use ekka_sdk_core::ekka_home_bootstrap::HomeBootstrap;
//! use ekka_sdk_core::ekka_vault::Vault;
//! ```
//!
//! ## Feature Flags
//!
//! Optional modules enabled via features:
//! - `module-vault`, `module-workspaces`, `module-actions`
//! - `module-github`, `module-git`, `module-jobs`
//! - `module-llm`, `module-agent`
//! - `all-modules` - Enable all

// =============================================================================
// Core (no deps on other layers)
// =============================================================================

pub use ekka_crypto;
pub use ekka_secure_storage;
pub use ekka_encrypted_db;
pub use ekka_ops;

// =============================================================================
// Security (depends on core only)
// =============================================================================

pub use ekka_home_bootstrap;
pub use ekka_path_guard;
pub use ekka_vault;

// =============================================================================
// Framework (depends on core + security)
// =============================================================================

pub use ekka_node_modules;

// =============================================================================
// Optional Modules (feature-gated, depends on framework)
// =============================================================================

#[cfg(feature = "module-vault")]
pub use ekka_node_module_vault;

#[cfg(feature = "module-workspaces")]
pub use ekka_node_module_workspaces;

#[cfg(feature = "module-actions")]
pub use ekka_node_module_actions;

#[cfg(feature = "module-github")]
pub use ekka_node_module_github;

#[cfg(feature = "module-git")]
pub use ekka_node_module_git;

#[cfg(feature = "module-jobs")]
pub use ekka_node_module_jobs;

#[cfg(feature = "module-llm")]
pub use ekka_node_module_llm;

#[cfg(feature = "module-agent")]
pub use ekka_node_module_agent;
