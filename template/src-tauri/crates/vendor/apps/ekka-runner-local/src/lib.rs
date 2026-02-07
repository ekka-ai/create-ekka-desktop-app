//! EKKA Runner Local Library
//!
//! Provides enhanced executor implementations with features like:
//! - Output contract validation
//! - Debug bundle support for troubleshooting
//! - Full prompt_run.result.v1 envelope support
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ekka_runner_local::dispatch::dispatch_task;
//! use ekka_runner_local::types::{EngineContext, TaskExecutionContext};
//! ```

pub mod dispatch;
pub mod executors;
pub mod types;
