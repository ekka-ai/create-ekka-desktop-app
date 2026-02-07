//! Task executors for ekka-runner-local
//!
//! Each executor handles a specific task_subtype.
//! New executors can be added as separate modules.

pub mod debug_bundle;
pub mod node_exec;
pub mod prompt_run;
