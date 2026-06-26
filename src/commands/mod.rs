//! CLI and supervisor command dispatch module.
//!
//! Provides typed command classification and execution for all CLI and
//! supervisor commands. The binary entrypoint (`src/main.rs`) should
//! remain a thin process-level composition root that delegates to this
//! module.
//!
//! ## Architecture
//!
//! ```text
//! Args parse -> plan_command() -> InitialCommandPlan -> execute_command() -> exit code
//! ```
//!
//! ### Layers
//!
//! 1. **Parse layer** (`synvoid-cli`): Parses CLI flags into `Args`.
//! 2. **Planning layer** (`plan.rs`): Classifies `Args` into a typed
//!    `SynvoidCommandPlan` (one-shot, supervisor-control, or runtime).
//! 3. **Execution layer** (`execute.rs`): Executes the plan, calling into
//!    existing runtime/supervisor modules for the actual work.

pub mod execute;
pub mod plan;
pub mod supervisor_control;

pub use execute::execute_command;
pub use plan::{plan_command, CommandPlan, CommandPlanError, CommandPreAction, SynvoidCommandPlan};
pub use supervisor_control::{
    execute_restart_pre_stop, execute_supervisor_control_command, SupervisorControlError,
    SupervisorControlOutcome,
};
