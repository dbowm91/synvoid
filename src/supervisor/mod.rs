//! Supervisor process module.
//!
//! Consolidates the legacy Overseer and Master process hierarchy into a single
//! unified supervisor process. The supervisor handles zero-downtime upgrades,
//! IPC communications, and uses `ProcessManager` to orchestrate worker processes.

pub mod api;
pub mod commands;
pub mod mesh;
pub mod process;
pub mod state;

pub use mesh::run_mesh_agent_mode;
pub use process::{run_supervisor_mode, SupervisorProcess};
pub use state::{SupervisorState, SupervisorStateTrackers};
