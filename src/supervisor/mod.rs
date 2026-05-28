//! Supervisor process module.
//!
//! Owns the unified supervisor process for worker lifecycle, upgrades, and control plane operations. The supervisor handles zero-downtime upgrades,
//! IPC communications, and uses `ProcessManager` to orchestrate worker processes.

pub mod api;
pub mod cli_commands;
pub mod commands;
pub mod drain_manager;
pub mod ipc;
pub mod mesh;
pub mod process;
pub mod state;

pub use mesh::run_mesh_agent_mode;
pub use process::{run_supervisor_mode, SupervisorProcess};
pub use state::{SupervisorState, SupervisorStateTrackers};
