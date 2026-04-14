//! Master process lifecycle management.
//!
//! Manages upgrade coordination, health monitoring, rollback,
//! socket handoff, and drain lifecycle for worker processes.

pub mod checksum;
pub mod cli;
pub mod connection_tracker;
pub mod constants;
pub mod drain_manager;
pub mod health;
pub mod ipc_client;
pub mod mode;
pub mod preflight;
pub mod process;
pub mod rollback;
pub mod socket_handoff;
pub mod spawn;
pub mod state;
pub mod upgrade;

pub use crate::config::OverseerConfig;
pub use crate::drain::{DrainStatus, WorkerConnectionInfo, WorkerDrainState};
pub use cli::{run_overseer_command, OverseerArgs, UpgradeCommand};
pub use connection_tracker::{ConnectionTracker, WorkerConnections};
pub use constants::{drain, restart, timeouts, upgrade as upgrade_config};
pub use drain_manager::{DrainManager, DrainProtocol};
pub use health::{
    retry_with_timeout, wait_for_condition, BaselineComparison, EnhancedHealthConfig,
    EnhancedHealthResult, HealthChecker, HealthStatus, ShadowTrafficResult,
};
pub use ipc_client::{
    connect_and_expect, map_ipc_error, send_and_receive, send_message, IpcClient,
};
pub use mode::{detect_upgrade_mode, probe_reuseport_support, UpgradeMode};
pub use preflight::{PreflightConfig, PreflightError, PreflightResult, PreflightValidator};
pub use process::{run_overseer_process, OverseerProcess};
pub use rollback::RollbackManager;
pub use socket_handoff::{
    DualMasterHandoff, SocketHandoffClient, SocketHandoffError, SocketHandoffServer,
};
pub use spawn::{
    build_spawn_command, cleanup_failed_spawns, spawn_and_log, spawn_process, ProcessMode,
    SpawnConfig,
};
pub use state::{OverseerState, Persistence, UpgradeState};
pub use upgrade::{AutoRollbackConfig, Orchestrator};
