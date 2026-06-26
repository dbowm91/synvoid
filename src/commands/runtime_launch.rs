//! Runtime launch boundary for Iteration 106.
//!
//! Separates runtime-launch planning (pure, testable) from runtime-launch
//! execution (side-effecting). `execute.rs` delegates to this module for
//! all runtime mode handling.
//!
//! ## Design
//!
//! - `RuntimeLaunchContext`: structured launch inputs derived from `CommandPlan`.
//! - `RuntimeLaunchPlan`: pure description of what to launch, one per runtime mode.
//! - `plan_runtime_launch()`: converts context into a plan. No I/O, no runtimes.
//! - `execute_runtime_launch()`: performs the side effects (runtime build, PID
//!   file, logging, panic handlers). Returns a process exit code.

use std::path::PathBuf;

use crate::startup::bootstrap::{init_logging_simple, print_test_mode_warning};
use crate::startup::daemon::acquire_pid_file;
use crate::startup::worker::{build_cpu_worker_args, build_unified_server_worker_args};
use crate::supervisor::commands::handle_configtest;
use crate::supervisor::run_supervisor_mode;
use crate::worker::{
    run_cpu_worker, run_unified_server_worker, setup_unified_server_panic_handler,
    setup_worker_panic_handler,
};

use super::plan::{CommandPlan, RuntimeCommand};

// ---------------------------------------------------------------------------
// RuntimeLaunchContext — structured inputs derived from CommandPlan
// ---------------------------------------------------------------------------

/// Structured launch inputs for runtime modes, derived from `CommandPlan`.
///
/// This struct carries only the fields needed for runtime launch decisions.
/// It is cheaply constructible and does not hold resources.
#[derive(Debug, Clone)]
pub struct RuntimeLaunchContext {
    pub config_path: Option<PathBuf>,
    pub foreground: bool,
    pub test_flags: Option<Vec<String>>,
    pub cpu_worker_id: Option<usize>,
    pub unified_worker_id: Option<usize>,
    pub worker_threads: Option<usize>,
    pub cpu_affinity: Option<usize>,
    pub total_workers: Option<usize>,
    pub reuse_port: bool,
}

impl RuntimeLaunchContext {
    /// Build a launch context from a command plan.
    ///
    /// Copies only the runtime-relevant fields; does not take ownership.
    pub fn from_command_plan(plan: &CommandPlan) -> Self {
        Self {
            config_path: plan.config_path.clone(),
            foreground: plan.foreground,
            test_flags: plan.test_flags.clone(),
            cpu_worker_id: plan.cpu_worker_id,
            unified_worker_id: plan.unified_worker_id,
            worker_threads: plan.worker_threads,
            cpu_affinity: plan.cpu_affinity,
            total_workers: plan.total_workers,
            reuse_port: plan.reuse_port,
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeLaunchPlan — pure description of what to launch
// ---------------------------------------------------------------------------

/// Pure description of a runtime launch. One variant per runtime mode.
///
/// Each variant carries the exact inputs needed to start that mode,
/// pre-resolved from the `RuntimeLaunchContext`. No I/O or Tokio runtime
/// construction happens in the planner.
#[derive(Debug, Clone)]
pub enum RuntimeLaunchPlan {
    /// Launch as supervisor (manages workers, acquires PID file).
    Supervisor {
        config_path: Option<PathBuf>,
        foreground: bool,
        test_flags: Option<Vec<String>>,
    },
    /// Launch as CPU offload worker.
    CpuWorker {
        cpu_worker_id: Option<usize>,
        config_path: Option<PathBuf>,
    },
    /// Launch as unified server worker.
    UnifiedServerWorker {
        unified_worker_id: Option<usize>,
        config_path: Option<PathBuf>,
        worker_threads: usize,
        cpu_affinity: Option<usize>,
        total_workers: usize,
        reuse_port: bool,
    },
    /// Launch as mesh agent process.
    MeshAgent {
        config_path: Option<PathBuf>,
        foreground: bool,
    },
    /// Launch as WASM plugin execution jail.
    WasmJail,
    /// Launch as YARA rule evaluation jail.
    YaraJail,
}

// ---------------------------------------------------------------------------
// RuntimeLaunchOutcome — structured result of a launch attempt
// ---------------------------------------------------------------------------

/// Outcome of a runtime launch attempt.
#[derive(Debug, Clone)]
pub enum RuntimeLaunchOutcome {
    /// Runtime completed normally.
    Completed,
    /// Runtime failed with a description of the error.
    Failed(String),
}

impl RuntimeLaunchOutcome {
    /// Convert the outcome to a process exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            RuntimeLaunchOutcome::Completed => 0,
            RuntimeLaunchOutcome::Failed(_) => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// plan_runtime_launch — pure planner, no side effects
// ---------------------------------------------------------------------------

/// Convert a `RuntimeCommand` and `RuntimeLaunchContext` into a
/// `RuntimeLaunchPlan`.
///
/// This function is pure — it does not build Tokio runtimes, launch workers,
/// acquire PID files, initialize logging, or perform any I/O. It constructs
/// plain data structures that describe the intended launch.
pub fn plan_runtime_launch(
    command: RuntimeCommand,
    ctx: &RuntimeLaunchContext,
) -> RuntimeLaunchPlan {
    match command {
        RuntimeCommand::Supervisor => RuntimeLaunchPlan::Supervisor {
            config_path: ctx.config_path.clone(),
            foreground: ctx.foreground,
            test_flags: ctx.test_flags.clone(),
        },
        RuntimeCommand::CpuWorker => RuntimeLaunchPlan::CpuWorker {
            cpu_worker_id: ctx.cpu_worker_id,
            config_path: ctx.config_path.clone(),
        },
        RuntimeCommand::UnifiedServerWorker => RuntimeLaunchPlan::UnifiedServerWorker {
            unified_worker_id: ctx.unified_worker_id,
            config_path: ctx.config_path.clone(),
            worker_threads: ctx.worker_threads.unwrap_or(2),
            cpu_affinity: ctx.cpu_affinity,
            total_workers: ctx.total_workers.unwrap_or(1),
            reuse_port: ctx.reuse_port,
        },
        RuntimeCommand::MeshAgent => RuntimeLaunchPlan::MeshAgent {
            config_path: ctx.config_path.clone(),
            foreground: ctx.foreground,
        },
        RuntimeCommand::WasmJail => RuntimeLaunchPlan::WasmJail,
        RuntimeCommand::YaraJail => RuntimeLaunchPlan::YaraJail,
    }
}

// ---------------------------------------------------------------------------
// execute_runtime_launch — side-effecting launcher
// ---------------------------------------------------------------------------

/// Execute a runtime launch plan by performing all necessary side effects.
///
/// This function builds Tokio runtimes, sets up panic handlers, acquires
/// PID files, initializes logging, and launches the appropriate runtime.
///
/// Behavior is preserved exactly from the original `execute_runtime()`.
pub fn execute_runtime_launch(plan: RuntimeLaunchPlan) -> RuntimeLaunchOutcome {
    match plan {
        RuntimeLaunchPlan::Supervisor {
            config_path,
            foreground,
            test_flags,
        } => {
            let pid_manager = acquire_pid_file();
            run_supervisor_mode(config_path, foreground, test_flags.as_deref(), &pid_manager);
            RuntimeLaunchOutcome::Completed
        }
        RuntimeLaunchPlan::CpuWorker {
            cpu_worker_id,
            config_path,
        } => {
            setup_worker_panic_handler();
            init_logging_simple();

            let cpu_worker_args =
                build_cpu_worker_args(cpu_worker_id, config_path, None, None, None);

            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");

            if let Err(e) = rt.block_on(run_cpu_worker(cpu_worker_args)) {
                tracing::error!("CPU worker error: {}", e);
                return RuntimeLaunchOutcome::Failed(e.to_string());
            }
            RuntimeLaunchOutcome::Completed
        }
        RuntimeLaunchPlan::UnifiedServerWorker {
            unified_worker_id,
            config_path,
            worker_threads,
            cpu_affinity,
            total_workers,
            reuse_port,
        } => {
            setup_unified_server_panic_handler();
            init_logging_simple();

            let unified_worker_args = build_unified_server_worker_args(
                unified_worker_id,
                config_path,
                None,
                None,
                worker_threads,
                cpu_affinity,
                total_workers,
                reuse_port,
            );

            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_threads)
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");

            if let Err(e) = rt.block_on(run_unified_server_worker(unified_worker_args)) {
                tracing::error!("Unified server worker error: {}", e);
                return RuntimeLaunchOutcome::Failed(e.to_string());
            }
            RuntimeLaunchOutcome::Completed
        }
        RuntimeLaunchPlan::MeshAgent {
            config_path,
            foreground,
        } => {
            init_logging_simple();
            let config_path = config_path.unwrap_or_else(|| PathBuf::from("config"));
            crate::supervisor::run_mesh_agent_mode(Some(config_path), foreground);
            RuntimeLaunchOutcome::Completed
        }
        RuntimeLaunchPlan::WasmJail => {
            init_logging_simple();
            crate::sandbox::run_wasm_jail_mode();
            RuntimeLaunchOutcome::Completed
        }
        RuntimeLaunchPlan::YaraJail => {
            init_logging_simple();
            crate::sandbox::run_yara_jail_mode();
            RuntimeLaunchOutcome::Completed
        }
    }
}

// ---------------------------------------------------------------------------
// execute_runtime — thin adapter used by execute.rs
// ---------------------------------------------------------------------------

/// Execute a runtime command by planning then launching.
///
/// This is the bridge called by `execute.rs`. It handles the test-mode
/// warning (a cross-cutting concern that belongs at the dispatch layer),
/// then delegates to the pure planner and side-effecting launcher.
pub fn execute_runtime(command: RuntimeCommand, plan: &CommandPlan) -> i32 {
    if let Some(ref test_flags) = plan.test_flags {
        print_test_mode_warning(test_flags);
    }

    let ctx = RuntimeLaunchContext::from_command_plan(plan);
    let launch = plan_runtime_launch(command, &ctx);
    execute_runtime_launch(launch).exit_code()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::plan::{CommandPlan, RuntimeCommand, SynvoidCommandPlan};

    fn base_context() -> RuntimeLaunchContext {
        RuntimeLaunchContext {
            config_path: None,
            foreground: false,
            test_flags: None,
            cpu_worker_id: None,
            unified_worker_id: None,
            worker_threads: None,
            cpu_affinity: None,
            total_workers: None,
            reuse_port: false,
        }
    }

    fn base_plan() -> CommandPlan {
        CommandPlan {
            plan: SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor),
            test_flags: None,
            config_path: None,
            pre_action: None,
            foreground: false,
            cpu_worker_id: None,
            unified_worker_id: None,
            worker_threads: None,
            cpu_affinity: None,
            total_workers: None,
            reuse_port: false,
        }
    }

    // --- From CommandPlan ---

    #[test]
    fn context_from_command_plan_copies_all_fields() {
        let mut plan = base_plan();
        plan.config_path = Some(PathBuf::from("/etc/synvoid"));
        plan.foreground = true;
        plan.test_flags = Some(vec!["all-off".into()]);
        plan.cpu_worker_id = Some(3);
        plan.unified_worker_id = Some(7);
        plan.worker_threads = Some(8);
        plan.cpu_affinity = Some(2);
        plan.total_workers = Some(4);
        plan.reuse_port = true;

        let ctx = RuntimeLaunchContext::from_command_plan(&plan);
        assert_eq!(ctx.config_path, Some(PathBuf::from("/etc/synvoid")));
        assert!(ctx.foreground);
        assert_eq!(ctx.test_flags, Some(vec!["all-off".into()]));
        assert_eq!(ctx.cpu_worker_id, Some(3));
        assert_eq!(ctx.unified_worker_id, Some(7));
        assert_eq!(ctx.worker_threads, Some(8));
        assert_eq!(ctx.cpu_affinity, Some(2));
        assert_eq!(ctx.total_workers, Some(4));
        assert!(ctx.reuse_port);
    }

    // --- CPU worker ---

    #[test]
    fn cpu_worker_plan_preserves_id_and_config() {
        let ctx = RuntimeLaunchContext {
            cpu_worker_id: Some(5),
            config_path: Some(PathBuf::from("/custom/config")),
            ..base_context()
        };

        let plan = plan_runtime_launch(RuntimeCommand::CpuWorker, &ctx);
        match plan {
            RuntimeLaunchPlan::CpuWorker {
                cpu_worker_id,
                config_path,
            } => {
                assert_eq!(cpu_worker_id, Some(5));
                assert_eq!(config_path, Some(PathBuf::from("/custom/config")));
            }
            _ => panic!("expected CpuWorker variant"),
        }
    }

    #[test]
    fn cpu_worker_plan_defaults() {
        let ctx = base_context();
        let plan = plan_runtime_launch(RuntimeCommand::CpuWorker, &ctx);
        match plan {
            RuntimeLaunchPlan::CpuWorker {
                cpu_worker_id,
                config_path,
            } => {
                assert_eq!(cpu_worker_id, None);
                assert_eq!(config_path, None);
            }
            _ => panic!("expected CpuWorker variant"),
        }
    }

    // --- Unified server worker ---

    #[test]
    fn unified_worker_plan_preserves_all_fields() {
        let ctx = RuntimeLaunchContext {
            unified_worker_id: Some(3),
            config_path: Some(PathBuf::from("/data/config")),
            worker_threads: Some(8),
            cpu_affinity: Some(2),
            total_workers: Some(4),
            reuse_port: true,
            ..base_context()
        };

        let plan = plan_runtime_launch(RuntimeCommand::UnifiedServerWorker, &ctx);
        match plan {
            RuntimeLaunchPlan::UnifiedServerWorker {
                unified_worker_id,
                config_path,
                worker_threads,
                cpu_affinity,
                total_workers,
                reuse_port,
            } => {
                assert_eq!(unified_worker_id, Some(3));
                assert_eq!(config_path, Some(PathBuf::from("/data/config")));
                assert_eq!(worker_threads, 8);
                assert_eq!(cpu_affinity, Some(2));
                assert_eq!(total_workers, 4);
                assert!(reuse_port);
            }
            _ => panic!("expected UnifiedServerWorker variant"),
        }
    }

    #[test]
    fn unified_worker_plan_defaults_to_two_threads() {
        let ctx = base_context();
        let plan = plan_runtime_launch(RuntimeCommand::UnifiedServerWorker, &ctx);
        match plan {
            RuntimeLaunchPlan::UnifiedServerWorker {
                worker_threads,
                total_workers,
                reuse_port,
                ..
            } => {
                assert_eq!(worker_threads, 2);
                assert_eq!(total_workers, 1);
                assert!(!reuse_port);
            }
            _ => panic!("expected UnifiedServerWorker variant"),
        }
    }

    // --- Supervisor ---

    #[test]
    fn supervisor_plan_preserves_config_foreground_test_flags() {
        let ctx = RuntimeLaunchContext {
            config_path: Some(PathBuf::from("/srv/synvoid")),
            foreground: true,
            test_flags: Some(vec!["challenge-off".into()]),
            ..base_context()
        };

        let plan = plan_runtime_launch(RuntimeCommand::Supervisor, &ctx);
        match plan {
            RuntimeLaunchPlan::Supervisor {
                config_path,
                foreground,
                test_flags,
            } => {
                assert_eq!(config_path, Some(PathBuf::from("/srv/synvoid")));
                assert!(foreground);
                assert_eq!(test_flags, Some(vec!["challenge-off".into()]));
            }
            _ => panic!("expected Supervisor variant"),
        }
    }

    // --- Mesh agent ---

    #[test]
    fn mesh_agent_plan_preserves_config_and_foreground() {
        let ctx = RuntimeLaunchContext {
            config_path: Some(PathBuf::from("/mesh/config")),
            foreground: true,
            ..base_context()
        };

        let plan = plan_runtime_launch(RuntimeCommand::MeshAgent, &ctx);
        match plan {
            RuntimeLaunchPlan::MeshAgent {
                config_path,
                foreground,
            } => {
                assert_eq!(config_path, Some(PathBuf::from("/mesh/config")));
                assert!(foreground);
            }
            _ => panic!("expected MeshAgent variant"),
        }
    }

    #[test]
    fn mesh_agent_plan_uses_config_as_default_path() {
        let ctx = base_context();
        let plan = plan_runtime_launch(RuntimeCommand::MeshAgent, &ctx);
        match plan {
            RuntimeLaunchPlan::MeshAgent { config_path, .. } => {
                // Default is None; execute_runtime_launch will use "config"
                assert_eq!(config_path, None);
            }
            _ => panic!("expected MeshAgent variant"),
        }
    }

    // --- Jails ---

    #[test]
    fn wasm_jail_plan_is_unit() {
        let ctx = base_context();
        let plan = plan_runtime_launch(RuntimeCommand::WasmJail, &ctx);
        assert!(matches!(plan, RuntimeLaunchPlan::WasmJail));
    }

    #[test]
    fn yara_jail_plan_is_unit() {
        let ctx = base_context();
        let plan = plan_runtime_launch(RuntimeCommand::YaraJail, &ctx);
        assert!(matches!(plan, RuntimeLaunchPlan::YaraJail));
    }

    // --- Outcome ---

    #[test]
    fn outcome_completed_exits_zero() {
        assert_eq!(RuntimeLaunchOutcome::Completed.exit_code(), 0);
    }

    #[test]
    fn outcome_failed_exits_one() {
        assert_eq!(RuntimeLaunchOutcome::Failed("test".into()).exit_code(), 1);
    }

    // --- All modes covered ---

    #[test]
    fn all_runtime_commands_produce_valid_plan() {
        let ctx = RuntimeLaunchContext {
            config_path: Some(PathBuf::from("config")),
            foreground: false,
            test_flags: None,
            cpu_worker_id: Some(0),
            unified_worker_id: Some(0),
            worker_threads: Some(4),
            cpu_affinity: None,
            total_workers: Some(2),
            reuse_port: false,
        };

        let modes = [
            RuntimeCommand::Supervisor,
            RuntimeCommand::CpuWorker,
            RuntimeCommand::UnifiedServerWorker,
            RuntimeCommand::MeshAgent,
            RuntimeCommand::WasmJail,
            RuntimeCommand::YaraJail,
        ];

        for mode in modes {
            let plan = plan_runtime_launch(mode, &ctx);
            // Every plan should be constructible; no panics
            let _ = plan;
        }
    }
}
