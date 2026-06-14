//! Worker-facing contract for mesh lifecycle management (Phase 14-15).
//!
//! Defines the `ManagedMeshService` trait that decouples worker supervision
//! from concrete mesh transport internals, and the `MeshFailureCause` type
//! that maps mesh task failures into worker-level shutdown causes.

use std::time::Duration;

use tokio::sync::broadcast;

use crate::lifecycle::{MeshShutdownReport, MeshTaskExit};
use crate::transport_core::MeshTransportError;

/// Worker-facing trait for managing mesh transport lifecycle.
///
/// This trait provides a narrow contract for worker-level code to observe
/// and control the mesh transport without depending on concrete internals.
pub trait ManagedMeshService: Send + Sync {
    /// Subscribe to critical mesh task exits before starting.
    ///
    /// The returned receiver will receive `MeshTaskExit` events for every
    /// task spawned by the mesh task group. Workers should call this before
    /// `start()` to avoid missing early exit events.
    fn subscribe_critical_exits(&self) -> broadcast::Receiver<MeshTaskExit>;

    /// Start the mesh transport.
    ///
    /// Transitions the transport from `Stopped` or `Failed` into `Running`.
    /// Returns an error if the transport is already starting/running.
    async fn start(&self) -> Result<(), MeshTransportError>;

    /// Perform a bounded shutdown with the given timeout.
    ///
    /// Returns a report describing which tasks were cleanly joined, which
    /// were aborted, and peer-child drainage statistics.
    async fn shutdown(&self, timeout: Duration) -> MeshShutdownReport;

    /// Check if the mesh is currently running.
    fn is_running(&self) -> bool;
}

/// Health status of the mesh service, as observed by the worker.
pub enum MeshServiceHealth {
    /// All critical services are running.
    Healthy,
    /// The mesh is running but one or more non-critical tasks have failed.
    Degraded {
        /// Human-readable reason for the degraded state.
        reason: String,
    },
    /// A critical service has exited, or startup/shutdown failed.
    Failed {
        /// The exit event that caused the failure.
        exit: MeshTaskExit,
    },
}

/// Maps mesh task failures into worker-level shutdown causes.
///
/// Workers use this type to classify mesh failures into actionable shutdown
/// decisions (e.g., process restart, alert, degraded mode).
pub enum MeshFailureCause {
    /// A critical mesh service exited unexpectedly.
    CriticalServiceExit(MeshTaskExit),
    /// Startup failed and was rolled back.
    StartupFailed(String),
    /// Shutdown timed out with remaining tasks.
    ShutdownTimeout {
        /// Tasks that were forcibly aborted.
        aborted_tasks: Vec<MeshTaskExit>,
        /// Number of peers still connected when shutdown timed out.
        remaining_peers: usize,
    },
}

impl MeshFailureCause {
    /// Returns the task name associated with this failure.
    ///
    /// For `StartupFailed` and `ShutdownTimeout`, returns a synthetic label.
    pub fn task_name(&self) -> &str {
        match self {
            MeshFailureCause::CriticalServiceExit(exit) => exit.name,
            MeshFailureCause::StartupFailed(_) => "mesh_startup",
            MeshFailureCause::ShutdownTimeout { .. } => "mesh_shutdown",
        }
    }

    /// Returns a human-readable description of the exit reason.
    pub fn exit_reason(&self) -> String {
        match self {
            MeshFailureCause::CriticalServiceExit(exit) => exit.reason.to_string(),
            MeshFailureCause::StartupFailed(msg) => format!("startup failed: {msg}"),
            MeshFailureCause::ShutdownTimeout {
                aborted_tasks,
                remaining_peers,
            } => {
                format!(
                    "shutdown timed out: {} tasks aborted, {} peers remaining",
                    aborted_tasks.len(),
                    remaining_peers
                )
            }
        }
    }

    /// Returns `true` if this failure should trigger a process-level restart.
    ///
    /// Critical service exits and startup failures are fatal. Shutdown
    /// timeouts are also considered fatal because they indicate the mesh
    /// could not drain gracefully.
    pub fn is_fatal(&self) -> bool {
        match self {
            MeshFailureCause::CriticalServiceExit(exit) => exit.is_fatal(),
            MeshFailureCause::StartupFailed(_) => true,
            MeshFailureCause::ShutdownTimeout { .. } => true,
        }
    }
}

#[cfg(feature = "dns")]
impl ManagedMeshService for std::sync::Arc<crate::transport::MeshTransport> {
    fn subscribe_critical_exits(&self) -> broadcast::Receiver<MeshTaskExit> {
        self.subscribe_exits()
    }

    async fn start(&self) -> Result<(), MeshTransportError> {
        crate::transport::MeshTransport::start(self).await
    }

    async fn shutdown(&self, timeout: Duration) -> MeshShutdownReport {
        self.shutdown_with_timeout(timeout).await
    }

    fn is_running(&self) -> bool {
        let state = self.lifecycle_state.blocking_lock();
        matches!(*state, crate::lifecycle::MeshLifecycleState::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{MeshTaskClass, MeshTaskExitReason, MeshTaskId};

    #[test]
    fn failure_cause_task_name() {
        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        let cause = MeshFailureCause::CriticalServiceExit(exit);
        assert_eq!(cause.task_name(), "server_run");

        let cause = MeshFailureCause::StartupFailed("bind failed".into());
        assert_eq!(cause.task_name(), "mesh_startup");

        let cause = MeshFailureCause::ShutdownTimeout {
            aborted_tasks: vec![],
            remaining_peers: 2,
        };
        assert_eq!(cause.task_name(), "mesh_shutdown");
    }

    #[test]
    fn failure_cause_exit_reason() {
        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Panic("overflow".into()),
        };
        let cause = MeshFailureCause::CriticalServiceExit(exit);
        assert_eq!(cause.exit_reason(), "panic: overflow");

        let cause = MeshFailureCause::StartupFailed("port in use".into());
        assert_eq!(cause.exit_reason(), "startup failed: port in use");

        let cause = MeshFailureCause::ShutdownTimeout {
            aborted_tasks: vec![MeshTaskExit {
                id: MeshTaskId(0),
                name: "bg_sync",
                class: MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::Aborted,
            }],
            remaining_peers: 1,
        };
        assert_eq!(
            cause.exit_reason(),
            "shutdown timed out: 1 tasks aborted, 1 peers remaining"
        );
    }

    #[test]
    fn failure_cause_is_fatal() {
        // Critical service exit with fatal reason
        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        let cause = MeshFailureCause::CriticalServiceExit(exit);
        assert!(cause.is_fatal());

        // Critical service exit with non-fatal reason
        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::CleanCompletion,
        };
        let cause = MeshFailureCause::CriticalServiceExit(exit);
        assert!(!cause.is_fatal());

        // Startup failure is always fatal
        let cause = MeshFailureCause::StartupFailed("bind".into());
        assert!(cause.is_fatal());

        // Shutdown timeout is always fatal
        let cause = MeshFailureCause::ShutdownTimeout {
            aborted_tasks: vec![],
            remaining_peers: 0,
        };
        assert!(cause.is_fatal());
    }

    #[test]
    fn mesh_service_health_variants() {
        let healthy = MeshServiceHealth::Healthy;
        match healthy {
            MeshServiceHealth::Healthy => {}
            _ => panic!("expected Healthy"),
        }

        let degraded = MeshServiceHealth::Degraded {
            reason: "peer health check failing".into(),
        };
        match &degraded {
            MeshServiceHealth::Degraded { reason } => {
                assert_eq!(reason, "peer health check failing");
            }
            _ => panic!("expected Degraded"),
        }

        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "datagram_listener",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Error("bind failed".into()),
        };
        let failed = MeshServiceHealth::Failed { exit };
        match &failed {
            MeshServiceHealth::Failed { exit } => {
                assert_eq!(exit.name, "datagram_listener");
            }
            _ => panic!("expected Failed"),
        }
    }
}
