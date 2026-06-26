// SAFETY_REASON: Supervisor shutdown cause taxonomy - classifies lifecycle termination reasons

use std::fmt;

/// Taxonomy of reasons the supervisor process may shut down.
///
/// Used for structured logging, metric labeling, and exit-code determination.
/// Fatal causes (all except `Requested` and `DrainTimeout`) should trigger
/// process restart or operator alerting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorShutdownCause {
    /// Clean shutdown requested via signal or admin command.
    Requested,
    /// The IPC accept loop failed (e.g., socket error).
    IpcListenerFailed(String),
    /// The gRPC control API failed.
    ControlApiFailed(String),
    /// A worker health check returned a fatal status.
    WorkerHealthFatal(String),
    /// The process manager encountered an unrecoverable error.
    ProcessManagerFailed(String),
    /// Drain timed out before all workers finished draining.
    DrainTimeout,
    /// A registered background task failed unexpectedly.
    TaskFailed { task: &'static str, reason: String },
    /// An internal invariant was violated (programming error).
    InternalInvariant(String),
}

impl SupervisorShutdownCause {
    /// Returns `true` if this cause represents a fatal error requiring restart.
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Self::Requested | Self::DrainTimeout)
    }

    /// Returns a snake_case metric label for this cause.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::IpcListenerFailed(_) => "ipc_listener_failed",
            Self::ControlApiFailed(_) => "control_api_failed",
            Self::WorkerHealthFatal(_) => "worker_health_fatal",
            Self::ProcessManagerFailed(_) => "process_manager_failed",
            Self::DrainTimeout => "drain_timeout",
            Self::TaskFailed { .. } => "task_failed",
            Self::InternalInvariant(_) => "internal_invariant",
        }
    }
}

impl fmt::Display for SupervisorShutdownCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => write!(f, "requested"),
            Self::IpcListenerFailed(msg) => write!(f, "ipc_listener_failed: {}", msg),
            Self::ControlApiFailed(msg) => write!(f, "control_api_failed: {}", msg),
            Self::WorkerHealthFatal(msg) => write!(f, "worker_health_fatal: {}", msg),
            Self::ProcessManagerFailed(msg) => write!(f, "process_manager_failed: {}", msg),
            Self::DrainTimeout => write!(f, "drain_timeout"),
            Self::TaskFailed { task, reason } => {
                write!(f, "task_failed({}): {}", task, reason)
            }
            Self::InternalInvariant(msg) => write!(f, "internal_invariant: {}", msg),
        }
    }
}

/// Summary of a drain cycle outcome.
#[derive(Debug, Default)]
pub struct SupervisorDrainReport {
    pub drain_id: u64,
    pub worker_count: usize,
    pub drained: usize,
    pub timed_out: usize,
    pub errored: usize,
    pub forced_shutdown: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_cause_is_fatal() {
        // Non-fatal causes
        assert!(!SupervisorShutdownCause::Requested.is_fatal());
        assert!(!SupervisorShutdownCause::DrainTimeout.is_fatal());

        // Fatal causes
        assert!(SupervisorShutdownCause::IpcListenerFailed("test".into()).is_fatal());
        assert!(SupervisorShutdownCause::ControlApiFailed("test".into()).is_fatal());
        assert!(SupervisorShutdownCause::WorkerHealthFatal("test".into()).is_fatal());
        assert!(SupervisorShutdownCause::ProcessManagerFailed("test".into()).is_fatal());
        assert!(SupervisorShutdownCause::TaskFailed {
            task: "test",
            reason: "test".into()
        }
        .is_fatal());
        assert!(SupervisorShutdownCause::InternalInvariant("test".into()).is_fatal());
    }

    #[test]
    fn test_shutdown_cause_metric_label() {
        assert_eq!(
            SupervisorShutdownCause::Requested.metric_label(),
            "requested"
        );
        assert_eq!(
            SupervisorShutdownCause::IpcListenerFailed(String::new()).metric_label(),
            "ipc_listener_failed"
        );
        assert_eq!(
            SupervisorShutdownCause::ControlApiFailed(String::new()).metric_label(),
            "control_api_failed"
        );
        assert_eq!(
            SupervisorShutdownCause::WorkerHealthFatal(String::new()).metric_label(),
            "worker_health_fatal"
        );
        assert_eq!(
            SupervisorShutdownCause::ProcessManagerFailed(String::new()).metric_label(),
            "process_manager_failed"
        );
        assert_eq!(
            SupervisorShutdownCause::DrainTimeout.metric_label(),
            "drain_timeout"
        );
        assert_eq!(
            SupervisorShutdownCause::TaskFailed {
                task: "foo",
                reason: String::new()
            }
            .metric_label(),
            "task_failed"
        );
        assert_eq!(
            SupervisorShutdownCause::InternalInvariant(String::new()).metric_label(),
            "internal_invariant"
        );
    }

    #[test]
    fn test_drain_report_defaults() {
        let report = SupervisorDrainReport::default();
        assert_eq!(report.drain_id, 0);
        assert_eq!(report.worker_count, 0);
        assert_eq!(report.drained, 0);
        assert_eq!(report.timed_out, 0);
        assert_eq!(report.errored, 0);
        assert!(!report.forced_shutdown);
    }
}
