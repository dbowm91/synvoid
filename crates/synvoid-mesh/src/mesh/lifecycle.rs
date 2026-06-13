//! Mesh transport lifecycle types (Iteration 68).
//!
//! Defines the state machine, task classification, and shutdown reporting
//! types used to manage mesh transport lifecycle transitions. These types
//! decouple lifecycle policy from concrete transport implementations.

use std::fmt;

use crate::transport_core::MeshTransportError;

/// Classification of mesh tasks by criticality and restart behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeshTaskClass {
    /// Core services that must be running for the mesh to function.
    /// A fatal exit triggers process shutdown.
    CriticalService,
    /// Background tasks that can be restarted on failure without
    /// affecting the overall mesh health.
    RestartableBackground,
    /// Short-lived child tasks with bounded lifetime (e.g., peer
    /// handler tasks). Completion is expected.
    BoundedChild,
    /// One-shot tasks that run during startup and complete once
    /// (e.g., bootstrap, initial sync).
    OneShotStartup,
}

impl MeshTaskClass {
    /// Returns a human-readable label for this task class.
    pub fn label(&self) -> &'static str {
        match self {
            MeshTaskClass::CriticalService => "critical-service",
            MeshTaskClass::RestartableBackground => "restartable-background",
            MeshTaskClass::BoundedChild => "bounded-child",
            MeshTaskClass::OneShotStartup => "one-shot-startup",
        }
    }
}

/// Reason a mesh task exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshTaskExitReason {
    /// Task completed successfully.
    CleanCompletion,
    /// Task was cancelled during shutdown.
    Cancelled,
    /// Task exited before shutdown was signaled.
    UnexpectedCompletion,
    /// Task exited with a recoverable error.
    Error(String),
    /// Task panicked.
    Panic(String),
    /// Task was forcibly aborted.
    Aborted,
}

impl fmt::Display for MeshTaskExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeshTaskExitReason::CleanCompletion => write!(f, "clean completion"),
            MeshTaskExitReason::Cancelled => write!(f, "cancelled"),
            MeshTaskExitReason::UnexpectedCompletion => write!(f, "unexpected completion"),
            MeshTaskExitReason::Error(msg) => write!(f, "error: {msg}"),
            MeshTaskExitReason::Panic(msg) => write!(f, "panic: {msg}"),
            MeshTaskExitReason::Aborted => write!(f, "aborted"),
        }
    }
}

/// Metadata for a mesh task exit event.
#[derive(Debug, Clone)]
pub struct MeshTaskExit {
    /// Static name identifying the task.
    pub name: &'static str,
    /// Classification of the task.
    pub class: MeshTaskClass,
    /// Reason the task exited.
    pub reason: MeshTaskExitReason,
}

impl MeshTaskExit {
    /// Returns `true` if this exit is considered fatal for the mesh process.
    ///
    /// A critical-service task that exits with `UnexpectedCompletion`,
    /// `Error`, or `Panic` is fatal — it indicates the mesh cannot
    /// continue operating without intervention.
    pub fn is_fatal(&self) -> bool {
        matches!(self.class, MeshTaskClass::CriticalService)
            && matches!(
                self.reason,
                MeshTaskExitReason::UnexpectedCompletion
                    | MeshTaskExitReason::Error(_)
                    | MeshTaskExitReason::Panic(_)
            )
    }

    /// Returns `true` if this task completed before shutdown was signaled.
    ///
    /// When `shutdown_started` is `false`, any non-cancelled exit
    /// is pre-shutdown. When `shutdown_started` is `true`, only
    /// `UnexpectedCompletion` qualifies as pre-shutdown (it exited
    /// before the cancel signal reached it).
    pub fn is_pre_shutdown(&self, shutdown_started: bool) -> bool {
        if shutdown_started {
            matches!(self.reason, MeshTaskExitReason::UnexpectedCompletion)
        } else {
            !matches!(self.reason, MeshTaskExitReason::Cancelled)
        }
    }
}

/// Lifecycle state machine for the mesh transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLifecycleState {
    /// Transport is fully stopped.
    Stopped,
    /// Transport is transitioning from stopped to running.
    Starting,
    /// Transport is actively running.
    Running,
    /// Transport is transitioning from running to stopped.
    Stopping,
    /// Transport failed and requires manual or automatic recovery.
    Failed,
}

impl fmt::Display for MeshLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeshLifecycleState::Stopped => write!(f, "stopped"),
            MeshLifecycleState::Starting => write!(f, "starting"),
            MeshLifecycleState::Running => write!(f, "running"),
            MeshLifecycleState::Stopping => write!(f, "stopping"),
            MeshLifecycleState::Failed => write!(f, "failed"),
        }
    }
}

impl MeshLifecycleState {
    /// Returns `true` if the transport can transition to `Starting`.
    ///
    /// Allowed from `Stopped` (initial start) or `Failed` (restart after rollback).
    pub fn can_start(&self) -> bool {
        matches!(
            self,
            MeshLifecycleState::Stopped | MeshLifecycleState::Failed
        )
    }

    /// Returns `true` if the transport can transition to `Stopping`.
    ///
    /// Only allowed from `Running`.
    pub fn can_stop(&self) -> bool {
        matches!(self, MeshLifecycleState::Running)
    }

    /// Transition from `Stopped` or `Failed` to `Starting`.
    pub fn transition_to_starting(&mut self) -> Result<(), MeshTransportError> {
        if !self.can_start() {
            return Err(MeshTransportError::NotAvailable);
        }
        *self = MeshLifecycleState::Starting;
        Ok(())
    }

    /// Transition from `Starting` to `Running`.
    pub fn transition_to_running(&mut self) -> Result<(), MeshTransportError> {
        if !matches!(self, MeshLifecycleState::Starting) {
            return Err(MeshTransportError::NotAvailable);
        }
        *self = MeshLifecycleState::Running;
        Ok(())
    }

    /// Transition from `Running` to `Stopping`.
    pub fn transition_to_stopping(&mut self) -> Result<(), MeshTransportError> {
        if !self.can_stop() {
            return Err(MeshTransportError::NotAvailable);
        }
        *self = MeshLifecycleState::Stopping;
        Ok(())
    }

    /// Transition to `Stopped` from any state.
    pub fn transition_to_stopped(&mut self) {
        *self = MeshLifecycleState::Stopped;
    }

    /// Transition to `Failed` from any state.
    pub fn transition_to_failed(&mut self) {
        *self = MeshLifecycleState::Failed;
    }
}

/// Report generated after a mesh transport shutdown sequence.
#[derive(Debug, Clone)]
pub struct MeshShutdownReport {
    /// Number of tasks that exited cleanly.
    pub clean_tasks: usize,
    /// Tasks that exited with an error (non-fatal).
    pub failed_tasks: Vec<MeshTaskExit>,
    /// Tasks that were forcibly aborted.
    pub aborted_tasks: Vec<MeshTaskExit>,
    /// Number of bounded peer children that drained cleanly.
    pub drained_peer_children: usize,
    /// Number of bounded peer children that were aborted.
    pub aborted_peer_children: usize,
    /// Number of peers remaining after shutdown (should be zero for clean shutdown).
    pub remaining_peers: usize,
}

impl Default for MeshShutdownReport {
    fn default() -> Self {
        Self {
            clean_tasks: 0,
            failed_tasks: Vec::new(),
            aborted_tasks: Vec::new(),
            drained_peer_children: 0,
            aborted_peer_children: 0,
            remaining_peers: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_class_labels() {
        assert_eq!(MeshTaskClass::CriticalService.label(), "critical-service");
        assert_eq!(
            MeshTaskClass::RestartableBackground.label(),
            "restartable-background"
        );
        assert_eq!(MeshTaskClass::BoundedChild.label(), "bounded-child");
        assert_eq!(MeshTaskClass::OneShotStartup.label(), "one-shot-startup");
    }

    #[test]
    fn exit_reason_display() {
        assert_eq!(
            MeshTaskExitReason::CleanCompletion.to_string(),
            "clean completion"
        );
        assert_eq!(
            MeshTaskExitReason::Error("timeout".into()).to_string(),
            "error: timeout"
        );
        assert_eq!(
            MeshTaskExitReason::Panic("overflow".into()).to_string(),
            "panic: overflow"
        );
    }

    #[test]
    fn lifecycle_can_start() {
        assert!(MeshLifecycleState::Stopped.can_start());
        assert!(MeshLifecycleState::Failed.can_start());
        assert!(!MeshLifecycleState::Starting.can_start());
        assert!(!MeshLifecycleState::Running.can_start());
        assert!(!MeshLifecycleState::Stopping.can_start());
    }

    #[test]
    fn lifecycle_can_stop() {
        assert!(MeshLifecycleState::Running.can_stop());
        assert!(!MeshLifecycleState::Stopped.can_stop());
        assert!(!MeshLifecycleState::Starting.can_stop());
        assert!(!MeshLifecycleState::Stopping.can_stop());
        assert!(!MeshLifecycleState::Failed.can_stop());
    }

    #[test]
    fn lifecycle_transitions() {
        let mut state = MeshLifecycleState::Stopped;

        state.transition_to_starting().unwrap();
        assert_eq!(state, MeshLifecycleState::Starting);

        state.transition_to_running().unwrap();
        assert_eq!(state, MeshLifecycleState::Running);

        state.transition_to_stopping().unwrap();
        assert_eq!(state, MeshLifecycleState::Stopping);

        state.transition_to_stopped();
        assert_eq!(state, MeshLifecycleState::Stopped);
    }

    #[test]
    fn lifecycle_transition_to_failed() {
        let mut state = MeshLifecycleState::Running;
        state.transition_to_failed();
        assert_eq!(state, MeshLifecycleState::Failed);
    }

    #[test]
    fn lifecycle_invalid_transitions() {
        let mut state = MeshLifecycleState::Running;
        assert!(state.transition_to_starting().is_err());

        let mut state = MeshLifecycleState::Starting;
        assert!(state.transition_to_stopping().is_err());
        // Starting -> Running is valid, so this should succeed
        assert!(state.transition_to_running().is_ok());

        let mut state = MeshLifecycleState::Stopped;
        assert!(state.transition_to_running().is_err());
        assert!(state.transition_to_stopping().is_err());
    }

    #[test]
    fn exit_fatal() {
        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(exit.is_fatal());

        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Error("bind failed".into()),
        };
        assert!(exit.is_fatal());

        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Panic("overflow".into()),
        };
        assert!(exit.is_fatal());

        // Non-critical task exits are never fatal
        let exit = MeshTaskExit {
            name: "bg_sync",
            class: MeshTaskClass::RestartableBackground,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(!exit.is_fatal());

        // Clean completion is never fatal
        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::CleanCompletion,
        };
        assert!(!exit.is_fatal());
    }

    #[test]
    fn exit_pre_shutdown() {
        // Before shutdown: non-cancelled exits are pre-shutdown
        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(exit.is_pre_shutdown(false));

        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Cancelled,
        };
        assert!(!exit.is_pre_shutdown(false));

        // After shutdown: only UnexpectedCompletion is pre-shutdown
        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(exit.is_pre_shutdown(true));

        let exit = MeshTaskExit {
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Error("timeout".into()),
        };
        assert!(!exit.is_pre_shutdown(true));
    }

    #[test]
    fn shutdown_report_default() {
        let report = MeshShutdownReport::default();
        assert_eq!(report.clean_tasks, 0);
        assert!(report.failed_tasks.is_empty());
        assert!(report.aborted_tasks.is_empty());
        assert_eq!(report.drained_peer_children, 0);
        assert_eq!(report.aborted_peer_children, 0);
        assert_eq!(report.remaining_peers, 0);
    }

    #[test]
    fn lifecycle_display() {
        assert_eq!(MeshLifecycleState::Stopped.to_string(), "stopped");
        assert_eq!(MeshLifecycleState::Starting.to_string(), "starting");
        assert_eq!(MeshLifecycleState::Running.to_string(), "running");
        assert_eq!(MeshLifecycleState::Stopping.to_string(), "stopping");
        assert_eq!(MeshLifecycleState::Failed.to_string(), "failed");
    }
}
