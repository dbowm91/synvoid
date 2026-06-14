//! Mesh transport lifecycle types (Iteration 68, 70).
//!
//! Defines the state machine, task classification, startup staging,
//! and shutdown reporting types used to manage mesh transport lifecycle
//! transitions. These types decouple lifecycle policy from concrete
//! transport implementations.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::transport_core::MeshTransportError;

/// Globally unique task ID generator shared across task-group generations.
///
/// Each `MeshTransport` owns one `Arc<MeshTaskIdGenerator>` and passes it
/// into every new `MeshTaskGroup`, ensuring no two events on the stable
/// exit channel share the same ID during process lifetime.
pub struct MeshTaskIdGenerator {
    seq: AtomicU64,
}

impl MeshTaskIdGenerator {
    /// Create a new generator starting at zero.
    pub fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
        }
    }

    /// Allocate the next globally unique task ID.
    pub fn next(&self) -> MeshTaskId {
        MeshTaskId(self.seq.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for MeshTaskIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a mesh task, assigned at spawn time.
///
/// IDs are globally unique across task-group generations when allocated
/// via `MeshTaskIdGenerator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MeshTaskId(pub u64);

impl Default for MeshTaskId {
    fn default() -> Self {
        Self(0)
    }
}

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshTaskExit {
    /// Unique identifier for the task, assigned at spawn time.
    pub id: MeshTaskId,
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
    /// **Non-authoritative**: currently always zero because the accept loop
    /// does not publish its report. Will be wired in a future iteration.
    pub drained_peer_children: usize,
    /// Number of bounded peer children that were aborted.
    /// **Non-authoritative**: currently always zero because the accept loop
    /// does not publish its report. Will be wired in a future iteration.
    pub aborted_peer_children: usize,
    /// Number of peers remaining after shutdown (should be zero for clean shutdown).
    pub remaining_peers: usize,
    /// Number of peers present at shutdown start (before drain).
    pub peers_at_shutdown_start: usize,
    /// Number of peer sessions that drained cleanly.
    pub drained_peer_sessions: usize,
    /// Number of peer sessions that were forcibly aborted.
    pub aborted_peer_sessions: usize,
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
            peers_at_shutdown_start: 0,
            drained_peer_sessions: 0,
            aborted_peer_sessions: 0,
        }
    }
}

/// Policy for classifying bootstrap failures during mesh startup.
#[derive(Debug, Clone)]
pub struct MeshStartupPolicy {
    /// If true, seed bootstrap failure is fatal (required for non-genesis nodes).
    pub require_seed_connectivity: bool,
    /// If true, configured peer connection failure is fatal.
    pub require_configured_peers: bool,
    /// If true, DHT bootstrap failure is fatal (required for node role).
    pub require_dht_bootstrap: bool,
}

impl Default for MeshStartupPolicy {
    fn default() -> Self {
        Self {
            require_seed_connectivity: false,
            require_configured_peers: false,
            require_dht_bootstrap: false,
        }
    }
}

/// Report of mesh startup outcomes.
#[derive(Debug, Clone, Default)]
pub struct MeshStartupReport {
    /// Non-fatal reasons the mesh is in a degraded state.
    pub degraded_reasons: Vec<String>,
    /// Number of seeds successfully connected.
    pub connected_seed_count: usize,
    /// Number of configured peers successfully connected.
    pub connected_configured_peer_count: usize,
    /// Whether DHT bootstrap succeeded.
    pub dht_bootstrapped: bool,
}

/// Report from the mesh accept loop about child task drainage.
///
/// Currently deferred — fields are not wired into the accept loop.
/// Values will always be zero. Do not rely on these for correctness
/// decisions until the accept loop publishes its report.
#[derive(Debug, Clone, Default)]
pub struct MeshAcceptLoopReport {
    /// Number of handshake children that drained cleanly.
    /// **Deferred**: always zero until accept-loop reporting is wired.
    pub drained_handshakes: usize,
    /// Number of handshake children that were forcibly aborted.
    /// **Deferred**: always zero until accept-loop reporting is wired.
    pub aborted_handshakes: usize,
    /// Number of connections rejected at capacity.
    /// **Deferred**: always zero until accept-loop reporting is wired.
    pub rejected_at_capacity: usize,
}

/// Records a single peer mutation created during startup, used for
/// precise rollback.
#[derive(Debug, Clone)]
pub struct StagedPeerResource {
    /// Session identifier for the peer connection.
    pub session_id: String,
    /// Node identifier for the peer.
    pub node_id: String,
    /// Whether a topology entry existed before this startup attempt.
    pub topology_existed_before: bool,
    /// Whether the connection was inserted into the connection map.
    pub connection_inserted: bool,
    /// Whether a session task was spawned.
    pub session_task_created: bool,
}

/// Report from a startup rollback attempt.
#[derive(Debug, Clone)]
pub struct RollbackReport {
    /// Whether the rollback completed without errors.
    pub clean: bool,
    /// Errors encountered during rollback (may be partial).
    pub errors: Vec<String>,
    /// Number of staged tasks that completed during rollback.
    pub tasks_joined: usize,
    /// Number of staged tasks that were still active after join timeout.
    pub tasks_aborted: usize,
    /// Number of peer connections closed during rollback.
    pub peer_connections_closed: usize,
    /// Number of topology entries restored (best-effort) during rollback.
    pub topology_entries_restored: usize,
    /// Number of peer sessions cleaned up during rollback.
    pub peer_sessions_cleaned: usize,
    /// Whether the runtime was marked as stopped during rollback.
    pub runtime_stopped: bool,
}

impl Default for RollbackReport {
    fn default() -> Self {
        Self {
            clean: true,
            errors: Vec::new(),
            tasks_joined: 0,
            tasks_aborted: 0,
            peer_connections_closed: 0,
            topology_entries_restored: 0,
            peer_sessions_cleaned: 0,
            runtime_stopped: false,
        }
    }
}

/// Tracks resources created during a single mesh startup attempt.
///
/// Every task and resource created between the first task spawn and the
/// lifecycle commit is owned by the stage. On success, the stage is
/// committed (transferring ownership to `MeshTransport`). On failure,
/// the stage is rolled back (cancelling tasks, closing connections,
/// and cleaning up topology state).
///
/// The stage is never dropped without explicit rollback or commit.
pub struct MeshStartupStage {
    /// The staged task group being built during startup.
    pub(crate) task_group: crate::task_group::MeshTaskGroup,
    /// Peer resources created during this startup attempt.
    pub(crate) created_peers: Vec<StagedPeerResource>,
    /// Whether the QUIC runtime was started during this attempt.
    pub(crate) runtime_started: bool,
    /// Whether this stage has been committed to the transport.
    pub(crate) committed: bool,
}

impl MeshStartupStage {
    /// Create a new stage with a fresh task group.
    pub fn new(task_group: crate::task_group::MeshTaskGroup) -> Self {
        Self {
            task_group,
            created_peers: Vec::new(),
            runtime_started: false,
            committed: false,
        }
    }

    /// Record a peer resource created during this attempt.
    pub fn record_peer(&mut self, resource: StagedPeerResource) {
        self.created_peers.push(resource);
    }

    /// Record a peer session created during this attempt (compatibility wrapper).
    ///
    /// Creates a `StagedPeerResource` with conservative defaults for callers
    /// that don't yet provide full resource metadata.
    pub fn record_peer_session(&mut self, session_id: String, node_id: String) {
        self.record_peer(StagedPeerResource {
            session_id,
            node_id,
            topology_existed_before: false,
            connection_inserted: true,
            session_task_created: true,
        });
    }

    /// Mark the runtime as started.
    pub fn mark_runtime_started(&mut self) {
        self.runtime_started = true;
    }

    /// Whether this stage has been committed.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Whether this stage has created any resources.
    pub fn has_resources(&self) -> bool {
        self.runtime_started || !self.created_peers.is_empty()
    }
}

/// Compute the remaining time until a deadline, returning `Duration::ZERO`
/// if the deadline has already passed.
pub fn remaining(deadline: std::time::Instant) -> Duration {
    deadline.saturating_duration_since(std::time::Instant::now())
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
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(exit.is_fatal());

        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Error("bind failed".into()),
        };
        assert!(exit.is_fatal());

        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Panic("overflow".into()),
        };
        assert!(exit.is_fatal());

        // Non-critical task exits are never fatal
        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "bg_sync",
            class: MeshTaskClass::RestartableBackground,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(!exit.is_fatal());

        // Clean completion is never fatal
        let exit = MeshTaskExit {
            id: MeshTaskId(0),
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
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(exit.is_pre_shutdown(false));

        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Cancelled,
        };
        assert!(!exit.is_pre_shutdown(false));

        // After shutdown: only UnexpectedCompletion is pre-shutdown
        let exit = MeshTaskExit {
            id: MeshTaskId(0),
            name: "server_run",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::UnexpectedCompletion,
        };
        assert!(exit.is_pre_shutdown(true));

        let exit = MeshTaskExit {
            id: MeshTaskId(0),
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
        assert_eq!(report.peers_at_shutdown_start, 0);
        assert_eq!(report.drained_peer_sessions, 0);
        assert_eq!(report.aborted_peer_sessions, 0);
    }

    #[test]
    fn lifecycle_display() {
        assert_eq!(MeshLifecycleState::Stopped.to_string(), "stopped");
        assert_eq!(MeshLifecycleState::Starting.to_string(), "starting");
        assert_eq!(MeshLifecycleState::Running.to_string(), "running");
        assert_eq!(MeshLifecycleState::Stopping.to_string(), "stopping");
        assert_eq!(MeshLifecycleState::Failed.to_string(), "failed");
    }

    #[test]
    fn staged_peer_resource_fields() {
        let resource = StagedPeerResource {
            session_id: "sess-1".to_string(),
            node_id: "node-1".to_string(),
            topology_existed_before: false,
            connection_inserted: true,
            session_task_created: true,
        };
        assert_eq!(resource.session_id, "sess-1");
        assert_eq!(resource.node_id, "node-1");
        assert!(!resource.topology_existed_before);
        assert!(resource.connection_inserted);
        assert!(resource.session_task_created);
    }

    #[test]
    fn rollback_report_expanded_defaults() {
        let report = RollbackReport::default();
        assert!(report.clean);
        assert!(report.errors.is_empty());
        assert_eq!(report.tasks_joined, 0);
        assert_eq!(report.tasks_aborted, 0);
        assert_eq!(report.peer_connections_closed, 0);
        assert_eq!(report.topology_entries_restored, 0);
        assert_eq!(report.peer_sessions_cleaned, 0);
        assert!(!report.runtime_stopped);
    }

    #[test]
    fn startup_stage_record_peer() {
        let tg = crate::task_group::MeshTaskGroup::new();
        let mut stage = MeshStartupStage::new(tg);

        stage.record_peer(StagedPeerResource {
            session_id: "sess-1".to_string(),
            node_id: "node-1".to_string(),
            topology_existed_before: false,
            connection_inserted: true,
            session_task_created: true,
        });

        assert_eq!(stage.created_peers.len(), 1);
        assert_eq!(stage.created_peers[0].session_id, "sess-1");
        assert!(stage.has_resources());
    }
}
