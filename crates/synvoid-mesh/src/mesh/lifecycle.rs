//! Mesh transport lifecycle types (Iteration 68, 70, 71, 73).
//!
//! Defines the state machine, task classification, startup staging,
//! and shutdown reporting types used to manage mesh transport lifecycle
//! transitions. These types decouple lifecycle policy from concrete
//! transport implementations.
//!
//! Iteration 73 corrects semantic mismatches:
//! - Non-empty task-group replacement is a hard failure (Phase 1)
//! - Topology snapshots are captured before mutation (Phase 2-3)
//! - DHT mutations are tracked explicitly, not inferred (Phase 4-6)
//! - Recovery consumes its timeout and verifies all registries (Phase 7-9)
//! - Cooperative deadline is separated from forced abort (Phase 10-12)
//! - Steady-state preflight is transport-owned (Phase 13-14)
//! - Peer-session completion is reaped (Phase 15-18)
//! - Shutdown reports distinguish drained/aborted/failed sessions (Phase 17)

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
    /// Only allowed from `Stopped`. `Failed` requires explicit recovery
    /// via `recover_failed_state()` before a new startup attempt.
    pub fn can_start(&self) -> bool {
        matches!(self, MeshLifecycleState::Stopped)
    }

    /// Returns `true` if the transport can transition to `Stopping`.
    ///
    /// Only allowed from `Running`.
    pub fn can_stop(&self) -> bool {
        matches!(self, MeshLifecycleState::Running)
    }

    /// Transition from `Stopped` to `Starting`.
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
    /// Number of peers present at shutdown start (before drain).
    pub peers_at_shutdown_start: usize,
    /// Number of peer sessions that drained cleanly.
    pub drained_peer_sessions: usize,
    /// Number of peer sessions that were forcibly aborted.
    pub aborted_peer_sessions: usize,
    /// Number of peer sessions that failed (panic or unexpected error).
    pub failed_peer_sessions: usize,
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
            failed_peer_sessions: 0,
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
/// Populated during shutdown when the accept loop drains its child tasks.
#[derive(Debug, Clone, Default)]
pub struct MeshAcceptLoopReport {
    /// Number of handshake children that drained cleanly.
    pub drained_handshakes: usize,
    /// Number of handshake children that were forcibly aborted.
    pub aborted_handshakes: usize,
    /// Number of connections rejected at capacity.
    pub rejected_at_capacity: usize,
    /// Generation counter to distinguish reports across startup cycles.
    pub generation: u64,
}

/// A tracked peer session task with its identity and handle (Iteration 73, Phase 18).
pub struct PeerSessionTask {
    /// Session identifier for this peer connection.
    pub session_id: String,
    /// Node identifier for the peer.
    pub node_id: String,
    /// Join handle for the session task.
    pub handle: tokio::task::JoinHandle<()>,
    /// Generation counter to prevent stale completions from removing newer entries.
    pub generation: u64,
}

/// Snapshot of a peer's topology state before a startup attempt modified it.
///
/// Stores the native `PeerState` for exact restoration (Iteration 73, Phase 3).
/// Previously this stored a lossy `MeshPeerInfo` conversion; now it preserves
/// the full peer record including audit counts, timestamps, and reputation.
#[derive(Debug, Clone)]
pub struct StagedTopologySnapshot {
    /// The complete peer state before modification.
    pub peer_state: crate::topology::PeerState,
}

/// Records a single peer mutation created during startup, used for
/// precise rollback (Iteration 73, Phases 1-6).
#[derive(Debug, Clone)]
pub struct StagedPeerResource {
    /// Session identifier for the peer connection.
    pub session_id: String,
    /// Node identifier for the peer.
    pub node_id: String,
    /// Topology snapshot captured before this startup attempt modified the peer entry.
    /// `None` means no prior topology entry existed (new peer).
    pub previous_topology: Option<StagedTopologySnapshot>,
    /// Whether the connection was inserted into the connection map.
    pub connection_inserted: bool,
    /// Session ID used as the key in the session-task registry, if a session task was spawned.
    pub session_task_id: Option<String>,
    /// The exact DHT mutation that occurred during this startup attempt.
    pub dht_mutation: DhtPeerMutation,
    /// Generation counter for the session, used to prevent stale completions.
    pub session_generation: u64,
}

/// Report from a startup rollback attempt (Iteration 73, Phases 10-12).
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
    /// Number of peer sessions drained cleanly during rollback.
    pub peer_sessions_drained: usize,
    /// Number of peer sessions that were forcibly aborted.
    pub peer_sessions_aborted: usize,
    /// Number of peer sessions that failed (panic or unexpected error).
    pub peer_sessions_failed: usize,
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
            peer_sessions_drained: 0,
            peer_sessions_aborted: 0,
            peer_sessions_failed: 0,
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
    /// Session generation counter, incremented for each peer session created.
    pub(crate) session_generation_counter: u64,
}

impl MeshStartupStage {
    /// Create a new stage with a fresh task group.
    pub fn new(task_group: crate::task_group::MeshTaskGroup) -> Self {
        Self {
            task_group,
            created_peers: Vec::new(),
            runtime_started: false,
            committed: false,
            session_generation_counter: 0,
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
        self.session_generation_counter += 1;
        self.record_peer(StagedPeerResource {
            session_id,
            node_id,
            previous_topology: None,
            connection_inserted: true,
            session_task_id: None,
            dht_mutation: DhtPeerMutation::None,
            session_generation: self.session_generation_counter,
        });
    }

    /// Allocate the next session generation ID.
    pub fn next_session_generation(&mut self) -> u64 {
        self.session_generation_counter += 1;
        self.session_generation_counter
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

/// Describes the DHT mutation that occurred when a peer connected during startup.
///
/// Used by `StagedPeerResource` to track exactly what DHT state was created or
/// modified, enabling precise rollback (Iteration 73, Phase 4).
#[derive(Debug, Clone)]
pub enum DhtPeerMutation {
    /// No DHT mutation occurred (DHT disabled or peer already registered with same state).
    None,
    /// A new routing entry was created for this peer.
    Created,
    /// An existing routing entry was replaced; contains the prior state for restoration.
    Replaced(DhtPeerSnapshot),
    /// An existing routing entry was updated in-place; contains the prior state for restoration.
    UpdatedInPlace(DhtPeerSnapshot),
}

/// Snapshot of a peer's DHT routing state before a startup mutation.
///
/// Used by `DhtPeerMutation::Replaced` and `DhtPeerMutation::UpdatedInPlace`
/// to enable precise rollback (Iteration 73, Phase 5).
#[derive(Debug, Clone)]
pub struct DhtPeerSnapshot {
    /// The node ID in the DHT routing table.
    pub node_id: String,
    /// The address recorded in the routing entry.
    pub address: String,
    /// The port recorded in the routing entry.
    pub port: u16,
    /// The role recorded in the routing entry.
    pub role: crate::config::MeshNodeRole,
}

/// Metadata for a peer session exit, used by the session reaper (Iteration 73, Phase 15-16).
#[derive(Debug, Clone)]
pub struct PeerSessionExit {
    /// Session identifier.
    pub session_id: String,
    /// Node identifier for the peer.
    pub node_id: String,
    /// Reason the session exited.
    pub reason: PeerSessionExitReason,
    /// Generation counter to prevent stale completions from removing newer entries.
    pub generation: u64,
}

/// Classification of how a peer session exited (Iteration 73, Phase 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSessionExitReason {
    /// Session completed cleanly (connection closed by peer or local).
    Clean,
    /// The QUIC connection was closed.
    ConnectionClosed,
    /// Session was cancelled during shutdown.
    Cancelled,
    /// Session exited with an error.
    Error(String),
    /// Session panicked.
    Panic(String),
    /// Session was forcibly aborted (deadline exceeded).
    Aborted,
}

impl fmt::Display for PeerSessionExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerSessionExitReason::Clean => write!(f, "clean"),
            PeerSessionExitReason::ConnectionClosed => write!(f, "connection closed"),
            PeerSessionExitReason::Cancelled => write!(f, "cancelled"),
            PeerSessionExitReason::Error(msg) => write!(f, "error: {msg}"),
            PeerSessionExitReason::Panic(msg) => write!(f, "panic: {msg}"),
            PeerSessionExitReason::Aborted => write!(f, "aborted"),
        }
    }
}

/// An auxiliary (preflight/best-effort) task owned by the transport (Iteration 73, Phase 13-14).
///
/// Auxiliary tasks are one-shot operations associated with peer connections
/// (e.g., route preflight queries). They are owned by the transport and
/// cancelled/awaited during shutdown and recovery.
#[derive(Debug)]
pub struct AuxiliaryTask {
    /// Unique identifier for this auxiliary task.
    pub task_id: MeshTaskId,
    /// Optional session ID linking this task to a peer session.
    pub session_id: Option<String>,
    /// Classification of the auxiliary task.
    pub kind: AuxiliaryTaskKind,
    /// Join handle for the task.
    pub handle: tokio::task::JoinHandle<MeshTaskExit>,
}

/// Classification of auxiliary tasks (Iteration 73, Phase 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxiliaryTaskKind {
    /// Preflight route query for a newly connected peer.
    PreflightRoute,
    /// Other one-shot best-effort work.
    Other,
}

/// Retained metadata from an incomplete startup rollback (Iteration 73, Phase 8).
///
/// When `rollback_and_return()` encounters errors, the `MeshStartupStage` is
/// partially consumed. This residue is stored on `MeshTransport` so that
/// `recover_failed_state()` can target the exact resources that were not cleaned up.
#[derive(Debug, Clone)]
pub struct FailedStartupResidue {
    /// Peer resources created during the failed startup.
    pub peers: Vec<StagedPeerResource>,
    /// The generation counter at the time of failure.
    pub generation: u64,
    /// Whether the QUIC runtime was started.
    pub runtime_started: bool,
    /// Errors encountered during the original rollback attempt.
    pub rollback_errors: Vec<String>,
}

/// Result of verifying recovery completeness (Iteration 73, Phase 20).
#[derive(Debug, Clone)]
pub struct RecoveryVerification {
    /// Whether all owned task counts are zero.
    pub tasks_empty: bool,
    /// Whether the peer-session registry is empty.
    pub sessions_empty: bool,
    /// Whether the auxiliary task registry is empty.
    pub auxiliary_empty: bool,
    /// Whether all peer connections are closed.
    pub connections_empty: bool,
    /// Whether the runtime is stopped.
    pub runtime_stopped: bool,
    /// Whether the failed-startup residue has been cleared.
    pub residue_cleared: bool,
    /// Whether the running projection is false.
    pub projection_clear: bool,
    /// Any issues found during verification.
    pub issues: Vec<String>,
}

impl RecoveryVerification {
    /// Returns true if all verifications passed.
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
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
        assert!(!MeshLifecycleState::Failed.can_start());
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
        assert_eq!(report.failed_peer_sessions, 0);
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
            previous_topology: None,
            connection_inserted: true,
            session_task_id: Some("sess-1".to_string()),
            dht_mutation: DhtPeerMutation::None,
            session_generation: 1,
        };
        assert_eq!(resource.session_id, "sess-1");
        assert_eq!(resource.node_id, "node-1");
        assert!(resource.previous_topology.is_none());
        assert!(resource.connection_inserted);
        assert_eq!(resource.session_task_id.as_deref(), Some("sess-1"));
        assert!(matches!(resource.dht_mutation, DhtPeerMutation::None));
        assert_eq!(resource.session_generation, 1);
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
        assert_eq!(report.peer_sessions_drained, 0);
        assert_eq!(report.peer_sessions_aborted, 0);
        assert_eq!(report.peer_sessions_failed, 0);
        assert!(!report.runtime_stopped);
    }

    #[test]
    fn startup_stage_record_peer() {
        let tg = crate::task_group::MeshTaskGroup::new();
        let mut stage = MeshStartupStage::new(tg);

        stage.record_peer(StagedPeerResource {
            session_id: "sess-1".to_string(),
            node_id: "node-1".to_string(),
            previous_topology: None,
            connection_inserted: true,
            session_task_id: Some("sess-1".to_string()),
            dht_mutation: DhtPeerMutation::None,
            session_generation: 1,
        });

        assert_eq!(stage.created_peers.len(), 1);
        assert_eq!(stage.created_peers[0].session_id, "sess-1");
        assert!(stage.has_resources());
    }

    #[test]
    fn dht_peer_mutation_variants() {
        let none = DhtPeerMutation::None;
        assert!(matches!(none, DhtPeerMutation::None));

        let created = DhtPeerMutation::Created;
        assert!(matches!(created, DhtPeerMutation::Created));

        let snapshot = DhtPeerSnapshot {
            node_id: "node-1".to_string(),
            address: "1.2.3.4:443".to_string(),
            port: 443,
            role: crate::config::MeshNodeRole::EDGE,
        };
        let replaced = DhtPeerMutation::Replaced(snapshot.clone());
        assert!(matches!(replaced, DhtPeerMutation::Replaced(_)));

        let updated = DhtPeerMutation::UpdatedInPlace(snapshot);
        assert!(matches!(updated, DhtPeerMutation::UpdatedInPlace(_)));
    }

    #[test]
    fn peer_session_exit_reason_display() {
        assert_eq!(PeerSessionExitReason::Clean.to_string(), "clean");
        assert_eq!(
            PeerSessionExitReason::Error("timeout".into()).to_string(),
            "error: timeout"
        );
        assert_eq!(
            PeerSessionExitReason::Panic("overflow".into()).to_string(),
            "panic: overflow"
        );
        assert_eq!(PeerSessionExitReason::Aborted.to_string(), "aborted");
    }

    #[test]
    fn failed_startup_residue() {
        let residue = FailedStartupResidue {
            peers: Vec::new(),
            generation: 42,
            runtime_started: true,
            rollback_errors: vec!["test error".to_string()],
        };
        assert!(residue.peers.is_empty());
        assert_eq!(residue.generation, 42);
        assert!(residue.runtime_started);
        assert_eq!(residue.rollback_errors.len(), 1);
    }

    #[test]
    fn recovery_verification() {
        let v = RecoveryVerification {
            tasks_empty: true,
            sessions_empty: true,
            auxiliary_empty: true,
            connections_empty: true,
            runtime_stopped: true,
            residue_cleared: true,
            projection_clear: true,
            issues: Vec::new(),
        };
        assert!(v.is_clean());

        let v = RecoveryVerification {
            tasks_empty: false,
            sessions_empty: true,
            auxiliary_empty: true,
            connections_empty: true,
            runtime_stopped: true,
            residue_cleared: true,
            projection_clear: true,
            issues: vec!["task count not zero".to_string()],
        };
        assert!(!v.is_clean());
    }

    #[test]
    fn session_generation_counter() {
        let tg = crate::task_group::MeshTaskGroup::new();
        let mut stage = MeshStartupStage::new(tg);

        let gen1 = stage.next_session_generation();
        let gen2 = stage.next_session_generation();
        let gen3 = stage.next_session_generation();

        assert_eq!(gen1, 1);
        assert_eq!(gen2, 2);
        assert_eq!(gen3, 3);
    }
}
