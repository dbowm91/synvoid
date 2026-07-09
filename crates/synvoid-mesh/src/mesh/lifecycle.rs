//! Mesh transport lifecycle types (Iteration 68, 70, 71, 73, 74).
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
use std::future::Future;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MeshTaskId(pub u64);

impl fmt::Display for MeshTaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

/// A descriptor for a background task that can be registered with a
/// `MeshTaskGroup` during transactional mesh startup.
///
/// Builders on `MeshTopology` and `DhtRoutingManager` produce these
/// descriptors without spawning — the caller registers them with the
/// staged task group so they participate in startup rollback and
/// unified shutdown. The future is fully constructed by the component
/// builder and captures the lifecycle-owned shutdown receiver.
pub struct MeshBackgroundTaskSpec {
    /// Static name identifying the task.
    pub name: &'static str,
    /// Classification of the task criticality.
    pub class: MeshTaskClass,
    /// The fully-constructed future. The lifecycle-owned shutdown receiver
    /// is already captured by the builder; callers do not pass it in.
    pub future: std::pin::Pin<
        Box<dyn Future<Output = Result<(), crate::transport_core::MeshTransportError>> + Send>,
    >,
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
#[derive(Debug, Clone, Default)]
pub struct MeshShutdownReport {
    /// Number of tasks that exited cleanly.
    pub clean_tasks: usize,
    /// Tasks that exited with an error (non-fatal).
    pub failed_tasks: Vec<MeshTaskExit>,
    /// Tasks that were forcibly aborted.
    pub aborted_tasks: Vec<MeshTaskExit>,
    /// Accept-loop report, if available and from the current generation.
    /// `None` means the report was stale or unavailable.
    pub accept_loop_report: Option<MeshAcceptLoopReport>,
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
    /// Aggregate stream handler drain statistics across all peer sessions.
    pub stream_handler_drain: PeerStreamDrainReport,
}

/// Policy for classifying bootstrap failures during mesh startup.
#[derive(Debug, Clone, Default)]
pub struct MeshStartupPolicy {
    /// If true, seed bootstrap failure is fatal (required for non-genesis nodes).
    pub require_seed_connectivity: bool,
    /// If true, configured peer connection failure is fatal.
    pub require_configured_peers: bool,
    /// If true, DHT bootstrap failure is fatal (required for node role).
    pub require_dht_bootstrap: bool,
    /// If true, DHT routing initialization failure is fatal (required when
    /// DHT routing is enabled and the node depends on DHT for operation).
    pub require_dht_initialization: bool,
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
    /// Whether DHT routing table was initialized or restored.
    pub dht_routing_initialized: bool,
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
///
/// `shutdown_tx` (Iteration 76, Phase 6) is a watch sender that the
/// `peer_message_loop` selects on. Sending `true` requests cooperative
/// cancellation: the loop stops accepting new streams and runs the normal
/// child-handler drain path before returning. Rollback/recovery/shutdown
/// paths send `true` before considering parent abort; forced parent abort
/// is then treated as incomplete cleanup.
pub struct PeerSessionTask {
    /// Session identifier for this peer connection.
    pub session_id: String,
    /// Node identifier for the peer.
    pub node_id: String,
    /// Join handle for the session task.
    pub handle: tokio::task::JoinHandle<()>,
    /// Generation counter to prevent stale completions from removing newer entries.
    pub generation: u64,
    /// Watch sender for cooperative cancellation (Iteration 76, Phase 6).
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
}

/// Outcome of stopping a single peer session task (Iteration 76, Phase 10).
///
/// Returned by `stop_peer_session_task()` so that rollback, recovery, and
/// shutdown can distinguish cooperative cleanup (which proves child stream
/// handlers were drained through the normal `drain_peer_stream_handlers`
/// path) from a forced parent abort (which cannot prove child cleanup).
#[derive(Debug)]
pub enum PeerSessionStopOutcome {
    /// Session returned cooperatively (or was cancelled) within the budget.
    /// Child stream handler cleanup is proven through the normal path.
    Drained(crate::lifecycle::PeerSessionExitReason),
    /// Cooperative cancellation timed out; the parent was forcibly aborted.
    /// Child stream handler cleanup is **not** proven — recorded as a
    /// cleanup error in rollback/recovery.
    ForcedParentAbort,
    /// Join itself failed (panic or unexpected JoinError).
    Failed(String),
}

/// Logical topology snapshot capturing the primary `PeerState` before modification.
///
/// Secondary per-peer metrics (PeerScore, connection_failures, connection_successes,
/// latency_history, peer_versions, route_stability, bandwidth_trackers) are
/// intentionally not included — they are operational metrics that naturally
/// repopulate through normal peer interaction after restoration.
///
/// The snapshot is used by startup rollback to restore exact audit counts,
/// timestamps, reputation, and all primary `PeerState` fields.
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
    /// Peers whose restoration or verification failed — retained in residue for retry.
    pub unresolved_peers: Vec<StagedPeerResource>,
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
            unresolved_peers: Vec::new(),
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
    /// Snapshot of DHT routing initialization state before this startup attempt.
    /// Used by rollback to restore prior state if initialization was new.
    pub(crate) dht_init_snapshot: Option<DhtInitializationSnapshot>,
}

/// Snapshot of DHT routing initialization state captured before a startup
/// attempt (Iteration 87, Phase 4). Enables rollback to restore prior state
/// when initialization created a new routing table during a failed startup.
#[derive(Debug, Clone)]
pub struct DhtInitializationSnapshot {
    /// Whether the routing table was initialized during this startup attempt
    /// (false if it was already initialized before).
    pub was_initialized_this_attempt: bool,
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
            dht_init_snapshot: None,
        }
    }

    /// Record a DHT initialization snapshot for this startup attempt.
    pub fn record_dht_init(&mut self, snapshot: DhtInitializationSnapshot) {
        self.dht_init_snapshot = Some(snapshot);
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
    /// The peer was present before; the previous contact is preserved for restoration.
    /// Covers both replacement and in-place update semantics (Iteration 74).
    Previous(Box<DhtPeerSnapshot>),
}

/// Complete snapshot of a DHT peer's routing state before mutation.
///
/// Stores the complete `PeerContact` for **logical** restoration on
/// rollback (Iteration 76, Phase 17). The contact carries all persistent
/// fields natively, avoiding lossy conversions.
///
/// **Snapshot contract (Iteration 76, Phase 17 — logical snapshot):**
///
/// Included logical fields:
/// - `node_id`, `node_id_string` (identity)
/// - `address`, `port` (network endpoint)
/// - `geo` (country/region/coords)
/// - `latency_ms` (operational metric, preserved)
/// - `is_global`, `is_trusted` (capability flags)
/// - `pow_nonce`, `public_key` (admission proof)
/// - `last_pinged` (preserved as captured; routing policy decides refresh
///   behavior — see `restore_peer`)
/// - `mark_seen_called` / mark flags: see `PeerContact`
///
/// Excluded / intentionally refreshed fields:
/// - `last_seen`: always set to `Instant::now()` on restore — recency is
///   an operational observation, not a logical state. The captured
///   `last_seen` is preserved on the snapshot for diagnostic purposes but
///   is not written back through the restore path.
///
/// Restoration may rewrite `last_seen` to `Instant::now()` and
/// `last_pinged` according to routing policy. Use the actual restored
/// contact for verification, not the raw snapshot.
#[derive(Debug, Clone)]
pub struct DhtPeerSnapshot {
    /// The complete DHT routing contact for logical restoration.
    pub contact: crate::dht::routing::contact::PeerContact,
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
    /// Stream handler drain/abort/failure diagnostics for this session.
    pub stream_drain: PeerStreamDrainReport,
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
    /// A child stream handler panicked or failed unexpectedly.
    ChildTaskFailed(String),
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
            PeerSessionExitReason::ChildTaskFailed(msg) => write!(f, "child task failed: {msg}"),
            PeerSessionExitReason::Aborted => write!(f, "aborted"),
        }
    }
}

/// A running auxiliary task in the registry (Iteration 81).
///
/// The gated-start pattern (oneshot signal before user-future execution)
/// is handled inside the spawned task itself; the registry only tracks
/// tasks with known join handles.
pub enum AuxiliaryRegistryEntry {
    /// Task is running with a known join handle.
    Running(AuxiliaryTask),
}

impl AuxiliaryRegistryEntry {
    /// Returns the task ID.
    pub fn task_id(&self) -> MeshTaskId {
        match self {
            AuxiliaryRegistryEntry::Running(t) => t.task_id,
        }
    }

    /// Returns the task kind.
    pub fn kind(&self) -> AuxiliaryTaskKind {
        match self {
            AuxiliaryRegistryEntry::Running(t) => t.kind,
        }
    }

    /// Returns a reference to the dedup key.
    pub fn dedup_key(&self) -> Option<&str> {
        match self {
            AuxiliaryRegistryEntry::Running(t) => t.dedup_key.as_deref(),
        }
    }

    /// Returns a reference to the session ID.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            AuxiliaryRegistryEntry::Running(t) => t.session_id.as_deref(),
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
    /// Optional deduplication key for coalescing concurrent refresh tasks.
    /// When set, a new task with the same key replaces any in-flight task
    /// sharing that key (e.g., `"edge_refresh:namespace:key_id"` for
    /// edge-replica refresh).
    pub dedup_key: Option<String>,
}

/// Classification of auxiliary tasks (Iteration 73, Phase 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxiliaryTaskKind {
    /// Preflight route query for a newly connected peer.
    PreflightRoute,
    /// Periodic edge-replica refresh to keep replica state synchronized.
    EdgeReplicaRefresh,
    /// Other one-shot best-effort work.
    Other,
}

/// Check whether auxiliary task submission is allowed in the given lifecycle state.
///
/// Submissions are rejected when the transport is `Stopping`, `Stopped`, or `Failed`.
/// `Starting` allows only task kinds explicitly required during startup.
/// `Running` allows all task kinds.
pub fn auxiliary_submission_allowed(state: MeshTransportState, kind: AuxiliaryTaskKind) -> bool {
    match state {
        MeshTransportState::Running => true,
        MeshTransportState::Starting => matches!(kind, AuxiliaryTaskKind::PreflightRoute),
        MeshTransportState::Stopping | MeshTransportState::Stopped | MeshTransportState::Failed => {
            false
        }
    }
}

/// Lifecycle states as a simple enum for submission eligibility checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshTransportState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

/// Error returned when `spawn_auxiliary_task` rejects a submission (Iteration 81, Phase 25).
///
/// Each variant identifies a specific rejection reason for diagnostics and metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnAuxiliaryError {
    /// Lifecycle state does not allow auxiliary submissions.
    LifecycleNotRunning(MeshTransportState),
    /// All capacity slots for this task kind are occupied.
    CapacityExceeded,
}

impl std::fmt::Display for SpawnAuxiliaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LifecycleNotRunning(state) => {
                write!(f, "auxiliary submission rejected: lifecycle state {state:?} does not allow submission")
            }
            Self::CapacityExceeded => {
                write!(f, "auxiliary submission rejected: capacity exceeded")
            }
        }
    }
}

impl std::error::Error for SpawnAuxiliaryError {}

/// Exit event from an auxiliary task (Iteration 74, Phase 20).
///
/// Published to the auxiliary reaper when an auxiliary task completes,
/// triggering removal from the `auxiliary_tasks` registry.
#[derive(Debug, Clone)]
pub struct AuxiliaryTaskExit {
    /// Unique identifier of the completed auxiliary task.
    pub task_id: MeshTaskId,
    /// Optional session ID linking this task to a peer session.
    pub session_id: Option<String>,
    /// Exit reason.
    pub reason: MeshTaskExitReason,
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

/// Report from draining per-stream message handlers before a peer session exits (Iteration 75).
///
/// Every stream handler spawned by `peer_message_loop` is drained cooperatively
/// with a deadline, then forcibly aborted if the deadline is exceeded. This
/// ensures no handler outlives the session that owns it.
#[derive(Debug, Clone, Default)]
pub struct PeerStreamDrainReport {
    /// Number of handlers that completed within the drain deadline.
    pub drained: usize,
    /// Number of handlers that were forcibly aborted after the deadline.
    pub aborted: usize,
    /// Number of handlers that failed (panic or error).
    pub failed: usize,
}

/// Internal report of recovery outcomes (Iteration 74, Phase 35).
///
/// Used for structured recovery accounting and testing. The public API
/// (`recover_failed_state`) returns `Result<(), MeshTransportError>`.
#[derive(Debug, Clone, Default)]
pub struct RecoveryReport {
    /// Number of tasks joined during recovery.
    pub tasks_joined: usize,
    /// Number of peer sessions joined.
    pub sessions_joined: usize,
    /// Number of auxiliary tasks joined.
    pub auxiliary_joined: usize,
    /// Number of topology entries restored from residue.
    pub topology_restored: usize,
    /// Number of DHT entries restored from residue.
    pub dht_restored: usize,
    /// Errors encountered during recovery.
    pub errors: Vec<String>,
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
        assert!(report.accept_loop_report.is_none());
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
        assert!(report.unresolved_peers.is_empty());
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

        let contact = crate::dht::routing::contact::PeerContact::new(
            crate::dht::routing::node_id::NodeId::from_node_id_string("node-1"),
            "node-1".to_string(),
            "1.2.3.4".to_string(),
            443,
        )
        .with_latency(15)
        .with_trusted(true)
        .with_pow(42, vec![1, 2, 3]);
        let snapshot = DhtPeerSnapshot { contact };
        let previous = DhtPeerMutation::Previous(Box::new(snapshot.clone()));
        assert!(matches!(previous, DhtPeerMutation::Previous(_)));

        if let DhtPeerMutation::Previous(s) = previous {
            assert_eq!(s.contact.node_id_string, "node-1");
            assert_eq!(s.contact.address, "1.2.3.4");
            assert_eq!(s.contact.port, 443);
            assert_eq!(s.contact.latency_ms, Some(15));
            assert!(s.contact.is_trusted);
            assert_eq!(s.contact.pow_nonce, Some(42));
        } else {
            panic!("Expected Previous variant");
        }
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
        assert_eq!(
            PeerSessionExitReason::ChildTaskFailed(
                "2 handler(s) panicked or errored during drain".into()
            )
            .to_string(),
            "child task failed: 2 handler(s) panicked or errored during drain"
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

    #[test]
    fn peer_stream_drain_report_default() {
        let report = PeerStreamDrainReport::default();
        assert_eq!(report.drained, 0);
        assert_eq!(report.aborted, 0);
        assert_eq!(report.failed, 0);
    }

    #[test]
    fn peer_stream_drain_report_fields() {
        let report = PeerStreamDrainReport {
            drained: 5,
            aborted: 2,
            failed: 1,
        };
        assert_eq!(report.drained, 5);
        assert_eq!(report.aborted, 2);
        assert_eq!(report.failed, 1);
    }

    #[tokio::test]
    async fn peer_session_task_has_shutdown_tx() {
        // Iteration 76, Phase 6: PeerSessionTask carries a watch sender
        // for cooperative cancellation. Verify the field is present and
        // the channel round-trips a `true` value.
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let task = PeerSessionTask {
            session_id: "s1".to_string(),
            node_id: "n1".to_string(),
            handle: tokio::spawn(async {}),
            generation: 1,
            shutdown_tx: shutdown_tx.clone(),
        };
        assert_eq!(task.session_id, "s1");
        assert_eq!(task.generation, 1);

        // Initially the receiver sees `false`.
        assert!(!*shutdown_rx.borrow());

        // Send `true`; the receiver observes it.
        let _ = task.shutdown_tx.send(true);
        // The watch channel delivers the new value to the receiver.
        assert!(*shutdown_rx.borrow_and_update());
    }

    #[test]
    fn peer_session_stop_outcome_variants() {
        // Iteration 76, Phase 10: PeerSessionStopOutcome distinguishes
        // cooperative drain from forced parent abort so rollback can
        // surface incomplete cleanup.
        let drained =
            PeerSessionStopOutcome::Drained(crate::lifecycle::PeerSessionExitReason::Cancelled);
        let abort = PeerSessionStopOutcome::ForcedParentAbort;
        let failed = PeerSessionStopOutcome::Failed("boom".to_string());

        // Just confirm Debug is implemented and variants are distinct.
        assert_ne!(format!("{drained:?}"), format!("{abort:?}"));
        assert_ne!(format!("{drained:?}"), format!("{failed:?}"));
        assert_ne!(format!("{abort:?}"), format!("{failed:?}"));
    }
}
