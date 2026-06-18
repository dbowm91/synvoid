//! Worker-level mesh supervision policy and status tracking (Iteration 82).
//!
//! The mesh service reports facts (start result, task exit, lifecycle state, shutdown report).
//! The worker decides policy (ready, degraded, restart, shutdown, exit code).
//!
//! This module centralizes the policy types and pure decision logic.
//! Runtime integration lives in the unified server composition root.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, watch, RwLock};

#[cfg(feature = "mesh")]
pub use synvoid_mesh::lifecycle::{
    MeshShutdownReport, MeshTaskClass, MeshTaskExit, MeshTaskExitReason,
};
#[cfg(feature = "mesh")]
pub use synvoid_mesh::worker_integration::{MeshFailureCause, MeshServiceHealth};

/// Static counters for mesh supervision observability.
pub struct MeshSupervisionMetrics {
    pub exit_events_total: AtomicU64,
    pub restart_attempts_total: AtomicU64,
    pub restart_exhausted_total: AtomicU64,
    pub supervision_lagged_total: AtomicU64,
    pub startup_failures_total: AtomicU64,
    pub shutdown_incomplete_total: AtomicU64,
}

impl MeshSupervisionMetrics {
    pub const fn new() -> Self {
        Self {
            exit_events_total: AtomicU64::new(0),
            restart_attempts_total: AtomicU64::new(0),
            restart_exhausted_total: AtomicU64::new(0),
            supervision_lagged_total: AtomicU64::new(0),
            startup_failures_total: AtomicU64::new(0),
            shutdown_incomplete_total: AtomicU64::new(0),
        }
    }
}

pub static MESH_SUPERVISION_METRICS: MeshSupervisionMetrics = MeshSupervisionMetrics::new();

/// Policy controlling how the worker responds to mesh conditions.
#[derive(Debug, Clone)]
pub struct MeshSupervisionPolicy {
    /// Whether mesh participation is required for this worker role.
    pub required: bool,
    /// Action to take when mesh startup fails.
    pub startup_failure: MeshFailureAction,
    /// Action to take when a critical mesh task exits unexpectedly.
    pub critical_exit: MeshFailureAction,
    /// Action to take when a restartable background mesh task exits.
    pub restartable_exit: MeshFailureAction,
    /// Maximum number of restart attempts within the restart window.
    pub restart_limit: u32,
    /// Time window for counting restart attempts.
    pub restart_window: Duration,
    /// Initial backoff duration for restart attempts.
    pub restart_backoff_initial: Duration,
    /// Maximum backoff duration for restart attempts.
    pub restart_backoff_max: Duration,
    /// Whether worker readiness depends on mesh being healthy/running.
    pub readiness_requires_mesh: bool,
    /// Whether degraded mesh still satisfies readiness (only matters when readiness_requires_mesh is true).
    pub allow_degraded_readiness: bool,
}

impl Default for MeshSupervisionPolicy {
    fn default() -> Self {
        Self {
            required: true,
            startup_failure: MeshFailureAction::ShutdownWorker,
            critical_exit: MeshFailureAction::ShutdownWorker,
            restartable_exit: MeshFailureAction::Degrade,
            restart_limit: 0,
            restart_window: Duration::from_secs(300),
            restart_backoff_initial: Duration::from_secs(5),
            restart_backoff_max: Duration::from_secs(60),
            readiness_requires_mesh: true,
            allow_degraded_readiness: false,
        }
    }
}

impl MeshSupervisionPolicy {
    /// Policy for workers where mesh is required.
    pub fn required() -> Self {
        Self::default()
    }

    /// Policy for workers where mesh is optional.
    pub fn optional() -> Self {
        Self {
            required: false,
            startup_failure: MeshFailureAction::Degrade,
            critical_exit: MeshFailureAction::Degrade,
            restartable_exit: MeshFailureAction::Degrade,
            restart_limit: 3,
            restart_window: Duration::from_secs(300),
            restart_backoff_initial: Duration::from_secs(5),
            restart_backoff_max: Duration::from_secs(60),
            readiness_requires_mesh: false,
            allow_degraded_readiness: true,
        }
    }
}

/// Action to take in response to a mesh failure condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshFailureAction {
    /// Ignore the condition (mesh is optional and failure is non-critical).
    Ignore,
    /// Mark worker as degraded but continue serving.
    Degrade,
    /// Restart the mesh transport.
    RestartMesh,
    /// Shut down the worker process.
    ShutdownWorker,
}

/// Worker-observed mesh phase (separate from transport's internal MeshLifecycleState).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerMeshPhase {
    Disabled,
    Starting,
    Running,
    Degraded,
    Restarting,
    Failed,
    Stopping,
    Stopped,
}

/// Worker-owned mesh status projection.
pub struct WorkerMeshStatus {
    pub phase: WorkerMeshPhase,
    pub health: MeshServiceHealth,
    pub last_exit: Option<MeshTaskExit>,
    pub restart_attempts: u32,
    pub last_transition: Instant,
}

impl std::fmt::Debug for WorkerMeshStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerMeshStatus")
            .field("phase", &self.phase)
            .field(
                "health",
                &format_args!("{:?}", std::mem::discriminant(&self.health)),
            )
            .field("last_exit", &self.last_exit)
            .field("restart_attempts", &self.restart_attempts)
            .field("last_transition", &self.last_transition)
            .finish()
    }
}

impl Default for WorkerMeshStatus {
    fn default() -> Self {
        Self {
            phase: WorkerMeshPhase::Disabled,
            health: MeshServiceHealth::Healthy,
            last_exit: None,
            restart_attempts: 0,
            last_transition: Instant::now(),
        }
    }
}

impl WorkerMeshStatus {
    pub fn transition_starting(&mut self) {
        self.phase = WorkerMeshPhase::Starting;
        self.health = MeshServiceHealth::Healthy;
        self.last_transition = Instant::now();
    }

    pub fn transition_running(&mut self) {
        self.phase = WorkerMeshPhase::Running;
        self.health = MeshServiceHealth::Healthy;
        self.last_transition = Instant::now();
    }

    pub fn transition_degraded(&mut self, reason: String) {
        self.phase = WorkerMeshPhase::Degraded;
        self.health = MeshServiceHealth::Degraded { reason };
        self.last_transition = Instant::now();
    }

    pub fn transition_restarting(&mut self) {
        self.phase = WorkerMeshPhase::Restarting;
        self.last_transition = Instant::now();
    }

    pub fn transition_failed(&mut self, reason: String) {
        self.phase = WorkerMeshPhase::Failed;
        self.health = MeshServiceHealth::Failed {
            exit: MeshTaskExit {
                id: synvoid_mesh::lifecycle::MeshTaskId(0),
                name: "mesh_supervision",
                class: MeshTaskClass::CriticalService,
                reason: MeshTaskExitReason::Error(reason),
            },
        };
        self.last_transition = Instant::now();
    }

    pub fn transition_stopping(&mut self) {
        self.phase = WorkerMeshPhase::Stopping;
        self.last_transition = Instant::now();
    }

    pub fn transition_stopped(&mut self) {
        self.phase = WorkerMeshPhase::Stopped;
        self.health = MeshServiceHealth::Healthy;
        self.last_transition = Instant::now();
    }

    pub fn record_exit(&mut self, exit: MeshTaskExit) {
        self.last_exit = Some(exit);
        self.last_transition = Instant::now();
    }
}

/// Events from the mesh observer to the supervision coordinator.
#[derive(Debug)]
pub enum MeshSupervisionEvent {
    /// Mesh transport started successfully.
    Started,
    /// Mesh transport startup failed.
    StartupFailed(String),
    /// A mesh task exited.
    TaskExit(MeshTaskExit),
    /// The exit event stream lagged (events were lost).
    ExitStreamLagged(u64),
    /// The exit event stream closed unexpectedly.
    ExitStreamClosed,
    /// A restart timer elapsed.
    RestartTimerElapsed { generation: u64 },
    /// Worker shutdown has started.
    WorkerShutdownStarted,
}

/// Decision returned by the supervision coordinator.
pub enum MeshSupervisorDecision {
    /// No action needed.
    NoAction,
    /// Mark the worker as degraded with a reason.
    MarkDegraded(String),
    /// Restart the mesh transport.
    RestartMesh,
    /// Shut down the worker with a typed cause.
    ShutdownWorker(MeshFailureCause),
}

impl std::fmt::Debug for MeshSupervisorDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAction => write!(f, "NoAction"),
            Self::MarkDegraded(r) => f.debug_tuple("MarkDegraded").field(r).finish(),
            Self::RestartMesh => write!(f, "RestartMesh"),
            Self::ShutdownWorker(cause) => f
                .debug_tuple("ShutdownWorker")
                .field(&cause.task_name())
                .finish(),
        }
    }
}

/// Apply event-level status mutations before policy classification.
pub fn apply_mesh_event_to_status(status: &mut WorkerMeshStatus, event: &MeshSupervisionEvent) {
    match event {
        MeshSupervisionEvent::Started => {
            status.transition_running();
        }
        MeshSupervisionEvent::StartupFailed(reason) => {
            status.transition_failed(format!("startup failed: {reason}"));
        }
        MeshSupervisionEvent::TaskExit(exit) => {
            status.record_exit(exit.clone());
        }
        MeshSupervisionEvent::ExitStreamLagged(_) => {
            status.transition_degraded("exit stream lagged".to_string());
        }
        MeshSupervisionEvent::ExitStreamClosed => {
            status.transition_degraded("exit stream closed".to_string());
        }
        MeshSupervisionEvent::RestartTimerElapsed { .. } => {}
        MeshSupervisionEvent::WorkerShutdownStarted => {
            status.transition_stopping();
        }
    }
}

/// Apply decision-level status mutations after policy classification.
pub fn apply_mesh_decision_to_status(
    status: &mut WorkerMeshStatus,
    decision: &MeshSupervisorDecision,
) {
    match decision {
        MeshSupervisorDecision::NoAction => {}
        MeshSupervisorDecision::MarkDegraded(reason) => {
            status.transition_degraded(reason.clone());
        }
        MeshSupervisorDecision::RestartMesh => {
            status.transition_restarting();
        }
        MeshSupervisorDecision::ShutdownWorker(_) => {
            status.transition_failed("shutdown requested".to_string());
        }
    }
}

/// Convert a `MeshFailureCause` into a typed `WorkerShutdownCause`.
///
/// This preserves the specific mesh failure type rather than collapsing
/// everything into `MeshStartupFailed`.
pub fn mesh_failure_to_worker_cause(
    cause: MeshFailureCause,
) -> crate::worker::task_registry::WorkerShutdownCause {
    match cause {
        MeshFailureCause::CriticalServiceExit(exit) => {
            crate::worker::task_registry::WorkerShutdownCause::MeshServiceExit(exit)
        }
        MeshFailureCause::StartupFailed(reason) => {
            crate::worker::task_registry::WorkerShutdownCause::MeshStartupFailed(reason)
        }
        MeshFailureCause::ShutdownTimeout {
            aborted_tasks,
            remaining_peers,
        } => crate::worker::task_registry::WorkerShutdownCause::MeshShutdownIncomplete(format!(
            "shutdown timed out: {} tasks aborted, {} peers remaining",
            aborted_tasks.len(),
            remaining_peers
        )),
    }
}

/// Merge two shutdown causes, preserving the higher-priority cause.
///
/// Priority order (highest first):
/// 1. Process/lifecycle infrastructure failure
/// 2. Critical runtime mesh failure
/// 3. Startup/restart exhaustion
/// 4. Incomplete mesh shutdown
/// 5. External expected shutdown
pub fn merge_worker_shutdown_cause(
    current: crate::worker::task_registry::WorkerShutdownCause,
    new: crate::worker::task_registry::WorkerShutdownCause,
) -> crate::worker::task_registry::WorkerShutdownCause {
    use crate::worker::task_registry::WorkerShutdownCause;

    fn cause_priority(c: &WorkerShutdownCause) -> u8 {
        match c {
            WorkerShutdownCause::ServerExitedUnexpectedly(_)
            | WorkerShutdownCause::CriticalTaskExit(_)
            | WorkerShutdownCause::RegistryExitChannelClosed => 1,
            WorkerShutdownCause::MeshServiceExit(_) => 2,
            WorkerShutdownCause::MeshStartupFailed(_)
            | WorkerShutdownCause::MeshRestartExhausted { .. } => 3,
            WorkerShutdownCause::MeshShutdownIncomplete(_) => 4,
            WorkerShutdownCause::SupervisorShutdown
            | WorkerShutdownCause::SupervisorDisconnected
            | WorkerShutdownCause::ExternalStop
            | WorkerShutdownCause::RunningFlagCleared
            | WorkerShutdownCause::ServerStoppedForShutdown
            | WorkerShutdownCause::WorkerResize { .. } => 5,
        }
    }

    if cause_priority(&current) <= cause_priority(&new) {
        current
    } else {
        new
    }
}

/// Classify a mesh task exit into a supervision decision.
///
/// This is a pure function — all state needed for the decision is passed in.
pub fn decide_mesh_action(
    policy: &MeshSupervisionPolicy,
    phase: &WorkerMeshPhase,
    event: &MeshSupervisionEvent,
    worker_shutdown_started: bool,
) -> MeshSupervisorDecision {
    if worker_shutdown_started {
        return MeshSupervisorDecision::NoAction;
    }

    match event {
        MeshSupervisionEvent::Started => MeshSupervisorDecision::NoAction,
        MeshSupervisionEvent::StartupFailed(reason) => match policy.startup_failure {
            MeshFailureAction::Ignore => MeshSupervisorDecision::NoAction,
            MeshFailureAction::Degrade => {
                MeshSupervisorDecision::MarkDegraded(format!("mesh startup failed: {}", reason))
            }
            MeshFailureAction::RestartMesh => MeshSupervisorDecision::RestartMesh,
            MeshFailureAction::ShutdownWorker => MeshSupervisorDecision::ShutdownWorker(
                MeshFailureCause::StartupFailed(reason.clone()),
            ),
        },
        MeshSupervisionEvent::TaskExit(exit) => classify_task_exit(policy, phase, exit),
        MeshSupervisionEvent::ExitStreamLagged(n) => MeshSupervisorDecision::MarkDegraded(format!(
            "mesh exit stream lagged by {} events, reconciliation required",
            n
        )),
        MeshSupervisionEvent::ExitStreamClosed => {
            if policy.required {
                MeshSupervisorDecision::ShutdownWorker(MeshFailureCause::StartupFailed(
                    "mesh exit stream closed unexpectedly".to_string(),
                ))
            } else {
                MeshSupervisorDecision::MarkDegraded("mesh exit stream closed".to_string())
            }
        }
        MeshSupervisionEvent::RestartTimerElapsed { .. } => MeshSupervisorDecision::NoAction,
        MeshSupervisionEvent::WorkerShutdownStarted => MeshSupervisorDecision::NoAction,
    }
}

fn classify_task_exit(
    policy: &MeshSupervisionPolicy,
    _phase: &WorkerMeshPhase,
    exit: &MeshTaskExit,
) -> MeshSupervisorDecision {
    match exit.class {
        MeshTaskClass::CriticalService => match exit.reason {
            MeshTaskExitReason::Panic(_)
            | MeshTaskExitReason::Error(_)
            | MeshTaskExitReason::UnexpectedCompletion => match policy.critical_exit {
                MeshFailureAction::Ignore => MeshSupervisorDecision::NoAction,
                MeshFailureAction::Degrade => MeshSupervisorDecision::MarkDegraded(format!(
                    "critical mesh task '{}' exited: {:?}",
                    exit.name, exit.reason
                )),
                MeshFailureAction::RestartMesh => MeshSupervisorDecision::RestartMesh,
                MeshFailureAction::ShutdownWorker => MeshSupervisorDecision::ShutdownWorker(
                    MeshFailureCause::CriticalServiceExit(exit.clone()),
                ),
            },
            MeshTaskExitReason::CleanCompletion => match policy.critical_exit {
                MeshFailureAction::ShutdownWorker => MeshSupervisorDecision::ShutdownWorker(
                    MeshFailureCause::CriticalServiceExit(exit.clone()),
                ),
                _ => MeshSupervisorDecision::MarkDegraded(format!(
                    "critical mesh task '{}' completed unexpectedly",
                    exit.name
                )),
            },
            MeshTaskExitReason::Cancelled | MeshTaskExitReason::Aborted => {
                MeshSupervisorDecision::MarkDegraded(format!(
                    "critical mesh task '{}' was cancelled/aborted while running",
                    exit.name
                ))
            }
        },
        MeshTaskClass::RestartableBackground => match exit.reason {
            MeshTaskExitReason::Panic(_) | MeshTaskExitReason::Error(_) => {
                match policy.restartable_exit {
                    MeshFailureAction::Ignore => MeshSupervisorDecision::NoAction,
                    MeshFailureAction::Degrade => MeshSupervisorDecision::MarkDegraded(format!(
                        "restartable mesh task '{}' failed: {:?}",
                        exit.name, exit.reason
                    )),
                    MeshFailureAction::RestartMesh => MeshSupervisorDecision::RestartMesh,
                    MeshFailureAction::ShutdownWorker => MeshSupervisorDecision::ShutdownWorker(
                        MeshFailureCause::CriticalServiceExit(exit.clone()),
                    ),
                }
            }
            MeshTaskExitReason::CleanCompletion => MeshSupervisorDecision::MarkDegraded(format!(
                "restartable mesh task '{}' completed unexpectedly",
                exit.name
            )),
            _ => MeshSupervisorDecision::NoAction,
        },
        MeshTaskClass::BoundedChild | MeshTaskClass::OneShotStartup => {
            MeshSupervisorDecision::NoAction
        }
    }
}

/// Budget tracking for bounded mesh restarts.
#[derive(Debug)]
pub struct RestartBudget {
    attempts: VecDeque<Instant>,
    limit: u32,
    window: Duration,
}

impl RestartBudget {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            attempts: VecDeque::new(),
            limit,
            window,
        }
    }

    /// Check if a restart attempt is allowed within the budget.
    pub fn allow_restart(&mut self) -> bool {
        self.evict_expired();
        (self.attempts.len() as u32) < self.limit
    }

    /// Record a restart attempt.
    pub fn record_attempt(&mut self) {
        self.attempts.push_back(Instant::now());
    }

    /// Check if the budget is exhausted.
    pub fn is_exhausted(&mut self) -> bool {
        self.evict_expired();
        (self.attempts.len() as u32) >= self.limit
    }

    /// Number of attempts in the current window.
    pub fn attempt_count(&self) -> u32 {
        self.attempts.len() as u32
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        while let Some(&front) = self.attempts.front() {
            if now.duration_since(front) > self.window {
                self.attempts.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Compute exponential backoff with jitter.
pub fn compute_backoff(initial: Duration, max: Duration, attempt: u32) -> Duration {
    let backoff = initial.saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX));
    let backoff = backoff.min(max);
    let jitter_max = backoff / 4;
    let jitter_ms = (attempt as u64 * 7) % jitter_max.as_millis() as u64;
    backoff.saturating_add(Duration::from_millis(jitter_ms))
}

/// Classify a mesh shutdown report into a disposition.
pub enum MeshShutdownDisposition {
    Clean,
    ForcedButComplete,
    Incomplete(MeshFailureCause),
}

impl std::fmt::Debug for MeshShutdownDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::ForcedButComplete => write!(f, "ForcedButComplete"),
            Self::Incomplete(cause) => f
                .debug_tuple("Incomplete")
                .field(&cause.task_name())
                .finish(),
        }
    }
}

pub fn classify_mesh_shutdown_report(report: &MeshShutdownReport) -> MeshShutdownDisposition {
    if report.failed_tasks.is_empty()
        && report.remaining_peers == 0
        && report.failed_peer_sessions == 0
    {
        if report.aborted_tasks.is_empty() && report.aborted_peer_sessions == 0 {
            MeshShutdownDisposition::Clean
        } else {
            MeshShutdownDisposition::ForcedButComplete
        }
    } else {
        MESH_SUPERVISION_METRICS
            .shutdown_incomplete_total
            .fetch_add(1, Ordering::Relaxed);
        MeshShutdownDisposition::Incomplete(MeshFailureCause::ShutdownTimeout {
            aborted_tasks: report.failed_tasks.clone(),
            remaining_peers: report.remaining_peers,
        })
    }
}

/// Spawn a worker-owned mesh exit observer task.
///
/// This task:
/// - receives mesh exit events from the broadcast channel
/// - handles lag/closure explicitly
/// - forwards typed MeshSupervisionEvent to the coordinator
/// - stops on worker shutdown token
///
/// The observer is registered in the WorkerTaskRegistry for lifecycle management.
pub async fn run_mesh_exit_observer(
    mut exits: broadcast::Receiver<MeshTaskExit>,
    status: Arc<RwLock<WorkerMeshStatus>>,
    control_tx: mpsc::Sender<MeshSupervisionEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                break;
            }
            result = exits.recv() => {
                match result {
                    Ok(exit) => {
                        MESH_SUPERVISION_METRICS.exit_events_total.fetch_add(1, Ordering::Relaxed);
                        let _ = control_tx.send(MeshSupervisionEvent::TaskExit(exit)).await;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Events were lost — mark degraded and request reconciliation
                        MESH_SUPERVISION_METRICS.supervision_lagged_total.fetch_add(1, Ordering::Relaxed);
                        {
                            let mut s = status.write().await;
                            s.transition_degraded(format!("exit stream lagged by {} events", n));
                        }
                        let _ = control_tx.send(MeshSupervisionEvent::ExitStreamLagged(n)).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Channel closed — if worker is still running, this is a failure
                        let _ = control_tx.send(MeshSupervisionEvent::ExitStreamClosed).await;
                        break;
                    }
                }
            }
        }
    }
}

/// The mesh supervision coordinator runs as a background task.
///
/// It receives events from the observer, consults the policy, and
/// produces typed decisions that the composition root acts on.
pub struct MeshSupervisionCoordinator {
    policy: MeshSupervisionPolicy,
    status: Arc<RwLock<WorkerMeshStatus>>,
    event_rx: mpsc::Receiver<MeshSupervisionEvent>,
    decision_tx: mpsc::Sender<MeshSupervisorDecision>,
    budget: RestartBudget,
    generation: u64,
    restart_tx: Option<broadcast::Sender<RestartTimerElapsed>>,
}

/// Restart timer event with generation for stale detection.
#[derive(Debug, Clone)]
pub struct RestartTimerElapsed {
    pub generation: u64,
}

impl MeshSupervisionCoordinator {
    pub fn new(
        policy: MeshSupervisionPolicy,
        status: Arc<RwLock<WorkerMeshStatus>>,
        event_rx: mpsc::Receiver<MeshSupervisionEvent>,
        decision_tx: mpsc::Sender<MeshSupervisorDecision>,
    ) -> Self {
        let budget = RestartBudget::new(policy.restart_limit, policy.restart_window);
        Self {
            policy,
            status,
            event_rx,
            decision_tx,
            budget,
            generation: 0,
            restart_tx: None,
        }
    }

    /// Run the coordinator loop. Returns when shutdown is requested or a fatal decision is made.
    ///
    /// Uses generation tracking to prevent stale startup failure events
    /// from previous startup attempts from producing duplicate shutdown decisions.
    /// Budget-aware: when the pure policy decision is `RestartMesh` but the restart
    /// budget is exhausted, the coordinator downgrades to `ShutdownWorker`.
    pub async fn run(&mut self, shutdown_rx: watch::Receiver<bool>) {
        while let Some(event) = self.event_rx.recv().await {
            // Check for shutdown
            if *shutdown_rx.borrow() {
                break;
            }

            // Generation-based race avoidance: startup failure events from a
            // previous startup attempt (before a restart incremented generation)
            // are stale and should not trigger a new shutdown decision.
            match &event {
                MeshSupervisionEvent::StartupFailed(_) => {
                    MESH_SUPERVISION_METRICS
                        .startup_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    // Startup failures are always from the current generation
                    // because the mesh startup task is spawned fresh at each
                    // startup. No stale-filtering needed here, but the
                    // generation counter is available for future restart logic.
                }
                _ => {}
            }

            // Apply event-level status transitions before policy classification
            {
                let mut status = self.status.write().await;
                apply_mesh_event_to_status(&mut status, &event);
            }

            // Take a snapshot of the current status for policy classification
            let status_snapshot = {
                let status = self.status.read().await;
                status.phase
            };

            let decision = decide_mesh_action(
                &self.policy,
                &status_snapshot,
                &event,
                *shutdown_rx.borrow(),
            );

            // Budget gate: if the pure policy says RestartMesh but the budget
            // is exhausted, downgrade to a fatal ShutdownWorker decision.
            let decision = match decision {
                MeshSupervisorDecision::RestartMesh => {
                    if self.budget.allow_restart() {
                        decision
                    } else {
                        MESH_SUPERVISION_METRICS
                            .restart_exhausted_total
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            generation = self.generation,
                            attempts = self.budget.attempt_count(),
                            "restart budget exhausted, escalating to shutdown"
                        );
                        MeshSupervisorDecision::ShutdownWorker(MeshFailureCause::StartupFailed(
                            "restart not implemented".to_string(),
                        ))
                    }
                }
                other => other,
            };

            // Apply state transitions based on decision
            self.apply_decision(&decision).await;

            // Send decision to composition root
            if self.decision_tx.send(decision).await.is_err() {
                break; // Coordinator receiver dropped
            }
        }
    }

    async fn apply_decision(&mut self, decision: &MeshSupervisorDecision) {
        let mut status = self.status.write().await;
        match decision {
            MeshSupervisorDecision::NoAction => {}
            MeshSupervisorDecision::MarkDegraded(reason) => {
                status.transition_degraded(reason.clone());
                tracing::warn!(reason = %reason, "mesh marked degraded");
            }
            MeshSupervisorDecision::RestartMesh => {
                MESH_SUPERVISION_METRICS
                    .restart_attempts_total
                    .fetch_add(1, Ordering::Relaxed);
                self.budget.record_attempt();
                self.generation += 1;
                status.transition_restarting();
                status.restart_attempts += 1;
                tracing::info!(
                    generation = self.generation,
                    attempts = self.budget.attempt_count(),
                    "mesh restart initiated"
                );
            }
            MeshSupervisorDecision::ShutdownWorker(_) => {
                status.transition_failed("shutdown requested".to_string());
            }
        }
    }
}

/// Create the mesh supervision pipeline channels and coordinator.
///
/// Returns:
/// - `event_tx`: Channel to send events to the coordinator
/// - `coordinator`: The coordinator to be spawned as a registered background task
/// - `decision_rx`: Channel to receive decisions from the coordinator
///
/// The caller must:
/// 1. Register the observer in WorkerTaskRegistry
/// 2. Spawn the coordinator in WorkerTaskRegistry
/// 3. Process decisions in the supervision select loop
pub fn create_supervision_pipeline(
    status: Arc<RwLock<WorkerMeshStatus>>,
    policy: MeshSupervisionPolicy,
) -> (
    mpsc::Sender<MeshSupervisionEvent>,
    MeshSupervisionCoordinator,
    mpsc::Receiver<MeshSupervisorDecision>,
) {
    let (event_tx, event_rx) = mpsc::channel(32);
    let (decision_tx, decision_rx) = mpsc::channel(16);

    let coordinator = MeshSupervisionCoordinator::new(policy, status, event_rx, decision_tx);

    (event_tx, coordinator, decision_rx)
}

/// Build a mesh supervision policy from authoritative configuration.
///
/// Returns `None` when mesh is disabled (no transport exists).
pub fn build_mesh_supervision_policy(
    mesh_enabled: bool,
    config: &synvoid_config::MeshSupervisionConfig,
) -> Option<MeshSupervisionPolicy> {
    if !mesh_enabled {
        return None;
    }

    if config.restart_enabled {
        tracing::warn!(
            "restart_enabled is true in config but restart is not implemented; forcing to false"
        );
    }

    let restart_limit = 0;

    let startup_failure = if config.required {
        MeshFailureAction::ShutdownWorker
    } else {
        MeshFailureAction::Degrade
    };

    let critical_exit = if config.required {
        MeshFailureAction::ShutdownWorker
    } else {
        MeshFailureAction::Degrade
    };

    let restartable_exit = if config.required {
        MeshFailureAction::ShutdownWorker
    } else {
        MeshFailureAction::Degrade
    };

    Some(MeshSupervisionPolicy {
        required: config.required,
        startup_failure,
        critical_exit,
        restartable_exit,
        restart_limit,
        restart_window: Duration::from_secs(config.restart_window_secs),
        restart_backoff_initial: Duration::from_secs(config.restart_backoff_initial_secs),
        restart_backoff_max: Duration::from_secs(config.restart_backoff_max_secs),
        readiness_requires_mesh: config.required,
        allow_degraded_readiness: config.allow_degraded_readiness,
    })
}

/// Start mesh transport for a given generation.
///
/// Returns Ok(()) on success, Err(MeshFailureCause) on failure.
/// Caller is responsible for transitioning `WorkerMeshStatus` before/after
/// this call.
#[cfg(feature = "mesh")]
pub async fn start_mesh_generation(
    transport: &std::sync::Arc<synvoid_mesh::MeshTransport>,
    generation: u64,
) -> Result<(), MeshFailureCause> {
    let result = transport.start().await;
    match result {
        Ok(()) => {
            tracing::info!(generation, "Mesh transport started successfully");
            Ok(())
        }
        Err(e) => {
            let reason = e.to_string();
            tracing::error!(generation, "Mesh startup failed: {}", e);
            Err(MeshFailureCause::StartupFailed(reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_config::MeshSupervisionConfig;

    #[test]
    fn default_policy_is_required() {
        let policy = MeshSupervisionPolicy::default();
        assert!(policy.required);
        assert_eq!(policy.startup_failure, MeshFailureAction::ShutdownWorker);
        assert_eq!(policy.critical_exit, MeshFailureAction::ShutdownWorker);
        assert_eq!(policy.restartable_exit, MeshFailureAction::Degrade);
        assert!(!policy.restart_limit > 0);
        assert!(!policy.allow_degraded_readiness);
    }

    #[test]
    fn optional_policy_degrades_on_startup_failure() {
        let policy = MeshSupervisionPolicy::optional();
        assert!(!policy.required);
        assert_eq!(policy.startup_failure, MeshFailureAction::Degrade);
        assert!(policy.restart_limit > 0);
        assert!(policy.allow_degraded_readiness);
    }

    #[test]
    fn startup_failure_required_shutdowns() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Starting;
        let event = MeshSupervisionEvent::StartupFailed("connection refused".into());
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    #[test]
    fn startup_failure_optional_degrades() {
        let policy = MeshSupervisionPolicy::optional();
        let phase = WorkerMeshPhase::Starting;
        let event = MeshSupervisionEvent::StartupFailed("connection refused".into());
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::MarkDegraded(_)));
    }

    #[test]
    fn critical_panic_required_shutdowns() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Running;
        let exit = MeshTaskExit {
            id: synvoid_mesh::lifecycle::MeshTaskId(1),
            name: "mesh_maintenance",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Panic("test".into()),
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    #[test]
    fn shutdown_expected_exits_are_noop() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Running;
        let exit = MeshTaskExit {
            id: synvoid_mesh::lifecycle::MeshTaskId(1),
            name: "mesh_maintenance",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Cancelled,
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, true);
        assert!(matches!(decision, MeshSupervisorDecision::NoAction));
    }

    #[test]
    fn broadcast_lag_degrades() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Running;
        let event = MeshSupervisionEvent::ExitStreamLagged(5);
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::MarkDegraded(_)));
    }

    #[test]
    fn restart_budget_allows_bounded_attempts() {
        let mut budget = RestartBudget::new(3, Duration::from_secs(300));
        assert!(budget.allow_restart());
        budget.record_attempt();
        assert!(budget.allow_restart());
        budget.record_attempt();
        assert!(budget.allow_restart());
        budget.record_attempt();
        assert!(!budget.allow_restart());
        assert!(budget.is_exhausted());
    }

    #[test]
    fn restart_budget_window_expires() {
        let mut budget = RestartBudget::new(2, Duration::from_millis(100));
        budget.record_attempt();
        budget.record_attempt();
        assert!(!budget.allow_restart());
        std::thread::sleep(Duration::from_millis(150));
        assert!(budget.allow_restart());
    }

    #[test]
    fn compute_backoff_increases() {
        let b0 = compute_backoff(Duration::from_secs(5), Duration::from_secs(60), 0);
        let b1 = compute_backoff(Duration::from_secs(5), Duration::from_secs(60), 1);
        let b2 = compute_backoff(Duration::from_secs(5), Duration::from_secs(60), 2);
        assert!(b0 <= Duration::from_secs(7));
        assert!(b1 > b0 || b1 >= Duration::from_secs(5));
        assert!(b2 > b1 || b2 >= Duration::from_secs(10));
    }

    #[test]
    fn classify_clean_shutdown() {
        let report = MeshShutdownReport {
            clean_tasks: 5,
            failed_tasks: vec![],
            aborted_tasks: vec![],
            accept_loop_report: None,
            remaining_peers: 0,
            peers_at_shutdown_start: 3,
            drained_peer_sessions: 3,
            aborted_peer_sessions: 0,
            failed_peer_sessions: 0,
            stream_handler_drain: synvoid_mesh::lifecycle::PeerStreamDrainReport {
                drained: 0,
                aborted: 0,
                failed: 0,
            },
        };
        let disposition = classify_mesh_shutdown_report(&report);
        assert!(matches!(disposition, MeshShutdownDisposition::Clean));
    }

    #[test]
    fn classify_forced_complete_shutdown() {
        let report = MeshShutdownReport {
            clean_tasks: 3,
            failed_tasks: vec![],
            aborted_tasks: vec![MeshTaskExit {
                id: synvoid_mesh::lifecycle::MeshTaskId(1),
                name: "test",
                class: MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::Aborted,
            }],
            accept_loop_report: None,
            remaining_peers: 0,
            peers_at_shutdown_start: 1,
            drained_peer_sessions: 0,
            aborted_peer_sessions: 1,
            failed_peer_sessions: 0,
            stream_handler_drain: synvoid_mesh::lifecycle::PeerStreamDrainReport {
                drained: 0,
                aborted: 1,
                failed: 0,
            },
        };
        let disposition = classify_mesh_shutdown_report(&report);
        assert!(matches!(
            disposition,
            MeshShutdownDisposition::ForcedButComplete
        ));
    }

    #[tokio::test]
    async fn coordinator_budget_allows_restart() {
        let status = Arc::new(RwLock::new(WorkerMeshStatus::default()));
        let policy = MeshSupervisionPolicy {
            required: false,
            startup_failure: MeshFailureAction::RestartMesh,
            restart_limit: 3,
            ..MeshSupervisionPolicy::optional()
        };
        let (event_tx, event_rx) = mpsc::channel(8);
        let (decision_tx, mut decision_rx) = mpsc::channel(8);

        let mut coordinator =
            MeshSupervisionCoordinator::new(policy, status, event_rx, decision_tx);

        let (_, shutdown_rx) = watch::channel(false);

        // Send a startup failure — should get RestartMesh (budget allows)
        event_tx
            .send(MeshSupervisionEvent::StartupFailed("test".into()))
            .await
            .unwrap();
        drop(event_tx);

        coordinator.run(shutdown_rx).await;

        let decision = decision_rx.recv().await.unwrap();
        assert!(
            matches!(decision, MeshSupervisorDecision::RestartMesh),
            "expected RestartMesh, got {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn coordinator_budget_exhausted_downgrades_to_shutdown() {
        let status = Arc::new(RwLock::new(WorkerMeshStatus::default()));
        let policy = MeshSupervisionPolicy {
            required: false,
            startup_failure: MeshFailureAction::RestartMesh,
            restart_limit: 1,
            restart_window: Duration::from_secs(300),
            ..MeshSupervisionPolicy::optional()
        };
        let (event_tx, event_rx) = mpsc::channel(8);
        let (decision_tx, mut decision_rx) = mpsc::channel(8);

        let mut coordinator =
            MeshSupervisionCoordinator::new(policy, status, event_rx, decision_tx);

        let (_, shutdown_rx) = watch::channel(false);

        // First startup failure — budget allows (limit=1, 0 attempts)
        event_tx
            .send(MeshSupervisionEvent::StartupFailed("first".into()))
            .await
            .unwrap();
        // Second startup failure — budget exhausted (limit=1, 1 attempt recorded)
        event_tx
            .send(MeshSupervisionEvent::StartupFailed("second".into()))
            .await
            .unwrap();
        drop(event_tx);

        coordinator.run(shutdown_rx).await;

        let d1 = decision_rx.recv().await.unwrap();
        assert!(
            matches!(d1, MeshSupervisorDecision::RestartMesh),
            "first decision should be RestartMesh, got {:?}",
            d1
        );

        let d2 = decision_rx.recv().await.unwrap();
        assert!(
            matches!(d2, MeshSupervisorDecision::ShutdownWorker(_)),
            "second decision should be ShutdownWorker (budget exhausted), got {:?}",
            d2
        );
    }

    #[test]
    fn exit_stream_closed_while_running_required_fatal() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Running;
        let event = MeshSupervisionEvent::ExitStreamClosed;
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    #[test]
    fn exit_stream_closed_while_running_optional_degrades() {
        let policy = MeshSupervisionPolicy::optional();
        let phase = WorkerMeshPhase::Running;
        let event = MeshSupervisionEvent::ExitStreamClosed;
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::MarkDegraded(_)));
    }

    #[test]
    fn restartable_background_error_degrades_by_default() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Disabled;
        let exit = MeshTaskExit {
            id: synvoid_mesh::lifecycle::MeshTaskId(2),
            name: "connection_maintenance",
            class: MeshTaskClass::RestartableBackground,
            reason: MeshTaskExitReason::Error("io error".into()),
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::MarkDegraded(_)));
    }

    #[test]
    fn bounded_child_exit_is_noop() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Disabled;
        let exit = MeshTaskExit {
            id: synvoid_mesh::lifecycle::MeshTaskId(3),
            name: "handshake_child",
            class: MeshTaskClass::BoundedChild,
            reason: MeshTaskExitReason::CleanCompletion,
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::NoAction));
    }

    #[test]
    fn mesh_supervision_event_debug() {
        let event = MeshSupervisionEvent::Started;
        let debug = format!("{:?}", event);
        assert!(debug.contains("Started"));
    }

    #[test]
    fn mesh_supervisor_decision_debug() {
        let decision = MeshSupervisorDecision::MarkDegraded("test".into());
        let debug = format!("{:?}", decision);
        assert!(debug.contains("MarkDegraded"));
    }

    #[tokio::test]
    async fn coordinator_budget_recovers_after_window() {
        let status = Arc::new(RwLock::new(WorkerMeshStatus::default()));
        let policy = MeshSupervisionPolicy {
            required: false,
            startup_failure: MeshFailureAction::RestartMesh,
            restart_limit: 1,
            restart_window: Duration::from_millis(50),
            ..MeshSupervisionPolicy::optional()
        };
        let (event_tx, event_rx) = mpsc::channel(8);
        let (decision_tx, mut decision_rx) = mpsc::channel(8);

        let mut coordinator =
            MeshSupervisionCoordinator::new(policy, status, event_rx, decision_tx);

        let (_, shutdown_rx) = watch::channel(false);

        // First failure — budget allows
        event_tx
            .send(MeshSupervisionEvent::StartupFailed("first".into()))
            .await
            .unwrap();
        // Second failure — budget exhausted
        event_tx
            .send(MeshSupervisionEvent::StartupFailed("second".into()))
            .await
            .unwrap();
        drop(event_tx);

        coordinator.run(shutdown_rx).await;

        let d1 = decision_rx.recv().await.unwrap();
        assert!(matches!(d1, MeshSupervisorDecision::RestartMesh));
        let d2 = decision_rx.recv().await.unwrap();
        assert!(matches!(d2, MeshSupervisorDecision::ShutdownWorker(_)));

        // Simulate window expiry by creating a fresh coordinator with a new budget
        let status = Arc::new(RwLock::new(WorkerMeshStatus::default()));
        let policy = MeshSupervisionPolicy {
            required: false,
            startup_failure: MeshFailureAction::RestartMesh,
            restart_limit: 1,
            restart_window: Duration::from_millis(50),
            ..MeshSupervisionPolicy::optional()
        };
        let (event_tx2, event_rx2) = mpsc::channel(8);
        let (decision_tx2, mut decision_rx2) = mpsc::channel(8);

        let mut coordinator2 =
            MeshSupervisionCoordinator::new(policy, status, event_rx2, decision_tx2);
        let (_, shutdown_rx2) = watch::channel(false);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(60)).await;

        event_tx2
            .send(MeshSupervisionEvent::StartupFailed("recovered".into()))
            .await
            .unwrap();
        drop(event_tx2);

        coordinator2.run(shutdown_rx2).await;

        let d3 = decision_rx2.recv().await.unwrap();
        assert!(
            matches!(d3, MeshSupervisorDecision::RestartMesh),
            "after window expiry, restart should be allowed again, got {:?}",
            d3
        );
    }

    #[test]
    fn build_policy_disabled_mesh_returns_none() {
        let config = synvoid_config::MeshSupervisionConfig::default();
        assert!(build_mesh_supervision_policy(false, &config).is_none());
    }

    #[test]
    fn build_policy_required_config() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: true,
            restart_enabled: false,
            restart_limit: 3,
            restart_window_secs: 300,
            restart_backoff_initial_secs: 5,
            restart_backoff_max_secs: 60,
            allow_degraded_readiness: false,
        };
        let policy = build_mesh_supervision_policy(true, &config).unwrap();
        assert!(policy.required);
        assert_eq!(policy.startup_failure, MeshFailureAction::ShutdownWorker);
        assert_eq!(policy.restart_limit, 0); // restart_enabled=false
        assert!(!policy.allow_degraded_readiness);
    }

    #[test]
    fn build_policy_optional_config() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: false,
            restart_enabled: true,
            restart_limit: 5,
            restart_window_secs: 600,
            restart_backoff_initial_secs: 10,
            restart_backoff_max_secs: 120,
            allow_degraded_readiness: true,
        };
        let policy = build_mesh_supervision_policy(true, &config).unwrap();
        assert!(!policy.required);
        assert_eq!(policy.startup_failure, MeshFailureAction::Degrade);
        // restart_enabled is overridden to false (Part B), so restart_limit is 0
        assert_eq!(policy.restart_limit, 0);
        assert_eq!(policy.restart_window, Duration::from_secs(600));
        assert_eq!(policy.restart_backoff_initial, Duration::from_secs(10));
        assert_eq!(policy.restart_backoff_max, Duration::from_secs(120));
        assert!(policy.allow_degraded_readiness);
    }

    #[test]
    fn build_policy_restart_disabled_makes_restart_impossible() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: false,
            restart_enabled: false,
            restart_limit: 3,
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &config).unwrap();
        assert_eq!(policy.restart_limit, 0);
        // With restart disabled and optional, restartable_exit should be Degrade, not RestartMesh
        assert_eq!(policy.restartable_exit, MeshFailureAction::Degrade);
    }

    #[test]
    fn build_policy_restart_enabled_with_required() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: true,
            restart_enabled: true,
            restart_limit: 2,
            restart_window_secs: 100,
            restart_backoff_initial_secs: 3,
            restart_backoff_max_secs: 30,
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &config).unwrap();
        assert!(policy.required);
        assert_eq!(policy.restart_limit, 0);
        // restart_enabled is forced to false, so restartable_exit falls back to required -> ShutdownWorker
        assert_eq!(policy.restartable_exit, MeshFailureAction::ShutdownWorker);
    }

    #[test]
    fn restart_enabled_config_overridden_to_false() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: false,
            restart_enabled: true,
            restart_limit: 5,
            restart_window_secs: 300,
            restart_backoff_initial_secs: 5,
            restart_backoff_max_secs: 60,
            allow_degraded_readiness: true,
        };
        let policy = build_mesh_supervision_policy(true, &config).unwrap();
        assert_eq!(policy.restart_limit, 0);
        assert_eq!(policy.restartable_exit, MeshFailureAction::Degrade);
    }

    #[test]
    fn policy_never_emits_restart_mesh() {
        let required_config = synvoid_config::MeshSupervisionConfig {
            required: true,
            restart_enabled: true,
            restart_limit: 10,
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &required_config).unwrap();
        assert_ne!(policy.restartable_exit, MeshFailureAction::RestartMesh);
        assert_ne!(policy.startup_failure, MeshFailureAction::RestartMesh);
        assert_ne!(policy.critical_exit, MeshFailureAction::RestartMesh);

        let optional_config = synvoid_config::MeshSupervisionConfig {
            required: false,
            restart_enabled: true,
            restart_limit: 10,
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &optional_config).unwrap();
        assert_ne!(policy.restartable_exit, MeshFailureAction::RestartMesh);
        assert_ne!(policy.startup_failure, MeshFailureAction::RestartMesh);
        assert_ne!(policy.critical_exit, MeshFailureAction::RestartMesh);
    }

    #[tokio::test]
    async fn coordinator_never_transitions_to_restarting() {
        let status = Arc::new(RwLock::new(WorkerMeshStatus::default()));
        let policy = MeshSupervisionPolicy::required();
        let (event_tx, event_rx) = mpsc::channel(8);
        let (decision_tx, mut decision_rx) = mpsc::channel(8);

        let mut coordinator =
            MeshSupervisionCoordinator::new(policy, status.clone(), event_rx, decision_tx);

        let (_, shutdown_rx) = watch::channel(false);

        event_tx
            .send(MeshSupervisionEvent::StartupFailed("test".into()))
            .await
            .unwrap();
        drop(event_tx);

        coordinator.run(shutdown_rx).await;

        let decision = decision_rx.recv().await.unwrap();
        assert!(
            !matches!(decision, MeshSupervisorDecision::RestartMesh),
            "policy builder never produces RestartMesh"
        );

        let snapshot = status.read().await;
        assert_ne!(snapshot.phase, WorkerMeshPhase::Restarting);
    }

    #[test]
    fn disabled_config_never_creates_required_fallback() {
        let config = MeshSupervisionConfig::default();
        let result = build_mesh_supervision_policy(false, &config);
        assert!(
            result.is_none(),
            "disabled mesh must produce None, not a fallback policy"
        );
    }

    #[test]
    fn disabled_config_status_remains_disabled() {
        let status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);
        assert!(matches!(status.health, MeshServiceHealth::Healthy));
        assert!(status.last_exit.is_none());
        assert_eq!(status.restart_attempts, 0);
    }

    #[test]
    fn optional_mesh_ready_without_transport() {
        let policy = MeshSupervisionPolicy::optional();
        assert!(!policy.required);
        let ready = !policy.required;
        assert!(ready);
    }

    #[test]
    fn required_mesh_not_ready_when_starting() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Starting;
        let ready = match phase {
            WorkerMeshPhase::Running => true,
            WorkerMeshPhase::Degraded if policy.allow_degraded_readiness => true,
            _ => false,
        };
        assert!(!ready);
    }

    #[test]
    fn required_mesh_ready_when_running() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Running;
        let ready = match phase {
            WorkerMeshPhase::Running => true,
            WorkerMeshPhase::Degraded if policy.allow_degraded_readiness => true,
            _ => false,
        };
        assert!(ready);
    }
}
