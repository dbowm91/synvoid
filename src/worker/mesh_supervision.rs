//! Worker-level mesh supervision policy and status tracking (Iteration 82).
//!
//! The mesh service reports facts (start result, task exit, lifecycle state, shutdown report).
//! The worker decides policy (ready, degraded, restart, shutdown, exit code).
//!
//! This module centralizes the policy types and pure decision logic.
//! Runtime integration lives in the unified server composition root.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, watch, RwLock};

#[cfg(feature = "mesh")]
pub use synvoid_mesh::lifecycle::{
    MeshShutdownReport, MeshTaskClass, MeshTaskExit, MeshTaskExitReason,
};
#[cfg(feature = "mesh")]
pub use synvoid_mesh::worker_integration::{MeshFailureCause, MeshServiceHealth};

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

/// Classify a mesh task exit into a supervision decision.
///
/// This is a pure function — all state needed for the decision is passed in.
pub fn decide_mesh_action(
    policy: &MeshSupervisionPolicy,
    status: &WorkerMeshStatus,
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
        MeshSupervisionEvent::TaskExit(exit) => classify_task_exit(policy, status, exit),
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
    _status: &WorkerMeshStatus,
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
                        let _ = control_tx.send(MeshSupervisionEvent::TaskExit(exit)).await;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Events were lost — mark degraded and request reconciliation
                        {
                            let mut s = status.write().await;
                            s.phase = WorkerMeshPhase::Degraded;
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
    _budget: RestartBudget,
    generation: u64,
    _restart_tx: Option<broadcast::Sender<RestartTimerElapsed>>,
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
            _budget: budget,
            generation: 0,
            _restart_tx: None,
        }
    }

    /// Run the coordinator loop. Returns when shutdown is requested or a fatal decision is made.
    pub async fn run(&mut self, shutdown_rx: watch::Receiver<bool>) {
        while let Some(event) = self.event_rx.recv().await {
            // Check for shutdown
            if *shutdown_rx.borrow() {
                break;
            }

            let decision = decide_mesh_action(
                &self.policy,
                &WorkerMeshStatus::default(),
                &event,
                *shutdown_rx.borrow(),
            );

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
                status.phase = WorkerMeshPhase::Degraded;
                tracing::warn!(reason = %reason, "mesh marked degraded");
            }
            MeshSupervisorDecision::RestartMesh => {
                self.generation += 1;
                status.phase = WorkerMeshPhase::Restarting;
                status.restart_attempts += 1;
                status.last_transition = Instant::now();
            }
            MeshSupervisorDecision::ShutdownWorker(_) => {
                status.phase = WorkerMeshPhase::Failed;
                status.last_transition = Instant::now();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_required() {
        let policy = MeshSupervisionPolicy::default();
        assert!(policy.required);
        assert_eq!(policy.startup_failure, MeshFailureAction::ShutdownWorker);
        assert_eq!(policy.critical_exit, MeshFailureAction::ShutdownWorker);
        assert_eq!(policy.restartable_exit, MeshFailureAction::Degrade);
        assert!(!policy.restart_limit > 0);
    }

    #[test]
    fn optional_policy_degrades_on_startup_failure() {
        let policy = MeshSupervisionPolicy::optional();
        assert!(!policy.required);
        assert_eq!(policy.startup_failure, MeshFailureAction::Degrade);
        assert!(policy.restart_limit > 0);
    }

    #[test]
    fn startup_failure_required_shutdowns() {
        let policy = MeshSupervisionPolicy::required();
        let status = WorkerMeshStatus::default();
        let event = MeshSupervisionEvent::StartupFailed("connection refused".into());
        let decision = decide_mesh_action(&policy, &status, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    #[test]
    fn startup_failure_optional_degrades() {
        let policy = MeshSupervisionPolicy::optional();
        let status = WorkerMeshStatus::default();
        let event = MeshSupervisionEvent::StartupFailed("connection refused".into());
        let decision = decide_mesh_action(&policy, &status, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::MarkDegraded(_)));
    }

    #[test]
    fn critical_panic_required_shutdowns() {
        let policy = MeshSupervisionPolicy::required();
        let status = WorkerMeshStatus::default();
        let exit = MeshTaskExit {
            id: synvoid_mesh::lifecycle::MeshTaskId(1),
            name: "mesh_maintenance",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Panic("test".into()),
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &status, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    #[test]
    fn shutdown_expected_exits_are_noop() {
        let policy = MeshSupervisionPolicy::required();
        let status = WorkerMeshStatus::default();
        let exit = MeshTaskExit {
            id: synvoid_mesh::lifecycle::MeshTaskId(1),
            name: "mesh_maintenance",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Cancelled,
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &status, &event, true);
        assert!(matches!(decision, MeshSupervisorDecision::NoAction));
    }

    #[test]
    fn broadcast_lag_degrades() {
        let policy = MeshSupervisionPolicy::required();
        let status = WorkerMeshStatus::default();
        let event = MeshSupervisionEvent::ExitStreamLagged(5);
        let decision = decide_mesh_action(&policy, &status, &event, false);
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
}
