//! Worker-level task lifecycle management.
//!
//! Provides [`WorkerTaskRegistry`] for registering, classifying, and
//! shutting down long-lived background tasks with bounded timeouts.
//!
//! # Task Classes
//!
//! | Class | Policy |
//! |-------|--------|
//! | [`TaskClass::CriticalService`] | Unexpected exit is fatal; shutdown awaits with timeout |
//! | [`TaskClass::RestartableBackground`] | Unexpected exit is logged; optional bounded restart |
//! | [`TaskClass::BoundedChild`] | Per-request/connection; drained or aborted after timeout |
//! | [`TaskClass::CpuOffload`] | Bounded queue; shutdown stops intake and drains |
//! | [`TaskClass::Detached`] | Fire-and-forget; explicitly documented with rationale |
//!
//! # Shutdown Ordering
//!
//! 1. Cancel all tasks via the shared watch channel
//! 2. Join critical tasks with timeout
//! 3. Join background tasks with timeout
//! 4. Abort remaining tasks and report

use std::collections::HashMap;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt;
#[cfg(feature = "mesh")]
use synvoid_mesh::lifecycle::MeshTaskExit;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Opaque task identifier for deduplication in exit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// Task classification for lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskClass {
    CriticalService,
    RestartableBackground,
    BoundedChild,
    CpuOffload,
    Detached,
    OneShot,
}

impl fmt::Display for TaskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CriticalService => write!(f, "critical_service"),
            Self::RestartableBackground => write!(f, "restartable_background"),
            Self::BoundedChild => write!(f, "bounded_child"),
            Self::CpuOffload => write!(f, "cpu_offload"),
            Self::Detached => write!(f, "detached"),
            Self::OneShot => write!(f, "one_shot"),
        }
    }
}

/// Outcome of a task exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExitReason {
    Cancelled,
    CleanCompletion,
    UnexpectedCompletion,
    Panic(String),
    Error(String),
    Aborted,
}

impl TaskExitReason {
    /// Returns true if this reason represents an abnormal termination.
    pub fn is_abnormal(&self) -> bool {
        matches!(
            self,
            TaskExitReason::UnexpectedCompletion
                | TaskExitReason::Panic(_)
                | TaskExitReason::Error(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerShutdownCause {
    ServerExitedUnexpectedly(NamedTaskExit),
    ServerStoppedForShutdown,
    CriticalTaskExit(NamedTaskExit),
    /// A critical mesh service exited unexpectedly.
    #[cfg(feature = "mesh")]
    MeshServiceExit(MeshTaskExit),
    /// Mesh startup failed and was rolled back.
    #[cfg(feature = "mesh")]
    MeshStartupFailed(String),
    /// Mesh restart budget exhausted.
    #[cfg(feature = "mesh")]
    MeshRestartExhausted {
        attempts: u32,
        last_error: String,
    },
    /// Mesh shutdown did not complete cleanly.
    #[cfg(feature = "mesh")]
    MeshShutdownIncomplete(String),
    /// Mesh policy/transport invariant violated at startup.
    #[cfg(feature = "mesh")]
    MeshConfigurationInvariant(String),
    SupervisorShutdown,
    SupervisorDisconnected,
    RegistryExitChannelClosed,
    ExternalStop,
    RunningFlagCleared,
    WorkerResize {
        worker_threads: usize,
    },
}

/// Typed outcome from the supervision loop.
///
/// Preserves the distinction between IPC lifecycle events (which carry an
/// acknowledgement sender) and direct worker shutdown causes (task failures,
/// registry channel failures) that should not be re-mapped through lifecycle events.
#[derive(Debug)]
pub enum SupervisionOutcome {
    /// An IPC lifecycle event was received (MasterShutdown, WorkerResize, SupervisorDisconnected).
    Lifecycle {
        event: crate::worker::unified_server::lifecycle::WorkerLifecycleEvent,
        accepted: tokio::sync::oneshot::Sender<()>,
    },
    /// A direct cause from task failure, registry channel failure, etc.
    DirectCause(WorkerShutdownCause),
}

impl WorkerShutdownCause {
    pub fn nonzero_exit_code(&self) -> bool {
        match self {
            Self::ServerExitedUnexpectedly(_) => true,
            Self::ServerStoppedForShutdown => false,
            Self::CriticalTaskExit(_) => true,
            #[cfg(feature = "mesh")]
            Self::MeshServiceExit(_) => true,
            #[cfg(feature = "mesh")]
            Self::MeshStartupFailed(_) => true,
            #[cfg(feature = "mesh")]
            Self::MeshRestartExhausted { .. } => true,
            #[cfg(feature = "mesh")]
            Self::MeshShutdownIncomplete(_) => true,
            #[cfg(feature = "mesh")]
            Self::MeshConfigurationInvariant(_) => true,
            Self::SupervisorShutdown => false,
            Self::SupervisorDisconnected => true,
            Self::RegistryExitChannelClosed => true,
            Self::ExternalStop => false,
            Self::RunningFlagCleared => false,
            Self::WorkerResize { .. } => false,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::WorkerResize { .. } => 100,
            cause if cause.nonzero_exit_code() => 1,
            _ => 0,
        }
    }

    pub fn should_notify_supervisor(&self) -> bool {
        matches!(
            self,
            Self::CriticalTaskExit(_)
                | Self::ServerExitedUnexpectedly(_)
                | Self::RegistryExitChannelClosed
        ) || {
            #[cfg(feature = "mesh")]
            {
                matches!(
                    self,
                    Self::MeshServiceExit(_)
                        | Self::MeshStartupFailed(_)
                        | Self::MeshRestartExhausted { .. }
                        | Self::MeshShutdownIncomplete(_)
                        | Self::MeshConfigurationInvariant(_)
                )
            }
            #[cfg(not(feature = "mesh"))]
            {
                false
            }
        }
    }

    pub fn is_expected(&self) -> bool {
        matches!(
            self,
            Self::ServerStoppedForShutdown
                | Self::SupervisorShutdown
                | Self::ExternalStop
                | Self::RunningFlagCleared
                | Self::WorkerResize { .. }
        )
    }
}

impl fmt::Display for WorkerShutdownCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerExitedUnexpectedly(exit) => {
                write!(
                    f,
                    "server_run exited unexpectedly: {} ({})",
                    exit.name, exit.reason
                )
            }
            Self::ServerStoppedForShutdown => write!(f, "server_stopped_for_shutdown"),
            Self::CriticalTaskExit(exit) => {
                write!(f, "critical_task_exit: {} ({})", exit.name, exit.reason)
            }
            #[cfg(feature = "mesh")]
            Self::MeshServiceExit(exit) => {
                write!(f, "mesh_service_exit: {} ({})", exit.name, exit.reason)
            }
            #[cfg(feature = "mesh")]
            Self::MeshStartupFailed(reason) => {
                write!(f, "mesh_startup_failed: {}", reason)
            }
            #[cfg(feature = "mesh")]
            Self::MeshRestartExhausted {
                attempts,
                last_error,
            } => {
                write!(
                    f,
                    "mesh_restart_exhausted: {} attempts, last: {}",
                    attempts, last_error
                )
            }
            #[cfg(feature = "mesh")]
            Self::MeshShutdownIncomplete(reason) => {
                write!(f, "mesh_shutdown_incomplete: {}", reason)
            }
            #[cfg(feature = "mesh")]
            Self::MeshConfigurationInvariant(msg) => {
                write!(f, "mesh_configuration_invariant: {}", msg)
            }
            Self::SupervisorShutdown => write!(f, "supervisor_shutdown"),
            Self::SupervisorDisconnected => write!(f, "supervisor_disconnected"),
            Self::RegistryExitChannelClosed => write!(f, "registry_exit_channel_closed"),
            Self::ExternalStop => write!(f, "external_stop"),
            Self::RunningFlagCleared => write!(f, "running_flag_cleared"),
            Self::WorkerResize { worker_threads } => {
                write!(f, "worker_resize(threads={})", worker_threads)
            }
        }
    }
}

impl fmt::Display for TaskExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "cancelled"),
            Self::CleanCompletion => write!(f, "clean_completion"),
            Self::UnexpectedCompletion => write!(f, "unexpected_completion"),
            Self::Panic(msg) => write!(f, "panic: {}", msg),
            Self::Error(msg) => write!(f, "error: {}", msg),
            Self::Aborted => write!(f, "aborted"),
        }
    }
}

/// Error from [`ManagedService::join`].
#[derive(Debug)]
pub enum ServiceExitError {
    Panic(String),
    Error(String),
    Cancelled,
    JoinFailed(String),
}

impl fmt::Display for ServiceExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panic(msg) => write!(f, "panic: {}", msg),
            Self::Error(msg) => write!(f, "error: {}", msg),
            Self::Cancelled => write!(f, "cancelled"),
            Self::JoinFailed(msg) => write!(f, "join failed: {}", msg),
        }
    }
}

impl std::error::Error for ServiceExitError {}

/// A long-lived service with explicit shutdown and join semantics.
pub trait ManagedService: Send + Sync {
    fn name(&self) -> &'static str;
    fn shutdown(&self);
    #[allow(async_fn_in_trait)]
    async fn join(&self) -> Result<(), ServiceExitError>;
}

/// Result of joining a single task, with metadata for logging and metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedTaskExit {
    pub id: TaskId,
    pub name: &'static str,
    pub class: TaskClass,
    pub reason: TaskExitReason,
    pub expected_during_shutdown: bool,
}

/// Metrics counters for the task registry.
#[derive(Debug, Default)]
pub struct TaskRegistryMetrics {
    pub tasks_started: AtomicU64,
    pub tasks_completed_cleanly: AtomicU64,
    pub tasks_cancelled: AtomicU64,
    pub tasks_panicked: AtomicU64,
    pub tasks_aborted: AtomicU64,
    pub tasks_errored: AtomicU64,
    pub tasks_unexpectedly_completed: AtomicU64,
    pub shutdown_duration_ms: AtomicU64,
    pub tasks_remaining_at_timeout: AtomicU64,
}

impl TaskRegistryMetrics {
    pub fn record_started(&self) {
        self.tasks_started.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("synvoid.worker.tasks_started_total").increment(1);
        synvoid_metrics::collection::record_worker_task_started();
    }
    pub fn record_completed_cleanly(&self) {
        self.tasks_completed_cleanly.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("synvoid.worker.tasks_completed_cleanly_total").increment(1);
        synvoid_metrics::collection::record_worker_task_completed_cleanly();
    }
    pub fn record_cancelled(&self) {
        self.tasks_cancelled.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("synvoid.worker.tasks_cancelled_total").increment(1);
        synvoid_metrics::collection::record_worker_task_cancelled();
    }
    pub fn record_panicked(&self) {
        self.tasks_panicked.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("synvoid.worker.tasks_panicked_total").increment(1);
        synvoid_metrics::collection::record_worker_task_panicked();
    }
    pub fn record_aborted(&self) {
        self.tasks_aborted.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("synvoid.worker.tasks_aborted_total").increment(1);
        synvoid_metrics::collection::record_worker_task_aborted();
    }
    pub fn record_errored(&self) {
        self.tasks_errored.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("synvoid.worker.tasks_errored_total").increment(1);
        synvoid_metrics::collection::record_worker_task_errored();
    }
    pub fn record_unexpectedly_completed(&self) {
        self.tasks_unexpectedly_completed
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("synvoid.worker.tasks_unexpectedly_completed_total").increment(1);
    }
}

/// Report from subset task cleanup (Iteration 88, Part B).
#[derive(Debug)]
pub struct TaskSubsetCleanupReport {
    /// Exits for all matched tasks (cooperative + forced).
    pub exits: Vec<NamedTaskExit>,
    /// IDs that were not found in the registry.
    pub not_found_ids: Vec<TaskId>,
}

impl TaskSubsetCleanupReport {
    /// Returns true if all tasks exited cleanly (no aborts, no failures).
    pub fn clean(&self) -> bool {
        self.exits.iter().all(|e| {
            matches!(
                e.reason,
                TaskExitReason::CleanCompletion | TaskExitReason::Cancelled
            )
        })
    }

    /// Number of tasks that required forced abort.
    pub fn aborted_count(&self) -> usize {
        self.exits
            .iter()
            .filter(|e| matches!(e.reason, TaskExitReason::Aborted))
            .count()
    }
}

/// Entry for a registered task.
struct RegisteredTask {
    id: TaskId,
    name: &'static str,
    class: TaskClass,
    handle: JoinHandle<()>,
}

/// A worker-level task registry that manages long-lived background tasks.
pub struct WorkerTaskRegistry {
    shutdown_tx: watch::Sender<bool>,
    critical: Vec<RegisteredTask>,
    background: Vec<RegisteredTask>,
    next_id: AtomicU64,
    pub metrics: Arc<TaskRegistryMetrics>,
    shutdown_started: AtomicBool,
    /// Shared shutdown flag passed into task wrappers for UnexpectedCompletion detection.
    shutdown_started_arc: Arc<AtomicBool>,
    exit_tx: tokio::sync::broadcast::Sender<NamedTaskExit>,
    /// Task IDs whose exit has been observed via the broadcast channel.
    reported_exits: Arc<Mutex<HashMap<TaskId, TaskExitReason>>>,
}

impl WorkerTaskRegistry {
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let (exit_tx, _) = tokio::sync::broadcast::channel(64);
        let shutdown_started_arc = Arc::new(AtomicBool::new(false));
        Self {
            shutdown_tx,
            critical: Vec::new(),
            background: Vec::new(),
            next_id: AtomicU64::new(1),
            metrics: Arc::new(TaskRegistryMetrics::default()),
            shutdown_started: AtomicBool::new(false),
            shutdown_started_arc,
            exit_tx,
            reported_exits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn child_token(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    pub fn subscribe_exits(&self) -> tokio::sync::broadcast::Receiver<NamedTaskExit> {
        self.exit_tx.subscribe()
    }

    pub fn is_shutdown_started(&self) -> bool {
        self.shutdown_started.load(Ordering::Relaxed)
    }

    /// Returns a clone of the shared shutdown-started flag for use in supervision logic.
    pub fn shutdown_started_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_started_arc)
    }

    pub fn spawn_critical<F>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id_val = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = TaskId(id_val);
        let exit_tx = self.exit_tx.clone();
        let metrics = Arc::clone(&self.metrics);
        let reported_exits = Arc::clone(&self.reported_exits);
        let shutdown_started = Arc::clone(&self.shutdown_started_arc);

        let handle = tokio::task::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;
            let shutdown = shutdown_started.load(Ordering::Acquire);
            let exit = classify_unit_result(id, name, TaskClass::CriticalService, result, shutdown);
            record_exit_metrics(&exit, &metrics, &reported_exits);
            let _ = exit_tx.send(exit);
        });

        self.metrics.record_started();
        self.critical.push(RegisteredTask {
            id,
            name,
            class: TaskClass::CriticalService,
            handle,
        });
        id_val as usize
    }

    pub fn spawn_critical_result<F, E>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = Result<(), E>> + Send + 'static,
        E: fmt::Display + Send + 'static,
    {
        let id_val = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = TaskId(id_val);
        let exit_tx = self.exit_tx.clone();
        let metrics = Arc::clone(&self.metrics);
        let reported_exits = Arc::clone(&self.reported_exits);
        let shutdown_started = Arc::clone(&self.shutdown_started_arc);

        let handle = tokio::task::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;
            let shutdown = shutdown_started.load(Ordering::Acquire);
            let exit = classify_result_task(id, name, TaskClass::CriticalService, result, shutdown);
            record_exit_metrics(&exit, &metrics, &reported_exits);
            let _ = exit_tx.send(exit);
        });

        self.metrics.record_started();
        self.critical.push(RegisteredTask {
            id,
            name,
            class: TaskClass::CriticalService,
            handle,
        });
        id_val as usize
    }

    pub fn spawn_background<F>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id_val = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = TaskId(id_val);
        let exit_tx = self.exit_tx.clone();
        let metrics = Arc::clone(&self.metrics);
        let reported_exits = Arc::clone(&self.reported_exits);
        let shutdown_started = Arc::clone(&self.shutdown_started_arc);

        let handle = tokio::task::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;
            let shutdown = shutdown_started.load(Ordering::Acquire);
            let exit =
                classify_unit_result(id, name, TaskClass::RestartableBackground, result, shutdown);
            record_exit_metrics(&exit, &metrics, &reported_exits);
            let _ = exit_tx.send(exit);
        });

        self.metrics.record_started();
        self.background.push(RegisteredTask {
            id,
            name,
            class: TaskClass::RestartableBackground,
            handle,
        });
        id_val as usize
    }

    pub fn spawn_cancellable_background<F>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id_val = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = TaskId(id_val);
        let exit_tx = self.exit_tx.clone();
        let metrics = Arc::clone(&self.metrics);
        let reported_exits = Arc::clone(&self.reported_exits);
        let shutdown_started = Arc::clone(&self.shutdown_started_arc);

        let handle = tokio::task::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;
            let shutdown = shutdown_started.load(Ordering::Acquire);
            let exit =
                classify_unit_result(id, name, TaskClass::RestartableBackground, result, shutdown);
            record_exit_metrics(&exit, &metrics, &reported_exits);
            let _ = exit_tx.send(exit);
        });

        self.metrics.record_started();
        self.background.push(RegisteredTask {
            id,
            name,
            class: TaskClass::RestartableBackground,
            handle,
        });
        id_val as usize
    }

    /// Spawn a one-shot task that runs once and completes.
    ///
    /// Clean completion is always expected (not fatal) regardless of
    /// whether shutdown has started. Panics and errors are still fatal
    /// for critical one-shot tasks.
    pub fn spawn_one_shot<F>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id_val = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id = TaskId(id_val);
        let exit_tx = self.exit_tx.clone();
        let metrics = Arc::clone(&self.metrics);
        let reported_exits = Arc::clone(&self.reported_exits);
        let shutdown_started = Arc::clone(&self.shutdown_started_arc);

        let handle = tokio::task::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;
            let shutdown = shutdown_started.load(Ordering::Acquire);
            let exit = classify_unit_result_one_shot(id, name, result, shutdown);
            record_exit_metrics(&exit, &metrics, &reported_exits);
            let _ = exit_tx.send(exit);
        });

        self.metrics.record_started();
        self.critical.push(RegisteredTask {
            id,
            name,
            class: TaskClass::OneShot,
            handle,
        });
        id_val as usize
    }

    pub fn begin_shutdown(&self) {
        self.shutdown_started.store(true, Ordering::Release);
        self.shutdown_started_arc.store(true, Ordering::Release);
    }

    pub fn broadcast_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn shutdown(&self) {
        self.begin_shutdown();
        self.broadcast_shutdown();
    }

    async fn join_task_until(
        task: RegisteredTask,
        deadline: tokio::time::Instant,
        metrics: &TaskRegistryMetrics,
        reported_exits: &Arc<Mutex<HashMap<TaskId, TaskExitReason>>>,
    ) -> NamedTaskExit {
        let mut handle = task.handle;

        match tokio::time::timeout_at(deadline, &mut handle).await {
            Ok(join_result) => match join_result {
                Ok(()) => {
                    let already_reported = reported_exits.lock().unwrap().remove(&task.id);
                    if let Some(reason) = already_reported {
                        return NamedTaskExit {
                            id: task.id,
                            name: task.name,
                            class: task.class,
                            reason,
                            expected_during_shutdown: true,
                        };
                    }
                    metrics.record_completed_cleanly();
                    NamedTaskExit {
                        id: task.id,
                        name: task.name,
                        class: task.class,
                        reason: TaskExitReason::CleanCompletion,
                        expected_during_shutdown: true,
                    }
                }
                Err(e) => {
                    let already_reported = reported_exits.lock().unwrap().remove(&task.id);
                    let reason = classify_join_error(e);
                    if already_reported.is_none() {
                        match &reason {
                            TaskExitReason::Cancelled => metrics.record_cancelled(),
                            TaskExitReason::Panic(_) => {
                                metrics.record_panicked();
                                tracing::error!("Task '{}' panicked", task.name);
                            }
                            _ => metrics.record_errored(),
                        }
                    }
                    tracing::debug!("Task '{}' exit: {}", task.name, reason);
                    NamedTaskExit {
                        id: task.id,
                        name: task.name,
                        class: task.class,
                        reason,
                        expected_during_shutdown: false,
                    }
                }
            },
            Err(_) => {
                tracing::error!("Task '{}' shutdown timeout exceeded, aborting", task.name);
                handle.abort();
                let _ = handle.await;
                metrics.record_aborted();
                metrics
                    .tasks_remaining_at_timeout
                    .fetch_add(1, Ordering::Relaxed);
                NamedTaskExit {
                    id: task.id,
                    name: task.name,
                    class: task.class,
                    reason: TaskExitReason::Aborted,
                    expected_during_shutdown: false,
                }
            }
        }
    }

    pub async fn shutdown_and_join(
        &mut self,
        critical_timeout: Duration,
        background_timeout: Duration,
    ) -> Vec<NamedTaskExit> {
        let shutdown_start = std::time::Instant::now();
        self.shutdown();

        let mut exits = Vec::new();

        let deadline = tokio::time::Instant::now() + critical_timeout;
        for task in self.critical.drain(..) {
            if tokio::time::Instant::now() >= deadline {
                tracing::error!(
                    "Critical task shutdown timeout after {:?}, aborting remaining",
                    critical_timeout,
                );
                task.handle.abort();
                let _ = task.handle.await;
                self.metrics.record_aborted();
                self.metrics
                    .tasks_remaining_at_timeout
                    .fetch_add(1, Ordering::Relaxed);
                exits.push(NamedTaskExit {
                    id: task.id,
                    name: task.name,
                    class: task.class,
                    reason: TaskExitReason::Aborted,
                    expected_during_shutdown: false,
                });
                continue;
            }
            let exit =
                Self::join_task_until(task, deadline, &self.metrics, &self.reported_exits).await;
            if exit.reason != TaskExitReason::CleanCompletion {
                exits.push(exit);
            }
        }

        let deadline = tokio::time::Instant::now() + background_timeout;
        for task in self.background.drain(..) {
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    "Background task shutdown timeout after {:?}, aborting remaining",
                    background_timeout,
                );
                task.handle.abort();
                let _ = task.handle.await;
                self.metrics.record_aborted();
                self.metrics
                    .tasks_remaining_at_timeout
                    .fetch_add(1, Ordering::Relaxed);
                exits.push(NamedTaskExit {
                    id: task.id,
                    name: task.name,
                    class: task.class,
                    reason: TaskExitReason::Aborted,
                    expected_during_shutdown: false,
                });
                continue;
            }
            let exit =
                Self::join_task_until(task, deadline, &self.metrics, &self.reported_exits).await;
            if exit.reason != TaskExitReason::CleanCompletion {
                exits.push(exit);
            }
        }

        let elapsed = shutdown_start.elapsed();
        self.metrics
            .shutdown_duration_ms
            .store(elapsed.as_millis() as u64, Ordering::Relaxed);
        tracing::info!(
            "Task registry shutdown complete in {:?}, {} tasks with non-clean exits",
            elapsed,
            exits.len()
        );

        exits
    }

    /// Cancel then join a specific subset of tasks by their IDs (Iteration 88, Part B).
    ///
    /// Performs cooperative cancellation first (waits up to `cooperative_timeout`),
    /// then aborts remaining tasks and awaits every handle without a second
    /// timeout. Returns a `TaskSubsetCleanupReport` with exit metadata for all
    /// matched tasks. Tasks not found in the registry are recorded in
    /// `not_found_ids`.
    ///
    /// `expected_during_shutdown` controls whether exits are classified as expected
    /// (true for whole-worker shutdown) or unexpected (false for live degradation).
    ///
    /// # Ownership Invariant (Iteration 90)
    ///
    /// Once extracted from the registry, `cancel_then_join_tasks()` is the sole
    /// owner of every matched handle and must return only after each handle is
    /// joined or returned as explicit residue. After `abort()`, the handle is
    /// awaited directly — no timeout is applied, because a timeout that drops the
    /// handle would lose ownership without proof the task ended.
    pub async fn cancel_then_join_tasks(
        &mut self,
        task_ids: &[TaskId],
        cooperative_timeout: Duration,
        _forced_timeout: Duration,
        expected_during_shutdown: bool,
    ) -> TaskSubsetCleanupReport {
        let id_set: std::collections::HashSet<TaskId> = task_ids.iter().copied().collect();
        let mut exits = Vec::new();
        let mut not_found_ids = Vec::new();

        // Phase 1: Collect matched tasks and remove from registry.
        let mut matched: Vec<RegisteredTask> = Vec::new();
        for vec in [&mut self.critical, &mut self.background] {
            let mut i = 0;
            while i < vec.len() {
                if id_set.contains(&vec[i].id) {
                    let task = vec.swap_remove(i);
                    matched.push(task);
                } else {
                    i += 1;
                }
            }
        }

        // Record IDs that were not found.
        for &id in &id_set {
            if !matched.iter().any(|t| t.id == id) {
                not_found_ids.push(id);
            }
        }

        // Phase 2: Cooperative wait — let tasks finish naturally.
        if !matched.is_empty() {
            let cooperative_deadline = tokio::time::Instant::now() + cooperative_timeout;
            let mut still_pending: Vec<RegisteredTask> = Vec::new();

            for mut task in matched {
                // Check if task is already finished (non-blocking).
                if task.handle.is_finished() {
                    // Task already completed — join without timeout.
                    let join_result = task.handle.await;
                    let reason = match join_result {
                        Ok(()) => {
                            let already_reported =
                                self.reported_exits.lock().unwrap().remove(&task.id);
                            already_reported.unwrap_or(TaskExitReason::CleanCompletion)
                        }
                        Err(e) => {
                            let already_reported =
                                self.reported_exits.lock().unwrap().remove(&task.id);
                            already_reported.unwrap_or(classify_join_error(e))
                        }
                    };
                    exits.push(NamedTaskExit {
                        id: task.id,
                        name: task.name,
                        class: task.class,
                        reason,
                        expected_during_shutdown,
                    });
                } else {
                    // Wait with timeout.
                    let join_result =
                        tokio::time::timeout_at(cooperative_deadline, &mut task.handle).await;
                    match join_result {
                        Ok(Ok(())) => {
                            let already_reported =
                                self.reported_exits.lock().unwrap().remove(&task.id);
                            let reason =
                                already_reported.unwrap_or(TaskExitReason::CleanCompletion);
                            exits.push(NamedTaskExit {
                                id: task.id,
                                name: task.name,
                                class: task.class,
                                reason,
                                expected_during_shutdown,
                            });
                        }
                        Ok(Err(e)) => {
                            let already_reported =
                                self.reported_exits.lock().unwrap().remove(&task.id);
                            let reason = already_reported.unwrap_or(classify_join_error(e));
                            exits.push(NamedTaskExit {
                                id: task.id,
                                name: task.name,
                                class: task.class,
                                reason,
                                expected_during_shutdown,
                            });
                        }
                        Err(_timeout) => {
                            still_pending.push(task);
                        }
                    }
                }
            }

            // Phase 3: Force abort remaining tasks and await every handle.
            //
            // `forced_timeout` is retained for API compatibility. Once a task is
            // aborted, this function awaits the handle to preserve ownership. Do
            // not wrap the aborted handle in timeout unless unjoined ownership
            // residue is returned.
            for task in still_pending {
                task.handle.abort();

                let join_result = task.handle.await;
                let reason = match join_result {
                    Ok(()) => TaskExitReason::CleanCompletion,
                    Err(error) => classify_join_error(error),
                };

                let already_reported = self.reported_exits.lock().unwrap().remove(&task.id);
                let final_reason = already_reported.unwrap_or(reason);

                exits.push(NamedTaskExit {
                    id: task.id,
                    name: task.name,
                    class: task.class,
                    reason: final_reason,
                    expected_during_shutdown,
                });
            }
        }

        tracing::debug!(
            "Subset join complete: {} tasks joined, {} not found",
            exits.len(),
            not_found_ids.len()
        );
        if !not_found_ids.is_empty() {
            tracing::warn!(
                "Subset cleanup: {} task IDs not found in registry (may have completed or been removed elsewhere): {:?}",
                not_found_ids.len(),
                not_found_ids.iter().map(|id| id.0).collect::<Vec<_>>()
            );
        }
        TaskSubsetCleanupReport {
            exits,
            not_found_ids,
        }
    }

    /// Returns true if the given task ID is registered in critical or background lists.
    pub fn contains_task(&self, id: TaskId) -> bool {
        self.critical.iter().any(|t| t.id == id) || self.background.iter().any(|t| t.id == id)
    }

    pub fn active_count(&self) -> usize {
        self.critical.len() + self.background.len()
    }

    pub fn critical_count(&self) -> usize {
        self.critical.len()
    }

    pub fn background_count(&self) -> usize {
        self.background.len()
    }
}

impl Default for WorkerTaskRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Record metrics for an exit and mark the task as reported.
fn record_exit_metrics(
    exit: &NamedTaskExit,
    metrics: &TaskRegistryMetrics,
    reported_exits: &Arc<Mutex<HashMap<TaskId, TaskExitReason>>>,
) {
    match &exit.reason {
        TaskExitReason::CleanCompletion => metrics.record_completed_cleanly(),
        TaskExitReason::UnexpectedCompletion => metrics.record_unexpectedly_completed(),
        TaskExitReason::Panic(_) => metrics.record_panicked(),
        TaskExitReason::Error(_) => metrics.record_errored(),
        TaskExitReason::Cancelled => metrics.record_cancelled(),
        _ => {}
    }
    reported_exits
        .lock()
        .unwrap()
        .insert(exit.id, exit.reason.clone());
}

/// Classify a `JoinError` into a `TaskExitReason`.
fn classify_join_error(e: tokio::task::JoinError) -> TaskExitReason {
    if e.is_cancelled() {
        TaskExitReason::Cancelled
    } else if e.is_panic() {
        TaskExitReason::Panic(format!("{}", e))
    } else {
        TaskExitReason::Error(format!("{}", e))
    }
}

/// Classify the result of `catch_unwind` around `Future<Output=()>`.
fn classify_unit_result(
    id: TaskId,
    name: &'static str,
    class: TaskClass,
    result: Result<(), Box<dyn std::any::Any + Send>>,
    shutdown_started: bool,
) -> NamedTaskExit {
    match result {
        Ok(()) => {
            let (reason, expected) = if shutdown_started {
                (TaskExitReason::CleanCompletion, true)
            } else {
                (TaskExitReason::UnexpectedCompletion, false)
            };
            NamedTaskExit {
                id,
                name,
                class,
                reason,
                expected_during_shutdown: expected,
            }
        }
        Err(panic) => {
            let msg = extract_panic_message(panic);
            NamedTaskExit {
                id,
                name,
                class,
                reason: TaskExitReason::Panic(msg),
                expected_during_shutdown: false,
            }
        }
    }
}

/// Classify a one-shot task result. Clean completion is always expected
/// regardless of shutdown state (unlike `classify_unit_result` which
/// treats clean completion before shutdown as `UnexpectedCompletion`).
fn classify_unit_result_one_shot(
    id: TaskId,
    name: &'static str,
    result: Result<(), Box<dyn std::any::Any + Send>>,
    _shutdown_started: bool,
) -> NamedTaskExit {
    match result {
        Ok(()) => NamedTaskExit {
            id,
            name,
            class: TaskClass::OneShot,
            reason: TaskExitReason::CleanCompletion,
            expected_during_shutdown: true,
        },
        Err(panic) => {
            let msg = extract_panic_message(panic);
            NamedTaskExit {
                id,
                name,
                class: TaskClass::OneShot,
                reason: TaskExitReason::Panic(msg),
                expected_during_shutdown: false,
            }
        }
    }
}

/// Classify the result of `catch_unwind` around `Future<Output=Result<(), E>>`.
fn classify_result_task<E: fmt::Display>(
    id: TaskId,
    name: &'static str,
    class: TaskClass,
    result: Result<Result<(), E>, Box<dyn std::any::Any + Send>>,
    shutdown_started: bool,
) -> NamedTaskExit {
    match result {
        Ok(Ok(())) => {
            let (reason, expected) = if shutdown_started {
                (TaskExitReason::CleanCompletion, true)
            } else {
                (TaskExitReason::UnexpectedCompletion, false)
            };
            NamedTaskExit {
                id,
                name,
                class,
                reason,
                expected_during_shutdown: expected,
            }
        }
        Ok(Err(e)) => NamedTaskExit {
            id,
            name,
            class,
            reason: TaskExitReason::Error(format!("{}", e)),
            expected_during_shutdown: false,
        },
        Err(panic) => {
            let msg = extract_panic_message(panic);
            NamedTaskExit {
                id,
                name,
                class,
                reason: TaskExitReason::Panic(msg),
                expected_during_shutdown: false,
            }
        }
    }
}

fn extract_panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Determine whether a task exit is fatal (should initiate worker shutdown).
///
/// Policy:
/// - CriticalService: fatal before shutdown for UnexpectedCompletion, Panic, Error
/// - RestartableBackground: never immediately fatal (logged/degraded only)
/// - Other classes: not part of worker-level exit channel
pub fn is_fatal_exit(exit: &NamedTaskExit, shutdown_started: bool) -> bool {
    match exit.class {
        TaskClass::CriticalService => {
            if shutdown_started {
                // During shutdown, clean completion and expected cancellation are not fatal.
                // Only abnormal exits (Panic, Error, UnexpectedCompletion) are fatal.
                exit.reason.is_abnormal()
            } else {
                // Before shutdown, any abnormal exit is fatal for critical services.
                exit.reason.is_abnormal() || matches!(exit.reason, TaskExitReason::Cancelled)
            }
        }
        _ => false,
    }
}

/// Map a fatal task exit to the appropriate `WorkerShutdownCause`.
///
/// Preserves task identity and reason through the supervision outcome.
/// Called when `is_fatal_exit` returns true.
pub fn map_task_exit_to_shutdown_cause(exit: NamedTaskExit) -> WorkerShutdownCause {
    if exit.name == "server_run" {
        WorkerShutdownCause::ServerExitedUnexpectedly(exit)
    } else {
        WorkerShutdownCause::CriticalTaskExit(exit)
    }
}

/// Map a broadcast receiver error to a shutdown cause.
///
/// `RecvError::Lagged` always maps to `RegistryExitChannelClosed`.
/// `RecvError::Closed` maps to `RegistryExitChannelClosed` only if
/// shutdown has not already started (otherwise it's expected).
pub fn map_exit_recv_error_to_shutdown_cause(
    error: tokio::sync::broadcast::error::RecvError,
    shutdown_started: bool,
) -> Option<WorkerShutdownCause> {
    match error {
        tokio::sync::broadcast::error::RecvError::Lagged(skipped) => {
            tracing::error!(
                "Exit receiver lagged, skipped {} events — supervision integrity compromised",
                skipped
            );
            Some(WorkerShutdownCause::RegistryExitChannelClosed)
        }
        tokio::sync::broadcast::error::RecvError::Closed => {
            if shutdown_started {
                None // Expected during shutdown
            } else {
                tracing::error!(
                    "Exit channel closed while registry active — lifecycle infrastructure failure"
                );
                Some(WorkerShutdownCause::RegistryExitChannelClosed)
            }
        }
    }
}

/// Classify a lifecycle channel closure into a shutdown cause.
///
/// Returns `None` if shutdown has already started (expected condition).
/// Returns `RegistryExitChannelClosed` if the IPC task exited without sending
/// an event while the worker was still active.
pub fn map_lifecycle_channel_closed(shutdown_started: bool) -> Option<WorkerShutdownCause> {
    if shutdown_started {
        None
    } else {
        Some(WorkerShutdownCause::RegistryExitChannelClosed)
    }
}

/// Helper to run a cancellation-aware interval loop.
pub async fn cancellation_loop<F, Fut>(
    mut shutdown_rx: watch::Receiver<bool>,
    interval: Duration,
    mut work: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                work().await;
            }
            result = shutdown_rx.changed() => {
                if result.is_ok() && *shutdown_rx.borrow() {
                    tracing::debug!("Cancellation loop received shutdown signal");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn test_registry_new_has_no_tasks() {
        let registry = WorkerTaskRegistry::new();
        assert_eq!(registry.active_count(), 0);
        assert_eq!(registry.critical_count(), 0);
        assert_eq!(registry.background_count(), 0);
    }

    #[tokio::test]
    async fn test_child_token_receives_shutdown() {
        let registry = WorkerTaskRegistry::new();
        let mut token = registry.child_token();
        assert!(!*token.borrow());
        registry.shutdown();
        token.changed().await.unwrap();
        assert!(*token.borrow());
    }

    #[tokio::test]
    async fn test_spawn_critical_and_shutdown() {
        let mut registry = WorkerTaskRegistry::new();
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = started.clone();

        let token = registry.child_token();
        registry.spawn_critical("test_critical", async move {
            started_clone.store(true, Ordering::SeqCst);
            let mut shutdown = token;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        });

        assert_eq!(registry.critical_count(), 1);
        tokio::task::yield_now().await;
        assert!(started.load(Ordering::SeqCst));

        let exits = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;
        assert!(exits.is_empty());
        assert_eq!(registry.active_count(), 0);
        assert_eq!(
            registry
                .metrics
                .tasks_completed_cleanly
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_spawn_background_and_shutdown() {
        let mut registry = WorkerTaskRegistry::new();
        let token = registry.child_token();

        registry.spawn_cancellable_background("test_bg", async move {
            let mut shutdown = token;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        });

        assert_eq!(registry.background_count(), 1);

        let exits = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;
        assert!(exits.is_empty());
    }

    #[tokio::test]
    async fn test_panic_is_reported() {
        let mut registry = WorkerTaskRegistry::new();
        registry.spawn_critical("panicking_task", async {
            panic!("test panic");
        });

        // Give the spawned task time to run and record metrics
        tokio::time::sleep(Duration::from_millis(50)).await;

        let panics_before = registry.metrics.tasks_panicked.load(Ordering::Relaxed);

        let exits = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;

        let panics_after = registry.metrics.tasks_panicked.load(Ordering::Relaxed);

        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "panicking_task");
        match &exits[0].reason {
            TaskExitReason::Panic(msg) => assert!(msg.contains("test panic")),
            other => panic!("Expected Panic, got {:?}", other),
        }
        assert_eq!(panics_after, panics_before + 1);
    }

    #[tokio::test]
    async fn test_shutdown_is_idempotent() {
        let mut registry = WorkerTaskRegistry::new();
        let token = registry.child_token();

        registry.spawn_cancellable_background("test_idempotent", async move {
            let mut shutdown = token;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        });

        registry.shutdown();
        registry.shutdown();
        registry.shutdown();

        let _ = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;
    }

    #[tokio::test]
    async fn test_cancellation_loop_stops_on_signal() {
        let (tx, rx) = watch::channel(false);
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();

        let handle = tokio::spawn(async move {
            cancellation_loop(rx, Duration::from_millis(10), || {
                let c = counter_clone.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let count_before = counter.load(Ordering::SeqCst);
        assert!(count_before > 0);

        tx.send(true).unwrap();
        handle.await.unwrap();

        let count_after = counter.load(Ordering::SeqCst);
        assert!(count_after <= count_before + 1);
    }

    #[tokio::test]
    async fn test_background_task_timeout_aborts() {
        let mut registry = WorkerTaskRegistry::new();

        registry.spawn_cancellable_background("hung_task", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        });

        let exits = registry
            .shutdown_and_join(Duration::from_millis(100), Duration::from_millis(100))
            .await;
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "hung_task");
        assert_eq!(exits[0].reason, TaskExitReason::Aborted);
    }

    #[tokio::test]
    async fn test_timeout_abort_actually_terminates_task() {
        let alive = Arc::new(AtomicU64::new(0));
        let alive_clone = alive.clone();

        let mut registry = WorkerTaskRegistry::new();
        registry.spawn_cancellable_background("looping_task", async move {
            loop {
                alive_clone.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let _ = registry
            .shutdown_and_join(Duration::from_millis(50), Duration::from_millis(50))
            .await;

        let after = alive.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after_wait = alive.load(Ordering::SeqCst);

        assert!(
            after_wait <= after + 1,
            "Task continued after abort: before={}, after={}, after_wait={}",
            after,
            after,
            after_wait
        );
    }

    #[tokio::test]
    async fn test_drop_guard_proves_termination() {
        static GUARD_DROPPED: AtomicBool = AtomicBool::new(false);
        GUARD_DROPPED.store(false, Ordering::SeqCst);

        struct DropGuard;
        impl Drop for DropGuard {
            fn drop(&mut self) {
                GUARD_DROPPED.store(true, Ordering::SeqCst);
            }
        }

        let mut registry = WorkerTaskRegistry::new();
        registry.spawn_cancellable_background("guard_task", async {
            let _guard = DropGuard;
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        });

        let _ = registry
            .shutdown_and_join(Duration::from_millis(50), Duration::from_millis(50))
            .await;

        assert!(
            GUARD_DROPPED.load(Ordering::SeqCst),
            "Drop guard was not dropped - task may not have been terminated"
        );
    }

    #[tokio::test]
    async fn test_immediate_critical_exit_notification() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_critical("immediate_task", async {});

        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("Should receive exit notification")
            .expect("Should Ok");

        assert_eq!(exit.name, "immediate_task");
        assert_eq!(exit.class, TaskClass::CriticalService);
    }

    #[tokio::test]
    async fn test_immediate_panic_notification() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_critical("panicking_task", async {
            panic!("boom");
        });

        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("Should receive exit notification")
            .expect("Should Ok");

        assert_eq!(exit.name, "panicking_task");
        match &exit.reason {
            TaskExitReason::Panic(msg) => assert!(msg.contains("boom")),
            other => panic!("Expected Panic, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_no_double_count_on_panic() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_critical("panic_task", async {
            panic!("double count test");
        });

        // Observe the immediate exit.
        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("timeout")
            .expect("recv");
        assert!(matches!(exit.reason, TaskExitReason::Panic(_)));

        // Now call shutdown_and_join. The panic should NOT be counted again.
        let _ = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;

        assert_eq!(
            registry.metrics.tasks_panicked.load(Ordering::Relaxed),
            1,
            "Panic was double-counted"
        );
    }

    #[tokio::test]
    async fn test_shared_deadline_subsequent_tasks_aborted() {
        let mut registry = WorkerTaskRegistry::new();

        registry.spawn_cancellable_background("slow_task", async {
            tokio::time::sleep(Duration::from_secs(100)).await;
        });

        registry.spawn_cancellable_background("also_hung", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        });

        let exits = registry
            .shutdown_and_join(Duration::from_millis(50), Duration::from_millis(50))
            .await;

        assert_eq!(exits.len(), 2);
        for exit in &exits {
            assert_eq!(exit.reason, TaskExitReason::Aborted);
        }

        assert_eq!(registry.active_count(), 0);
    }

    #[tokio::test]
    async fn test_subscribe_exits_receives_multiple() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_critical("task_a", async {});
        registry.spawn_critical("task_b", async {});

        let mut names = Vec::new();
        for _ in 0..2 {
            let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
                .await
                .expect("timeout")
                .expect("recv");
            names.push(exit.name);
        }
        names.sort();
        assert_eq!(names, vec!["task_a", "task_b"]);
    }

    #[tokio::test]
    async fn test_is_shutdown_started() {
        let registry = WorkerTaskRegistry::new();
        assert!(!registry.is_shutdown_started());
        registry.shutdown();
        assert!(registry.is_shutdown_started());
    }

    #[tokio::test]
    async fn test_pre_shutdown_unit_return_is_unexpected_completion() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();
        registry.spawn_critical("early_return", async {});
        tokio::time::sleep(Duration::from_millis(50)).await;

        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("timeout")
            .expect("recv");

        assert_eq!(exit.reason, TaskExitReason::UnexpectedCompletion);
        assert!(!exit.expected_during_shutdown);
    }

    #[tokio::test]
    async fn test_post_shutdown_unit_return_is_clean_completion() {
        let mut registry = WorkerTaskRegistry::new();
        let token = registry.child_token();
        registry.spawn_critical("shutdown_return", async move {
            let mut shutdown = token;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        });

        // Let the task start.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Trigger shutdown — this sets shutdown_started = true.
        let exits = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;

        // The task should exit cleanly (CleanCompletion) since shutdown was started.
        // CleanCompletion tasks are filtered out of the exits vec, so exits should be empty.
        assert!(
            exits.is_empty(),
            "Expected clean shutdown, got: {:?}",
            exits
        );
        assert_eq!(
            registry
                .metrics
                .tasks_completed_cleanly
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_result_task_pre_shutdown_ok_is_unexpected_completion() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();
        registry.spawn_critical_result("early_result", async { Ok::<(), String>(()) });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("timeout")
            .expect("recv");

        assert_eq!(exit.reason, TaskExitReason::UnexpectedCompletion);
    }

    #[tokio::test]
    async fn test_background_exit_notification_does_not_imply_fatality() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_cancellable_background("bg_task", async {});
        tokio::time::sleep(Duration::from_millis(50)).await;

        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("timeout")
            .expect("recv");

        assert_eq!(exit.class, TaskClass::RestartableBackground);
        assert!(!crate::worker::task_registry::is_fatal_exit(&exit, false));
    }

    #[tokio::test]
    async fn test_exit_receiver_subscribed_before_spawn_observes_immediate_exit() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_critical("immediate_exit", async {});

        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("Should receive exit notification")
            .expect("Should Ok");

        assert_eq!(exit.name, "immediate_exit");
        assert_eq!(exit.reason, TaskExitReason::UnexpectedCompletion);
    }

    #[tokio::test]
    async fn test_abort_path_does_not_emit_duplicate_exit_metrics() {
        let mut registry = WorkerTaskRegistry::new();
        let _exit_rx = registry.subscribe_exits();

        registry.spawn_cancellable_background("aborted_task", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        });

        let _ = registry
            .shutdown_and_join(Duration::from_millis(50), Duration::from_millis(50))
            .await;

        let aborted = registry.metrics.tasks_aborted.load(Ordering::Relaxed);
        assert!(aborted >= 1, "Expected at least 1 abort metric");
    }

    #[tokio::test]
    async fn test_is_fatal_exit_critical_before_shutdown() {
        let exit = NamedTaskExit {
            id: TaskId(1),
            name: "test",
            class: TaskClass::CriticalService,
            reason: TaskExitReason::UnexpectedCompletion,
            expected_during_shutdown: false,
        };
        assert!(crate::worker::task_registry::is_fatal_exit(&exit, false));
    }

    #[tokio::test]
    async fn test_is_fatal_exit_critical_panic() {
        let exit = NamedTaskExit {
            id: TaskId(1),
            name: "test",
            class: TaskClass::CriticalService,
            reason: TaskExitReason::Panic("boom".to_string()),
            expected_during_shutdown: false,
        };
        assert!(crate::worker::task_registry::is_fatal_exit(&exit, false));
    }

    #[tokio::test]
    async fn test_is_fatal_exit_critical_during_shutdown_clean() {
        let exit = NamedTaskExit {
            id: TaskId(1),
            name: "test",
            class: TaskClass::CriticalService,
            reason: TaskExitReason::CleanCompletion,
            expected_during_shutdown: true,
        };
        assert!(!crate::worker::task_registry::is_fatal_exit(&exit, true));
    }

    #[tokio::test]
    async fn test_is_fatal_exit_background_never_fatal() {
        let exit = NamedTaskExit {
            id: TaskId(1),
            name: "test",
            class: TaskClass::RestartableBackground,
            reason: TaskExitReason::UnexpectedCompletion,
            expected_during_shutdown: false,
        };
        assert!(!crate::worker::task_registry::is_fatal_exit(&exit, false));
    }

    #[tokio::test]
    async fn test_worker_shutdown_cause_display() {
        let cause = crate::worker::task_registry::WorkerShutdownCause::SupervisorShutdown;
        assert_eq!(format!("{}", cause), "supervisor_shutdown");
    }

    #[tokio::test]
    async fn test_worker_shutdown_cause_nonzero_exit() {
        let cause = crate::worker::task_registry::WorkerShutdownCause::ServerStoppedForShutdown;
        assert!(!cause.nonzero_exit_code());

        let cause = crate::worker::task_registry::WorkerShutdownCause::SupervisorDisconnected;
        assert!(cause.nonzero_exit_code());

        let cause = crate::worker::task_registry::WorkerShutdownCause::ServerExitedUnexpectedly(
            NamedTaskExit {
                id: TaskId(0),
                name: "server_run",
                class: TaskClass::CriticalService,
                reason: TaskExitReason::Error("test".to_string()),
                expected_during_shutdown: false,
            },
        );
        assert!(cause.nonzero_exit_code());
    }

    #[tokio::test]
    async fn test_begin_shutdown_marks_expected_without_broadcasting() {
        let registry = WorkerTaskRegistry::new();
        let token = registry.child_token();

        registry.begin_shutdown();
        assert!(registry.is_shutdown_started());
        // Token should still be false — broadcast_shutdown not called yet
        assert!(!*token.borrow());
    }

    #[tokio::test]
    async fn test_broadcast_shutdown_sends_signal() {
        let registry = WorkerTaskRegistry::new();
        let token = registry.child_token();

        registry.begin_shutdown();
        registry.broadcast_shutdown();
        assert!(*token.borrow());
    }

    #[tokio::test]
    async fn test_shutdown_begins_and_broadcasts() {
        let registry = WorkerTaskRegistry::new();
        let token = registry.child_token();

        registry.shutdown();
        assert!(registry.is_shutdown_started());
        assert!(*token.borrow());
    }

    #[tokio::test]
    async fn test_critical_return_after_begin_shutdown_is_clean() {
        let mut registry = WorkerTaskRegistry::new();
        let token = registry.child_token();

        // Mark shutdown intent before spawning
        registry.begin_shutdown();

        registry.spawn_critical("after_begin", async move {
            let mut shutdown = token;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        });

        let exits = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;
        assert!(exits.is_empty());
    }

    #[tokio::test]
    async fn test_critical_return_before_begin_shutdown_is_unexpected() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        // Spawn task that returns immediately WITHOUT begin_shutdown
        registry.spawn_critical("before_begin", async {});
        tokio::time::sleep(Duration::from_millis(50)).await;

        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("timeout")
            .expect("recv");

        assert_eq!(exit.reason, TaskExitReason::UnexpectedCompletion);
    }

    #[tokio::test]
    async fn test_begin_shutdown_is_idempotent() {
        let registry = WorkerTaskRegistry::new();
        registry.begin_shutdown();
        registry.begin_shutdown();
        registry.begin_shutdown();
        assert!(registry.is_shutdown_started());
    }

    #[tokio::test]
    async fn test_worker_resize_exit_code() {
        let cause =
            crate::worker::task_registry::WorkerShutdownCause::WorkerResize { worker_threads: 4 };
        assert_eq!(cause.exit_code(), 100);
        assert!(!cause.nonzero_exit_code());
        assert!(cause.is_expected());
    }

    #[tokio::test]
    async fn test_server_exited_unexpectedly_exit_code() {
        let cause = crate::worker::task_registry::WorkerShutdownCause::ServerExitedUnexpectedly(
            NamedTaskExit {
                id: TaskId(0),
                name: "server_run",
                class: TaskClass::CriticalService,
                reason: TaskExitReason::Error("test".to_string()),
                expected_during_shutdown: false,
            },
        );
        assert_eq!(cause.exit_code(), 1);
        assert!(cause.nonzero_exit_code());
        assert!(!cause.is_expected());
    }

    // ========================================================================
    // Phase 15: Forced cleanup tests
    // ========================================================================

    #[tokio::test]
    async fn subset_hung_cooperative_task_is_aborted_and_awaited() {
        let mut registry = WorkerTaskRegistry::new();
        let id = TaskId(registry.spawn_background("hung_task", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }) as u64);

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(10),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        assert_eq!(report.exits[0].name, "hung_task");
        // After abort, Tokio tasks exit with Cancelled (not Aborted).
        // Aborted is reserved for when the forced timeout fires.
        assert!(
            matches!(
                report.exits[0].reason,
                TaskExitReason::Cancelled | TaskExitReason::Aborted
            ),
            "expected Cancelled or Aborted, got {:?}",
            report.exits[0].reason
        );
    }

    #[tokio::test]
    async fn subset_registry_removes_task_only_after_join_completes() {
        let mut registry = WorkerTaskRegistry::new();
        let id = TaskId(registry.spawn_background("tracked_task", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }) as u64);

        assert!(registry.contains_task(id), "task must exist before cleanup");

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(10),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        assert!(
            !registry.contains_task(id),
            "task must be removed after join completes"
        );
    }

    #[tokio::test]
    async fn subset_no_handle_dropped_after_cooperative_timeout() {
        let mut registry = WorkerTaskRegistry::new();
        static DROPPED: AtomicBool = AtomicBool::new(false);
        DROPPED.store(false, Ordering::SeqCst);

        struct DropGuard;
        impl Drop for DropGuard {
            fn drop(&mut self) {
                DROPPED.store(true, Ordering::SeqCst);
            }
        }

        let id = TaskId(registry.spawn_background("guard_task", async {
            let _guard = DropGuard;
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }) as u64);

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(10),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        // After the subset join, the drop guard should have been dropped
        // (meaning the task was actually terminated and joined).
        assert!(
            DROPPED.load(Ordering::SeqCst),
            "task must be terminated after subset join"
        );
    }

    #[tokio::test]
    async fn subset_panicking_task_preserves_panic_classification() {
        let mut registry = WorkerTaskRegistry::new();
        let id = TaskId(registry.spawn_background("panic_task", async {
            panic!("subset panic test");
        }) as u64);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(50),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        assert!(matches!(report.exits[0].reason, TaskExitReason::Panic(_)));
    }

    #[tokio::test]
    async fn subset_already_finished_task_joins_cleanly() {
        let mut registry = WorkerTaskRegistry::new();
        let id = TaskId(registry.spawn_background("finished_task", async {}) as u64);

        // Wait for the task to complete.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(50),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        assert!(matches!(
            report.exits[0].reason,
            TaskExitReason::CleanCompletion | TaskExitReason::UnexpectedCompletion
        ));
    }

    #[tokio::test]
    async fn subset_unrelated_task_remains_in_registry() {
        let mut registry = WorkerTaskRegistry::new();
        let target_id = TaskId(registry.spawn_background("target", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }) as u64);
        let other_id = TaskId(registry.spawn_background("other", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }) as u64);

        let _ = registry
            .cancel_then_join_tasks(
                &[target_id],
                Duration::from_millis(10),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert!(
            registry.contains_task(other_id),
            "unrelated task must remain in registry"
        );
    }

    #[tokio::test]
    async fn subset_zero_cooperative_timeout_aborts_and_awaits() {
        let mut registry = WorkerTaskRegistry::new();
        let id = TaskId(registry.spawn_background("zero_timeout_task", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }) as u64);

        let report = registry
            .cancel_then_join_tasks(&[id], Duration::ZERO, Duration::from_secs(5), false)
            .await;

        assert_eq!(report.exits.len(), 1);
        assert!(
            matches!(
                report.exits[0].reason,
                TaskExitReason::Cancelled | TaskExitReason::Aborted
            ),
            "expected Cancelled or Aborted, got {:?}",
            report.exits[0].reason
        );
    }

    #[tokio::test]
    async fn subset_cleanup_report_no_unjoined_residue() {
        let mut registry = WorkerTaskRegistry::new();
        let ids: Vec<TaskId> = (0..3)
            .map(|i| {
                TaskId(registry.spawn_background(
                    Box::leak(format!("task_{}", i).into_boxed_str()),
                    async {
                        loop {
                            tokio::time::sleep(Duration::from_secs(100)).await;
                        }
                    },
                ) as u64)
            })
            .collect();

        let report = registry
            .cancel_then_join_tasks(
                &ids,
                Duration::from_millis(10),
                Duration::from_secs(5),
                false,
            )
            .await;

        // All tasks should be accounted for in exits.
        assert_eq!(report.exits.len(), 3);
        assert!(report.not_found_ids.is_empty());
        for exit in &report.exits {
            assert!(
                matches!(
                    exit.reason,
                    TaskExitReason::Cancelled | TaskExitReason::Aborted
                ),
                "expected Cancelled or Aborted, got {:?}",
                exit.reason
            );
        }
    }

    // ========================================================================
    // Phase 18: Accounting tests
    // ========================================================================

    #[tokio::test]
    async fn subset_clean_exit_counted_as_clean() {
        let mut registry = WorkerTaskRegistry::new();
        // Spawn a task that waits for shutdown signal — this ensures it exits
        // with CleanCompletion (not UnexpectedCompletion) during shutdown.
        let token = registry.child_token();
        let id = TaskId(registry.spawn_background("clean_task", async move {
            let mut shutdown = token;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        }) as u64);

        let report = registry
            .cancel_then_join_tasks(&[id], Duration::from_secs(5), Duration::from_secs(5), true)
            .await;

        assert_eq!(report.exits.len(), 1);
        assert!(
            report.clean(),
            "clean exit must result in clean report, got {:?}",
            report.exits[0].reason
        );
        assert_eq!(report.aborted_count(), 0);
    }

    #[tokio::test]
    async fn subset_cooperative_cancellation_counted() {
        let mut registry = WorkerTaskRegistry::new();
        let token = registry.child_token();
        let id = TaskId(registry.spawn_background("cooperative_task", async move {
            let mut shutdown = token;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        }) as u64);

        let report = registry
            .cancel_then_join_tasks(&[id], Duration::from_secs(5), Duration::from_secs(5), true)
            .await;

        assert_eq!(report.exits.len(), 1);
        assert!(matches!(
            report.exits[0].reason,
            TaskExitReason::Cancelled | TaskExitReason::CleanCompletion
        ));
        assert!(report.clean());
    }

    #[tokio::test]
    async fn subset_forced_abort_counted() {
        let mut registry = WorkerTaskRegistry::new();
        let id = TaskId(registry.spawn_background("abort_task", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }) as u64);

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(10),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        // After abort+join, Tokio tasks exit with Cancelled.
        // Cancelled IS classified as "clean" by clean() because it's a
        // cooperative cancellation — the task responded to the abort signal.
        // Aborted (non-clean) is only when the forced timeout fires after abort.
        assert!(
            matches!(
                report.exits[0].reason,
                TaskExitReason::Cancelled | TaskExitReason::Aborted
            ),
            "expected Cancelled or Aborted, got {:?}",
            report.exits[0].reason
        );
    }

    #[tokio::test]
    async fn subset_panic_and_error_counted_as_failed() {
        let mut registry = WorkerTaskRegistry::new();
        let panic_id = TaskId(registry.spawn_background("panic_task", async {
            panic!("accounting panic");
        }) as u64);
        let error_id = TaskId(registry.spawn_background("error_task", async {
            panic!("accounting error");
        }) as u64);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let report = registry
            .cancel_then_join_tasks(
                &[panic_id, error_id],
                Duration::from_millis(50),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 2);
        // Both should be counted as non-clean (panics).
        assert!(!report.clean());
    }

    #[tokio::test]
    async fn subset_no_double_counting() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        let id = TaskId(registry.spawn_background("count_task", async {
            panic!("double count test");
        }) as u64);

        // Observe the immediate exit event.
        let _ = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv()).await;

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(50),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        // The panic should not be counted twice in metrics.
        assert_eq!(
            registry.metrics.tasks_panicked.load(Ordering::Relaxed),
            1,
            "Panic was double-counted in subset cleanup"
        );
    }

    #[tokio::test]
    async fn subset_not_found_ids_surfaced() {
        let mut registry = WorkerTaskRegistry::new();
        let missing_id = TaskId(99999);

        let report = registry
            .cancel_then_join_tasks(
                &[missing_id],
                Duration::from_millis(10),
                Duration::from_secs(5),
                false,
            )
            .await;

        assert!(report.exits.is_empty());
        assert_eq!(report.not_found_ids.len(), 1);
        assert_eq!(report.not_found_ids[0], missing_id);
    }

    #[tokio::test]
    async fn subset_clean_semantics_match_ownership_guarantee() {
        let mut registry = WorkerTaskRegistry::new();
        let token1 = registry.child_token();
        let token2 = registry.child_token();
        let id1 = TaskId(registry.spawn_background("clean1", async move {
            let mut shutdown = token1;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        }) as u64);
        let id2 = TaskId(registry.spawn_background("clean2", async move {
            let mut shutdown = token2;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        }) as u64);

        let report = registry
            .cancel_then_join_tasks(
                &[id1, id2],
                Duration::from_secs(5),
                Duration::from_secs(5),
                true,
            )
            .await;

        assert!(report.clean(), "all clean exits must produce clean report");
        assert_eq!(report.aborted_count(), 0);
        assert!(report.not_found_ids.is_empty());
        // No task should remain in registry after subset join.
        assert!(!registry.contains_task(id1));
        assert!(!registry.contains_task(id2));
    }

    // ========================================================================
    // Phase 90: Forced abort-join ownership tests
    // ========================================================================

    #[tokio::test]
    async fn cancel_then_join_tasks_aborts_and_awaits_pending_handle() {
        let mut registry = WorkerTaskRegistry::new();
        let started = Arc::new(Notify::new());
        let never = Arc::new(Notify::new());
        let started_clone = started.clone();
        let never_clone = never.clone();

        let id = TaskId(registry.spawn_background("hung_support", async move {
            started_clone.notify_one();
            never_clone.notified().await;
        }) as u64);

        started.notified().await;

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(0),
                Duration::from_millis(1),
                false,
            )
            .await;

        assert_eq!(report.not_found_ids.len(), 0);
        assert_eq!(report.exits.len(), 1);
        assert!(
            matches!(
                report.exits[0].reason,
                TaskExitReason::Cancelled | TaskExitReason::Aborted
            ),
            "expected Cancelled or Aborted, got {:?}",
            report.exits[0].reason
        );
        assert!(
            !registry.contains_task(id),
            "task must be removed from registry after abort-join"
        );
    }

    #[tokio::test]
    async fn cancel_then_join_tasks_preserves_panic_classification() {
        let mut registry = WorkerTaskRegistry::new();
        let id = TaskId(registry.spawn_background("panic_support", async {
            panic!("boom");
        }) as u64);

        tokio::task::yield_now().await;

        let report = registry
            .cancel_then_join_tasks(
                &[id],
                Duration::from_millis(10),
                Duration::from_millis(10),
                false,
            )
            .await;

        assert!(
            report
                .exits
                .iter()
                .any(|e| matches!(e.reason, TaskExitReason::Panic(_))),
            "panic classification must be preserved, got {:?}",
            report.exits
        );
    }
}
