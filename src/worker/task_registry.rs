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
}

impl fmt::Display for TaskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CriticalService => write!(f, "critical_service"),
            Self::RestartableBackground => write!(f, "restartable_background"),
            Self::BoundedChild => write!(f, "bounded_child"),
            Self::CpuOffload => write!(f, "cpu_offload"),
            Self::Detached => write!(f, "detached"),
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

/// The primary cause of a worker shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerShutdownCause {
    /// The unified-server run task exited (normal or error).
    ServerExited,
    /// A critical service task exited abnormally before or during shutdown.
    CriticalTaskExit(NamedTaskExit),
    /// The supervisor initiated a coordinated shutdown (MasterShutdown).
    SupervisorShutdown,
    /// The IPC connection to the supervisor was lost.
    SupervisorDisconnected,
    /// The registry exit broadcast channel closed unexpectedly.
    RegistryExitChannelClosed,
    /// An external stop signal was received.
    ExternalStop,
    /// The worker running flag was cleared (e.g. resize command).
    RunningFlagCleared,
}

impl WorkerShutdownCause {
    /// Returns true if this cause should result in a nonzero exit code.
    pub fn nonzero_exit_code(&self) -> bool {
        match self {
            Self::ServerExited => false,
            Self::CriticalTaskExit(_) => true,
            Self::SupervisorShutdown => false,
            Self::SupervisorDisconnected => true,
            Self::RegistryExitChannelClosed => true,
            Self::ExternalStop => false,
            Self::RunningFlagCleared => false,
        }
    }

    /// Returns true if this cause should trigger supervisor notification.
    pub fn should_notify_supervisor(&self) -> bool {
        matches!(
            self,
            Self::CriticalTaskExit(_)
                | Self::SupervisorDisconnected
                | Self::RegistryExitChannelClosed
        )
    }

    /// Returns true if this cause represents an expected shutdown.
    pub fn is_expected(&self) -> bool {
        matches!(
            self,
            Self::ServerExited
                | Self::SupervisorShutdown
                | Self::ExternalStop
                | Self::RunningFlagCleared
        )
    }
}

impl fmt::Display for WorkerShutdownCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerExited => write!(f, "server_exited"),
            Self::CriticalTaskExit(exit) => {
                write!(f, "critical_task_exit: {} ({})", exit.name, exit.reason)
            }
            Self::SupervisorShutdown => write!(f, "supervisor_shutdown"),
            Self::SupervisorDisconnected => write!(f, "supervisor_disconnected"),
            Self::RegistryExitChannelClosed => write!(f, "registry_exit_channel_closed"),
            Self::ExternalStop => write!(f, "external_stop"),
            Self::RunningFlagCleared => write!(f, "running_flag_cleared"),
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
    }
    pub fn record_completed_cleanly(&self) {
        self.tasks_completed_cleanly.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_cancelled(&self) {
        self.tasks_cancelled.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_panicked(&self) {
        self.tasks_panicked.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_aborted(&self) {
        self.tasks_aborted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_errored(&self) {
        self.tasks_errored.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_unexpectedly_completed(&self) {
        self.tasks_unexpectedly_completed
            .fetch_add(1, Ordering::Relaxed);
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

    pub fn shutdown(&self) {
        self.shutdown_started.store(true, Ordering::Relaxed);
        self.shutdown_started_arc.store(true, Ordering::Release);
        let _ = self.shutdown_tx.send(true);
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
        assert_eq!(panics_after, 1);
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
        let cause = crate::worker::task_registry::WorkerShutdownCause::SupervisorShutdown;
        assert!(!cause.nonzero_exit_code());

        let cause = crate::worker::task_registry::WorkerShutdownCause::SupervisorDisconnected;
        assert!(cause.nonzero_exit_code());
    }
}
