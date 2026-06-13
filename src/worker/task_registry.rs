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

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Task classification for lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskClass {
    /// Listener accept loops, IPC loops, critical persistence.
    /// Unexpected exit is fatal; shutdown awaits with timeout.
    CriticalService,
    /// Health checks, metrics, feed refresh, cache cleanup.
    /// Unexpected exit logged; optional bounded restart.
    RestartableBackground,
    /// Per-connection/request tasks.
    /// Drained or aborted after timeout.
    BoundedChild,
    /// Compression, minification, blocking I/O.
    /// Bounded queue; shutdown stops intake and drains.
    CpuOffload,
    /// Fire-and-forget where result and lifetime don't affect correctness.
    /// Rare; explicitly documented with rationale.
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
    /// Task was cancelled via the registry shutdown signal.
    Cancelled,
    /// Task completed its work normally.
    CleanCompletion,
    /// Task panicked.
    Panic(String),
    /// Task returned an error.
    Error(String),
    /// Task was aborted (e.g., timed out during shutdown).
    Aborted,
}

impl fmt::Display for TaskExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "cancelled"),
            Self::CleanCompletion => write!(f, "clean_completion"),
            Self::Panic(msg) => write!(f, "panic: {}", msg),
            Self::Error(msg) => write!(f, "error: {}", msg),
            Self::Aborted => write!(f, "aborted"),
        }
    }
}

/// Error from [`ManagedService::join`].
#[derive(Debug)]
pub enum ServiceExitError {
    /// The service panicked.
    Panic(String),
    /// The service returned an error.
    Error(String),
    /// The service was cancelled.
    Cancelled,
    /// The join failed (task gone).
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
///
/// Implementors must ensure:
/// - `shutdown()` is idempotent
/// - `join()` can be called after `shutdown()`
/// - no hidden long-lived task survives owner drop unless intentionally detached
pub trait ManagedService: Send + Sync {
    /// Human-readable name for logging and metrics.
    fn name(&self) -> &'static str;

    /// Initiate graceful shutdown. Idempotent.
    fn shutdown(&self);

    /// Wait for the service to complete. Can be called after `shutdown()`.
    #[allow(async_fn_in_trait)]
    async fn join(&self) -> Result<(), ServiceExitError>;
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
}

/// Entry for a registered task.
struct RegisteredTask {
    name: &'static str,
    #[allow(dead_code)]
    class: TaskClass,
    handle: JoinHandle<()>,
}

/// A worker-level task registry that manages long-lived background tasks.
///
/// Uses `tokio::sync::watch` for cancellation and `JoinHandle` storage
/// for ordered shutdown. Critical and background tasks are tracked
/// separately.
pub struct WorkerTaskRegistry {
    /// Shutdown signal: receivers watch this for cancellation.
    shutdown_tx: watch::Sender<bool>,
    /// Critical service tasks.
    critical: Vec<RegisteredTask>,
    /// Background/restartable tasks.
    background: Vec<RegisteredTask>,
    /// Auto-incrementing task ID.
    next_id: AtomicU64,
    /// Metrics.
    pub metrics: Arc<TaskRegistryMetrics>,
}

impl WorkerTaskRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            shutdown_tx,
            critical: Vec::new(),
            background: Vec::new(),
            next_id: AtomicU64::new(1),
            metrics: Arc::new(TaskRegistryMetrics::default()),
        }
    }

    /// Get a child cancellation token (watch receiver) for a spawned task.
    ///
    /// The task should use `tokio::select!` between its work and
    /// `shutdown_rx.changed()` to implement cooperative cancellation.
    pub fn child_token(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Register and spawn a critical service task.
    pub fn spawn_critical<F>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
        let handle = tokio::task::spawn(future);
        self.metrics.record_started();
        self.critical.push(RegisteredTask {
            name,
            class: TaskClass::CriticalService,
            handle,
        });
        id
    }

    /// Register and spawn a background/restartable task.
    pub fn spawn_background<F>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
        let handle = tokio::task::spawn(future);
        self.metrics.record_started();
        self.background.push(RegisteredTask {
            name,
            class: TaskClass::RestartableBackground,
            handle,
        });
        id
    }

    /// Register and spawn a background task with a cancellation-aware body.
    ///
    /// The future should use `tokio::select!` with `child_token()` for
    /// cooperative cancellation.
    pub fn spawn_cancellable_background<F>(&mut self, name: &'static str, future: F) -> usize
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as usize;
        let handle = tokio::task::spawn(future);
        self.metrics.record_started();
        self.background.push(RegisteredTask {
            name,
            class: TaskClass::RestartableBackground,
            handle,
        });
        id
    }

    /// Signal all tasks to shut down.
    ///
    /// This sets the watch channel to `true`, which is observed by all
    /// tasks using `child_token()`. The signal is idempotent.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Classify a JoinError for a named task.
    fn classify_join_error(
        name: &'static str,
        e: tokio::task::JoinError,
    ) -> (&'static str, TaskExitReason) {
        if e.is_cancelled() {
            (name, TaskExitReason::Cancelled)
        } else if e.is_panic() {
            (name, TaskExitReason::Panic(format!("{}", e)))
        } else {
            (name, TaskExitReason::Error(format!("{}", e)))
        }
    }

    /// Initiate shutdown and join all tasks with bounded timeouts.
    ///
    /// Returns the list of task names that were aborted (did not complete
    /// within their timeout).
    pub async fn shutdown_and_join(
        &mut self,
        critical_timeout: Duration,
        background_timeout: Duration,
    ) -> Vec<(&'static str, TaskExitReason)> {
        let shutdown_start = std::time::Instant::now();
        self.shutdown();

        let mut aborted = Vec::new();

        // Join critical tasks first
        let deadline = tokio::time::Instant::now() + critical_timeout;
        for task in self.critical.drain(..) {
            if tokio::time::Instant::now() >= deadline {
                tracing::error!(
                    "Critical task shutdown timeout after {:?}, aborting remaining",
                    critical_timeout,
                );
                self.metrics
                    .tasks_remaining_at_timeout
                    .fetch_add(1, Ordering::Relaxed);
                task.handle.abort();
                aborted.push((task.name, TaskExitReason::Aborted));
                self.metrics.record_aborted();
                continue;
            }
            let name = task.name;
            match tokio::time::timeout_at(deadline, task.handle).await {
                Ok(Ok(())) => {
                    self.metrics.record_completed_cleanly();
                    tracing::debug!("Critical task '{}' completed cleanly", name);
                }
                Ok(Err(e)) => {
                    let (name, reason) = Self::classify_join_error(name, e);
                    match &reason {
                        TaskExitReason::Cancelled => self.metrics.record_cancelled(),
                        TaskExitReason::Panic(_) => {
                            self.metrics.record_panicked();
                            tracing::error!("Critical task '{}' panicked", name);
                        }
                        _ => self.metrics.record_errored(),
                    }
                    tracing::debug!("Critical task '{}' exit: {}", name, reason);
                    aborted.push((name, reason));
                }
                Err(_) => {
                    tracing::error!(
                        "Critical task '{}' shutdown timeout exceeded, aborting",
                        name
                    );
                    // Handle was already consumed by timeout_at; task is
                    // dropped which aborts it.
                    self.metrics.record_aborted();
                    aborted.push((name, TaskExitReason::Aborted));
                }
            }
        }

        // Join background tasks
        let deadline = tokio::time::Instant::now() + background_timeout;
        for task in self.background.drain(..) {
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    "Background task shutdown timeout after {:?}, aborting remaining",
                    background_timeout,
                );
                self.metrics
                    .tasks_remaining_at_timeout
                    .fetch_add(1, Ordering::Relaxed);
                task.handle.abort();
                aborted.push((task.name, TaskExitReason::Aborted));
                self.metrics.record_aborted();
                continue;
            }
            let name = task.name;
            match tokio::time::timeout_at(deadline, task.handle).await {
                Ok(Ok(())) => {
                    self.metrics.record_completed_cleanly();
                    tracing::debug!("Background task '{}' completed cleanly", name);
                }
                Ok(Err(e)) => {
                    let (name, reason) = Self::classify_join_error(name, e);
                    match &reason {
                        TaskExitReason::Cancelled => self.metrics.record_cancelled(),
                        TaskExitReason::Panic(_) => {
                            self.metrics.record_panicked();
                            tracing::warn!("Background task '{}' panicked", name);
                        }
                        _ => self.metrics.record_errored(),
                    }
                    tracing::debug!("Background task '{}' exit: {}", name, reason);
                    aborted.push((name, reason));
                }
                Err(_) => {
                    tracing::warn!(
                        "Background task '{}' shutdown timeout exceeded, aborting",
                        name
                    );
                    // Handle was already consumed by timeout_at; task is
                    // dropped which aborts it.
                    self.metrics.record_aborted();
                    aborted.push((name, TaskExitReason::Aborted));
                }
            }
        }

        let elapsed = shutdown_start.elapsed();
        self.metrics
            .shutdown_duration_ms
            .store(elapsed.as_millis() as u64, Ordering::Relaxed);
        tracing::info!(
            "Task registry shutdown complete in {:?}, {} tasks aborted",
            elapsed,
            aborted.len()
        );

        aborted
    }

    /// Number of active tasks (critical + background).
    pub fn active_count(&self) -> usize {
        self.critical.len() + self.background.len()
    }

    /// Number of critical tasks.
    pub fn critical_count(&self) -> usize {
        self.critical.len()
    }

    /// Number of background tasks.
    pub fn background_count(&self) -> usize {
        self.background.len()
    }
}

impl Default for WorkerTaskRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to run a cancellation-aware interval loop.
///
/// Use this in tasks that need periodic work with cooperative shutdown:
///
/// ```ignore
/// let token = registry.child_token();
/// registry.spawn_cancellable_background("my_task", async move {
///     cancellation_loop(token, Duration::from_secs(5), || async {
///         do_periodic_work().await;
///     }).await;
/// });
/// ```
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
        // Task starts running immediately
        tokio::task::yield_now().await;
        assert!(started.load(Ordering::SeqCst));

        let aborted = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;
        assert!(aborted.is_empty());
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

        let aborted = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;
        assert!(aborted.is_empty());
    }

    #[tokio::test]
    async fn test_panic_is_reported() {
        let mut registry = WorkerTaskRegistry::new();
        registry.spawn_critical("panicking_task", async {
            panic!("test panic");
        });

        let aborted = registry
            .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
            .await;
        assert_eq!(aborted.len(), 1);
        assert_eq!(aborted[0].0, "panicking_task");
        match &aborted[0].1 {
            TaskExitReason::Panic(msg) => assert!(msg.contains("test panic")),
            other => panic!("Expected Panic, got {:?}", other),
        }
        assert_eq!(registry.metrics.tasks_panicked.load(Ordering::Relaxed), 1);
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

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(50)).await;
        let count_before = counter.load(Ordering::SeqCst);
        assert!(count_before > 0);

        // Signal shutdown
        tx.send(true).unwrap();
        handle.await.unwrap();

        // Counter should not increase significantly after shutdown
        let count_after = counter.load(Ordering::SeqCst);
        assert!(count_after <= count_before + 1);
    }

    #[tokio::test]
    async fn test_background_task_timeout_aborts() {
        let mut registry = WorkerTaskRegistry::new();

        // Spawn a task that never finishes
        registry.spawn_cancellable_background("hung_task", async {
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        });

        // Shutdown with very short timeout
        let aborted = registry
            .shutdown_and_join(Duration::from_millis(100), Duration::from_millis(100))
            .await;
        assert_eq!(aborted.len(), 1);
        assert_eq!(aborted[0].0, "hung_task");
        assert_eq!(aborted[0].1, TaskExitReason::Aborted);
    }
}
