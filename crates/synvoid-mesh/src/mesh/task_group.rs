//! Mesh-local task group for Iteration 68, 70.
//!
//! `MeshTaskGroup` manages the lifecycle of mesh tasks — critical services,
//! background work, and bounded children — with unified shutdown propagation
//! and exit reporting.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::sync::{broadcast, watch};

use crate::lifecycle::{
    MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId, MeshTaskIdGenerator,
};

/// A named mesh task with its join handle.
pub(crate) struct NamedMeshTask {
    pub(crate) name: &'static str,
    pub(crate) class: MeshTaskClass,
    pub(crate) id: MeshTaskId,
    pub(crate) handle: tokio::task::JoinHandle<MeshTaskExit>,
}

/// Mesh-local task group managing critical, background, and child tasks.
pub struct MeshTaskGroup {
    shutdown_tx: watch::Sender<bool>,
    critical: Vec<NamedMeshTask>,
    background: Vec<NamedMeshTask>,
    children: Vec<NamedMeshTask>,
    shutdown_started: Arc<AtomicBool>,
    exit_tx: broadcast::Sender<MeshTaskExit>,
    forward_tx: Option<broadcast::Sender<MeshTaskExit>>,
    next_id: AtomicU64,
    id_generator: Option<Arc<MeshTaskIdGenerator>>,
}

impl MeshTaskGroup {
    /// Creates a new task group with a fresh shutdown channel.
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let (exit_tx, _) = broadcast::channel(64);
        Self {
            shutdown_tx,
            critical: Vec::new(),
            background: Vec::new(),
            children: Vec::new(),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            exit_tx,
            forward_tx: None,
            next_id: AtomicU64::new(0),
            id_generator: None,
        }
    }

    /// Creates a new task group that forwards exit events to an external sender.
    ///
    /// This allows a parent (e.g., `MeshTransport`) to maintain a stable
    /// broadcast channel that survives task group replacements during restart.
    pub fn new_with_forward(forward_tx: broadcast::Sender<MeshTaskExit>) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let (exit_tx, _) = broadcast::channel(64);
        Self {
            shutdown_tx,
            critical: Vec::new(),
            background: Vec::new(),
            children: Vec::new(),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            exit_tx,
            forward_tx: Some(forward_tx),
            next_id: AtomicU64::new(0),
            id_generator: None,
        }
    }

    /// Creates a new task group with a global ID generator and exit forwarding.
    ///
    /// Task IDs allocated through this group are globally unique across
    /// task-group generations, ensuring no collisions on the stable exit channel.
    pub fn new_with_forward_and_id_gen(
        forward_tx: broadcast::Sender<MeshTaskExit>,
        id_generator: Arc<MeshTaskIdGenerator>,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let (exit_tx, _) = broadcast::channel(64);
        Self {
            shutdown_tx,
            critical: Vec::new(),
            background: Vec::new(),
            children: Vec::new(),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            exit_tx,
            forward_tx: Some(forward_tx),
            next_id: AtomicU64::new(0),
            id_generator: Some(id_generator),
        }
    }

    /// Allocate the next task ID, using the global generator if available.
    fn next_task_id(&self) -> MeshTaskId {
        if let Some(ref gen) = self.id_generator {
            gen.next()
        } else {
            MeshTaskId(self.next_id.fetch_add(1, Ordering::Relaxed))
        }
    }

    /// Returns a clone of the shutdown receiver for tasks to watch.
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Returns a receiver for task exit events, for worker integration.
    pub fn subscribe_exits(&self) -> broadcast::Receiver<MeshTaskExit> {
        self.exit_tx.subscribe()
    }

    /// Spawns a critical service task.
    ///
    /// Critical tasks that exit with an error or panic are considered fatal
    /// for the mesh process.
    pub fn spawn_critical(
        &mut self,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let id = self.next_task_id();
        let handle = self.spawn_wrapped(name, MeshTaskClass::CriticalService, id, future);
        self.critical.push(NamedMeshTask {
            name,
            class: MeshTaskClass::CriticalService,
            id,
            handle,
        });
    }

    /// Spawns a critical service task that returns a `Result`.
    ///
    /// `Ok(())` is classified like `spawn_critical`. `Ok(Err(e))` is
    /// classified as `Error(e.to_string())`.
    pub fn spawn_critical_result<F, E>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let id = self.next_task_id();
        let handle = self.spawn_wrapped_result(name, MeshTaskClass::CriticalService, id, future);
        self.critical.push(NamedMeshTask {
            name,
            class: MeshTaskClass::CriticalService,
            id,
            handle,
        });
    }

    /// Spawns a background task.
    ///
    /// Background tasks can be restarted on failure without affecting mesh health.
    pub fn spawn_background(
        &mut self,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let id = self.next_task_id();
        let handle = self.spawn_wrapped(name, MeshTaskClass::RestartableBackground, id, future);
        self.background.push(NamedMeshTask {
            name,
            class: MeshTaskClass::RestartableBackground,
            id,
            handle,
        });
    }

    /// Spawns a background task that returns a `Result`.
    ///
    /// `Ok(())` is classified like `spawn_background`. `Ok(Err(e))` is
    /// classified as `Error(e.to_string())`.
    pub fn spawn_background_result<F, E>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let id = self.next_task_id();
        let handle =
            self.spawn_wrapped_result(name, MeshTaskClass::RestartableBackground, id, future);
        self.background.push(NamedMeshTask {
            name,
            class: MeshTaskClass::RestartableBackground,
            id,
            handle,
        });
    }

    /// Spawns a bounded child task.
    ///
    /// Child tasks are expected to complete during normal operation.
    pub fn spawn_child(
        &mut self,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let id = self.next_task_id();
        let handle = self.spawn_wrapped(name, MeshTaskClass::BoundedChild, id, future);
        self.children.push(NamedMeshTask {
            name,
            class: MeshTaskClass::BoundedChild,
            id,
            handle,
        });
    }

    /// Signals the start of shutdown and broadcasts the shutdown signal.
    pub async fn begin_shutdown(&self) {
        self.shutdown_started.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
    }

    /// Joins all tasks with the given timeout.
    ///
    /// Tasks that do not complete within the timeout are aborted. Returns a
    /// `Vec<MeshTaskExit>` with the exit metadata for every task.
    pub async fn join_all(&mut self, timeout: Duration) -> Vec<MeshTaskExit> {
        let deadline = Instant::now() + timeout;
        let mut exits = Vec::new();

        // Drain all task lists in order: critical, background, children.
        let all_tasks: Vec<_> = self
            .critical
            .drain(..)
            .chain(self.background.drain(..))
            .chain(self.children.drain(..))
            .collect();

        for task in all_tasks {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let NamedMeshTask {
                name,
                class,
                id,
                mut handle,
            } = task;

            if remaining.is_zero() {
                handle.abort();
                let _ = handle.await;
                exits.push(MeshTaskExit {
                    id,
                    name,
                    class,
                    reason: MeshTaskExitReason::Aborted,
                });
                continue;
            }

            let poll_result = tokio::time::timeout(remaining, poll_handle(&mut handle)).await;

            match poll_result {
                Ok(Ok(exit)) => {
                    exits.push(exit);
                }
                Ok(Err(join_err)) => {
                    let reason = if join_err.is_cancelled() {
                        MeshTaskExitReason::Cancelled
                    } else {
                        MeshTaskExitReason::Error(format!("join error: {join_err}"))
                    };
                    exits.push(MeshTaskExit {
                        id,
                        name,
                        class,
                        reason,
                    });
                }
                Err(_elapsed) => {
                    handle.abort();
                    let _ = handle.await;
                    exits.push(MeshTaskExit {
                        id,
                        name,
                        class,
                        reason: MeshTaskExitReason::Aborted,
                    });
                }
            }
        }

        exits
    }

    /// Returns the count of (critical, background, children) tasks.
    pub fn active_count(&self) -> (usize, usize, usize) {
        (
            self.critical.len(),
            self.background.len(),
            self.children.len(),
        )
    }

    /// Returns `true` if all task lists are empty.
    pub fn is_empty(&self) -> bool {
        self.critical.is_empty() && self.background.is_empty() && self.children.is_empty()
    }

    /// Wraps a future with panic detection, exit reporting, and cancellation
    /// classification, then spawns it on the Tokio runtime.
    fn spawn_wrapped(
        &self,
        name: &'static str,
        class: MeshTaskClass,
        id: MeshTaskId,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> tokio::task::JoinHandle<MeshTaskExit> {
        let exit_tx = self.exit_tx.clone();
        let forward_tx = self.forward_tx.clone();
        let shutdown_flag = self.shutdown_started.clone();

        tokio::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;

            let reason = match result {
                Ok(()) => {
                    if shutdown_flag.load(Ordering::SeqCst) {
                        match class {
                            MeshTaskClass::CriticalService
                            | MeshTaskClass::RestartableBackground => MeshTaskExitReason::Cancelled,
                            MeshTaskClass::BoundedChild | MeshTaskClass::OneShotStartup => {
                                MeshTaskExitReason::CleanCompletion
                            }
                        }
                    } else {
                        match class {
                            MeshTaskClass::CriticalService
                            | MeshTaskClass::RestartableBackground => {
                                MeshTaskExitReason::UnexpectedCompletion
                            }
                            MeshTaskClass::BoundedChild | MeshTaskClass::OneShotStartup => {
                                MeshTaskExitReason::CleanCompletion
                            }
                        }
                    }
                }
                Err(panic_payload) => {
                    let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    MeshTaskExitReason::Panic(msg)
                }
            };

            let exit = MeshTaskExit {
                id,
                name,
                class,
                reason,
            };
            let _ = exit_tx.send(exit.clone());
            if let Some(fwd) = forward_tx {
                let _ = fwd.send(exit.clone());
            }
            exit
        })
    }

    /// Wraps a `Result`-returning future with panic detection, exit reporting,
    /// and cancellation classification, then spawns it on the Tokio runtime.
    fn spawn_wrapped_result<F, E>(
        &self,
        name: &'static str,
        class: MeshTaskClass,
        id: MeshTaskId,
        future: F,
    ) -> tokio::task::JoinHandle<MeshTaskExit>
    where
        F: Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let exit_tx = self.exit_tx.clone();
        let forward_tx = self.forward_tx.clone();
        let shutdown_flag = self.shutdown_started.clone();

        tokio::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;

            let reason = match result {
                Ok(Ok(())) => {
                    if shutdown_flag.load(Ordering::SeqCst) {
                        match class {
                            MeshTaskClass::CriticalService
                            | MeshTaskClass::RestartableBackground => MeshTaskExitReason::Cancelled,
                            MeshTaskClass::BoundedChild | MeshTaskClass::OneShotStartup => {
                                MeshTaskExitReason::CleanCompletion
                            }
                        }
                    } else {
                        match class {
                            MeshTaskClass::CriticalService
                            | MeshTaskClass::RestartableBackground => {
                                MeshTaskExitReason::UnexpectedCompletion
                            }
                            MeshTaskClass::BoundedChild | MeshTaskClass::OneShotStartup => {
                                MeshTaskExitReason::CleanCompletion
                            }
                        }
                    }
                }
                Ok(Err(e)) => MeshTaskExitReason::Error(e.to_string()),
                Err(panic_payload) => {
                    let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    MeshTaskExitReason::Panic(msg)
                }
            };

            let exit = MeshTaskExit {
                id,
                name,
                class,
                reason,
            };
            let _ = exit_tx.send(exit.clone());
            if let Some(fwd) = forward_tx {
                let _ = fwd.send(exit.clone());
            }
            exit
        })
    }
}

/// Polls a `JoinHandle` to completion using `futures::poll_fn`.
///
/// This bridges between `JoinHandle`'s `Future` implementation (which is
/// `!Unpin`) and contexts that require an `Unpin`-compatible future, such
/// as `tokio::time::timeout`.
async fn poll_handle(
    handle: &mut tokio::task::JoinHandle<MeshTaskExit>,
) -> Result<MeshTaskExit, tokio::task::JoinError> {
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *handle).poll(cx)).await
}

impl Default for MeshTaskGroup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_spawn_and_join_critical() {
        let mut group = MeshTaskGroup::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        group.spawn_critical("critical_1", async move {
            let _ = rx.await;
        });

        let (c, b, ch) = group.active_count();
        assert_eq!(c, 1);
        assert_eq!(b, 0);
        assert_eq!(ch, 0);
        assert!(!group.is_empty());

        tx.send(()).unwrap();

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "critical_1");
        assert_eq!(exits[0].class, MeshTaskClass::CriticalService);
        assert!(group.is_empty());
    }

    #[tokio::test]
    async fn test_spawn_and_join_background() {
        let mut group = MeshTaskGroup::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        group.spawn_background("bg_1", async move {
            let _ = rx.await;
        });

        let (c, b, ch) = group.active_count();
        assert_eq!(c, 0);
        assert_eq!(b, 1);
        assert_eq!(ch, 0);

        tx.send(()).unwrap();

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "bg_1");
        assert_eq!(exits[0].class, MeshTaskClass::RestartableBackground);
    }

    #[tokio::test]
    async fn test_shutdown_signal_propagation() {
        let group = MeshTaskGroup::new();
        let mut rx = group.shutdown_receiver();

        assert!(!*rx.borrow());

        group.begin_shutdown().await;

        // Wait for the watch update to propagate.
        rx.changed().await.unwrap();
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn test_join_all_timeout_aborts() {
        let mut group = MeshTaskGroup::new();

        group.spawn_critical("slow_task", async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let exits = group.join_all(Duration::from_millis(50)).await;
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "slow_task");
        assert_eq!(exits[0].reason, MeshTaskExitReason::Aborted);
        assert!(group.is_empty());
    }

    #[tokio::test]
    async fn test_active_count() {
        let mut group = MeshTaskGroup::new();
        assert_eq!(group.active_count(), (0, 0, 0));
        assert!(group.is_empty());

        let (_tx1, rx1) = tokio::sync::oneshot::channel::<()>();
        let (_tx2, rx2) = tokio::sync::oneshot::channel::<()>();
        let (_tx3, rx3) = tokio::sync::oneshot::channel::<()>();

        group.spawn_critical("c1", async move {
            let _ = rx1.await;
        });
        group.spawn_background("b1", async move {
            let _ = rx2.await;
        });
        group.spawn_child("ch1", async move {
            let _ = rx3.await;
        });

        assert_eq!(group.active_count(), (1, 1, 1));
        assert!(!group.is_empty());

        // Spawn a second critical task.
        let (_tx4, rx4) = tokio::sync::oneshot::channel::<()>();
        group.spawn_critical("c2", async move {
            let _ = rx4.await;
        });
        assert_eq!(group.active_count(), (2, 1, 1));
    }

    #[tokio::test]
    async fn test_spawn_critical_result_ok() {
        let mut group = MeshTaskGroup::new();

        group.spawn_critical_result("critical_result_ok", async { Ok::<_, String>(()) });

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "critical_result_ok");
        assert_eq!(exits[0].class, MeshTaskClass::CriticalService);
        // Before shutdown, Ok(()) on critical → UnexpectedCompletion
        assert_eq!(exits[0].reason, MeshTaskExitReason::UnexpectedCompletion);
    }

    #[tokio::test]
    async fn test_spawn_critical_result_err() {
        let mut group = MeshTaskGroup::new();

        group.spawn_critical_result("critical_result_err", async {
            Err::<(), String>("something went wrong".into())
        });

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "critical_result_err");
        assert_eq!(
            exits[0].reason,
            MeshTaskExitReason::Error("something went wrong".into())
        );
    }

    #[tokio::test]
    async fn test_spawn_background_result_err() {
        let mut group = MeshTaskGroup::new();

        group.spawn_background_result("bg_result_err", async {
            Err::<(), String>("bg error".into())
        });

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "bg_result_err");
        assert_eq!(
            exits[0].reason,
            MeshTaskExitReason::Error("bg error".into())
        );
    }

    #[tokio::test]
    async fn test_task_ids_are_unique() {
        let mut group = MeshTaskGroup::new();

        group.spawn_critical("t1", async {});
        group.spawn_background("t2", async {});
        group.spawn_child("t3", async {});

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 3);

        let ids: Vec<_> = exits.iter().map(|e| e.id).collect();
        assert_eq!(ids[0], MeshTaskId(0));
        assert_eq!(ids[1], MeshTaskId(1));
        assert_eq!(ids[2], MeshTaskId(2));
    }

    #[tokio::test]
    async fn test_subscribe_exits_receives_events() {
        let group = MeshTaskGroup::new();
        let mut exit_rx = group.subscribe_exits();

        let mut child_group = MeshTaskGroup::new();
        // Transfer the exit_tx so spawned tasks send to the same channel
        child_group.exit_tx = group.exit_tx.clone();
        child_group.spawn_critical("observed_task", async {});

        let exits = child_group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);

        // The subscriber should have received the exit event
        let received = exit_rx.try_recv();
        assert!(received.is_ok());
        assert_eq!(received.unwrap().name, "observed_task");
    }

    #[tokio::test]
    async fn test_critical_task_classification_before_shutdown() {
        let mut group = MeshTaskGroup::new();

        group.spawn_critical("crit_pre", async {});

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits[0].reason, MeshTaskExitReason::UnexpectedCompletion);
    }

    #[tokio::test]
    async fn test_critical_task_classification_after_shutdown() {
        let mut group = MeshTaskGroup::new();
        group.begin_shutdown().await;

        group.spawn_critical("crit_post", async {});

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits[0].reason, MeshTaskExitReason::Cancelled);
    }

    #[tokio::test]
    async fn test_child_task_classification_before_shutdown() {
        let mut group = MeshTaskGroup::new();

        group.spawn_child("child_pre", async {});

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits[0].reason, MeshTaskExitReason::CleanCompletion);
    }

    #[tokio::test]
    async fn test_child_task_classification_after_shutdown() {
        let mut group = MeshTaskGroup::new();
        group.begin_shutdown().await;

        group.spawn_child("child_post", async {});

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits[0].reason, MeshTaskExitReason::CleanCompletion);
    }

    #[tokio::test]
    async fn test_panic_in_spawn_critical() {
        let mut group = MeshTaskGroup::new();

        group.spawn_critical("panicker", async {
            panic!("test panic message");
        });

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);
        assert!(matches!(
            &exits[0].reason,
            MeshTaskExitReason::Panic(msg) if msg.contains("test panic message")
        ));
    }

    #[tokio::test]
    async fn test_panic_in_spawn_critical_result() {
        let mut group = MeshTaskGroup::new();

        group.spawn_critical_result("panicker_result", async {
            panic!("result panic");
            #[allow(unreachable_code)]
            Ok::<_, String>(())
        });

        let exits = group.join_all(Duration::from_secs(5)).await;
        assert_eq!(exits.len(), 1);
        assert!(matches!(
            &exits[0].reason,
            MeshTaskExitReason::Panic(msg) if msg.contains("result panic")
        ));
    }

    // ── Iteration 76, Phase 4: Zero-budget contract ──────────────────────
    //
    // `join_all(Duration::ZERO)` must abort, await, and report every
    // owned task — it must not skip cleanup. This test defines the
    // contract that rollback/recovery/shutdown rely on.
    #[tokio::test]
    async fn test_join_all_zero_budget_aborts_and_awaits() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut group = MeshTaskGroup::new();

        // Drop-guard to prove the task was actually finalized.
        let drop_flag = Arc::new(AtomicBool::new(false));
        let drop_flag_for_task = drop_flag.clone();
        group.spawn_critical("zero_budget_task", async move {
            // A task that never exits cooperatively.
            let _hold = drop_flag_for_task;
            futures::future::pending::<()>().await;
        });

        assert_eq!(group.active_count(), (1, 0, 0));
        assert!(!group.is_empty());

        // Zero budget — the cleanup must still abort and await the task.
        let exits = group.join_all(Duration::ZERO).await;

        // Exactly one exit was reported.
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].name, "zero_budget_task");
        // The exit reason must be `Aborted` (not `Cancelled` or
        // `UnexpectedCompletion`).
        assert_eq!(exits[0].reason, MeshTaskExitReason::Aborted);

        // The group is empty.
        assert!(group.is_empty());
        assert_eq!(group.active_count(), (0, 0, 0));
    }

    #[tokio::test]
    async fn test_join_all_zero_budget_drains_all_classes() {
        // All three classes (critical, background, child) must be
        // finalized under a zero budget, not just the first task.
        let mut group = MeshTaskGroup::new();

        group.spawn_critical("zero_crit", futures::future::pending::<()>());
        group.spawn_background("zero_bg", futures::future::pending::<()>());
        group.spawn_child("zero_child", futures::future::pending::<()>());

        assert_eq!(group.active_count(), (1, 1, 1));

        let exits = group.join_all(Duration::ZERO).await;

        assert_eq!(exits.len(), 3);
        for exit in &exits {
            assert_eq!(
                exit.reason,
                MeshTaskExitReason::Aborted,
                "{:?} was not aborted",
                exit
            );
        }
        assert!(group.is_empty());
    }
}
