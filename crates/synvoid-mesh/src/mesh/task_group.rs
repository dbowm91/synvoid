//! Mesh-local task group for Iteration 68.
//!
//! `MeshTaskGroup` manages the lifecycle of mesh tasks — critical services,
//! background work, and bounded children — with unified shutdown propagation
//! and exit reporting.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::sync::{broadcast, watch};

use crate::lifecycle::{MeshTaskClass, MeshTaskExit, MeshTaskExitReason};

/// A named mesh task with its join handle.
struct NamedMeshTask {
    name: &'static str,
    class: MeshTaskClass,
    handle: tokio::task::JoinHandle<()>,
}

/// Mesh-local task group managing critical, background, and child tasks.
pub struct MeshTaskGroup {
    shutdown_tx: watch::Sender<bool>,
    critical: Vec<NamedMeshTask>,
    background: Vec<NamedMeshTask>,
    children: Vec<NamedMeshTask>,
    shutdown_started: Arc<AtomicBool>,
    exit_tx: broadcast::Sender<MeshTaskExit>,
    exit_rx: broadcast::Receiver<MeshTaskExit>,
}

impl MeshTaskGroup {
    /// Creates a new task group with a fresh shutdown channel.
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let (exit_tx, exit_rx) = broadcast::channel(64);
        Self {
            shutdown_tx,
            critical: Vec::new(),
            background: Vec::new(),
            children: Vec::new(),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            exit_tx,
            exit_rx,
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
        let handle = self.spawn_wrapped(name, MeshTaskClass::CriticalService, future);
        self.critical.push(NamedMeshTask {
            name,
            class: MeshTaskClass::CriticalService,
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
        let handle = self.spawn_wrapped(name, MeshTaskClass::RestartableBackground, future);
        self.background.push(NamedMeshTask {
            name,
            class: MeshTaskClass::RestartableBackground,
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
        let handle = self.spawn_wrapped(name, MeshTaskClass::BoundedChild, future);
        self.children.push(NamedMeshTask {
            name,
            class: MeshTaskClass::BoundedChild,
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
                mut handle,
            } = task;

            if remaining.is_zero() {
                handle.abort();
                let _ = handle.await;
                exits.push(MeshTaskExit {
                    name,
                    class,
                    reason: MeshTaskExitReason::Aborted,
                });
                continue;
            }

            // Poll the handle with a deadline. We use futures::poll_fn to
            // bridge between JoinHandle's poll and tokio's timeout.
            let poll_result = tokio::time::timeout(remaining, poll_handle(&mut handle)).await;

            match poll_result {
                Ok(Ok(())) => {
                    // The wrapper completed. Check the exit channel for
                    // detailed exit info (panics are caught by spawn_wrapped
                    // and sent through exit_tx before the handle resolves).
                    if let Some(exit) = self.drain_exit_for(name) {
                        exits.push(exit);
                    } else {
                        let reason = if self.shutdown_started.load(Ordering::SeqCst) {
                            MeshTaskExitReason::Cancelled
                        } else {
                            MeshTaskExitReason::CleanCompletion
                        };
                        exits.push(MeshTaskExit {
                            name,
                            class,
                            reason,
                        });
                    }
                }
                Ok(Err(join_err)) => {
                    let reason = if join_err.is_cancelled() {
                        MeshTaskExitReason::Cancelled
                    } else {
                        MeshTaskExitReason::Error(format!("join error: {join_err}"))
                    };
                    exits.push(MeshTaskExit {
                        name,
                        class,
                        reason,
                    });
                }
                Err(_elapsed) => {
                    handle.abort();
                    let _ = handle.await;
                    exits.push(MeshTaskExit {
                        name,
                        class,
                        reason: MeshTaskExitReason::Aborted,
                    });
                }
            }
        }

        exits
    }

    /// Drains the exit channel looking for an event matching the given task name.
    fn drain_exit_for(&mut self, name: &str) -> Option<MeshTaskExit> {
        let mut found = None;
        while let Ok(exit) = self.exit_rx.try_recv() {
            if exit.name == name {
                found = Some(exit);
            }
        }
        found
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
        future: impl Future<Output = ()> + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let exit_tx = self.exit_tx.clone();
        let shutdown_flag = self.shutdown_started.clone();

        tokio::spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;

            let reason = match result {
                Ok(()) => {
                    // The future completed without panic. Determine if this was
                    // expected based on shutdown state.
                    if shutdown_flag.load(Ordering::SeqCst) {
                        MeshTaskExitReason::Cancelled
                    } else {
                        MeshTaskExitReason::CleanCompletion
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

            let _ = exit_tx.send(MeshTaskExit {
                name,
                class,
                reason,
            });
        })
    }
}

/// Polls a `JoinHandle` to completion using `futures::poll_fn`.
///
/// This bridges between `JoinHandle`'s `Future` implementation (which is
/// `!Unpin`) and contexts that require an `Unpin`-compatible future, such
/// as `tokio::time::timeout`.
async fn poll_handle(
    handle: &mut tokio::task::JoinHandle<()>,
) -> Result<(), tokio::task::JoinError> {
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
}
