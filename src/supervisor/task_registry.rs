//! Supervisor-level task lifecycle management.
//!
//! Provides [`SupervisorTaskRegistry`] for registering, classifying, and
//! shutting down long-lived supervisor tasks with bounded timeouts.
//!
//! This is a simpler version of the worker-side `WorkerTaskRegistry`,
//! since the supervisor has fewer long-lived tasks.
//!
//! # Task Classes
//!
//! | Class | Policy |
//! |-------|--------|
//! | [`SupervisorTaskClass::CriticalControlPlane`] | Fatal if exits unexpectedly during shutdown |
//! | [`SupervisorTaskClass::RestartableControlPlane`] | Logged and optionally restarted |
//! | [`SupervisorTaskClass::BestEffortMaintenance`] | Drained during shutdown, best-effort |
//! | [`SupervisorTaskClass::ShutdownOnly`] | Only joined during shutdown |

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use tokio::task::JoinHandle;

/// Opaque task identifier for supervisor tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SupervisorTaskId(u64);

/// Task classification for supervisor lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupervisorTaskClass {
    /// Unexpected exit is fatal; shutdown awaits with timeout.
    CriticalControlPlane,
    /// Unexpected exit is logged; optional bounded restart.
    RestartableControlPlane,
    /// Drained during shutdown, best-effort.
    BestEffortMaintenance,
    /// Only joined during shutdown, not monitored live.
    ShutdownOnly,
}

impl fmt::Display for SupervisorTaskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CriticalControlPlane => write!(f, "critical_control_plane"),
            Self::RestartableControlPlane => write!(f, "restartable_control_plane"),
            Self::BestEffortMaintenance => write!(f, "best_effort_maintenance"),
            Self::ShutdownOnly => write!(f, "shutdown_only"),
        }
    }
}

/// Outcome of a task exit.
#[derive(Debug)]
pub enum SupervisorTaskOutcome {
    Completed,
    Failed(String),
    Cancelled,
}

/// Entry for a registered task.
pub struct SupervisorTaskEntry {
    pub name: &'static str,
    pub class: SupervisorTaskClass,
    pub handle: JoinHandle<SupervisorTaskOutcome>,
}

/// Report from [`SupervisorTaskRegistry::shutdown_and_join`].
#[derive(Debug, Default)]
pub struct SupervisorTaskShutdownReport {
    pub completed: usize,
    pub failed: usize,
    pub aborted: usize,
    pub timed_out: usize,
}

/// A supervisor-level task registry that manages long-lived background tasks.
pub struct SupervisorTaskRegistry {
    next_id: u64,
    tasks: BTreeMap<SupervisorTaskId, SupervisorTaskEntry>,
}

impl SupervisorTaskRegistry {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            tasks: BTreeMap::new(),
        }
    }

    /// Register a new task and return its unique ID.
    pub fn register(
        &mut self,
        name: &'static str,
        class: SupervisorTaskClass,
        handle: JoinHandle<SupervisorTaskOutcome>,
    ) -> SupervisorTaskId {
        let id = SupervisorTaskId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.tasks.insert(
            id,
            SupervisorTaskEntry {
                name,
                class,
                handle,
            },
        );
        id
    }

    /// Poll all tasks with a 10ms timeout, returning completed/failed/cancelled ones.
    ///
    /// Finished tasks are removed from the registry.
    pub async fn join_finished(&mut self) -> Vec<(SupervisorTaskId, SupervisorTaskOutcome)> {
        let mut results = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);

        let ids: Vec<SupervisorTaskId> = self.tasks.keys().copied().collect();

        for id in ids {
            if let Some(task) = self.tasks.get_mut(&id) {
                let outcome = tokio::select! {
                    biased;
                    result = &mut task.handle => {
                        match result {
                            Ok(outcome) => outcome,
                            Err(e) if e.is_cancelled() => SupervisorTaskOutcome::Cancelled,
                            Err(e) => SupervisorTaskOutcome::Failed(format!("join error: {}", e)),
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        continue;
                    }
                };
                self.tasks.remove(&id);
                results.push((id, outcome));
            }
        }

        results
    }

    /// Wait up to `timeout` for all tasks to complete, then abort remaining.
    ///
    /// Returns a report with counts of completed, failed, aborted, and timed-out tasks.
    pub async fn shutdown_and_join(&mut self, timeout: Duration) -> SupervisorTaskShutdownReport {
        let mut report = SupervisorTaskShutdownReport::default();
        let deadline = tokio::time::Instant::now() + timeout;

        let ids: Vec<SupervisorTaskId> = self.tasks.keys().copied().collect();

        for id in ids {
            let task = match self.tasks.remove(&id) {
                Some(t) => t,
                None => continue,
            };

            let SupervisorTaskEntry {
                name: _,
                class: _,
                mut handle,
            } = task;

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                handle.abort();
                let _ = handle.await;
                report.timed_out += 1;
                continue;
            }

            match tokio::time::timeout(remaining, &mut handle).await {
                Ok(Ok(outcome)) => match outcome {
                    SupervisorTaskOutcome::Completed => report.completed += 1,
                    SupervisorTaskOutcome::Failed(_) => report.failed += 1,
                    SupervisorTaskOutcome::Cancelled => report.failed += 1,
                },
                Ok(Err(e)) if e.is_cancelled() => report.failed += 1,
                Ok(Err(_)) => report.failed += 1,
                Err(_timeout) => {
                    // Timed out — abort and await to prove termination.
                    handle.abort();
                    let _ = handle.await;
                    report.timed_out += 1;
                }
            }
        }

        // Any remaining tasks that weren't drained get aborted.
        let remaining = std::mem::take(&mut self.tasks);
        for (_id, task) in remaining {
            task.handle.abort();
            let _ = task.handle.await;
            report.aborted += 1;
        }

        report
    }

    /// Returns the number of active tasks.
    pub fn active_count(&self) -> usize {
        self.tasks.len()
    }

    /// Returns true if the given task ID is registered.
    pub fn contains_task(&self, id: SupervisorTaskId) -> bool {
        self.tasks.contains_key(&id)
    }
}

impl Default for SupervisorTaskRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_assigns_unique_ids() {
        let mut registry = SupervisorTaskRegistry::new();

        let id1 = registry.register(
            "task_a",
            SupervisorTaskClass::CriticalControlPlane,
            tokio::spawn(async { SupervisorTaskOutcome::Completed }),
        );
        let id2 = registry.register(
            "task_b",
            SupervisorTaskClass::RestartableControlPlane,
            tokio::spawn(async { SupervisorTaskOutcome::Completed }),
        );
        let id3 = registry.register(
            "task_c",
            SupervisorTaskClass::BestEffortMaintenance,
            tokio::spawn(async { SupervisorTaskOutcome::Completed }),
        );

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
        assert_eq!(registry.active_count(), 3);
    }

    #[tokio::test]
    async fn test_join_finished_returns_completed_task() {
        let mut registry = SupervisorTaskRegistry::new();

        let _id = registry.register(
            "immediate_task",
            SupervisorTaskClass::CriticalControlPlane,
            tokio::spawn(async { SupervisorTaskOutcome::Completed }),
        );

        // Give the spawned task time to complete.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let results = registry.join_finished().await;
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0].1, SupervisorTaskOutcome::Completed));
        assert_eq!(registry.active_count(), 0);
    }

    #[tokio::test]
    async fn test_shutdown_and_join_reports_completed_tasks() {
        let mut registry = SupervisorTaskRegistry::new();

        let _id = registry.register(
            "completed_task",
            SupervisorTaskClass::CriticalControlPlane,
            tokio::spawn(async { SupervisorTaskOutcome::Completed }),
        );

        // Give the task time to finish.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let report = registry.shutdown_and_join(Duration::from_secs(5)).await;
        assert_eq!(report.completed, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.aborted, 0);
        assert_eq!(report.timed_out, 0);
    }

    #[tokio::test]
    async fn test_shutdown_and_join_aborts_timeout_tasks() {
        let mut registry = SupervisorTaskRegistry::new();

        let _id = registry.register(
            "forever_task",
            SupervisorTaskClass::ShutdownOnly,
            tokio::spawn(async {
                loop {
                    tokio::time::sleep(Duration::from_secs(100)).await;
                }
            }),
        );

        let report = registry.shutdown_and_join(Duration::from_millis(50)).await;
        assert!(
            report.timed_out > 0 || report.aborted > 0,
            "Expected timed_out or aborted > 0, got report: {:?}",
            report
        );
    }

    #[tokio::test]
    async fn test_display_impl() {
        assert_eq!(
            SupervisorTaskClass::CriticalControlPlane.to_string(),
            "critical_control_plane"
        );
        assert_eq!(
            SupervisorTaskClass::RestartableControlPlane.to_string(),
            "restartable_control_plane"
        );
        assert_eq!(
            SupervisorTaskClass::BestEffortMaintenance.to_string(),
            "best_effort_maintenance"
        );
        assert_eq!(
            SupervisorTaskClass::ShutdownOnly.to_string(),
            "shutdown_only"
        );
    }
}
