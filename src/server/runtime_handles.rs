use std::time::Duration;

use metrics::counter;

pub type ServerTaskResult = Result<(), String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeTaskExit {
    Completed,
    Failed(String),
    JoinError(String),
    Aborted,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHandleClass {
    CriticalServer,
    ProtocolListener,
    Maintenance,
    HotReloadWatcher,
    BestEffort,
}

pub struct NamedRuntimeHandle {
    pub name: &'static str,
    pub class: RuntimeHandleClass,
    join: tokio::task::JoinHandle<ServerTaskResult>,
}

impl NamedRuntimeHandle {
    pub fn new(
        name: &'static str,
        class: RuntimeHandleClass,
        join: tokio::task::JoinHandle<ServerTaskResult>,
    ) -> Self {
        Self { name, class, join }
    }
}

pub struct UnifiedServerRuntimeHandles {
    handles: Vec<NamedRuntimeHandle>,
}

impl UnifiedServerRuntimeHandles {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    pub fn register(&mut self, handle: NamedRuntimeHandle) {
        self.handles.push(handle);
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn names(&self) -> Vec<(&'static str, RuntimeHandleClass)> {
        self.handles.iter().map(|h| (h.name, h.class)).collect()
    }

    pub async fn shutdown_and_join(
        &mut self,
        timeout: Duration,
    ) -> UnifiedServerRuntimeShutdownReport {
        let mut report = UnifiedServerRuntimeShutdownReport::default();

        for handle in self.handles.drain(..) {
            let name = handle.name;
            let class = handle.class;
            let result = tokio::time::timeout(timeout, handle.join).await;
            match result {
                Ok(Ok(Ok(()))) => {
                    report.completed += 1;
                    counter!("synvoid_runtime_task_exit_total", "owner" => "unified_server", "class" => format!("{:?}", class), "status" => "completed").increment(1);
                }
                Ok(Ok(Err(e))) => {
                    tracing::error!(task = name, "task failed: {}", e);
                    report.failed += 1;
                    counter!("synvoid_runtime_task_exit_total", "owner" => "unified_server", "class" => format!("{:?}", class), "status" => "failed").increment(1);
                    if class == RuntimeHandleClass::CriticalServer {
                        report.critical_failures += 1;
                        counter!("synvoid_runtime_task_critical_failures_total", "owner" => "unified_server").increment(1);
                    }
                }
                Ok(Err(e)) => {
                    if e.is_cancelled() {
                        report.aborted += 1;
                        counter!("synvoid_runtime_task_exit_total", "owner" => "unified_server", "class" => format!("{:?}", class), "status" => "aborted").increment(1);
                    } else {
                        tracing::error!(task = name, "task panicked: {}", e);
                        report.join_errors += 1;
                        counter!("synvoid_runtime_task_exit_total", "owner" => "unified_server", "class" => format!("{:?}", class), "status" => "failed").increment(1);
                        if class == RuntimeHandleClass::CriticalServer {
                            report.critical_failures += 1;
                            counter!("synvoid_runtime_task_critical_failures_total", "owner" => "unified_server").increment(1);
                        }
                    }
                }
                Err(_) => {
                    tracing::warn!(task = name, "task timed out, aborting");
                    report.timed_out += 1;
                    counter!("synvoid_runtime_task_exit_total", "owner" => "unified_server", "class" => format!("{:?}", class), "status" => "timed_out").increment(1);
                    if class == RuntimeHandleClass::CriticalServer {
                        report.critical_failures += 1;
                        counter!("synvoid_runtime_task_critical_failures_total", "owner" => "unified_server").increment(1);
                    }
                }
            }
        }

        counter!("synvoid_runtime_shutdown_total", "owner" => "unified_server", "status" => "completed").increment(1);
        report
    }
}

#[derive(Debug, Default)]
pub struct UnifiedServerRuntimeShutdownReport {
    pub completed: usize,
    pub failed: usize,
    pub join_errors: usize,
    pub aborted: usize,
    pub timed_out: usize,
    pub critical_failures: usize,
}

/// Spawn a future that returns `Result<(), E>` and register it with the handles.
pub fn spawn_registered<F, E>(
    handles: &mut UnifiedServerRuntimeHandles,
    name: &'static str,
    class: RuntimeHandleClass,
    fut: F,
) where
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    // reason: Registration infrastructure — all server spawns go through this helper
    let join = tokio::spawn(async move { fut.await.map_err(|e| e.to_string()) });
    counter!("synvoid_runtime_task_registered_total", "owner" => "unified_server", "class" => format!("{:?}", class)).increment(1);
    handles.register(NamedRuntimeHandle::new(name, class, join));
}

/// Spawn a unit future and register it with the handles.
pub fn spawn_registered_unit<F>(
    handles: &mut UnifiedServerRuntimeHandles,
    name: &'static str,
    class: RuntimeHandleClass,
    fut: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // reason: Registration infrastructure — all server spawns go through this helper
    let join = tokio::spawn(async move {
        fut.await;
        Ok(())
    });
    counter!("synvoid_runtime_task_registered_total", "owner" => "unified_server", "class" => format!("{:?}", class)).increment(1);
    handles.register(NamedRuntimeHandle::new(name, class, join));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_handles_is_empty() {
        let handles = UnifiedServerRuntimeHandles::new();
        assert!(handles.is_empty());
        assert_eq!(handles.len(), 0);
    }

    #[tokio::test]
    async fn register_increments_len() {
        let mut handles = UnifiedServerRuntimeHandles::new();
        let join = tokio::spawn(async { Ok::<(), String>(()) });
        handles.register(NamedRuntimeHandle::new(
            "test",
            RuntimeHandleClass::BestEffort,
            join,
        ));
        assert!(!handles.is_empty());
        assert_eq!(handles.len(), 1);
    }

    #[tokio::test]
    async fn critical_task_failure_counted_in_report() {
        let mut handles = UnifiedServerRuntimeHandles::new();
        let join = tokio::spawn(async { Err::<(), String>("boom".into()) });
        handles.register(NamedRuntimeHandle::new(
            "failing_task",
            RuntimeHandleClass::CriticalServer,
            join,
        ));

        let report = handles.shutdown_and_join(Duration::from_secs(1)).await;
        assert_eq!(report.failed, 1);
        assert_eq!(report.critical_failures, 1);
    }

    #[tokio::test]
    async fn shutdown_and_join_aborts_timeout_task() {
        let mut handles = UnifiedServerRuntimeHandles::new();
        let join = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok::<(), String>(())
        });
        handles.register(NamedRuntimeHandle::new(
            "slow_task",
            RuntimeHandleClass::ProtocolListener,
            join,
        ));

        let report = handles.shutdown_and_join(Duration::from_millis(10)).await;
        assert_eq!(report.timed_out, 1);
        assert_eq!(report.completed, 0);
    }

    #[tokio::test]
    async fn maintenance_task_clean_exit_on_shutdown() {
        let mut handles = UnifiedServerRuntimeHandles::new();
        let join = tokio::spawn(async { Ok::<(), String>(()) });
        handles.register(NamedRuntimeHandle::new(
            "maintenance_task",
            RuntimeHandleClass::Maintenance,
            join,
        ));

        let report = handles.shutdown_and_join(Duration::from_secs(1)).await;
        assert_eq!(report.completed, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.critical_failures, 0);
    }

    #[tokio::test]
    async fn spawn_registered_helpers_work() {
        let mut handles = UnifiedServerRuntimeHandles::new();

        spawn_registered(
            &mut handles,
            "result_task",
            RuntimeHandleClass::CriticalServer,
            async { Ok::<(), String>(()) },
        );

        spawn_registered_unit(
            &mut handles,
            "unit_task",
            RuntimeHandleClass::Maintenance,
            async {},
        );

        assert_eq!(handles.len(), 2);

        let report = handles.shutdown_and_join(Duration::from_secs(1)).await;
        assert_eq!(report.completed, 2);
        assert_eq!(report.critical_failures, 0);
    }

    #[tokio::test]
    async fn names_returns_all() {
        let mut handles = UnifiedServerRuntimeHandles::new();
        let join = tokio::spawn(async { Ok::<(), String>(()) });
        handles.register(NamedRuntimeHandle::new(
            "task_a",
            RuntimeHandleClass::CriticalServer,
            join,
        ));
        let join = tokio::spawn(async { Ok::<(), String>(()) });
        handles.register(NamedRuntimeHandle::new(
            "task_b",
            RuntimeHandleClass::Maintenance,
            join,
        ));

        let names = handles.names();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], ("task_a", RuntimeHandleClass::CriticalServer));
        assert_eq!(names[1], ("task_b", RuntimeHandleClass::Maintenance));
    }
}
