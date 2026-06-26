use std::time::Duration;

pub struct UnifiedServerRuntimeHandles {
    handles: Vec<NamedRuntimeHandle>,
}

pub struct NamedRuntimeHandle {
    pub name: &'static str,
    pub class: RuntimeHandleClass,
    join: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHandleClass {
    CriticalServer,
    ProtocolListener,
    Maintenance,
    HotReloadWatcher,
    BestEffort,
}

impl NamedRuntimeHandle {
    pub fn new(
        name: &'static str,
        class: RuntimeHandleClass,
        join: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self { name, class, join }
    }
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

    pub async fn shutdown_and_join(
        mut self,
        timeout: Duration,
    ) -> UnifiedServerRuntimeShutdownReport {
        let mut completed = Vec::new();
        let mut aborted = Vec::new();
        let mut timed_out = Vec::new();

        for handle in self.handles.drain(..) {
            let result = tokio::time::timeout(timeout, handle.join).await;
            match result {
                Ok(Ok(())) => completed.push((handle.name, handle.class)),
                Ok(Err(e)) => {
                    if e.is_cancelled() {
                        aborted.push((handle.name, handle.class));
                    } else {
                        tracing::error!("Task {} panicked: {}", handle.name, e);
                        aborted.push((handle.name, handle.class));
                    }
                }
                Err(_) => timed_out.push((handle.name, handle.class)),
            }
        }

        UnifiedServerRuntimeShutdownReport {
            completed,
            aborted,
            timed_out,
        }
    }
}

#[derive(Debug)]
pub struct UnifiedServerRuntimeShutdownReport {
    pub completed: Vec<(&'static str, RuntimeHandleClass)>,
    pub aborted: Vec<(&'static str, RuntimeHandleClass)>,
    pub timed_out: Vec<(&'static str, RuntimeHandleClass)>,
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
        let join = tokio::spawn(async {});
        handles.register(NamedRuntimeHandle::new(
            "test",
            RuntimeHandleClass::BestEffort,
            join,
        ));
        assert!(!handles.is_empty());
        assert_eq!(handles.len(), 1);
    }
}
