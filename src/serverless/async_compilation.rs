use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{oneshot, RwLock};

use crate::plugin::WasmPluginError;

#[derive(Debug, Clone)]
pub enum CompilationState {
    Pending,
    Compiling { started_at: Instant },
    Ready,
    Failed { error: String },
}

impl CompilationState {
    pub fn is_ready(&self) -> bool {
        matches!(self, CompilationState::Ready)
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, CompilationState::Failed { .. })
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            CompilationState::Failed { error } => Some(error),
            _ => None,
        }
    }
}

pub struct AsyncCompilationHandle {
    state: Arc<RwLock<CompilationState>>,
    completion_sender: Arc<std::sync::Mutex<Option<oneshot::Sender<Result<(), WasmPluginError>>>>>,
    completion_receiver: Arc<std::sync::Mutex<Option<oneshot::Receiver<Result<(), WasmPluginError>>>>>,
}

impl AsyncCompilationHandle {
    pub fn new() -> Self {
        let (tx, rx) = oneshot::channel();
        Self {
            state: Arc::new(RwLock::const_new(CompilationState::Pending)),
            completion_sender: Arc::new(std::sync::Mutex::new(Some(tx))),
            completion_receiver: Arc::new(std::sync::Mutex::new(Some(rx))),
        }
    }

    pub fn start_compilation(&self) {
        let state = self.state.clone();
        tokio::spawn(async move {
            *state.write().await = CompilationState::Compiling {
                started_at: Instant::now(),
            };
        });
    }

    pub fn set_ready(&self) {
        let state = self.state.clone();
        let sender = self.completion_sender.clone();
        tokio::spawn(async move {
            *state.write().await = CompilationState::Ready;
            if let Some(tx) = sender.lock().unwrap().take() {
                let _ = tx.send(Ok(()));
            }
        });
    }

    pub fn set_failed(&self, error: String) {
        let state = self.state.clone();
        let sender = self.completion_sender.clone();
        tokio::spawn(async move {
            *state.write().await = CompilationState::Failed { error };
            if let Some(tx) = sender.lock().unwrap().take() {
                let _ = tx.send(Ok(()));
            }
        });
    }

    pub fn state(&self) -> CompilationState {
        self.state.try_read().map(|g| g.clone()).unwrap_or(CompilationState::Pending)
    }

    pub async fn wait_for_completion(&self) -> Result<(), WasmPluginError> {
        let receiver = self.completion_receiver.lock().unwrap().take();
        if let Some(rx) = receiver {
            match rx.await {
                Ok(result) => result,
                Err(_) => Err(WasmPluginError::LoadFailed(
                    "Compilation channel closed".to_string(),
                )),
            }
        } else {
            Err(WasmPluginError::LoadFailed(
                "Already awaited".to_string(),
            ))
        }
    }

    pub fn poll_state(&self) -> CompilationState {
        self.state.try_read().map(|g| g.clone()).unwrap_or(CompilationState::Pending)
    }
}

impl Default for AsyncCompilationHandle {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AsyncCompilationManager {
    handles: std::sync::RwLock<std::collections::HashMap<String, Arc<AsyncCompilationHandle>>>,
}

unsafe impl Send for AsyncCompilationManager {}
unsafe impl Sync for AsyncCompilationManager {}

impl AsyncCompilationManager {
    pub fn new() -> Self {
        Self {
            handles: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn get_or_create(&self, function_name: &str) -> Arc<AsyncCompilationHandle> {
        let mut handles = self.handles.write().unwrap();
        if let Some(handle) = handles.get(function_name) {
            return handle.clone();
        }
        let handle = Arc::new(AsyncCompilationHandle::new());
        handles.insert(function_name.to_string(), handle.clone());
        handle
    }

    pub fn get(&self, function_name: &str) -> Option<Arc<AsyncCompilationHandle>> {
        self.handles.read().unwrap().get(function_name).cloned()
    }

    pub fn remove(&self, function_name: &str) {
        self.handles.write().unwrap().remove(function_name);
    }

    pub fn mark_compiling(&self, function_name: &str) {
        if let Some(handle) = self.get(function_name) {
            handle.start_compilation();
        }
    }

    pub fn mark_ready(&self, function_name: &str) {
        if let Some(handle) = self.get(function_name) {
            handle.set_ready();
        }
    }

    pub fn mark_failed(&self, function_name: &str, error: String) {
        if let Some(handle) = self.get(function_name) {
            handle.set_failed(error);
        }
    }
}

impl Default for AsyncCompilationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compilation_state() {
        let state = CompilationState::Pending;
        assert!(!state.is_ready());
        assert!(!state.is_failed());

        let ready = CompilationState::Ready;
        assert!(ready.is_ready());
        assert!(!ready.is_failed());

        let failed = CompilationState::Failed {
            error: "test error".to_string(),
        };
        assert!(!failed.is_ready());
        assert!(failed.is_failed());
        assert_eq!(failed.error(), Some("test error"));
    }

    #[tokio::test]
    async fn test_async_compilation_handle() {
        let handle = AsyncCompilationHandle::new();

        assert!(matches!(handle.poll_state(), CompilationState::Pending));

        handle.start_compilation();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert!(matches!(
            handle.poll_state(),
            CompilationState::Compiling { .. }
        ));

        handle.set_ready();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert!(handle.poll_state().is_ready());
    }
}
