use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::HeaderMap;
use http::Response;
use parking_lot::{Mutex, RwLock};

use super::deno_runtime::{DenoIsolate, DenoPluginManager, DenoResourceLimits, DenoRuntime};
use crate::plugin::WasmPluginError;

#[allow(dead_code)]
pub struct DenoPool {
    manager: Arc<DenoPluginManager>,
    warm_isolates: RwLock<Vec<IsolateHandle>>,
    limits: DenoResourceLimits,
    max_pool_size: usize,
    warmup_count: usize,
    active_count: Mutex<usize>,
}

#[allow(dead_code)]
struct IsolateHandle {
    isolate: Arc<Mutex<DenoIsolate>>,
    runtime_name: String,
    last_used: Instant,
    invocation_count: usize,
}

impl DenoPool {
    pub fn new(limits: DenoResourceLimits) -> Self {
        let max_pool_size = limits.max_instances.max(1);
        let warmup_count = (max_pool_size / 2).max(1);

        Self {
            manager: Arc::new(DenoPluginManager::new()),
            warm_isolates: RwLock::new(Vec::new()),
            limits,
            max_pool_size,
            warmup_count,
            active_count: Mutex::new(0),
        }
    }

    pub fn load_plugin(&self, path: &Path) -> Result<String, WasmPluginError> {
        let runtime = self.manager.load_plugin(path)?;
        let name = runtime.name().to_string();
        self.warmup_pool(&runtime)?;
        Ok(name)
    }

    fn warmup_pool(&self, runtime: &Arc<DenoRuntime>) -> Result<(), WasmPluginError> {
        let runtime_name = runtime.name().to_string();
        let mut warm = self.warm_isolates.write();

        for _ in 0..self.warmup_count {
            let mut isolate = DenoIsolate::new(runtime)?;
            isolate.reset();

            let handle = IsolateHandle {
                isolate: Arc::new(Mutex::new(isolate)),
                runtime_name: runtime_name.clone(),
                last_used: Instant::now(),
                invocation_count: 0,
            };
            warm.push(handle);
        }

        tracing::debug!(
            "Warmed up {} Deno isolates for '{}'",
            warm.len(),
            runtime.name()
        );

        Ok(())
    }

    pub fn invoke_handler(
        &self,
        name: &str,
        method: &str,
        uri: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let start = Instant::now();

        let isolate = self.acquire_isolate(name)?;

        let result = {
            let mut isolate_guard = isolate.isolate.lock();
            isolate_guard.invoke(method, uri, headers, body)
        };

        self.release_isolate(isolate, start.elapsed());

        result
    }

    fn acquire_isolate(&self, name: &str) -> Result<IsolateHandle, WasmPluginError> {
        let mut active = self.active_count.lock();

        if *active >= self.max_pool_size {
            let waited = self.wait_for_available_isolate()?;
            if waited {
                return self.acquire_isolate(name);
            }
        }

        *active += 1;
        drop(active);

        let runtime = self
            .manager
            .get_runtime(name)
            .ok_or_else(|| WasmPluginError::FunctionNotFound(name.to_string()))?;

        let runtime_name = runtime.name().to_string();
        let isolate = DenoIsolate::new(&runtime)?;

        Ok(IsolateHandle {
            isolate: Arc::new(Mutex::new(isolate)),
            runtime_name,
            last_used: Instant::now(),
            invocation_count: 0,
        })
    }

    fn release_isolate(&self, handle: IsolateHandle, _duration: Duration) {
        let runtime_name = handle.runtime_name;
        let invocation_count = handle.invocation_count;
        let isolate = handle.isolate;

        {
            let mut isolate_guard = isolate.lock();
            isolate_guard.reset();
        }

        let mut warm = self.warm_isolates.write();

        if warm.len() < self.max_pool_size {
            warm.push(IsolateHandle {
                isolate,
                runtime_name,
                last_used: Instant::now(),
                invocation_count: invocation_count + 1,
            });
        }

        drop(warm);

        let mut active = self.active_count.lock();
        *active = active.saturating_sub(1);
    }

    fn wait_for_available_isolate(&self) -> Result<bool, WasmPluginError> {
        let timeout = Duration::from_millis(100);
        let start = Instant::now();

        while start.elapsed() < timeout {
            let active = *self.active_count.lock();
            if active < self.max_pool_size {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        Ok(false)
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.manager.list_plugins()
    }

    pub fn pool_stats(&self) -> PoolStats {
        let warm = self.warm_isolates.read();
        let active = *self.active_count.lock();

        PoolStats {
            warm_isolates: warm.len(),
            active_isolates: active,
            max_isolates: self.max_pool_size,
            warmup_count: self.warmup_count,
        }
    }

    pub fn clear(&self) {
        self.warm_isolates.write().clear();
        let mut active = self.active_count.lock();
        *active = 0;
    }
}

impl Default for DenoPool {
    fn default() -> Self {
        Self::new(DenoResourceLimits::default())
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub warm_isolates: usize,
    pub active_isolates: usize,
    pub max_isolates: usize,
    pub warmup_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_stats_default() {
        let pool = DenoPool::default();
        let stats = pool.pool_stats();
        assert_eq!(stats.warm_isolates, 0);
        assert_eq!(stats.active_isolates, 0);
        assert_eq!(stats.max_isolates, 4);
        assert_eq!(stats.warmup_count, 2);
    }

    #[test]
    fn test_pool_with_custom_limits() {
        let limits = DenoResourceLimits {
            max_memory_mb: 128,
            max_cpu_time_ms: 10000,
            timeout_seconds: 60,
            max_instances: 8,
        };
        let pool = DenoPool::new(limits);
        let stats = pool.pool_stats();
        assert_eq!(stats.max_isolates, 8);
    }

    #[test]
    fn test_pool_clear() {
        let pool = DenoPool::default();
        pool.clear();
        let stats = pool.pool_stats();
        assert_eq!(stats.warm_isolates, 0);
        assert_eq!(stats.active_isolates, 0);
    }
}
