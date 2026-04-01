use std::sync::Arc;

use parking_lot::Mutex;
use wasmtime::{Engine, Instance, Linker, Module, Store};

#[allow(dead_code)]
pub struct WasmInstancePool {
    pool: Arc<Mutex<Vec<WasmPooledInstance>>>,
    engine: Arc<Engine>,
    max_size: usize,
}

#[allow(dead_code)]
pub(crate) struct WasmPooledInstance {
    instance: Instance,
    store: Store<()>,
    filter_name: String,
    max_cpu_fuel: u64,
}

#[allow(dead_code)]
impl WasmInstancePool {
    pub fn new(engine: Arc<Engine>, max_size: usize) -> Self {
        Self {
            pool: Arc::new(Mutex::new(Vec::new())),
            engine,
            max_size,
        }
    }

    pub(crate) fn get(&self, filter_name: &str, _module: &Module) -> Option<WasmPooledInstance> {
        let mut pool = self.pool.lock();
        pool.pop().map(|mut inst| {
            inst.filter_name = filter_name.to_string();
            if inst.max_cpu_fuel > 0 {
                inst.store.set_fuel(inst.max_cpu_fuel).ok();
            }
            inst
        })
    }

    pub(crate) fn return_instance(&self, instance: WasmPooledInstance) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size {
            pool.push(instance);
        }
    }

    pub async fn warmup(&self, modules: &[(String, Module)]) {
        let mut warm_instances = Vec::new();

        for (filter_name, module) in modules {
            let mut store = Store::new(&self.engine, ());

            let mut linker = Linker::new(&self.engine);

            linker
                .func_wrap(
                    "env",
                    "abort",
                    |_caller: wasmtime::Caller<'_, ()>, _msg_ptr: i32, _msg_len: i32| {
                        tracing::error!("WASM plugin abort at ptr={}, len={}", _msg_ptr, _msg_len);
                    },
                )
                .ok();

            linker
                .func_wrap(
                    "env",
                    "check_timeout",
                    |_caller: wasmtime::Caller<'_, ()>| -> i32 { 0 },
                )
                .ok();

            match linker.instantiate(&mut store, module) {
                Ok(instance) => {
                    warm_instances.push(WasmPooledInstance {
                        instance,
                        store,
                        filter_name: filter_name.clone(),
                        max_cpu_fuel: 0,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to warmup WASM instance for '{}': {}",
                        filter_name,
                        e
                    );
                }
            }
        }

        if !warm_instances.is_empty() {
            let count = warm_instances.len();
            let mut pool = self.pool.lock();
            pool.extend(warm_instances);
            tracing::debug!(
                "Warmed up {} WASM instances (total pool: {})",
                count,
                pool.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let pool = WasmInstancePool::new(Arc::new(Engine::default()), 4);
        assert_eq!(pool.max_size, 4);
    }

    #[tokio::test]
    async fn test_pool_warmup_empty() {
        let engine = Arc::new(Engine::default());
        let pool = WasmInstancePool::new(engine, 4);

        pool.warmup(&[]).await;
    }

    #[test]
    fn test_pool_get_empty() {
        let pool = WasmInstancePool::new(Arc::new(Engine::default()), 4);
        let engine = pool.engine.clone();

        let module_result = Module::from_file(&*engine, std::path::Path::new("/nonexistent.wasm"));
        assert!(module_result.is_err());
    }
}
