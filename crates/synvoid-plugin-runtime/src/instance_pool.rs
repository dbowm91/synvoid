use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use wasmtime::{Engine, Instance, Linker, Module, Store};

use crate::pool::{PooledInstance, WasmPool};
use crate::sandbox::types::PluginCapabilities;
use crate::wasm_runtime::{GuestExports, RequestContext, WasmResourceLimits};

pub struct WasmInstancePool {
    pool: Arc<Mutex<VecDeque<WasmPooledInstance>>>,
    #[allow(dead_code)]
    engine: Arc<Engine>,
    max_size: usize,
    #[allow(dead_code)]
    default_allowed_dht_prefixes: Vec<String>,
    #[allow(dead_code)]
    default_capabilities: Arc<PluginCapabilities>,
}

pub(crate) struct WasmPooledInstance {
    pub(crate) instance: Instance,
    pub(crate) store: Store<RequestContext>,
    pub(crate) filter_name: String,
    pub(crate) max_cpu_fuel: u64,
    pub(crate) default_allowed_dht_prefixes: Vec<String>,
    pub(crate) capabilities: Arc<PluginCapabilities>,
}

impl WasmInstancePool {
    pub fn new(
        engine: Arc<Engine>,
        max_size: usize,
        default_allowed_dht_prefixes: Vec<String>,
        default_capabilities: Arc<PluginCapabilities>,
    ) -> Self {
        Self {
            pool: Arc::new(Mutex::new(VecDeque::new())),
            engine,
            max_size,
            default_allowed_dht_prefixes,
            default_capabilities,
        }
    }

    pub(crate) fn get(&self, _filter_name: &str) -> Option<WasmPooledInstance> {
        let mut pool = self.pool.lock();
        pool.pop_back()
    }

    pub(crate) fn return_instance(&self, instance: WasmPooledInstance) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size {
            pool.push_back(instance);
        }
    }

    pub(crate) fn resolve_exports_from_instance(
        instance: &Instance,
        store: &mut Store<RequestContext>,
    ) -> GuestExports {
        let filter_request = instance
            .get_func(&mut *store, "filter_request")
            .and_then(|f| f.typed(&mut *store).ok());
        let transform_response = instance
            .get_func(&mut *store, "transform_response")
            .and_then(|f| f.typed(&mut *store).ok());
        let handle_request = instance
            .get_func(&mut *store, "handle_request")
            .and_then(|f| f.typed(&mut *store).ok());
        let guest_alloc = instance
            .get_func(&mut *store, "guest_alloc")
            .and_then(|f| f.typed(&mut *store).ok());
        let guest_free = instance
            .get_func(&mut *store, "guest_free")
            .and_then(|f| f.typed(&mut *store).ok());
        let memory = instance
            .get_export(&mut *store, "memory")
            .and_then(|ext| ext.into_memory());

        GuestExports {
            filter_request,
            transform_response,
            handle_request,
            guest_alloc,
            guest_free,
            memory,
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn warmup(
        &self,
        modules: &[(String, Module)],
        limits: &WasmResourceLimits,
        linker: Option<&Linker<RequestContext>>,
    ) {
        let mut warm_instances = VecDeque::new();

        for (filter_name, module) in modules {
            let timeout = limits.timeout;
            let max_memory = limits.max_memory_mb * 1024 * 1024;
            let max_table_elements = limits.max_table_elements.unwrap_or(0);

            let mut store = Store::new(
                &self.engine,
                RequestContext {
                    start: Instant::now(),
                    timeout,
                    env: std::collections::HashMap::new(),
                    allowed_dht_prefixes: limits.allowed_dht_prefixes.clone(),
                    max_memory,
                    max_table_elements,
                    body_receiver: None,
                    capabilities: limits.capabilities.clone(),
                    capability_violation: None,
                    host_call_budget: limits.host_call_budget.clone(),
                },
            );

            store.limiter(|state| state);

            if limits.max_cpu_fuel > 0 {
                store.set_fuel(limits.max_cpu_fuel).ok();
            }

            if limits.epoch_deadline_enabled {
                let ticks = limits.epoch_ticks_per_timeout.max(1);
                store.set_epoch_deadline(ticks);
            }

            let instance_result = match linker {
                Some(linker) => linker.instantiate(&mut store, module),
                None => {
                    let mut stub_linker = Linker::new(&self.engine);

                    stub_linker
                        .func_wrap(
                            "env",
                            "abort",
                            |_caller: wasmtime::Caller<'_, RequestContext>,
                             _msg_ptr: i32,
                             _msg_len: i32| {
                                tracing::error!(
                                    "WASM plugin abort at ptr={}, len={}",
                                    _msg_ptr,
                                    _msg_len
                                );
                            },
                        )
                        .ok();

                    stub_linker
                        .func_wrap(
                            "env",
                            "check_timeout",
                            |_caller: wasmtime::Caller<'_, RequestContext>| -> i32 { 0 },
                        )
                        .ok();

                    stub_linker
                        .func_wrap(
                            "env",
                            "get_env",
                            |_caller: wasmtime::Caller<'_, RequestContext>,
                             _key_ptr: i32,
                             _key_len: i32,
                             _out_ptr: i32,
                             _out_max: i32|
                             -> i32 { 0 },
                        )
                        .ok();

                    stub_linker
                        .func_wrap(
                            "env",
                            "synvoid_read_body_chunk",
                            |_caller: wasmtime::Caller<'_, RequestContext>,
                             _out_ptr: i32,
                             _out_max: i32|
                             -> i32 { 0 },
                        )
                        .ok();

                    stub_linker
                        .func_wrap(
                            "env",
                            "mesh_query_dht",
                            |_caller: wasmtime::Caller<'_, RequestContext>,
                             _key_ptr: i32,
                             _key_len: i32,
                             _out_ptr: i32,
                             _out_max: i32|
                             -> i32 { 0 },
                        )
                        .ok();

                    stub_linker
                        .func_wrap(
                            "env",
                            "mesh_check_threat",
                            |_caller: wasmtime::Caller<'_, RequestContext>,
                             _ip_ptr: i32,
                             _ip_len: i32|
                             -> i32 { 0 },
                        )
                        .ok();

                    stub_linker
                        .func_wrap(
                            "env",
                            "mesh_emit_event",
                            |_caller: wasmtime::Caller<'_, RequestContext>,
                             _topic_ptr: i32,
                             _topic_len: i32,
                             _data_ptr: i32,
                             _data_len: i32|
                             -> i32 { 0 },
                        )
                        .ok();

                    stub_linker.instantiate(&mut store, module)
                }
            };

            match instance_result {
                Ok(instance) => {
                    warm_instances.push_back(WasmPooledInstance {
                        instance,
                        store,
                        filter_name: filter_name.clone(),
                        max_cpu_fuel: limits.max_cpu_fuel,
                        default_allowed_dht_prefixes: limits.allowed_dht_prefixes.clone(),
                        capabilities: limits.capabilities.clone(),
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

impl WasmPooledInstance {
    /// Reset host-side state for a new request.
    ///
    /// Host-side context is always reset for both RequestIsolated and StatefulPooled.
    /// Guest memory/globals persist in both cases — this is a Wasmtime limitation.
    /// For RequestIsolated: callers must not assume guest state persists.
    /// For StatefulPooled: callers may rely on guest state persistence.
    pub(crate) fn prepare_for_request(
        &mut self,
        env: std::collections::HashMap<String, String>,
        timeout: Duration,
        allowed_dht_prefixes: Vec<String>,
        capabilities: Arc<PluginCapabilities>,
    ) {
        self.store.data_mut().start = Instant::now();
        self.store.data_mut().timeout = timeout;
        self.store.data_mut().env = env;
        self.store.data_mut().body_receiver = None;
        self.store.data_mut().allowed_dht_prefixes = allowed_dht_prefixes;
        self.store.data_mut().capabilities = capabilities;
        self.store.data_mut().capability_violation = None;
        if self.max_cpu_fuel > 0 {
            self.store.set_fuel(self.max_cpu_fuel).ok();
        }
    }
}

impl WasmPool for WasmInstancePool {
    fn get(&self, filter_name: &str) -> Option<PooledInstance> {
        self.get(filter_name).map(|inst| PooledInstance {
            instance: inst.instance,
            store: inst.store,
            filter_name: inst.filter_name,
            max_cpu_fuel: inst.max_cpu_fuel,
            allowed_dht_prefixes: inst.default_allowed_dht_prefixes.clone(),
            capabilities: inst.capabilities,
        })
    }

    fn return_instance(&self, instance: PooledInstance) {
        self.return_instance(WasmPooledInstance {
            instance: instance.instance,
            store: instance.store,
            filter_name: instance.filter_name,
            max_cpu_fuel: instance.max_cpu_fuel,
            default_allowed_dht_prefixes: instance.allowed_dht_prefixes,
            capabilities: instance.capabilities,
        })
    }

    fn max_size(&self) -> usize {
        self.max_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_runtime::HostCallBudget;

    #[test]
    fn test_pool_creation() {
        let pool = WasmInstancePool::new(
            Arc::new(Engine::default()),
            4,
            vec![],
            Arc::new(PluginCapabilities::default()),
        );
        assert_eq!(pool.max_size, 4);
    }

    #[tokio::test]
    async fn test_pool_warmup_empty() {
        let engine = Arc::new(Engine::default());
        let pool =
            WasmInstancePool::new(engine, 4, vec![], Arc::new(PluginCapabilities::default()));

        let limits = WasmResourceLimits::default();
        pool.warmup(&[], &limits, None).await;
    }

    #[test]
    fn test_pool_get_empty() {
        let pool = WasmInstancePool::new(
            Arc::new(Engine::default()),
            4,
            vec![],
            Arc::new(PluginCapabilities::default()),
        );
        let engine = pool.engine.clone();

        let module_result = Module::from_file(&engine, std::path::Path::new("/nonexistent.wasm"));
        assert!(module_result.is_err());
    }

    #[test]
    fn test_warmup_uses_provided_limits() {
        let limits = WasmResourceLimits {
            max_cpu_fuel: 500000,
            timeout: Duration::from_millis(100),
            max_memory_mb: 32,
            max_table_elements: Some(512),
            epoch_deadline_enabled: false,
            epoch_ticks_per_timeout: 5,
            host_call_budget: HostCallBudget::default(),
            ..Default::default()
        };
        assert_eq!(limits.max_cpu_fuel, 500000);
        assert_eq!(limits.timeout, Duration::from_millis(100));
        assert_eq!(limits.max_memory_mb, 32);
        assert_eq!(limits.max_table_elements, Some(512));
        assert!(!limits.epoch_deadline_enabled);
        assert_eq!(limits.epoch_ticks_per_timeout, 5);
    }
}
