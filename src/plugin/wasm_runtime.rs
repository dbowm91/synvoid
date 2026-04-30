use std::collections::HashMap;
use std::convert::TryInto;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use parking_lot::RwLock;
use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{
    Config, Engine, Instance, Linker, Memory, Module, OptLevel, ResourceLimiter, Store, TypedFunc,
};

use crate::plugin::instance_pool::WasmInstancePool;
use crate::plugin::wasm_metrics::{
    record_wasm_decision_block, record_wasm_decision_challenge, record_wasm_decision_pass,
    record_wasm_duration, record_wasm_error, record_wasm_fuel_consumed, record_wasm_invocation,
};
use crate::plugin::{WasmFilterResult, WasmPluginError};

/// Maximum size of request/response data passed through WASM memory (1MB)
const MAX_WASM_DATA_SIZE: usize = 1024 * 1024;

// ─── Guest ABI function signatures ───────────────────────────────────────────

/// filter_request(method_ptr, method_len, uri_ptr, uri_len,
///                headers_ptr, headers_len, body_ptr, body_len) -> i32
/// Returns: 0=pass, 1=block, 2=challenge, -1=error
type FilterRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32), i32>;

/// transform_response(status_code, body_ptr, body_len, out_ptr, out_max) -> i32
/// Returns: new body length, or -1 on error
type TransformResponseFn = TypedFunc<(i32, i32, i32, i32, i32), i32>;

/// handle_request(method_ptr, method_len, uri_ptr, uri_len,
///                headers_ptr, headers_len, body_ptr, body_len,
///                out_status_ptr, out_body_ptr, out_body_max) -> i32
/// Returns: 0=success, -1=error; out_status and out_body written to memory
type HandleRequestFn = TypedFunc<(i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32), i32>;

/// guest_alloc(size) -> i32
type GuestAllocFn = TypedFunc<i32, i32>;

/// guest_free(ptr, size)
type GuestFreeFn = TypedFunc<(i32, i32), ()>;

#[derive(Clone)]
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,
    pub max_table_elements: Option<usize>,
    pub max_cpu_fuel: u64,
    pub timeout_seconds: u64,
    pub max_instances: usize,
    pub memory_budget_mb: Option<usize>,
    pub wasi_enabled: bool,
    pub allowed_dht_prefixes: Vec<String>,
}

impl Default for WasmResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_table_elements: None,
            max_cpu_fuel: 1000000,
            timeout_seconds: 30,
            max_instances: 1,
            memory_budget_mb: None,
            wasi_enabled: false,
            allowed_dht_prefixes: Vec::new(),
        }
    }
}

/// Tracks which guest ABI functions are available in a loaded module
pub(crate) struct GuestExports {
    pub(crate) filter_request: Option<FilterRequestFn>,
    pub(crate) transform_response: Option<TransformResponseFn>,
    pub(crate) handle_request: Option<HandleRequestFn>,
    pub(crate) guest_alloc: Option<GuestAllocFn>,
    pub(crate) guest_free: Option<GuestFreeFn>,
    pub(crate) memory: Option<Memory>,
}

pub struct WasmRuntime {
    engine: Engine,
    module: Module,
    limits: WasmResourceLimits,
    name: String,
    priority: i32,
    pool: Arc<WasmInstancePool>,
    linker: Linker<RequestContext>,
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub path: Option<PathBuf>,
}

pub struct WasmPluginManager {
    runtimes: RwLock<Vec<Arc<WasmRuntime>>>,
    sorted_runtimes_cache: RwLock<Option<Vec<Arc<WasmRuntime>>>>,
    default_limits: WasmResourceLimits,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    pool: Arc<WasmInstancePool>,
    plugin_paths: RwLock<HashMap<String, PathBuf>>,
}

impl WasmPluginManager {
    pub fn new() -> Self {
        Self {
            runtimes: RwLock::new(Vec::new()),
            sorted_runtimes_cache: RwLock::new(None),
            default_limits: WasmResourceLimits::default(),
            pool: Arc::new(WasmInstancePool::new(Arc::new(Engine::default()), 100)),
            plugin_paths: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_limits(mut self, limits: WasmResourceLimits) -> Self {
        self.default_limits = limits;
        self
    }

    pub fn get_default_limits(&self) -> WasmResourceLimits {
        self.default_limits.clone()
    }

    fn sorted_runtimes(&self) -> Vec<Arc<WasmRuntime>> {
        if let Some(cache) = self.sorted_runtimes_cache.read().as_ref() {
            return cache.clone();
        }
        let mut runtimes: Vec<Arc<WasmRuntime>> = self.runtimes.read().iter().cloned().collect();
        runtimes.sort_by_key(|r| r.priority());
        let result = runtimes.clone();
        *self.sorted_runtimes_cache.write() = Some(runtimes);
        result
    }

    pub fn load_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let runtime = WasmRuntime::load(path, self.default_limits.clone())?;
        let arc = Arc::new(runtime);
        let name = arc.name().to_string();
        self.runtimes.write().push(arc.clone());
        *self.sorted_runtimes_cache.write() = None;
        self.plugin_paths.write().insert(name, path.to_path_buf());
        Ok(arc)
    }

    pub fn load_plugin_from_memory(
        &self,
        name: &str,
        data: &[u8],
        limits: WasmResourceLimits,
    ) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let runtime = WasmRuntime::load_from_bytes(name, data, limits)?;
        let arc = Arc::new(runtime);
        let runtime_name = arc.name().to_string();
        self.runtimes.write().push(arc.clone());
        *self.sorted_runtimes_cache.write() = None;
        self.plugin_paths
            .write()
            .insert(runtime_name, PathBuf::from(format!("mesh://{}", name)));
        Ok(arc)
    }

    /// Load a WASM component using the Component Model with WIT-defined interface.
    ///
    /// This method supports plugins compiled against the new Component Model ABI,
    /// as defined in `plugin.wit`. The old `load_plugin` method continues to work
    /// for legacy plugins using the linear-memory ABI.
    pub fn load_component(&self, path: &Path) -> Result<(), WasmPluginError> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config)
            .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;

        let component = Component::from_file(&engine, path)
            .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;

        tracing::info!("Loaded WASM component from '{}'", path.display());

        let mut linker: ComponentLinker<RequestContext> = ComponentLinker::new(&engine);

        Self::link_host_functions(&mut linker)?;

        let mut store = Self::create_component_store(&engine, &self.default_limits);
        let instance = linker.instantiate(&mut store, &component).map_err(|e| {
            WasmPluginError::ExecutionFailed(format!("component instantiation failed: {}", e))
        })?;

        let _func = instance
            .get_export(&mut store, None, "filter-request")
            .ok_or_else(|| WasmPluginError::FunctionNotFound("filter-request".to_string()))?;

        tracing::info!("WASM component instantiated successfully with WIT-defined host interface");
        Ok(())
    }

    fn create_component_store(
        engine: &Engine,
        limits: &WasmResourceLimits,
    ) -> Store<RequestContext> {
        let timeout = Duration::from_secs(limits.timeout_seconds);
        let max_memory = limits.max_memory_mb * 1024 * 1024;
        let max_table_elements = limits.max_table_elements.unwrap_or(0);
        let mut store = Store::new(
            engine,
            RequestContext {
                start: Instant::now(),
                timeout,
                env: HashMap::new(),
                allowed_dht_prefixes: limits.allowed_dht_prefixes.clone(),
                max_memory,
                max_table_elements,
            },
        );
        store.limiter(|state| state);
        if limits.max_cpu_fuel > 0 {
            store.set_fuel(limits.max_cpu_fuel).ok();
        }
        store
    }

    fn link_host_functions(
        linker: &mut ComponentLinker<RequestContext>,
    ) -> Result<(), WasmPluginError> {
        let mut inst = linker
            .instance("host")
            .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;

        inst.func_wrap(
            "log",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>,
             (level, message): (String, String)| {
                match level.as_str() {
                    "error" => tracing::error!("[plugin] {}", message),
                    "warn" => tracing::warn!("[plugin] {}", message),
                    "info" => tracing::info!("[plugin] {}", message),
                    "debug" => tracing::debug!("[plugin] {}", message),
                    _ => tracing::trace!("[plugin] {}", message),
                }
                Ok(())
            },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::log: {}", e)))?;

        inst.func_wrap(
            "get-header",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, (_name,): (String,)| {
                Ok((None::<String>,))
            },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::get-header: {}", e)))?;

        inst.func_wrap(
            "set-header",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>,
             (_name, _value): (String, String)| { Ok(()) },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::set-header: {}", e)))?;

        inst.func_wrap(
            "get-method",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, _: ()| Ok(("GET".to_string(),)),
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::get-method: {}", e)))?;

        inst.func_wrap(
            "get-uri",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, _: ()| Ok(("/".to_string(),)),
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::get-uri: {}", e)))?;

        inst.func_wrap(
            "get-body",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, _: ()| Ok((Vec::<u8>::new(),)),
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::get-body: {}", e)))?;

        inst.func_wrap(
            "set-body",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, (_data,): (Vec<u8>,)| Ok(()),
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::set-body: {}", e)))?;

        inst.func_wrap(
            "set-status",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, (_code,): (u16,)| Ok(()),
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::set-status: {}", e)))?;

        inst.func_wrap(
            "get-env",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, (_key,): (String,)| {
                Ok((None::<String>,))
            },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::get-env: {}", e)))?;

        inst.func_wrap(
            "check-timeout",
            |store: wasmtime::StoreContextMut<'_, RequestContext>,
             _: ()|
             -> Result<(bool,), wasmtime::Error> {
                Ok((store.data().start.elapsed() > store.data().timeout,))
            },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::check-timeout: {}", e)))?;

        inst.func_wrap(
            "mesh-query-dht",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>,
             (_key,): (String,)|
             -> Result<(Result<Vec<u8>, i8>,), wasmtime::Error> {
                Ok((Result::<Vec<u8>, i8>::Ok(Vec::new()),))
            },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::mesh-query-dht: {}", e)))?;

        inst.func_wrap(
            "mesh-check-threat",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>,
             (_ip,): (String,)|
             -> Result<(i8,), wasmtime::Error> { Ok((0i8,)) },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::mesh-check-threat: {}", e)))?;

        inst.func_wrap(
            "mesh-emit-event",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>,
             (_topic, _data): (String, Vec<u8>)|
             -> Result<(Result<(), i8>,), wasmtime::Error> {
                Ok((Result::<(), i8>::Ok(()),))
            },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::mesh-emit-event: {}", e)))?;

        inst.func_wrap(
            "guest-alloc",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>,
             (_size,): (u32,)|
             -> Result<(u32,), wasmtime::Error> { Ok((0u32,)) },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::guest-alloc: {}", e)))?;

        inst.func_wrap(
            "guest-free",
            |_store: wasmtime::StoreContextMut<'_, RequestContext>, (_ptr, _size): (u32, u32)| {
                Ok(())
            },
        )
        .map_err(|e| WasmPluginError::LoadFailed(format!("host::guest-free: {}", e)))?;

        Ok(())
    }

    pub fn load_plugin_with_limits(
        &self,
        path: &Path,
        limits: WasmResourceLimits,
    ) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let runtime = WasmRuntime::load(path, limits)?;
        let arc = Arc::new(runtime);
        let name = arc.name().to_string();
        self.runtimes.write().push(arc.clone());
        *self.sorted_runtimes_cache.write() = None;
        self.plugin_paths.write().insert(name, path.to_path_buf());
        Ok(arc)
    }

    pub fn unload_plugin(&self, name: &str) -> bool {
        let mut runtimes = self.runtimes.write();
        let before = runtimes.len();
        runtimes.retain(|r| r.name() != name);
        if runtimes.len() < before {
            *self.sorted_runtimes_cache.write() = None;
            self.plugin_paths.write().remove(name);
            return true;
        }
        false
    }

    pub fn reload_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let priority = self
            .runtimes
            .read()
            .iter()
            .find(|r| r.name() == name)
            .map(|r| r.priority())
            .unwrap_or(0);

        let new_runtime =
            WasmRuntime::load_with_priority(path, self.default_limits.clone(), priority)?;
        let new_arc = Arc::new(new_runtime);

        {
            let mut runtimes = self.runtimes.write();
            runtimes.retain(|r| r.name() != name);
            runtimes.push(new_arc.clone());
        }
        *self.sorted_runtimes_cache.write() = None;

        self.plugin_paths.write().insert(name, path.to_path_buf());

        Ok(new_arc)
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.runtimes
            .read()
            .iter()
            .map(|r| r.name().to_string())
            .collect()
    }

    pub fn get_plugin_info(&self) -> Vec<PluginInfo> {
        let runtimes = self.runtimes.read();
        let paths = self.plugin_paths.read();
        runtimes
            .iter()
            .map(|r| {
                let name = r.name();
                PluginInfo {
                    name: name.to_string(),
                    path: paths.get(name).cloned(),
                }
            })
            .collect()
    }

    pub fn reload_plugin_by_name(&self, name: &str) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let path =
            self.plugin_paths.read().get(name).cloned().ok_or_else(|| {
                WasmPluginError::LoadFailed(format!("plugin '{}' not found", name))
            })?;
        self.reload_plugin(&path)
    }

    pub fn filter_request(
        &self,
        request: Request<Bytes>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        let env = Arc::new(env);
        for runtime in self.sorted_runtimes().iter() {
            match runtime.filter_request(request.clone(), Arc::clone(&env))? {
                WasmFilterResult::Pass => continue,
                result => return Ok(result),
            }
        }
        Ok(WasmFilterResult::Pass)
    }

    pub fn filter_request_with_plugins(
        &self,
        request: Request<Bytes>,
        plugin_names: &[String],
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        let env = Arc::new(env);
        let runtimes = self.sorted_runtimes();
        for name in plugin_names {
            if let Some(runtime) = runtimes.iter().find(|r| r.name() == name) {
                match runtime.filter_request(request.clone(), Arc::clone(&env))? {
                    WasmFilterResult::Pass => continue,
                    result => return Ok(result),
                }
            }
        }
        Ok(WasmFilterResult::Pass)
    }

    pub fn transform_response(
        &self,
        response: Response<Bytes>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let env = Arc::new(env);
        let mut result = response;
        for runtime in self.sorted_runtimes().iter() {
            result = runtime.transform_response(result, Arc::clone(&env))?;
        }
        Ok(result)
    }

    pub fn transform_response_with_plugins(
        &self,
        response: Response<Bytes>,
        plugin_names: &[String],
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let env = Arc::new(env);
        let runtimes = self.runtimes.read();
        let mut result = response;
        for name in plugin_names {
            if let Some(runtime) = runtimes.iter().find(|r| r.name() == name) {
                result = runtime.transform_response(result, Arc::clone(&env))?;
            }
        }
        Ok(result)
    }
}

impl Default for WasmPluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-request store data with wall-clock timeout tracking
pub(crate) struct RequestContext {
    pub(crate) start: Instant,
    pub(crate) timeout: Duration,
    pub(crate) env: std::collections::HashMap<String, String>,
    pub(crate) allowed_dht_prefixes: Vec<String>,
    pub(crate) max_memory: usize,
    pub(crate) max_table_elements: usize,
}

impl ResourceLimiter for RequestContext {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_memory)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_table_elements)
    }
}

impl WasmRuntime {
    pub fn load(path: &Path, limits: WasmResourceLimits) -> Result<Self, WasmPluginError> {
        Self::load_with_priority(path, limits, 0)
    }

    pub fn load_from_bytes(
        name: &str,
        bytes: &[u8],
        limits: WasmResourceLimits,
    ) -> Result<Self, WasmPluginError> {
        Self::load_from_bytes_with_priority(name, bytes, limits, 0)
    }

    pub fn load_from_bytes_with_priority(
        name: &str,
        bytes: &[u8],
        limits: WasmResourceLimits,
        priority: i32,
    ) -> Result<Self, WasmPluginError> {
        let mut config = Config::new();
        config
            .cranelift_opt_level(OptLevel::SpeedAndSize)
            .max_wasm_stack(1 << 20)
            .memory_init_cow(true);

        if limits.max_cpu_fuel > 0 {
            config.consume_fuel(true);
        }

        let engine =
            Engine::new(&config).map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;

        let module = Module::from_binary(&engine, bytes)
            .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;

        let has_filter = module.get_export("filter_request").is_some();
        let has_transform = module.get_export("transform_response").is_some();
        let has_handle = module.get_export("handle_request").is_some();
        if !has_filter && !has_transform && !has_handle {
            tracing::warn!(
                "WASM plugin '{}' does not export filter_request, transform_response, or handle_request; will be a pass-through",
                name
            );
        }

        tracing::info!(
            "Loaded WASM plugin '{}' from memory with limits: {}MB memory, {} fuel, {}s timeout, priority {} (filter={}, transform={}, handle={})",
            name,
            limits.max_memory_mb,
            limits.max_cpu_fuel,
            limits.timeout_seconds,
            priority,
            has_filter,
            has_transform,
            has_handle,
        );

        let max_instances = limits.max_instances.max(1);
        let pool = Arc::new(WasmInstancePool::new(
            Arc::new(engine.clone()),
            max_instances,
        ));

        let linker = Self::create_linker(&engine, &limits)?;

        Ok(Self {
            engine,
            module,
            limits,
            name: name.to_string(),
            priority,
            pool,
            linker,
        })
    }

    pub fn load_with_priority(
        path: &Path,
        limits: WasmResourceLimits,
        priority: i32,
    ) -> Result<Self, WasmPluginError> {
        let mut config = Config::new();
        config
            .cranelift_opt_level(OptLevel::SpeedAndSize)
            .max_wasm_stack(1 << 20)
            .memory_init_cow(true);

        if limits.max_cpu_fuel > 0 {
            config.consume_fuel(true);
        }

        let engine =
            Engine::new(&config).map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;

        let module = Module::from_file(&engine, path)
            .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Validate that the module exports at least one of the expected functions
        let has_filter = module.get_export("filter_request").is_some();
        let has_transform = module.get_export("transform_response").is_some();
        let has_handle = module.get_export("handle_request").is_some();
        if !has_filter && !has_transform && !has_handle {
            tracing::warn!(
                "WASM plugin '{}' does not export filter_request, transform_response, or handle_request; will be a pass-through",
                name
            );
        }

        tracing::info!(
            "Loaded WASM plugin '{}' with limits: {}MB memory, {} fuel, {}s timeout, priority {} (filter={}, transform={}, handle={})",
            name,
            limits.max_memory_mb,
            limits.max_cpu_fuel,
            limits.timeout_seconds,
            priority,
            has_filter,
            has_transform,
            has_handle,
        );

        let max_instances = limits.max_instances.max(1);
        let pool = Arc::new(WasmInstancePool::new(
            Arc::new(engine.clone()),
            max_instances,
        ));

        let linker = Self::create_linker(&engine, &limits)?;

        Ok(Self {
            engine,
            module,
            limits,
            name,
            priority,
            pool,
            linker,
        })
    }

    /// Create a cached Linker with all host functions pre-registered
    fn create_linker(
        engine: &Engine,
        limits: &WasmResourceLimits,
    ) -> Result<Linker<RequestContext>, WasmPluginError> {
        let mut linker = Linker::new(engine);

        if limits.wasi_enabled {
            tracing::debug!("WASI support enabled for plugin");
        }

        linker
            .func_wrap(
                "env",
                "abort",
                |_caller: wasmtime::Caller<'_, RequestContext>, msg_ptr: i32, msg_len: i32| {
                    tracing::error!("WASM plugin abort at ptr={}, len={}", msg_ptr, msg_len);
                },
            )
            .map_err(|e| WasmPluginError::LoadFailed(format!("failed to link abort: {}", e)))?;

        linker
            .func_wrap(
                "env",
                "check_timeout",
                |caller: wasmtime::Caller<'_, RequestContext>| -> i32 {
                    let elapsed = caller.data().start.elapsed();
                    if elapsed > caller.data().timeout {
                        1
                    } else {
                        0
                    }
                },
            )
            .map_err(|e| {
                WasmPluginError::LoadFailed(format!("failed to link check_timeout: {}", e))
            })?;

        linker
            .func_wrap(
                "env",
                "get_env",
                |mut caller: wasmtime::Caller<'_, RequestContext>,
                 key_ptr: i32,
                 key_len: i32,
                 out_ptr: i32,
                 out_max: i32|
                 -> i32 {
                    let mem = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .unwrap();
                    let mem_data = mem.data(&caller);

                    let key_start = key_ptr as usize;
                    let key_end = key_start.saturating_add(key_len as usize);
                    if key_end > mem_data.len() {
                        return -1;
                    }

                    let key = String::from_utf8_lossy(&mem_data[key_start..key_end]);

                    let value = caller.data().env.get(key.as_ref());
                    let fallback = String::new();
                    let value_str = value.unwrap_or(&fallback);
                    let value_bytes = value_str.as_bytes();
                    let value_len = value_bytes.len().min(out_max as usize);

                    let out_start = out_ptr as usize;
                    let out_end = out_start.saturating_add(value_len);
                    if out_end > mem_data.len() {
                        return -1;
                    }

                    unsafe {
                        let mem_ptr = mem.data_ptr(&caller) as *mut u8;
                        let slice = std::slice::from_raw_parts_mut(
                            mem_ptr.add(out_start),
                            out_end - out_start,
                        );
                        slice.copy_from_slice(&value_bytes[..value_len]);
                    }

                    value_len as i32
                },
            )
            .map_err(|e| WasmPluginError::LoadFailed(format!("failed to link get_env: {}", e)))?;

        linker
            .func_wrap(
                "env",
                "mesh_query_dht",
                |mut caller: wasmtime::Caller<'_, RequestContext>,
                 key_ptr: i32,
                 key_len: i32,
                 out_ptr: i32,
                 out_max: i32|
                 -> i32 {
                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let mem_data = mem.data(&caller);

                    let key_start = key_ptr as usize;
                    let key_end = key_start.saturating_add(key_len as usize);
                    if key_end > mem_data.len() {
                        return -1;
                    }

                    let key = String::from_utf8_lossy(&mem_data[key_start..key_end]).to_string();

                    let sensitive_prefixes = [
                        "threat_indicator:",
                        "yara_rule:",
                        "yara_rules_manifest:",
                        "edge_attestation:",
                        "dns_zone:",
                        "dns_record:",
                        "dns_domain_reg:",
                    ];

                    let is_sensitive = sensitive_prefixes.iter().any(|p| key.starts_with(p));
                    let is_explicitly_allowed = caller
                        .data()
                        .allowed_dht_prefixes
                        .iter()
                        .any(|p| key.starts_with(p));

                    if is_sensitive && !is_explicitly_allowed {
                        tracing::warn!(
                            "WASM plugin attempted unauthorized DHT query: key='{}'",
                            key
                        );
                        return -2;
                    }

                    let result = if let Some(rs) = crate::mesh::get_global_record_store() {
                        if let Some(record) = rs.get_record(&key) {
                            let value = &record.value;
                            let value_len = value.len().min(out_max as usize);
                            let out_start = out_ptr as usize;
                            let out_end = out_start.saturating_add(value_len);
                            if out_end <= mem_data.len() {
                                unsafe {
                                    let mem_ptr = mem.data_ptr(&caller) as *mut u8;
                                    std::slice::from_raw_parts_mut(
                                        mem_ptr.add(out_start),
                                        out_end - out_start,
                                    )
                                    .copy_from_slice(&value[..value_len]);
                                }
                                value_len as i32
                            } else {
                                -1
                            }
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                    if result > 0 {
                        tracing::debug!("WASM mesh_query_dht('{}') -> {} bytes", key, result);
                    }
                    result
                },
            )
            .map_err(|e| {
                WasmPluginError::LoadFailed(format!("failed to link mesh_query_dht: {}", e))
            })?;

        linker
            .func_wrap(
                "env",
                "mesh_check_threat",
                |mut caller: wasmtime::Caller<'_, RequestContext>,
                 ip_ptr: i32,
                 ip_len: i32|
                 -> i32 {
                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let mem_data = mem.data(&caller);

                    let ip_start = ip_ptr as usize;
                    let ip_end = ip_start.saturating_add(ip_len as usize);
                    if ip_end > mem_data.len() {
                        return -1;
                    }

                    let ip_str = String::from_utf8_lossy(&mem_data[ip_start..ip_end]).to_string();

                    if let Some(rs) = crate::mesh::get_global_record_store() {
                        let key = format!("threat_indicator:{}:IpBlock", ip_str);
                        if rs.get_record(&key).is_some() {
                            tracing::debug!("WASM mesh_check_threat('{}') -> THREATENED", ip_str);
                            return 1;
                        }
                    }

                    tracing::debug!("WASM mesh_check_threat('{}') -> CLEAN", ip_str);
                    0
                },
            )
            .map_err(|e| {
                WasmPluginError::LoadFailed(format!("failed to link mesh_check_threat: {}", e))
            })?;

        linker
            .func_wrap(
                "env",
                "mesh_emit_event",
                |mut caller: wasmtime::Caller<'_, RequestContext>,
                 topic_ptr: i32,
                 topic_len: i32,
                 data_ptr: i32,
                 data_len: i32|
                 -> i32 {
                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1,
                    };
                    let mem_data = mem.data(&caller);

                    let topic_start = topic_ptr as usize;
                    let topic_end = topic_start.saturating_add(topic_len as usize);
                    if topic_end > mem_data.len() {
                        return -1;
                    }

                    let data_start = data_ptr as usize;
                    let data_end = data_start.saturating_add(data_len as usize);
                    if data_end > mem_data.len() {
                        return -1;
                    }

                    let topic =
                        String::from_utf8_lossy(&mem_data[topic_start..topic_end]).to_string();
                    let data = mem_data[data_start..data_end].to_vec();

                    tracing::debug!("WASM mesh_emit_event('{}', {} bytes)", topic, data.len());

                    if let Some(rs) = crate::mesh::get_global_record_store() {
                        let key = format!("event:{}", topic);
                        if let Ok(bytes) = serde_json::to_vec(&data) {
                            rs.store_and_announce(key, bytes, 300);
                        }
                    }

                    0
                },
            )
            .map_err(|e| {
                WasmPluginError::LoadFailed(format!("failed to link mesh_emit_event: {}", e))
            })?;

        Ok(linker)
    }

    /// Create a fresh Store with resource limits configured
    fn create_store(
        &self,
        env: std::collections::HashMap<String, String>,
    ) -> Store<RequestContext> {
        let timeout = Duration::from_secs(self.limits.timeout_seconds);
        let max_memory = self.limits.max_memory_mb * 1024 * 1024;
        let max_table_elements = self.limits.max_table_elements.unwrap_or(0);
        let mut store = Store::new(
            &self.engine,
            RequestContext {
                start: Instant::now(),
                timeout,
                env,
                allowed_dht_prefixes: self.limits.allowed_dht_prefixes.clone(),
                max_memory,
                max_table_elements,
            },
        );

        store.limiter(|state| state);

        if self.limits.max_cpu_fuel > 0 {
            store.set_fuel(self.limits.max_cpu_fuel).ok();
        }

        store
    }

    /// Instantiate the module and resolve guest exports
    fn instantiate(
        &self,
        store: &mut Store<RequestContext>,
    ) -> Result<GuestExports, WasmPluginError> {
        let linker = self.linker.clone();

        let instance = linker
            .instantiate(&mut *store, &self.module)
            .map_err(|e| WasmPluginError::ExecutionFailed(format!("instantiate failed: {}", e)))?;

        let memory = instance
            .get_export(&mut *store, "memory")
            .and_then(|ext| ext.into_memory());

        let filter_request = self.resolve_filter_request(&instance, store);
        let transform_response = self.resolve_transform_response(&instance, store);
        let handle_request = self.resolve_handle_request(&instance, store);
        let guest_alloc = self.resolve_guest_alloc(&instance, store);
        let guest_free = self.resolve_guest_free(&instance, store);

        Ok(GuestExports {
            filter_request,
            transform_response,
            handle_request,
            guest_alloc,
            guest_free,
            memory,
        })
    }

    fn resolve_filter_request(
        &self,
        instance: &Instance,
        store: &mut Store<RequestContext>,
    ) -> Option<FilterRequestFn> {
        let func = instance.get_func(&mut *store, "filter_request")?;
        func.typed(&mut *store).ok()
    }

    fn resolve_transform_response(
        &self,
        instance: &Instance,
        store: &mut Store<RequestContext>,
    ) -> Option<TransformResponseFn> {
        let func = instance.get_func(&mut *store, "transform_response")?;
        func.typed(&mut *store).ok()
    }

    fn resolve_handle_request(
        &self,
        instance: &Instance,
        store: &mut Store<RequestContext>,
    ) -> Option<HandleRequestFn> {
        let func = instance.get_func(&mut *store, "handle_request")?;
        func.typed(&mut *store).ok()
    }

    fn resolve_guest_alloc(
        &self,
        instance: &Instance,
        store: &mut Store<RequestContext>,
    ) -> Option<GuestAllocFn> {
        let func = instance.get_func(&mut *store, "guest_alloc")?;
        func.typed(&mut *store).ok()
    }

    fn resolve_guest_free(
        &self,
        instance: &Instance,
        store: &mut Store<RequestContext>,
    ) -> Option<GuestFreeFn> {
        let func = instance.get_func(&mut *store, "guest_free")?;
        func.typed(&mut *store).ok()
    }

    /// Write data into WASM linear memory, using guest_alloc if available,
    /// otherwise writing at offset 1024 (reserved header area).
    fn write_to_guest_memory(
        &self,
        store: &mut Store<RequestContext>,
        exports: &GuestExports,
        data: &[u8],
    ) -> Result<(i32, i32), WasmPluginError> {
        let memory = exports
            .memory
            .as_ref()
            .ok_or_else(|| WasmPluginError::ExecutionFailed("no memory export".into()))?;

        let data_len = data.len();
        if data_len > MAX_WASM_DATA_SIZE {
            return Err(WasmPluginError::SandboxError(format!(
                "data size {} exceeds max {}",
                data_len, MAX_WASM_DATA_SIZE
            )));
        }

        let ptr = if let Some(alloc_fn) = &exports.guest_alloc {
            alloc_fn.call(&mut *store, data_len as i32).map_err(|e| {
                WasmPluginError::ExecutionFailed(format!("guest_alloc failed: {}", e))
            })?
        } else {
            // Fallback: use a fixed offset after the reserved header area
            1024i32
        };

        if ptr < 0 {
            return Err(WasmPluginError::ExecutionFailed(
                "guest_alloc returned negative pointer".into(),
            ));
        }

        // Check memory bounds
        let mem_size = memory.data_size(&*store);
        let end = (ptr as usize) + data_len;
        if end > mem_size {
            // Try to grow memory
            let pages_needed = (end - mem_size).div_ceil(65536);
            let max_pages = (self.limits.max_memory_mb * 1024 * 1024) / 65536;
            let current_pages = mem_size / 65536;
            if current_pages + pages_needed > max_pages {
                return Err(WasmPluginError::SandboxError(format!(
                    "memory growth would exceed limit: need {} pages, max {}",
                    current_pages + pages_needed,
                    max_pages
                )));
            }
            memory.grow(&mut *store, pages_needed as u64).map_err(|e| {
                WasmPluginError::ExecutionFailed(format!("memory grow failed: {}", e))
            })?;
        }

        let mem_data = memory.data_mut(&mut *store);
        mem_data[ptr as usize..end].copy_from_slice(data);

        Ok((ptr, data_len as i32))
    }

    /// Read data from WASM linear memory
    fn read_from_guest_memory(
        &self,
        store: &mut Store<RequestContext>,
        exports: &GuestExports,
        ptr: i32,
        len: i32,
    ) -> Result<Vec<u8>, WasmPluginError> {
        if ptr < 0 || len < 0 {
            return Err(WasmPluginError::ExecutionFailed(
                "invalid read parameters".into(),
            ));
        }
        if len as usize > MAX_WASM_DATA_SIZE {
            return Err(WasmPluginError::SandboxError(format!(
                "read size {} exceeds max {}",
                len, MAX_WASM_DATA_SIZE
            )));
        }

        let memory = exports
            .memory
            .as_ref()
            .ok_or_else(|| WasmPluginError::ExecutionFailed("no memory export".into()))?;

        let mem_data = memory.data(&*store);
        let start = ptr as usize;
        let end = start + (len as usize);

        if end > mem_data.len() {
            return Err(WasmPluginError::ExecutionFailed(format!(
                "read out of bounds: [{}, {}] but memory is {}",
                start,
                end,
                mem_data.len()
            )));
        }

        Ok(mem_data[start..end].to_vec())
    }

    /// Free guest memory if guest_free is available
    fn free_guest_memory(
        &self,
        store: &mut Store<RequestContext>,
        exports: &GuestExports,
        ptr: i32,
        len: i32,
    ) {
        if let Some(free_fn) = &exports.guest_free {
            free_fn.call(&mut *store, (ptr, len)).ok();
        }
    }

    /// Serialize headers to a compact binary format for passing to WASM guest.
    ///
    /// Format: [header_count: u16]
    ///         [for each header: [name_len: u16][name][value_len: u16][value]]
    fn serialize_headers(headers: &HeaderMap) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);

        buf.extend_from_slice(&(headers.len() as u16).to_le_bytes());
        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            buf.extend_from_slice(&(name_str.len() as u16).to_le_bytes());
            buf.extend_from_slice(name_str.as_bytes());
            let val_bytes = value.as_bytes();
            buf.extend_from_slice(&(val_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(val_bytes);
        }

        buf
    }

    /// Check if the request timed out
    fn check_timeout(store: &Store<RequestContext>) -> Result<(), WasmPluginError> {
        let elapsed = store.data().start.elapsed();
        if elapsed > store.data().timeout {
            return Err(WasmPluginError::ExecutionFailed(format!(
                "WASM execution timed out after {:.2}s",
                elapsed.as_secs_f64()
            )));
        }
        Ok(())
    }

    pub fn filter_request(
        &self,
        request: Request<Bytes>,
        env: Arc<std::collections::HashMap<String, String>>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        let plugin_name = &self.name;

        record_wasm_invocation(plugin_name);

        let (parts, body) = request.into_parts();

        tracing::debug!(
            "WASM plugin '{}' filtering request {} {}",
            self.name,
            parts.method,
            parts.uri
        );

        let pooled_instance = self.pool.get(&self.name);

        if let Some(mut inst) = pooled_instance {
            inst.prepare_for_request((*env).clone(), self.limits.timeout_seconds);
            let exports =
                WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
            let result = self.do_filter_request_with_exports(parts, body, &mut inst.store, exports);
            self.pool.return_instance(inst);
            return result;
        }

        let mut store = self.create_store((*env).clone());
        let exports = self.instantiate(&mut store)?;
        self.do_filter_request_with_exports(parts, body, &mut store, exports)
    }

    fn do_filter_request_with_exports(
        &self,
        parts: http::request::Parts,
        body: Bytes,
        store: &mut Store<RequestContext>,
        exports: GuestExports,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        let start = Instant::now();
        let plugin_name = &self.name;

        let filter_fn = match exports.filter_request.as_ref() {
            Some(f) => f,
            None => {
                let duration_ms = start.elapsed().as_millis() as u64;
                record_wasm_duration(plugin_name, duration_ms);
                record_wasm_decision_pass(plugin_name);
                return Ok(WasmFilterResult::Pass);
            }
        };

        Self::check_timeout(&*store)?;

        let method_str = parts.method.as_str();
        let method_bytes = method_str.as_bytes();
        let uri_str = parts.uri.to_string();
        let uri_bytes = uri_str.as_bytes();

        let (method_ptr, method_len) =
            self.write_to_guest_memory(&mut *store, &exports, method_bytes)?;
        let (uri_ptr, uri_len) = self.write_to_guest_memory(&mut *store, &exports, uri_bytes)?;

        let headers_meta = Self::serialize_headers(&parts.headers);
        let (hdr_ptr, hdr_len) =
            self.write_to_guest_memory(&mut *store, &exports, &headers_meta)?;

        let body_bytes = body.as_ref();
        let (body_ptr, body_len) = if !body_bytes.is_empty() {
            self.write_to_guest_memory(&mut *store, &exports, body_bytes)?
        } else {
            (0, 0i32)
        };

        let result = filter_fn.call(
            &mut *store,
            (
                method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len,
            ),
        );

        self.free_guest_memory(&mut *store, &exports, method_ptr, method_len);
        self.free_guest_memory(&mut *store, &exports, uri_ptr, uri_len);
        self.free_guest_memory(&mut *store, &exports, hdr_ptr, hdr_len);
        if body_len > 0 {
            self.free_guest_memory(&mut *store, &exports, body_ptr, body_len);
        }

        if self.limits.max_cpu_fuel > 0 {
            if let Ok(remaining) = store.get_fuel() {
                let consumed = self.limits.max_cpu_fuel.saturating_sub(remaining);
                record_wasm_fuel_consumed(plugin_name, consumed);
            }
        }

        let code = result.map_err(|e| {
            if e.to_string().contains("fuel") || e.to_string().contains("all fuel") {
                WasmPluginError::SandboxError(format!(
                    "WASM plugin '{}' exhausted fuel budget",
                    self.name
                ))
            } else {
                WasmPluginError::ExecutionFailed(format!(
                    "filter_request failed in '{}': {}",
                    self.name, e
                ))
            }
        })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        record_wasm_duration(plugin_name, duration_ms);

        match code {
            0 => {
                record_wasm_decision_pass(plugin_name);
                Ok(WasmFilterResult::Pass)
            }
            1 => {
                record_wasm_decision_block(plugin_name);
                Ok(WasmFilterResult::Block(
                    StatusCode::FORBIDDEN,
                    format!("Blocked by WASM plugin '{}'", self.name),
                ))
            }
            2 => {
                record_wasm_decision_challenge(plugin_name);
                Ok(WasmFilterResult::Challenge(format!(
                    "challenge:wasm:{}",
                    self.name
                )))
            }
            -1 => {
                record_wasm_error(plugin_name);
                Err(WasmPluginError::ExecutionFailed(format!(
                    "WASM plugin '{}' returned error",
                    self.name
                )))
            }
            other => {
                tracing::warn!(
                    "WASM plugin '{}' returned unknown filter code {}",
                    self.name,
                    other
                );
                record_wasm_decision_pass(plugin_name);
                Ok(WasmFilterResult::Pass)
            }
        }
    }

    pub fn transform_response(
        &self,
        response: Response<Bytes>,
        env: Arc<std::collections::HashMap<String, String>>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let plugin_name = &self.name;

        record_wasm_invocation(plugin_name);

        let (parts, body) = response.into_parts();

        tracing::debug!(
            "WASM plugin '{}' transforming response with status {}",
            self.name,
            parts.status
        );

        let pooled_instance = self.pool.get(&self.name);

        if let Some(mut inst) = pooled_instance {
            inst.prepare_for_request((*env).clone(), self.limits.timeout_seconds);
            let exports =
                WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
            let result =
                self.do_transform_response_with_exports(parts, body, &mut inst.store, exports);
            self.pool.return_instance(inst);
            return result;
        }

        let mut store = self.create_store((*env).clone());
        let exports = self.instantiate(&mut store)?;
        self.do_transform_response_with_exports(parts, body, &mut store, exports)
    }

    fn do_transform_response_with_exports(
        &self,
        parts: http::response::Parts,
        body: Bytes,
        store: &mut Store<RequestContext>,
        exports: GuestExports,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let start = Instant::now();
        let plugin_name = &self.name;

        let transform_fn = match exports.transform_response.as_ref() {
            Some(f) => f,
            None => {
                let duration_ms = start.elapsed().as_millis() as u64;
                record_wasm_duration(plugin_name, duration_ms);
                record_wasm_decision_pass(plugin_name);
                return Ok(Response::from_parts(parts, body));
            }
        };

        let body_bytes = body.as_ref();
        let (body_ptr, body_len) = if !body_bytes.is_empty() {
            self.write_to_guest_memory(&mut *store, &exports, body_bytes)?
        } else {
            let (p, _) = self.write_to_guest_memory(&mut *store, &exports, &[])?;
            (p, 0i32)
        };

        Self::check_timeout(&*store)?;

        let out_max = (body_bytes.len() + 65536).min(MAX_WASM_DATA_SIZE) as i32;
        let (out_ptr, _) =
            self.write_to_guest_memory(&mut *store, &exports, &vec![0u8; out_max as usize])?;

        let status_code = parts.status.as_u16() as i32;

        let new_len = transform_fn
            .call(
                &mut *store,
                (status_code, body_ptr, body_len, out_ptr, out_max),
            )
            .map_err(|e| {
                record_wasm_error(plugin_name);
                WasmPluginError::ExecutionFailed(format!(
                    "transform_response failed in '{}': {}",
                    self.name, e
                ))
            })?;

        if self.limits.max_cpu_fuel > 0 {
            if let Ok(remaining) = store.get_fuel() {
                let consumed = self.limits.max_cpu_fuel.saturating_sub(remaining);
                record_wasm_fuel_consumed(plugin_name, consumed);
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        record_wasm_duration(plugin_name, duration_ms);
        record_wasm_decision_pass(plugin_name);

        let result_body = if new_len > 0 && (new_len as usize) <= MAX_WASM_DATA_SIZE {
            let data = self.read_from_guest_memory(&mut *store, &exports, out_ptr, new_len)?;
            Bytes::from(data)
        } else if new_len == 0 {
            Bytes::new()
        } else {
            tracing::warn!(
                "WASM plugin '{}' returned invalid transform length {}",
                self.name,
                new_len
            );
            body
        };

        self.free_guest_memory(&mut *store, &exports, body_ptr, body_len);
        self.free_guest_memory(&mut *store, &exports, out_ptr, out_max);

        Ok(Response::from_parts(parts, result_body))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn priority(&self) -> i32 {
        self.priority
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn module(&self) -> &Module {
        &self.module
    }

    pub fn invoke_handler(
        &self,
        method: &str,
        uri: &str,
        headers: &str,
        body: &[u8],
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let start = Instant::now();
        let plugin_name = &self.name;

        record_wasm_invocation(plugin_name);

        tracing::debug!(
            "WASM serverless function '{}' handling {} {}",
            self.name,
            method,
            uri
        );

        let mut store = self.create_store(env);
        let exports = self.instantiate(&mut store)?;

        let handle_fn = match exports.handle_request.as_ref() {
            Some(f) => f,
            None => {
                let duration_ms = start.elapsed().as_millis() as u64;
                record_wasm_duration(plugin_name, duration_ms);
                record_wasm_error(plugin_name);
                return Err(WasmPluginError::ExecutionFailed(
                    "handle_request function not exported".into(),
                ));
            }
        };

        Self::check_timeout(&store)?;

        let method_bytes = method.as_bytes();
        let uri_bytes = uri.as_bytes();
        let headers_bytes = headers.as_bytes();

        let (method_ptr, method_len) =
            self.write_to_guest_memory(&mut store, &exports, method_bytes)?;
        let (uri_ptr, uri_len) = self.write_to_guest_memory(&mut store, &exports, uri_bytes)?;
        let (hdr_ptr, hdr_len) = self.write_to_guest_memory(&mut store, &exports, headers_bytes)?;
        let (body_ptr, body_len) = self.write_to_guest_memory(&mut store, &exports, body)?;

        const OUT_BODY_MAX: usize = 65536;
        let (out_status_ptr, _) = self.write_to_guest_memory(&mut store, &exports, &[0u8; 4])?;
        let (out_body_ptr, _) =
            self.write_to_guest_memory(&mut store, &exports, &[0u8; OUT_BODY_MAX])?;

        let result = handle_fn.call(
            &mut store,
            (
                method_ptr,
                method_len,
                uri_ptr,
                uri_len,
                hdr_ptr,
                hdr_len,
                body_ptr,
                body_len,
                out_status_ptr,
                out_body_ptr,
                OUT_BODY_MAX as i32,
            ),
        );

        self.free_guest_memory(&mut store, &exports, method_ptr, method_len);
        self.free_guest_memory(&mut store, &exports, uri_ptr, uri_len);
        self.free_guest_memory(&mut store, &exports, hdr_ptr, hdr_len);
        self.free_guest_memory(&mut store, &exports, body_ptr, body_len);

        if self.limits.max_cpu_fuel > 0 {
            if let Ok(remaining) = store.get_fuel() {
                let consumed = self.limits.max_cpu_fuel.saturating_sub(remaining);
                record_wasm_fuel_consumed(plugin_name, consumed);
            }
        }

        let code = result.map_err(|e| {
            record_wasm_error(plugin_name);
            WasmPluginError::ExecutionFailed(format!(
                "handle_request failed in '{}': {}",
                self.name, e
            ))
        })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        record_wasm_duration(plugin_name, duration_ms);

        if code < 0 {
            record_wasm_error(plugin_name);
            return Err(WasmPluginError::ExecutionFailed(format!(
                "Serverless function '{}' returned error",
                self.name
            )));
        }

        record_wasm_decision_pass(plugin_name);

        let status_data = self.read_from_guest_memory(&mut store, &exports, out_status_ptr, 4)?;
        let status_code = u32::from_le_bytes(
            status_data
                .try_into()
                .map_err(|_| WasmPluginError::ExecutionFailed("Invalid status read".into()))?,
        ) as u16;

        let body_data = self.read_from_guest_memory(&mut store, &exports, out_body_ptr, code)?;
        let result_body = Bytes::from(body_data);

        self.free_guest_memory(&mut store, &exports, out_status_ptr, 4);
        self.free_guest_memory(
            &mut store,
            &exports,
            out_body_ptr,
            OUT_BODY_MAX.try_into().unwrap(),
        );

        let response = Response::builder()
            .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK))
            .body(result_body)
            .map_err(|e| WasmPluginError::ExecutionFailed(e.to_string()))?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn test_resource_limits_default() {
        let limits = WasmResourceLimits::default();
        assert_eq!(limits.max_memory_mb, 64);
        assert_eq!(limits.max_cpu_fuel, 1_000_000);
        assert_eq!(limits.timeout_seconds, 30);
        assert_eq!(limits.max_instances, 1);
    }

    #[test]
    fn test_plugin_manager_new() {
        let mgr = WasmPluginManager::new();
        assert!(mgr.list_plugins().is_empty());
    }

    #[test]
    fn test_serialize_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let data = WasmRuntime::serialize_headers(&headers);

        // Should be non-empty
        assert!(data.len() > 4);

        // Verify header count is encoded
        let header_count = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(header_count, 2);

        // First header: host: example.com
        let name_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        assert_eq!(name_len, 4);
        assert_eq!(&data[4..8], b"host");
        let val_start = 8;
        let val_len = u16::from_le_bytes([data[val_start], data[val_start + 1]]) as usize;
        assert_eq!(val_len, 11);
        assert_eq!(
            &data[val_start + 2..val_start + 2 + val_len],
            b"example.com"
        );
    }

    #[test]
    fn test_filter_request_no_module() {
        // Without a real WASM module, load should fail
        let result = WasmRuntime::load(
            Path::new("/nonexistent/plugin.wasm"),
            WasmResourceLimits::default(),
        );
        assert!(result.is_err());
    }
}
