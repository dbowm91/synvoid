use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use parking_lot::RwLock;
use wasmtime::{Config, Engine, Instance, Linker, Memory, Module, OptLevel, Store, TypedFunc};

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

/// guest_alloc(size) -> i32
type GuestAllocFn = TypedFunc<i32, i32>;

/// guest_free(ptr, size)
type GuestFreeFn = TypedFunc<(i32, i32), ()>;

#[derive(Clone)]
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,
    pub max_cpu_fuel: u64,
    pub timeout_seconds: u64,
    pub max_instances: usize,
}

impl Default for WasmResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_cpu_fuel: 1000000,
            timeout_seconds: 30,
            max_instances: 1,
        }
    }
}

/// Tracks which guest ABI functions are available in a loaded module
struct GuestExports {
    filter_request: Option<FilterRequestFn>,
    transform_response: Option<TransformResponseFn>,
    guest_alloc: Option<GuestAllocFn>,
    guest_free: Option<GuestFreeFn>,
    memory: Option<Memory>,
}

pub struct WasmRuntime {
    engine: Engine,
    module: Module,
    limits: WasmResourceLimits,
    name: String,
}

pub struct WasmPluginManager {
    runtimes: RwLock<Vec<Arc<WasmRuntime>>>,
    default_limits: WasmResourceLimits,
}

impl WasmPluginManager {
    pub fn new() -> Self {
        Self {
            runtimes: RwLock::new(Vec::new()),
            default_limits: WasmResourceLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: WasmResourceLimits) -> Self {
        self.default_limits = limits;
        self
    }

    pub fn load_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let runtime = WasmRuntime::load(path, self.default_limits.clone())?;
        let arc = Arc::new(runtime);
        self.runtimes.write().push(arc.clone());
        Ok(arc)
    }

    pub fn load_plugin_with_limits(
        &self,
        path: &Path,
        limits: WasmResourceLimits,
    ) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let runtime = WasmRuntime::load(path, limits)?;
        let arc = Arc::new(runtime);
        self.runtimes.write().push(arc.clone());
        Ok(arc)
    }

    pub fn unload_plugin(&self, name: &str) -> bool {
        let mut runtimes = self.runtimes.write();
        let before = runtimes.len();
        runtimes.retain(|r| r.name() != name);
        runtimes.len() < before
    }

    pub fn reload_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Unload existing plugin with same name
        self.unload_plugin(&name);

        // Load fresh
        self.load_plugin(path)
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.runtimes
            .read()
            .iter()
            .map(|r| r.name().to_string())
            .collect()
    }

    pub fn filter_request(
        &self,
        request: Request<Bytes>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        for runtime in self.runtimes.read().iter() {
            match runtime.filter_request(request.clone())? {
                WasmFilterResult::Pass => continue,
                result => return Ok(result),
            }
        }
        Ok(WasmFilterResult::Pass)
    }

    pub fn transform_response(
        &self,
        response: Response<Bytes>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let mut result = response;
        for runtime in self.runtimes.read().iter() {
            result = runtime.transform_response(result)?;
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
struct RequestContext {
    start: Instant,
    timeout: Duration,
}

impl WasmRuntime {
    pub fn load(path: &Path, limits: WasmResourceLimits) -> Result<Self, WasmPluginError> {
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
        if !has_filter && !has_transform {
            tracing::warn!(
                "WASM plugin '{}' does not export filter_request or transform_response; will be a pass-through",
                name
            );
        }

        tracing::info!(
            "Loaded WASM plugin '{}' with limits: {}MB memory, {} fuel, {}s timeout (filter={}, transform={})",
            name,
            limits.max_memory_mb,
            limits.max_cpu_fuel,
            limits.timeout_seconds,
            has_filter,
            has_transform,
        );

        Ok(Self {
            engine,
            module,
            limits,
            name,
        })
    }

    /// Create a fresh Store with resource limits configured
    fn create_store(&self) -> Store<RequestContext> {
        let timeout = Duration::from_secs(self.limits.timeout_seconds);
        let mut store = Store::new(
            &self.engine,
            RequestContext {
                start: Instant::now(),
                timeout,
            },
        );

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
        let mut linker = Linker::new(&self.engine);

        // Provide a minimal abort host function
        linker
            .func_wrap(
                "env",
                "abort",
                |_caller: wasmtime::Caller<'_, RequestContext>, msg_ptr: i32, msg_len: i32| {
                    tracing::error!("WASM plugin abort at ptr={}, len={}", msg_ptr, msg_len);
                },
            )
            .map_err(|e| WasmPluginError::LoadFailed(format!("failed to link abort: {}", e)))?;

        // Provide a wall-clock timeout check host function
        linker
            .func_wrap(
                "env",
                "check_timeout",
                |caller: wasmtime::Caller<'_, RequestContext>| -> i32 {
                    let elapsed = caller.data().start.elapsed();
                    if elapsed > caller.data().timeout {
                        1 // timed out
                    } else {
                        0 // ok
                    }
                },
            )
            .map_err(|e| {
                WasmPluginError::LoadFailed(format!("failed to link check_timeout: {}", e))
            })?;

        let instance = linker
            .instantiate(&mut *store, &self.module)
            .map_err(|e| WasmPluginError::ExecutionFailed(format!("instantiate failed: {}", e)))?;

        // Resolve memory
        let memory = instance
            .get_export(&mut *store, "memory")
            .and_then(|ext| ext.into_memory());

        // Resolve optional guest ABI functions
        let filter_request = self.resolve_filter_request(&instance, store);
        let transform_response = self.resolve_transform_response(&instance, store);
        let guest_alloc = self.resolve_guest_alloc(&instance, store);
        let guest_free = self.resolve_guest_free(&instance, store);

        Ok(GuestExports {
            filter_request,
            transform_response,
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
            let pages_needed = (end - mem_size + 65535) / 65536;
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
    ) -> Result<WasmFilterResult, WasmPluginError> {
        let (parts, body) = request.into_parts();

        tracing::debug!(
            "WASM plugin '{}' filtering request {} {}",
            self.name,
            parts.method,
            parts.uri
        );

        let mut store = self.create_store();
        let exports = self.instantiate(&mut store)?;

        let filter_fn = match exports.filter_request.as_ref() {
            Some(f) => f,
            None => {
                return Ok(WasmFilterResult::Pass);
            }
        };

        Self::check_timeout(&store)?;

        // Write request components to guest memory
        let method_str = parts.method.as_str();
        let method_bytes = method_str.as_bytes();
        let uri_str = parts.uri.to_string();
        let uri_bytes = uri_str.as_bytes();

        let (method_ptr, method_len) =
            self.write_to_guest_memory(&mut store, &exports, method_bytes)?;
        let (uri_ptr, uri_len) = self.write_to_guest_memory(&mut store, &exports, uri_bytes)?;

        // Write headers as serialized metadata
        let headers_meta = Self::serialize_headers(&parts.headers);
        let (hdr_ptr, hdr_len) = self.write_to_guest_memory(&mut store, &exports, &headers_meta)?;

        // Write body
        let body_bytes = body.as_ref();
        let (body_ptr, body_len) = if !body_bytes.is_empty() {
            self.write_to_guest_memory(&mut store, &exports, body_bytes)?
        } else {
            (0, 0i32)
        };

        let result = filter_fn.call(
            &mut store,
            (
                method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len,
            ),
        );

        // Free guest allocations
        self.free_guest_memory(&mut store, &exports, method_ptr, method_len);
        self.free_guest_memory(&mut store, &exports, uri_ptr, uri_len);
        self.free_guest_memory(&mut store, &exports, hdr_ptr, hdr_len);
        if body_len > 0 {
            self.free_guest_memory(&mut store, &exports, body_ptr, body_len);
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

        match code {
            0 => Ok(WasmFilterResult::Pass),
            1 => Ok(WasmFilterResult::Block(
                StatusCode::FORBIDDEN,
                format!("Blocked by WASM plugin '{}'", self.name),
            )),
            2 => Ok(WasmFilterResult::Challenge(format!(
                "challenge:wasm:{}",
                self.name
            ))),
            -1 => Err(WasmPluginError::ExecutionFailed(format!(
                "WASM plugin '{}' returned error",
                self.name
            ))),
            other => {
                tracing::warn!(
                    "WASM plugin '{}' returned unknown filter code {}",
                    self.name,
                    other
                );
                Ok(WasmFilterResult::Pass)
            }
        }
    }

    pub fn transform_response(
        &self,
        response: Response<Bytes>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let (parts, body) = response.into_parts();

        tracing::debug!(
            "WASM plugin '{}' transforming response with status {}",
            self.name,
            parts.status
        );

        let mut store = self.create_store();
        let exports = self.instantiate(&mut store)?;

        let transform_fn = match exports.transform_response.as_ref() {
            Some(f) => f,
            None => {
                // Module doesn't export transform_response; pass through
                return Ok(Response::from_parts(parts, body));
            }
        };

        let body_bytes = body.as_ref();
        let (body_ptr, body_len) = if !body_bytes.is_empty() {
            self.write_to_guest_memory(&mut store, &exports, body_bytes)?
        } else {
            // Allocate a zero-length buffer so the guest gets a valid pointer
            let (p, _) = self.write_to_guest_memory(&mut store, &exports, &[])?;
            (p, 0i32)
        };

        Self::check_timeout(&store)?;

        // Allocate output buffer (same size as input + 64KB headroom)
        let out_max = (body_bytes.len() + 65536).min(MAX_WASM_DATA_SIZE) as i32;
        let (out_ptr, _) =
            self.write_to_guest_memory(&mut store, &exports, &vec![0u8; out_max as usize])?;

        let status_code = parts.status.as_u16() as i32;

        let new_len = transform_fn
            .call(
                &mut store,
                (status_code, body_ptr, body_len, out_ptr, out_max),
            )
            .map_err(|e| {
                WasmPluginError::ExecutionFailed(format!(
                    "transform_response failed in '{}': {}",
                    self.name, e
                ))
            })?;

        let result_body = if new_len > 0 && (new_len as usize) <= MAX_WASM_DATA_SIZE {
            let data = self.read_from_guest_memory(&mut store, &exports, out_ptr, new_len)?;
            Bytes::from(data)
        } else if new_len == 0 {
            Bytes::new()
        } else {
            // Negative or implausible size: return original body
            tracing::warn!(
                "WASM plugin '{}' returned invalid transform length {}",
                self.name,
                new_len
            );
            body
        };

        // Free allocations
        self.free_guest_memory(&mut store, &exports, body_ptr, body_len);
        self.free_guest_memory(&mut store, &exports, out_ptr, out_max);

        Ok(Response::from_parts(parts, result_body))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn module(&self) -> &Module {
        &self.module
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
