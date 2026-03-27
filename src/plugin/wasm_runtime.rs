use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response};
use parking_lot::RwLock;
use wasmtime::{Config, Engine, Module, OptLevel};

use crate::plugin::{WasmFilterResult, WasmPluginError};

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

pub struct WasmRuntime {
    #[allow(dead_code)] // Reserved for WASM execution
    engine: Engine,
    #[allow(dead_code)]
    module: Module,
    #[allow(dead_code)]
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
}

impl Default for WasmPluginManager {
    fn default() -> Self {
        Self::new()
    }
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

        tracing::info!(
            "Loaded WASM plugin: {} with limits: {}MB memory, {} fuel, {}s timeout",
            name,
            limits.max_memory_mb,
            limits.max_cpu_fuel,
            limits.timeout_seconds
        );

        Ok(Self {
            engine,
            module,
            limits,
            name,
        })
    }

    pub fn filter_request(
        &self,
        request: Request<Bytes>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        tracing::debug!(
            "WASM plugin {} filtering request to {}",
            self.name,
            request.uri()
        );

        Ok(WasmFilterResult::Pass)
    }

    pub fn transform_response(
        &self,
        response: Response<Bytes>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        tracing::debug!(
            "WASM plugin {} transforming response with status {}",
            self.name,
            response.status()
        );

        Ok(response)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
