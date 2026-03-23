use std::path::Path;
use std::sync::Arc;

use axum::Router;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use parking_lot::RwLock;

pub mod axum_loader;
pub mod wasm_runtime;

pub use wasm_runtime::{WasmPluginManager, WasmResourceLimits, WasmRuntime};

pub struct WasmPlugin {
    _path: String,
    name: String,
}

impl WasmPlugin {
    pub fn load(path: &Path) -> Result<WasmPlugin, WasmPluginError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        tracing::info!("Loading WASM plugin: {} from {:?}", name, path);

        Ok(WasmPlugin {
            _path: path.to_string_lossy().to_string(),
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
        Ok(response)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

pub enum WasmFilterResult {
    Pass,
    Block(StatusCode, String),
    Challenge(String),
}

#[derive(Debug, thiserror::Error)]
pub enum WasmPluginError {
    #[error("Failed to load WASM module: {0}")]
    LoadFailed(String),
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Sandbox error: {0}")]
    SandboxError(String),
}

pub struct PluginManager {
    wasm_plugins: RwLock<Vec<Arc<WasmPlugin>>>,
    axum_plugins: RwLock<Vec<Arc<AxumPluginWrapper>>>,
}

struct AxumPluginWrapper {
    router: axum::Router<()>,
    name: String,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            wasm_plugins: RwLock::new(Vec::new()),
            axum_plugins: RwLock::new(Vec::new()),
        }
    }

    pub fn load_wasm_plugin(&self, path: &Path) -> Result<Arc<WasmPlugin>, WasmPluginError> {
        let plugin = WasmPlugin::load(path)?;
        let arc = Arc::new(plugin);
        self.wasm_plugins.write().push(arc.clone());
        tracing::info!("Loaded WASM plugin: {}", arc.name());
        Ok(arc)
    }

    pub fn load_axum_plugin(&self, path: &Path) -> Result<Arc<Router>, AxumPluginError> {
        let (router, wrapper_name) = axum_loader::load_plugin(path)?;

        let wrapper_name_for_log = wrapper_name.clone();

        let wrapper = AxumPluginWrapper {
            router: Router::new(),
            name: wrapper_name,
        };

        self.axum_plugins.write().push(Arc::new(wrapper));
        tracing::info!("Loaded Axum plugin: {}", wrapper_name_for_log);

        Ok(Arc::new(router))
    }

    pub fn apply_wasm_filters(
        &self,
        request: Request<Bytes>,
    ) -> Result<Request<Bytes>, WasmPluginError> {
        for plugin in self.wasm_plugins.read().iter() {
            match plugin.filter_request(request.clone())? {
                WasmFilterResult::Pass => continue,
                WasmFilterResult::Block(_, _) => return Ok(request),
                WasmFilterResult::Challenge(_) => return Ok(request),
            }
        }
        Ok(request)
    }

    pub fn apply_wasm_response_transforms(
        &self,
        response: Response<Bytes>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let mut result = response;
        for plugin in self.wasm_plugins.read().iter() {
            result = plugin.transform_response(result)?;
        }
        Ok(result)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AxumPluginError {
    #[error("Failed to load plugin: {0}")]
    LoadFailed(String),
    #[error("Plugin ABI version {plugin} does not match expected version {expected}")]
    AbiMismatch { plugin: String, expected: String },
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}
