use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use parking_lot::RwLock;
use thiserror::Error;

use crate::config::serverless::{FunctionDefinition, ServerlessConfig};
use crate::plugin::{WasmPluginManager, WasmResourceLimits};

#[derive(Error, Debug)]
pub enum ServerlessError {
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    #[error("WASM runtime error: {0}")]
    WasmError(String),
    #[error("Function execution error: {0}")]
    ExecutionError(String),
    #[error("No serverless configuration")]
    NoConfig,
    #[error("Function disabled")]
    Disabled,
}

#[derive(Clone)]
pub struct ServerlessFunction {
    pub definition: FunctionDefinition,
    pub runtime: Option<Arc<crate::plugin::wasm_runtime::WasmRuntime>>,
}

pub struct ServerlessManager {
    functions: RwLock<HashMap<String, ServerlessFunction>>,
    config: RwLock<Option<ServerlessConfig>>,
    runtime: Arc<WasmPluginManager>,
}

impl ServerlessManager {
    pub fn new() -> Self {
        Self {
            functions: RwLock::new(HashMap::new()),
            config: RwLock::new(None),
            runtime: Arc::new(WasmPluginManager::new()),
        }
    }

    pub fn with_runtime(mut self, runtime: Arc<WasmPluginManager>) -> Self {
        self.runtime = runtime;
        self
    }

    pub fn initialize(&self, config: ServerlessConfig) -> Result<(), ServerlessError> {
        if !config.enabled {
            return Err(ServerlessError::Disabled);
        }

        *self.config.write() = Some(config.clone());

        for func_def in &config.functions {
            let runtime = if config.enabled {
                self.load_function_wasm(func_def).ok()
            } else {
                None
            };

            let function = ServerlessFunction {
                definition: func_def.clone(),
                runtime,
            };

            self.functions
                .write()
                .insert(func_def.name.clone(), function);
        }

        Ok(())
    }

    fn load_function_wasm(
        &self,
        func_def: &FunctionDefinition,
    ) -> Result<Arc<crate::plugin::wasm_runtime::WasmRuntime>, ServerlessError> {
        let wasm_dir = std::path::PathBuf::from("plugins");
        let wasm_path = wasm_dir.join(&func_def.name).with_extension("wasm");

        if !wasm_path.exists() {
            return Err(ServerlessError::FunctionNotFound(format!(
                "WASM file not found: {}",
                wasm_path.display()
            )));
        }

        let _limits = WasmResourceLimits {
            max_memory_mb: func_def.memory_mb.unwrap_or(64),
            max_cpu_fuel: func_def.cpu_fuel.unwrap_or(1000000),
            timeout_seconds: func_def.timeout_seconds.unwrap_or(30),
            max_instances: 1,
        };

        self.runtime
            .load_plugin(&wasm_path)
            .map_err(|e| ServerlessError::WasmError(e.to_string()))
    }

    pub fn get_function(&self, name: &str) -> Option<ServerlessFunction> {
        self.functions.read().get(name).cloned()
    }

    pub fn has_function(&self, name: &str) -> bool {
        self.functions.read().contains_key(name)
    }

    pub fn find_matching_function(&self, path: &str) -> Option<ServerlessFunction> {
        let config = self.config.read();
        if let Some(ref cfg) = *config {
            for func in &cfg.functions {
                if path == func.path || path.starts_with(&format!("{}/", func.path)) {
                    return self.functions.read().get(&func.name).cloned();
                }
            }
        }
        None
    }

    pub fn is_enabled(&self) -> bool {
        self.config
            .read()
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
    }
}

impl Default for ServerlessManager {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn handle_serverless_function(
    manager: &ServerlessManager,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
) -> Result<Response<Bytes>, ServerlessError> {
    let function = manager
        .find_matching_function(path)
        .ok_or_else(|| ServerlessError::FunctionNotFound(path.to_string()))?;

    let Some(runtime) = function.runtime else {
        return Err(ServerlessError::WasmError(
            "No WASM runtime available".to_string(),
        ));
    };

    let uri = path.to_string();
    let method_str = method.to_string();

    let headers_map: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let headers_json = serde_json::to_string(&headers_map)
        .map_err(|e| ServerlessError::ExecutionError(e.to_string()))?;

    let body_vec = body.map(|b| b.to_vec()).unwrap_or_default();

    runtime
        .invoke_handler(&method_str, &uri, &headers_json, &body_vec)
        .map_err(|e| ServerlessError::ExecutionError(e.to_string()))
}
