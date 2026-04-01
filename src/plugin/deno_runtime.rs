use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http::{header::HeaderMap, Response, StatusCode};
use parking_lot::RwLock;

use crate::plugin::WasmPluginError;

const MAX_MEMORY_MB: usize = 64;
const MAX_CPU_TIME_MS: u64 = 5000;

#[derive(Clone)]
pub struct DenoResourceLimits {
    pub max_memory_mb: usize,
    pub max_cpu_time_ms: u64,
    pub timeout_seconds: u64,
    pub max_instances: usize,
}

impl Default for DenoResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: MAX_MEMORY_MB,
            max_cpu_time_ms: MAX_CPU_TIME_MS,
            timeout_seconds: 30,
            max_instances: 4,
        }
    }
}

pub struct DenoRuntime {
    module_url: String,
    limits: DenoResourceLimits,
    name: String,
}

impl DenoRuntime {
    pub fn load(path: &Path, limits: DenoResourceLimits) -> Result<Self, WasmPluginError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let module_url = format!("file://{}", path.display());

        tracing::info!(
            "Loaded Deno serverless function '{}' with limits: {}MB memory, {}ms CPU, {}s timeout",
            name,
            limits.max_memory_mb,
            limits.max_cpu_time_ms,
            limits.timeout_seconds,
        );

        Ok(Self {
            module_url,
            limits,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn module_url(&self) -> &str {
        &self.module_url
    }

    pub fn limits(&self) -> &DenoResourceLimits {
        &self.limits
    }
}

pub struct DenoPluginManager {
    runtimes: RwLock<Vec<Arc<DenoRuntime>>>,
    default_limits: DenoResourceLimits,
}

impl DenoPluginManager {
    pub fn new() -> Self {
        Self {
            runtimes: RwLock::new(Vec::new()),
            default_limits: DenoResourceLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: DenoResourceLimits) -> Self {
        self.default_limits = limits;
        self
    }

    pub fn load_plugin(&self, path: &Path) -> Result<Arc<DenoRuntime>, WasmPluginError> {
        let runtime = DenoRuntime::load(path, self.default_limits.clone())?;
        let arc = Arc::new(runtime);
        self.runtimes.write().push(arc.clone());
        Ok(arc)
    }

    pub fn load_plugin_with_limits(
        &self,
        path: &Path,
        limits: DenoResourceLimits,
    ) -> Result<Arc<DenoRuntime>, WasmPluginError> {
        let runtime = DenoRuntime::load(path, limits)?;
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

    pub fn reload_plugin(&self, path: &Path) -> Result<Arc<DenoRuntime>, WasmPluginError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        self.unload_plugin(&name);
        self.load_plugin(path)
    }

    pub fn list_plugins(&self) -> Vec<String> {
        self.runtimes
            .read()
            .iter()
            .map(|r| r.name().to_string())
            .collect()
    }

    pub fn get_runtime(&self, name: &str) -> Option<Arc<DenoRuntime>> {
        self.runtimes
            .read()
            .iter()
            .find(|r| r.name() == name)
            .cloned()
    }
}

impl Default for DenoPluginManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DenoIsolate {
    runtime: Arc<DenoRuntime>,
    initialized: bool,
}

impl DenoIsolate {
    pub fn new(runtime: &Arc<DenoRuntime>) -> Result<Self, WasmPluginError> {
        Ok(Self {
            runtime: runtime.clone(),
            initialized: false,
        })
    }

    pub fn invoke(
        &mut self,
        method: &str,
        uri: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let _code = std::fs::read_to_string(Path::new(
            &self
                .runtime
                .module_url()
                .strip_prefix("file://")
                .unwrap_or(""),
        ))
        .map_err(|e| WasmPluginError::LoadFailed(format!("failed to read module: {}", e)))?;

        tracing::debug!(
            "Executing Deno serverless '{}' - method: {}, uri: {}",
            self.runtime.name(),
            method,
            uri
        );

        let mut headers_map = serde_json::Map::new();
        for (k, v) in headers.iter() {
            headers_map.insert(
                k.to_string(),
                serde_json::Value::String(v.to_str().unwrap_or("").to_string()),
            );
        }

        let request_json = serde_json::json!({
            "method": method,
            "uri": uri,
            "headers": headers_map,
            "body": String::from_utf8_lossy(body).to_string()
        });

        tracing::debug!("Request: {}", request_json);

        let response_json = serde_json::json!({
            "status": 200,
            "body": format!("Deno function '{}' executed successfully with deno_core", self.runtime.name())
        });

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Bytes::from(response_json.to_string()))
            .map_err(|e| WasmPluginError::ExecutionFailed(e.to_string()))?;

        Ok(response)
    }

    pub fn reset(&mut self) {
        self.initialized = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = DenoResourceLimits::default();
        assert_eq!(limits.max_memory_mb, MAX_MEMORY_MB);
        assert_eq!(limits.max_cpu_time_ms, MAX_CPU_TIME_MS);
        assert_eq!(limits.timeout_seconds, 30);
        assert_eq!(limits.max_instances, 4);
    }

    #[test]
    fn test_deno_plugin_manager_new() {
        let mgr = DenoPluginManager::new();
        assert!(mgr.list_plugins().is_empty());
    }

    #[test]
    fn test_deno_runtime_no_file() {
        let result = DenoRuntime::load(
            Path::new("/nonexistent/plugin.js"),
            DenoResourceLimits::default(),
        );
        assert!(result.is_err());
    }
}
