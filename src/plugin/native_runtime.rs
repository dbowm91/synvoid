use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http::{Response, StatusCode};
use parking_lot::RwLock;

use crate::plugin::WasmPluginError;

const MAX_MEMORY_MB: usize = 64;
const MAX_CPU_TIME_MS: u64 = 5000;

#[derive(Clone)]
pub struct NativeResourceLimits {
    pub max_memory_mb: usize,
    pub max_cpu_time_ms: u64,
    pub timeout_seconds: u64,
    pub max_instances: usize,
}

impl Default for NativeResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: MAX_MEMORY_MB,
            max_cpu_time_ms: MAX_CPU_TIME_MS,
            timeout_seconds: 30,
            max_instances: 4,
        }
    }
}

pub struct NativeRuntime {
    library_path: String,
    limits: NativeResourceLimits,
    name: String,
}

impl NativeRuntime {
    pub fn load(path: &Path, limits: NativeResourceLimits) -> Result<Self, WasmPluginError> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        if !path.exists() {
            return Err(WasmPluginError::LoadFailed(format!(
                "native library not found: {}",
                path.display()
            )));
        }

        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        #[cfg(unix)]
        let valid_extensions = ["so", "dylib"];
        #[cfg(windows)]
        let valid_extensions = ["dll"];
        #[cfg(not(any(unix, windows)))]
        let valid_extensions: &[&str] = &[];

        if !valid_extensions.contains(&extension) {
            return Err(WasmPluginError::LoadFailed(format!(
                "unsupported native library extension '{}' (supported: {:?})",
                extension, valid_extensions
            )));
        }

        tracing::info!(
            "Loaded native serverless function '{}' from {} with limits: {}MB memory, {}ms CPU, {}s timeout",
            name,
            path.display(),
            limits.max_memory_mb,
            limits.max_cpu_time_ms,
            limits.timeout_seconds,
        );

        Ok(Self {
            library_path: path.to_string_lossy().into_owned(),
            limits,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn library_path(&self) -> &str {
        &self.library_path
    }

    pub fn limits(&self) -> &NativeResourceLimits {
        &self.limits
    }
}

pub struct NativePluginManager {
    runtimes: RwLock<Vec<Arc<NativeRuntime>>>,
    default_limits: NativeResourceLimits,
}

impl NativePluginManager {
    pub fn new() -> Self {
        Self {
            runtimes: RwLock::new(Vec::new()),
            default_limits: NativeResourceLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: NativeResourceLimits) -> Self {
        self.default_limits = limits;
        self
    }

    pub fn load_plugin(&self, path: &Path) -> Result<Arc<NativeRuntime>, WasmPluginError> {
        let runtime = NativeRuntime::load(path, self.default_limits.clone())?;
        let arc = Arc::new(runtime);
        self.runtimes.write().push(arc.clone());
        Ok(arc)
    }

    pub fn load_plugin_with_limits(
        &self,
        path: &Path,
        limits: NativeResourceLimits,
    ) -> Result<Arc<NativeRuntime>, WasmPluginError> {
        let runtime = NativeRuntime::load(path, limits)?;
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

    pub fn reload_plugin(&self, path: &Path) -> Result<Arc<NativeRuntime>, WasmPluginError> {
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

    pub fn get_runtime(&self, name: &str) -> Option<Arc<NativeRuntime>> {
        self.runtimes
            .read()
            .iter()
            .find(|r| r.name() == name)
            .cloned()
    }
}

impl Default for NativePluginManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NativeFunction {
    runtime: Arc<NativeRuntime>,
    initialized: bool,
}

impl NativeFunction {
    pub fn new(runtime: &Arc<NativeRuntime>) -> Result<Self, WasmPluginError> {
        Ok(Self {
            runtime: runtime.clone(),
            initialized: false,
        })
    }

    pub fn invoke(
        &mut self,
        method: &str,
        uri: &str,
        _headers: &str,
        _body: &[u8],
    ) -> Result<Response<Bytes>, WasmPluginError> {
        tracing::debug!(
            "Invoking native serverless '{}' - method: {}, uri: {}",
            self.runtime.name(),
            method,
            uri
        );

        let response_json = serde_json::json!({
            "status": 501,
            "error": "Native FFI runtime is experimental - full execution not yet implemented",
            "function": self.runtime.name()
        });

        let response = Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .header("content-type", "application/json")
            .header("x-experimental-runtime", "native-ffi")
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
        let limits = NativeResourceLimits::default();
        assert_eq!(limits.max_memory_mb, MAX_MEMORY_MB);
        assert_eq!(limits.max_cpu_time_ms, MAX_CPU_TIME_MS);
        assert_eq!(limits.timeout_seconds, 30);
        assert_eq!(limits.max_instances, 4);
    }

    #[test]
    fn test_native_plugin_manager_new() {
        let mgr = NativePluginManager::new();
        assert!(mgr.list_plugins().is_empty());
    }

    #[test]
    fn test_native_runtime_no_file() {
        let result = NativeRuntime::load(
            Path::new("/nonexistent/libplugin.so"),
            NativeResourceLimits::default(),
        );
        assert!(result.is_err());
    }
}
