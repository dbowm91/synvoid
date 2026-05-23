use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Response};
use parking_lot::RwLock;
use wasmtime::{Config, Engine, OptLevel};

use crate::plugin::wasm_runtime::WasmResourceLimits;
use crate::plugin::WasmRuntime;
use crate::spin::kv_store::SpinKvStore;
use crate::spin::manifest::Manifest;

#[derive(Debug, Clone)]
pub struct SpinRuntimeConfig {
    pub manifest_path: PathBuf,
    pub app_name: String,
    pub instance_id: String,
    pub max_instances: usize,
    pub default_timeout_seconds: u64,
    pub kv_store: Option<Arc<SpinKvStore>>,
    pub idle_timeout_seconds: u64,
}

impl Default for SpinRuntimeConfig {
    fn default() -> Self {
        Self {
            manifest_path: PathBuf::new(),
            app_name: String::new(),
            instance_id: uuid::Uuid::new_v4().to_string(),
            max_instances: 10,
            default_timeout_seconds: 30,
            kv_store: None,
            idle_timeout_seconds: 300,
        }
    }
}

pub struct SpinAppInstance {
    pub manifest: Manifest,
    pub wasm_runtime: Arc<WasmRuntime>,
    pub component_id: String,
    pub kv_store: Arc<SpinKvStore>,
    pub env: HashMap<String, String>,
    pub started_at: Instant,
    pub last_request: RwLock<Instant>,
    pub request_count: RwLock<u64>,
}

impl Clone for SpinAppInstance {
    fn clone(&self) -> Self {
        Self {
            manifest: self.manifest.clone(),
            wasm_runtime: self.wasm_runtime.clone(),
            component_id: self.component_id.clone(),
            kv_store: self.kv_store.clone(),
            env: self.env.clone(),
            started_at: self.started_at,
            last_request: RwLock::new(*self.last_request.read()),
            request_count: RwLock::new(*self.request_count.read()),
        }
    }
}

impl SpinAppInstance {
    pub fn new(
        manifest: Manifest,
        wasm_runtime: Arc<WasmRuntime>,
        component_id: String,
        kv_store: Arc<SpinKvStore>,
    ) -> Self {
        let env = Self::build_env(&manifest, &component_id);
        Self {
            manifest,
            wasm_runtime,
            component_id,
            kv_store,
            env,
            started_at: Instant::now(),
            last_request: RwLock::new(Instant::now()),
            request_count: RwLock::new(0),
        }
    }

    fn build_env(manifest: &Manifest, component_id: &str) -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("SPIN_APP_NAME".to_string(), manifest.name.clone());
        env.insert("SPIN_COMPONENT".to_string(), component_id.to_string());
        env.insert("SPIN_APP_VERSION".to_string(), manifest.version.clone());
        if let Some(component) = manifest.get_component(component_id) {
            for (key, value) in &component.env {
                env.insert(key.clone(), value.clone());
            }
        }
        env
    }

    pub fn record_request(&self) {
        *self.last_request.write() = Instant::now();
        *self.request_count.write() += 1;
    }

    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_request.read().elapsed() > idle_timeout
    }
}

pub struct SpinRuntime {
    pub config: SpinRuntimeConfig,
    manifest: RwLock<Option<Manifest>>,
    instances: RwLock<HashMap<String, SpinAppInstance>>,
    compiled_runtimes: RwLock<HashMap<String, Arc<WasmRuntime>>>,
    #[allow(dead_code)]
    engine: Engine,
}

impl SpinRuntime {
    pub fn new(config: SpinRuntimeConfig) -> Result<Self, SpinRuntimeError> {
        let manifest = if config.manifest_path.exists() {
            Some(Manifest::load(&config.manifest_path).map_err(SpinRuntimeError::ManifestError)?)
        } else {
            None
        };

        let mut wasm_config = Config::new();
        wasm_config
            .cranelift_opt_level(OptLevel::SpeedAndSize)
            .max_wasm_stack(1 << 20)
            .memory_init_cow(true)
            .consume_fuel(true);

        let engine = Engine::new(&wasm_config)
            .map_err(|e| SpinRuntimeError::WasmError(format!("failed to create engine: {}", e)))?;

        Ok(Self {
            config,
            manifest: RwLock::new(manifest),
            instances: RwLock::new(HashMap::new()),
            compiled_runtimes: RwLock::new(HashMap::new()),
            engine,
        })
    }

    pub fn load_manifest(&self, path: &Path) -> Result<(), SpinRuntimeError> {
        let manifest = Manifest::load(path).map_err(SpinRuntimeError::ManifestError)?;
        *self.manifest.write() = Some(manifest);
        Ok(())
    }

    pub fn get_manifest(&self) -> Option<Manifest> {
        self.manifest.read().clone()
    }

    pub fn instantiate_app(&self, component_id: &str) -> Result<SpinAppInstance, SpinRuntimeError> {
        let manifest = self
            .manifest
            .read()
            .clone()
            .ok_or(SpinRuntimeError::ManifestNotLoaded)?;

        let component = manifest
            .get_component(component_id)
            .ok_or_else(|| SpinRuntimeError::ComponentNotFound(component_id.to_string()))?;

        let wasm_path = component
            .source
            .as_ref()
            .ok_or_else(|| SpinRuntimeError::MissingModule(component_id.to_string()))?;

        let wasm_path = Path::new(wasm_path);
        if !wasm_path.exists() {
            return Err(SpinRuntimeError::ModuleNotFound(
                wasm_path.display().to_string(),
            ));
        }

        let wasm_runtime = {
            let cache = self.compiled_runtimes.read();
            if let Some(runtime) = cache.get(component_id) {
                runtime.clone()
            } else {
                drop(cache);
                let limits = WasmResourceLimits {
                    max_memory_mb: 64,
                    max_table_elements: None,
                    max_cpu_fuel: 1000000,
                    timeout_seconds: self.config.default_timeout_seconds,
                    max_instances: 1,
                    memory_budget_mb: None,
                    wasi_enabled: true,
                    allowed_dht_prefixes: Vec::new(),
                };

                let runtime = WasmRuntime::load_with_priority(wasm_path, limits, 0)
                    .map_err(|e| SpinRuntimeError::WasmError(e.to_string()))?;

                let runtime = Arc::new(runtime);
                self.compiled_runtimes
                    .write()
                    .insert(component_id.to_string(), runtime.clone());
                runtime
            }
        };

        let kv_store = self
            .config
            .kv_store
            .clone()
            .unwrap_or_else(|| Arc::new(SpinKvStore::new()));

        let instance =
            SpinAppInstance::new(manifest, wasm_runtime, component_id.to_string(), kv_store);

        let instance_id = uuid::Uuid::new_v4().to_string();
        self.instances.write().insert(instance_id, instance.clone());

        tracing::info!(
            "Instantiated Spin app '{}' component '{}'",
            self.config.app_name,
            component_id
        );

        Ok(instance)
    }

    pub fn get_instance(&self, instance_id: &str) -> Option<SpinAppInstance> {
        self.instances.read().get(instance_id).cloned()
    }

    pub fn list_instances(&self) -> Vec<String> {
        self.instances.read().keys().cloned().collect()
    }

    pub fn remove_instance(&self, instance_id: &str) -> bool {
        self.instances.write().remove(instance_id).is_some()
    }

    pub fn handle_http_request(
        &self,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        env: HashMap<String, String>,
    ) -> Result<Response<Bytes>, SpinRuntimeError> {
        let manifest = self
            .manifest
            .read()
            .clone()
            .ok_or(SpinRuntimeError::ManifestNotLoaded)?;

        let route = self.find_route(&manifest, path)?;

        let instance = self.instantiate_app(&route.0)?;

        instance.record_request();

        let headers_json = Self::serialize_headers_spin(headers);
        let body_vec = body.map(|b| b.to_vec()).unwrap_or_default();

        let mut full_env = instance.env.clone();
        full_env.extend(env);
        full_env.insert("HTTP_METHOD".to_string(), method.to_string());
        full_env.insert("HTTP_PATH".to_string(), path.to_string());
        full_env.insert(
            "SPIN_REQUEST_URI".to_string(),
            format!("{}://{}{}", "http", "localhost", path),
        );

        instance
            .wasm_runtime
            .invoke_handler(method, path, &headers_json, &body_vec, full_env)
            .map_err(|e| SpinRuntimeError::WasmError(e.to_string()))
    }

    fn find_route(
        &self,
        manifest: &Manifest,
        path: &str,
    ) -> Result<(String, String), SpinRuntimeError> {
        let mut matches = Vec::new();
        for component in &manifest.components {
            if let Some(ref route) = component.url {
                let normalized_route = route.trim_end_matches('/');
                if path == normalized_route || path.starts_with(&format!("{}/", normalized_route)) {
                    matches.push((component.id.clone(), route.clone(), normalized_route.len()));
                }
            }
        }
        matches
            .into_iter()
            .max_by_key(|m| m.2)
            .map(|(id, route, _)| (id, route))
            .ok_or_else(|| SpinRuntimeError::RouteNotFound(path.to_string()))
    }

    fn serialize_headers_spin(headers: &HeaderMap) -> String {
        let mut map = HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(val) = value.to_str() {
                map.insert(name.to_string(), val.to_string());
            }
        }
        serde_json::to_string(&map).unwrap_or_default()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SpinRuntimeError {
    #[error("Manifest error: {0}")]
    ManifestError(#[from] crate::spin::manifest::SpinManifestError),
    #[error("Manifest not loaded")]
    ManifestNotLoaded,
    #[error("Component not found: {0}")]
    ComponentNotFound(String),
    #[error("Module not found: {0}")]
    ModuleNotFound(String),
    #[error("Missing module for component: {0}")]
    MissingModule(String),
    #[error("Route not found: {0}")]
    RouteNotFound(String),
    #[error("WASM error: {0}")]
    WasmError(String),
    #[error("KV store error: {0}")]
    KvStoreError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spin_runtime_config_default() {
        let config = SpinRuntimeConfig::default();
        assert_eq!(config.max_instances, 10);
        assert_eq!(config.default_timeout_seconds, 30);
    }

    #[test]
    fn test_serialize_headers_spin() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let json = SpinRuntime::serialize_headers_spin(&headers);
        let parsed: HashMap<String, String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.get("host"), Some(&"localhost".to_string()));
    }
}
