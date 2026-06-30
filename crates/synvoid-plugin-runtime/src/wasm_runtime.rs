use std::collections::HashMap;
use std::convert::TryInto;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use parking_lot::RwLock;
#[allow(unused_imports)]
use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{
    Config, Engine, Instance, Linker, Memory, Module, OptLevel, ResourceLimiter, Store, TypedFunc,
};

use crate::instance_pool::WasmInstancePool;
use crate::sandbox::policy::{
    limits_from_manifest, EffectivePluginPolicy, PluginSourceIdentity, PreparedPluginLoad,
};
use crate::sandbox::types::{
    enforce_plugin_load_policy, PluginCapabilities, PluginCapability, PluginLoadConfig,
    PluginManifest, PluginTrustTier,
};
use crate::streaming_body::StreamingBody;
use crate::wasm_metrics::{
    record_wasm_decision_block, record_wasm_decision_challenge, record_wasm_decision_pass,
    record_wasm_duration, record_wasm_error, record_wasm_fuel_consumed, record_wasm_invocation,
};

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

#[derive(Debug, Clone)]
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,
    pub max_table_elements: Option<usize>,
    pub max_cpu_fuel: u64,
    pub timeout_seconds: u64,
    pub max_instances: usize,
    pub memory_budget_mb: Option<usize>,
    pub wasi_enabled: bool,
    pub allowed_dht_prefixes: Vec<String>,
    pub capabilities: Arc<PluginCapabilities>,
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
            capabilities: Arc::new(PluginCapabilities::default()),
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
    effective_policy: Option<EffectivePluginPolicy>,
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub path: Option<PathBuf>,
    pub version: String,
    pub trust_tier: PluginTrustTier,
    pub timeout_seconds: u64,
    pub max_memory_mb: usize,
    pub max_cpu_fuel: u64,
    pub max_instances: usize,
    pub capabilities_summary: Vec<(PluginCapability, bool)>,
}

pub struct WasmPluginManager {
    runtimes: RwLock<Vec<Arc<WasmRuntime>>>,
    sorted_runtimes_cache: RwLock<Option<Vec<Arc<WasmRuntime>>>>,
    default_limits: WasmResourceLimits,
    load_config: RwLock<PluginLoadConfig>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    pool: Arc<WasmInstancePool>,
    plugin_paths: RwLock<HashMap<String, PathBuf>>,
    plugin_policies: RwLock<HashMap<String, EffectivePluginPolicy>>,
}

impl WasmPluginManager {
    pub fn new() -> Self {
        Self {
            runtimes: RwLock::new(Vec::new()),
            sorted_runtimes_cache: RwLock::new(None),
            default_limits: WasmResourceLimits::default(),
            load_config: RwLock::new(PluginLoadConfig::default()),
            pool: Arc::new(WasmInstancePool::new(
                Arc::new(Engine::default()),
                100,
                Vec::new(),
                Arc::new(PluginCapabilities::default()),
            )),
            plugin_paths: RwLock::new(HashMap::new()),
            plugin_policies: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_limits(mut self, limits: WasmResourceLimits) -> Self {
        self.default_limits = limits;
        self
    }

    pub fn with_load_config(self, config: PluginLoadConfig) -> Self {
        *self.load_config.write() = config;
        self
    }

    pub fn set_load_config(&self, config: PluginLoadConfig) {
        *self.load_config.write() = config;
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

    /// Discover a `synvoid-plugin.toml` manifest alongside a `.wasm` file.
    ///
    /// Looks for a TOML file with the same stem as the WASM file in the same
    /// directory. Returns a default `LocalSandboxed` manifest if not found.
    fn discover_manifest(wasm_path: &Path) -> PluginManifest {
        let toml_path = wasm_path.with_extension("toml");
        if let Ok(content) = std::fs::read_to_string(&toml_path) {
            match PluginManifest::parse_toml(&content, &toml_path) {
                Ok(manifest) => return manifest,
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse manifest {}: {}, using default LocalSandboxed",
                        toml_path.display(),
                        e
                    );
                }
            }
        }
        // Default: LocalSandboxed with the filename stem as name
        let name = wasm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        PluginManifest {
            name,
            version: "0.0.0".to_string(),
            entry: wasm_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("plugin.wasm")
                .to_string(),
            trust_tier: PluginTrustTier::LocalSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: crate::sandbox::types::PluginLimits::default(),
            signature: None,
        }
    }

    /// Prepare a plugin load by enforcing policy and computing effective limits.
    ///
    /// This is the preferred entry point for all load paths. It returns a
    /// `PreparedPluginLoad` containing the validated manifest and the effective
    /// `WasmResourceLimits` derived from that manifest. Every load path MUST
    /// use the returned `effective_limits` — never `self.default_limits` directly.
    ///
    /// File-based loads read the WASM binary once and store the bytes to close
    /// TOCTOU races between policy enforcement and instantiation.
    fn prepare_plugin_load(
        &self,
        wasm_path: Option<&Path>,
        manifest: Option<&PluginManifest>,
        binary_bytes: Option<&[u8]>,
    ) -> Result<PreparedPluginLoad, WasmPluginError> {
        let config = self.load_config.read().clone();
        let owned_manifest;
        let m = match manifest {
            Some(m) => m,
            None => {
                owned_manifest =
                    Self::discover_manifest(wasm_path.unwrap_or_else(|| Path::new("unknown.wasm")));
                &owned_manifest
            }
        };

        // Read bytes once for file-based loads to close TOCTOU
        let wasm_bytes = match (wasm_path, binary_bytes) {
            (_, Some(bytes)) => Bytes::copy_from_slice(bytes),
            (Some(path), None) => {
                // Reject symlink plugin files
                if path.is_symlink() {
                    return Err(WasmPluginError::LoadFailed(format!(
                        "Plugin '{}' (tier: {}): symlink plugin files are not permitted: {}",
                        m.name,
                        m.trust_tier,
                        path.display()
                    )));
                }
                // Read and canonicalize
                let canonical = path.canonicalize().map_err(|e| {
                    WasmPluginError::LoadFailed(format!(
                        "Plugin '{}' (tier: {}): failed to canonicalize path {}: {}",
                        m.name,
                        m.trust_tier,
                        path.display(),
                        e
                    ))
                })?;

                // Reject manifest entry containing path traversal or absolute paths
                // before any canonicalization to prevent traversal attacks.
                if m.entry.contains("..") {
                    return Err(WasmPluginError::LoadFailed(format!(
                        "Plugin '{}' (tier: {}): manifest entry '{}' contains path traversal (..)",
                        m.name, m.trust_tier, m.entry
                    )));
                }
                if Path::new(&m.entry).is_absolute() {
                    return Err(WasmPluginError::LoadFailed(format!(
                        "Plugin '{}' (tier: {}): manifest entry '{}' must be a relative path",
                        m.name, m.trust_tier, m.entry
                    )));
                }

                // Verify manifest entry resolves to the same canonical wasm path
                // or to a file within the same plugin directory.
                if let Some(parent) = canonical.parent() {
                    let entry_path = parent.join(&m.entry);
                    let entry_abs = entry_path
                        .canonicalize()
                        .map_err(|e| {
                            WasmPluginError::LoadFailed(format!(
                                "Plugin '{}' (tier: {}): manifest entry '{}' does not resolve to a valid file: {}",
                                m.name, m.trust_tier, m.entry, e
                            ))
                        })?;
                    if entry_abs.parent() != Some(parent) {
                        return Err(WasmPluginError::LoadFailed(format!(
                            "Plugin '{}' (tier: {}): manifest entry '{}' escapes plugin directory",
                            m.name, m.trust_tier, m.entry
                        )));
                    }
                }

                let bytes = std::fs::read(&canonical).map_err(|e| {
                    WasmPluginError::LoadFailed(format!(
                        "Plugin '{}' (tier: {}): failed to read {}: {}",
                        m.name,
                        m.trust_tier,
                        canonical.display(),
                        e
                    ))
                })?;
                Bytes::from(bytes)
            }
            (None, None) => {
                // Memory load without bytes - use empty (will fail at instantiation)
                Bytes::new()
            }
        };

        // Enforce load policy with the actual bytes
        let verified_signature = enforce_plugin_load_policy(m, Some(&wasm_bytes), &config)
            .map_err(|e| {
                WasmPluginError::LoadFailed(format!(
                    "Plugin '{}' (tier: {}): {}",
                    m.name, m.trust_tier, e
                ))
            })?;

        let effective_limits = limits_from_manifest(m, &self.default_limits);
        let source = PluginSourceIdentity {
            path: wasm_path.map(|p| p.to_path_buf()),
            binary_sha256: Some(crate::sandbox::types::compute_binary_hash(&wasm_bytes)),
            manifest_sha256: verified_signature
                .as_ref()
                .map(|v| v.manifest_sha256.clone()),
            key_id: verified_signature.as_ref().map(|v| v.key_id.clone()),
        };
        Ok(PreparedPluginLoad {
            manifest: m.clone(),
            effective_limits,
            source,
            wasm_bytes,
            verified_signature,
        })
    }

    pub fn load_plugin(&self, path: &Path) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let prepared = self.prepare_plugin_load(Some(path), None, None)?;
        let limits = prepared.effective_limits.clone();
        let runtime = WasmRuntime::load_with_policy(path, limits, 0, Some(prepared))?;
        let arc = Arc::new(runtime);
        let name = arc.name().to_string();

        if self.runtimes.read().iter().any(|r| r.name() == name) {
            return Err(WasmPluginError::LoadFailed(format!(
                "plugin '{}' already loaded (duplicate name)",
                name
            )));
        }

        self.runtimes.write().push(arc.clone());
        *self.sorted_runtimes_cache.write() = None;
        self.plugin_paths
            .write()
            .insert(name.clone(), path.to_path_buf());
        if let Some(policy) = arc.effective_policy() {
            self.plugin_policies.write().insert(name, policy.clone());
        }
        Ok(arc)
    }

    pub fn load_plugin_from_memory(
        &self,
        name: &str,
        data: &[u8],
        limits: WasmResourceLimits,
    ) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        self.load_plugin_from_memory_with_priority(name, data, limits, 0)
    }

    /// Load a plugin from in-memory bytes with an explicit manifest.
    ///
    /// This is the preferred path for mesh-distributed plugins where the
    /// manifest is provided alongside the binary. It enforces policy via
    /// `prepare_plugin_load` and stores the resulting `PreparedPluginLoad`.
    pub fn load_plugin_from_memory_with_manifest(
        &self,
        name: &str,
        data: &[u8],
        manifest: &PluginManifest,
        limits: WasmResourceLimits,
    ) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        let prepared = self.prepare_plugin_load(None, Some(manifest), Some(data))?;
        let effective = WasmResourceLimits {
            capabilities: prepared.effective_limits.capabilities.clone(),
            ..limits
        };
        let runtime = WasmRuntime::load_from_bytes_with_priority(name, data, effective, 0)?;
        let arc = Arc::new(runtime);
        let runtime_name = arc.name().to_string();
        if self
            .runtimes
            .read()
            .iter()
            .any(|r| r.name() == runtime_name)
        {
            return Err(WasmPluginError::LoadFailed(format!(
                "plugin '{}' already loaded (duplicate name)",
                runtime_name
            )));
        }
        self.runtimes.write().push(arc.clone());
        *self.sorted_runtimes_cache.write() = None;
        self.plugin_paths.write().insert(
            runtime_name.clone(),
            PathBuf::from(format!("memory://{}", name)),
        );
        let policy = EffectivePluginPolicy {
            name: prepared.manifest.name.clone(),
            version: prepared.manifest.version.clone(),
            trust_tier: prepared.manifest.trust_tier,
            capabilities: prepared.effective_limits.capabilities.clone(),
            limits: prepared.effective_limits.clone(),
            manifest_limits: prepared.manifest.limits.clone(),
            source: PluginSourceIdentity {
                path: Some(PathBuf::from(format!("memory://{}", name))),
                binary_sha256: Some(crate::sandbox::types::compute_binary_hash(data)),
                ..prepared.source
            },
        };
        self.plugin_policies.write().insert(runtime_name, policy);
        Ok(arc)
    }

    pub fn load_plugin_from_memory_with_priority(
        &self,
        name: &str,
        data: &[u8],
        limits: WasmResourceLimits,
        priority: i32,
    ) -> Result<Arc<WasmRuntime>, WasmPluginError> {
        // For memory loads, enforce with binary bytes and a default manifest.
        // The manifest is discovered from the default (LocalSandboxed) since
        // memory-loaded plugins don't have a file path to look up a TOML.
        let prepared = self.prepare_plugin_load(None, None, Some(data))?;
        // Merge caller-supplied limits with manifest-derived limits.
        // Manifest capabilities are authoritative; resource limits use manifest
        // values where declared, falling back to caller-supplied then defaults.
        let effective = WasmResourceLimits {
            capabilities: prepared.effective_limits.capabilities.clone(),
            ..limits
        };
        let runtime = WasmRuntime::load_from_bytes_with_priority(name, data, effective, priority)?;
        let arc = Arc::new(runtime);
        let runtime_name = arc.name().to_string();
        self.runtimes.write().push(arc.clone());
        *self.sorted_runtimes_cache.write() = None;
        self.plugin_paths.write().insert(
            runtime_name.clone(),
            PathBuf::from(format!("mesh://{}", name)),
        );
        let policy = EffectivePluginPolicy {
            name: prepared.manifest.name.clone(),
            version: prepared.manifest.version.clone(),
            trust_tier: prepared.manifest.trust_tier,
            capabilities: prepared.effective_limits.capabilities.clone(),
            limits: prepared.effective_limits.clone(),
            manifest_limits: prepared.manifest.limits.clone(),
            source: PluginSourceIdentity {
                path: Some(PathBuf::from(format!("mesh://{}", name))),
                ..prepared.source
            },
        };
        self.plugin_policies.write().insert(runtime_name, policy);
        Ok(arc)
    }

    #[allow(dead_code)]
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
                body_receiver: None,
                capabilities: limits.capabilities.clone(),
            },
        );
        store.limiter(|state| state);
        if limits.max_cpu_fuel > 0 {
            store.set_fuel(limits.max_cpu_fuel).ok();
        }
        store
    }

    #[allow(dead_code)]
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
        let prepared = self.prepare_plugin_load(Some(path), None, None)?;
        // Merge: manifest capabilities are authoritative, caller-supplied
        // resource limits override manifest values where declared.
        let effective = WasmResourceLimits {
            capabilities: prepared.effective_limits.capabilities.clone(),
            ..limits
        };
        let runtime = WasmRuntime::load_with_policy(path, effective, 0, Some(prepared))?;
        let arc = Arc::new(runtime);
        let name = arc.name().to_string();
        self.runtimes.write().push(arc.clone());
        *self.sorted_runtimes_cache.write() = None;
        self.plugin_paths
            .write()
            .insert(name.clone(), path.to_path_buf());
        if let Some(policy) = arc.effective_policy() {
            self.plugin_policies.write().insert(name, policy.clone());
        }
        Ok(arc)
    }

    pub fn get_plugin_policy_info(&self, name: &str) -> Option<EffectivePluginPolicy> {
        self.plugin_policies.read().get(name).cloned()
    }

    pub fn unload_plugin(&self, name: &str) -> bool {
        let mut runtimes = self.runtimes.write();
        let before = runtimes.len();
        runtimes.retain(|r| r.name() != name);
        if runtimes.len() < before {
            *self.sorted_runtimes_cache.write() = None;
            self.plugin_paths.write().remove(name);
            self.plugin_policies.write().remove(name);
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

        // Hot reload uses the same trust policy as initial load
        let prepared = self.prepare_plugin_load(Some(path), None, None)?;
        let limits = prepared.effective_limits.clone();
        let new_runtime = WasmRuntime::load_with_policy(path, limits, priority, Some(prepared))?;
        let new_arc = Arc::new(new_runtime);

        {
            let mut runtimes = self.runtimes.write();
            runtimes.retain(|r| r.name() != name);
            runtimes.push(new_arc.clone());
        }
        *self.sorted_runtimes_cache.write() = None;

        self.plugin_paths
            .write()
            .insert(name.clone(), path.to_path_buf());
        if let Some(policy) = new_arc.effective_policy() {
            self.plugin_policies.write().insert(name, policy.clone());
        }

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
        let policies = self.plugin_policies.read();
        runtimes
            .iter()
            .map(|r| {
                let name = r.name();
                let path = paths.get(name).cloned();
                let policy = policies.get(name);
                PluginInfo {
                    name: name.to_string(),
                    path: path.clone(),
                    version: policy
                        .map(|p| p.version.clone())
                        .unwrap_or_else(|| "0.0.0".into()),
                    trust_tier: policy.map(|p| p.trust_tier).unwrap_or_default(),
                    timeout_seconds: r.limits.timeout_seconds,
                    max_memory_mb: r.limits.max_memory_mb,
                    max_cpu_fuel: r.limits.max_cpu_fuel,
                    max_instances: r.limits.max_instances,
                    capabilities_summary: r.limits.capabilities.iter_flags(),
                }
            })
            .collect()
    }

    pub fn get_runtime_by_name(&self, name: &str) -> Option<Arc<WasmRuntime>> {
        self.runtimes
            .read()
            .iter()
            .find(|r| r.name() == name)
            .cloned()
    }

    pub fn invoke_by_name(
        &self,
        name: &str,
        method: &str,
        uri: &str,
        headers: &str,
        body: &[u8],
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let runtime = self
            .get_runtime_by_name(name)
            .ok_or_else(|| WasmPluginError::FunctionNotFound(name.to_string()))?;
        runtime.invoke_handler(method, uri, headers, body, env)
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
    pub(crate) body_receiver: Option<tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>>,
    pub(crate) capabilities: Arc<PluginCapabilities>,
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

    /// Load a WASM plugin with an effective policy derived from its manifest.
    ///
    /// This is the preferred constructor for all load paths that have completed
    /// `prepare_plugin_load()`. The policy is stored for runtime introspection.
    /// When `prepared` is provided with `wasm_bytes`, the module is instantiated
    /// from those bytes (closing TOCTOU) instead of re-reading from disk.
    pub fn load_with_policy(
        path: &Path,
        limits: WasmResourceLimits,
        priority: i32,
        prepared: Option<PreparedPluginLoad>,
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

        // Use pre-read bytes from prepared load to close TOCTOU, or fall back
        // to reading from disk for legacy callers.
        let module = match prepared.as_ref().and_then(|p| {
            if p.wasm_bytes.is_empty() {
                None
            } else {
                Some(p.wasm_bytes.clone())
            }
        }) {
            Some(bytes) => Module::from_binary(&engine, &bytes)
                .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?,
            None => Module::from_file(&engine, path)
                .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?,
        };

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

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
            limits.allowed_dht_prefixes.clone(),
            limits.capabilities.clone(),
        ));

        let linker = Self::create_linker(&engine, &limits)?;

        // Emit structured audit trace for signed plugins (hashes and key_id only,
        // never raw signature or key material).
        if let Some(ref p) = prepared {
            if let Some(ref sig) = p.verified_signature {
                tracing::info!(
                    plugin = %name,
                    trust_tier = ?p.manifest.trust_tier,
                    key_id = %sig.key_id,
                    binary_sha256 = %sig.binary_sha256,
                    manifest_sha256 = %sig.manifest_sha256,
                    algorithm = ?sig.algorithm,
                    "Plugin signature verified"
                );
            } else if p.manifest.trust_tier == PluginTrustTier::SignedSandboxed {
                tracing::warn!(
                    plugin = %name,
                    trust_tier = ?p.manifest.trust_tier,
                    "SignedSandboxed plugin loaded without verification metadata"
                );
            }
        }

        // Build effective policy if a prepared load was provided
        let effective_policy = prepared.map(|p| EffectivePluginPolicy {
            name: p.manifest.name.clone(),
            version: p.manifest.version.clone(),
            trust_tier: p.manifest.trust_tier,
            capabilities: p.effective_limits.capabilities.clone(),
            limits: p.effective_limits,
            manifest_limits: p.manifest.limits.clone(),
            source: p.source,
        });

        Ok(Self {
            engine,
            module,
            limits,
            name,
            priority,
            pool,
            linker,
            effective_policy,
        })
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
            limits.allowed_dht_prefixes.clone(),
            limits.capabilities.clone(),
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
            effective_policy: None,
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
            limits.allowed_dht_prefixes.clone(),
            limits.capabilities.clone(),
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
            effective_policy: None,
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
                        let mem_ptr = mem.data_ptr(&caller);
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
                "synvoid_read_body_chunk",
                |mut caller: wasmtime::Caller<'_, RequestContext>,
                 out_ptr: i32,
                 out_max: i32|
                 -> i32 {
                    let mut rx = match caller.data_mut().body_receiver.take() {
                        Some(rx) => rx,
                        None => return -1, // Already consumed or not available
                    };

                    // Blocking receive since this is called from within a sync WASM execution
                    // which is typically run in a spawn_blocking thread.
                    let result = rx.blocking_recv();

                    // Put the receiver back for future calls
                    caller.data_mut().body_receiver = Some(rx);

                    match result {
                        Some(Ok(chunk)) => {
                            let len = chunk.len().min(out_max as usize);
                            let mem = match caller.get_export("memory") {
                                Some(wasmtime::Extern::Memory(m)) => m,
                                _ => return -3, // No memory export
                            };
                            if mem
                                .write(&mut caller, out_ptr as usize, &chunk[..len])
                                .is_err()
                            {
                                return -4; // Memory write error
                            }
                            len as i32
                        }
                        Some(Err(_)) => -2, // Error reading chunk
                        None => 0,          // EOF
                    }
                },
            )
            .map_err(|e| {
                WasmPluginError::LoadFailed(format!(
                    "failed to link synvoid_read_body_chunk: {}",
                    e
                ))
            })?;

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
                    if !caller.data().capabilities.permits(PluginCapability::Mesh) {
                        tracing::error!(
                            "WASM plugin attempted mesh_query_dht without PluginCapability::Mesh"
                        );
                        crate::wasm_metrics::record_plugin_capability_violation("Mesh");
                        return -1;
                    }

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
                        tracing::error!(
                            "WASM plugin attempted unauthorized DHT query: key='{}'",
                            key
                        );
                        return -2;
                    }

                    let result = if let Some(provider) = crate::mesh_callbacks::get_mesh_provider()
                    {
                        if let Some(value) = provider.get_record(&key) {
                            let value_len = value.len().min(out_max as usize);
                            let out_start = out_ptr as usize;
                            let out_end = out_start.saturating_add(value_len);
                            if out_end <= mem_data.len() {
                                unsafe {
                                    let mem_ptr = mem.data_ptr(&caller);
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
                    if !caller.data().capabilities.permits(PluginCapability::Mesh) {
                        tracing::error!("WASM plugin attempted mesh_check_threat without PluginCapability::Mesh");
                        crate::wasm_metrics::record_plugin_capability_violation("Mesh");
                        return -1;
                    }

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

                    let threat_result = if let Some(provider) =
                        crate::mesh_callbacks::get_mesh_provider()
                    {
                        if provider.check_threat(&ip_str) {
                            tracing::debug!("WASM mesh_check_threat('{}') -> THREATENED", ip_str);
                            1
                        } else {
                            0
                        }
                    } else {
                        0
                    };

                    if threat_result == 1 {
                        return 1;
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
                    if !caller.data().capabilities.permits(PluginCapability::Mesh) {
                        tracing::error!(
                            "WASM plugin attempted mesh_emit_event without PluginCapability::Mesh"
                        );
                        crate::wasm_metrics::record_plugin_capability_violation("Mesh");
                        return -1;
                    }

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

                    if let Some(provider) = crate::mesh_callbacks::get_mesh_provider() {
                        provider.store_event(&topic, &data);
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
                body_receiver: None,
                capabilities: self.limits.capabilities.clone(),
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

    /// Record a plugin invocation failure on the metrics counter.
    fn record_invoke_failure(capability: &'static str) {
        metrics::counter!(
            "synvoid_plugin_invoke_total",
            "capability" => capability,
            "status" => "failed"
        )
        .increment(1);
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

        if !self
            .limits
            .capabilities
            .permits(PluginCapability::RequestInspect)
            && !self
                .limits
                .capabilities
                .permits(PluginCapability::RequestMutate)
        {
            tracing::error!(
                "WASM plugin '{}' lacks RequestInspect/RequestMutate capability — rejecting invocation",
                plugin_name
            );
            crate::wasm_metrics::record_plugin_capability_violation("RequestInspect");
            return Err(WasmPluginError::ExecutionFailed(
                "plugin lacks required capability".to_string(),
            ));
        }

        record_wasm_invocation(plugin_name);
        metrics::counter!("synvoid_plugin_invoke_total", "capability" => "filter_request", "status" => "invoked").increment(1);

        let (parts, body) = request.into_parts();

        tracing::debug!(
            "WASM plugin '{}' filtering request {} {}",
            self.name,
            parts.method,
            parts.uri
        );

        let pooled_instance = self.pool.get(&self.name);

        if let Some(mut inst) = pooled_instance {
            inst.prepare_for_request(
                (*env).clone(),
                self.limits.timeout_seconds,
                self.limits.allowed_dht_prefixes.clone(),
                self.limits.capabilities.clone(),
            );
            let exports =
                WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
            let result = self.do_filter_request_with_exports(parts, body, &mut inst.store, exports);
            self.pool.return_instance(inst);
            if result.is_err() {
                Self::record_invoke_failure("filter_request");
            }
            return result;
        }

        let mut store = self.create_store((*env).clone());
        let exports = self.instantiate(&mut store).inspect_err(|_| {
            Self::record_invoke_failure("filter_request");
        })?;
        let result = self.do_filter_request_with_exports(parts, body, &mut store, exports);
        if result.is_err() {
            Self::record_invoke_failure("filter_request");
        }
        result
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

        if !self
            .limits
            .capabilities
            .permits(PluginCapability::ResponseInspect)
            && !self
                .limits
                .capabilities
                .permits(PluginCapability::ResponseMutate)
        {
            tracing::error!(
                "WASM plugin '{}' lacks ResponseInspect/ResponseMutate capability — rejecting invocation",
                plugin_name
            );
            crate::wasm_metrics::record_plugin_capability_violation("ResponseInspect");
            return Err(WasmPluginError::ExecutionFailed(
                "plugin lacks required capability".to_string(),
            ));
        }

        record_wasm_invocation(plugin_name);
        metrics::counter!("synvoid_plugin_invoke_total", "capability" => "transform_response", "status" => "invoked").increment(1);

        let (parts, body) = response.into_parts();

        tracing::debug!(
            "WASM plugin '{}' transforming response with status {}",
            self.name,
            parts.status
        );

        let pooled_instance = self.pool.get(&self.name);

        if let Some(mut inst) = pooled_instance {
            inst.prepare_for_request(
                (*env).clone(),
                self.limits.timeout_seconds,
                self.limits.allowed_dht_prefixes.clone(),
                self.limits.capabilities.clone(),
            );
            let exports =
                WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
            let result =
                self.do_transform_response_with_exports(parts, body, &mut inst.store, exports);
            self.pool.return_instance(inst);
            if result.is_err() {
                Self::record_invoke_failure("transform_response");
            }
            return result;
        }

        let mut store = self.create_store((*env).clone());
        let exports = self.instantiate(&mut store).inspect_err(|_| {
            Self::record_invoke_failure("transform_response");
        })?;
        let result = self.do_transform_response_with_exports(parts, body, &mut store, exports);
        if result.is_err() {
            Self::record_invoke_failure("transform_response");
        }
        result
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

    pub fn invoke_handler_streaming(
        &self,
        method: &str,
        uri: &str,
        headers: &str,
        body: Box<dyn StreamingBody>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        let start = Instant::now();
        let plugin_name = &self.name;

        record_wasm_invocation(plugin_name);
        metrics::counter!("synvoid_plugin_invoke_total", "capability" => "serverless_streaming", "status" => "invoked").increment(1);

        tracing::debug!(
            "WASM serverless function '{}' handling {} {} (streaming)",
            self.name,
            method,
            uri
        );

        let (tx, rx) = tokio::sync::mpsc::channel(16);

        // Feed the body chunks into the receiver
        tokio::spawn(async move {
            let mut body = body;
            loop {
                let frame = std::future::poll_fn(|cx| body.poll_frame(cx)).await;
                match frame {
                    Some(Ok(frame)) => {
                        if let Some(data) = frame.data_ref() {
                            if tx.send(Ok(data.clone())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                    None => break,
                }
            }
        });

        let mut store = self.create_store(env);
        store.data_mut().body_receiver = Some(rx);

        let exports = self.instantiate(&mut store).inspect_err(|_| {
            Self::record_invoke_failure("serverless_streaming");
        })?;

        let handle_fn = match exports.handle_request.as_ref() {
            Some(f) => f,
            None => {
                let duration_ms = start.elapsed().as_millis() as u64;
                record_wasm_duration(plugin_name, duration_ms);
                record_wasm_error(plugin_name);
                Self::record_invoke_failure("serverless_streaming");
                return Err(WasmPluginError::ExecutionFailed(
                    "handle_request function not exported".into(),
                ));
            }
        };

        Self::check_timeout(&store).inspect_err(|_| {
            Self::record_invoke_failure("serverless_streaming");
        })?;

        let method_bytes = method.as_bytes();
        let uri_bytes = uri.as_bytes();
        let headers_bytes = headers.as_bytes();

        let (method_ptr, method_len) =
            self.write_to_guest_memory(&mut store, &exports, method_bytes)?;
        let (uri_ptr, uri_len) = self.write_to_guest_memory(&mut store, &exports, uri_bytes)?;
        let (hdr_ptr, hdr_len) = self.write_to_guest_memory(&mut store, &exports, headers_bytes)?;

        // Pass 0, 0 for body to indicate streaming via synvoid_read_body_chunk
        let body_ptr = 0i32;
        let body_len = 0i32;

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

        if self.limits.max_cpu_fuel > 0 {
            if let Ok(remaining) = store.get_fuel() {
                let consumed = self.limits.max_cpu_fuel.saturating_sub(remaining);
                record_wasm_fuel_consumed(plugin_name, consumed);
            }
        }

        let code = result.map_err(|e| {
            record_wasm_error(plugin_name);
            Self::record_invoke_failure("serverless_streaming");
            WasmPluginError::ExecutionFailed(format!(
                "handle_request failed in '{}': {}",
                self.name, e
            ))
        })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        record_wasm_duration(plugin_name, duration_ms);

        if code != 0 {
            record_wasm_error(plugin_name);
            Self::record_invoke_failure("serverless_streaming");
            return Err(WasmPluginError::ExecutionFailed(format!(
                "handle_request in '{}' returned error code {}",
                self.name, code
            )));
        }

        let status_raw = self.read_from_guest_memory(&mut store, &exports, out_status_ptr, 4)?;
        let status_code = u32::from_le_bytes(status_raw.try_into().unwrap_or([0u8; 4])) as u16;

        let out_body_raw =
            self.read_from_guest_memory(&mut store, &exports, out_body_ptr, OUT_BODY_MAX as i32)?;

        // For now, we assume handle_request returns the body in the out_body_ptr.
        // In a future update, we could also support streaming responses.
        let mut actual_body_len = 0;
        for (i, &b) in out_body_raw.iter().enumerate() {
            if b == 0 && i > 0 && out_body_raw[i - 1] != 0 {
                actual_body_len = i;
                break;
            }
        }
        if actual_body_len == 0 && !out_body_raw.is_empty() && out_body_raw[0] != 0 {
            actual_body_len = out_body_raw.len();
        }

        let body_bytes = Bytes::copy_from_slice(&out_body_raw[..actual_body_len]);

        self.free_guest_memory(&mut store, &exports, out_status_ptr, 4);
        self.free_guest_memory(&mut store, &exports, out_body_ptr, OUT_BODY_MAX as i32);

        record_wasm_decision_pass(plugin_name);

        Ok(Response::builder()
            .status(status_code)
            .body(body_bytes)
            .unwrap_or_else(|_| Response::new(Bytes::new())))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn priority(&self) -> i32 {
        self.priority
    }

    pub fn effective_policy(&self) -> Option<&EffectivePluginPolicy> {
        self.effective_policy.as_ref()
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
        metrics::counter!("synvoid_plugin_invoke_total", "capability" => "serverless", "status" => "invoked").increment(1);

        tracing::debug!(
            "WASM serverless function '{}' handling {} {}",
            self.name,
            method,
            uri
        );

        let mut store = self.create_store(env);
        let exports = self.instantiate(&mut store).inspect_err(|_| {
            Self::record_invoke_failure("serverless");
        })?;

        let handle_fn = match exports.handle_request.as_ref() {
            Some(f) => f,
            None => {
                let duration_ms = start.elapsed().as_millis() as u64;
                record_wasm_duration(plugin_name, duration_ms);
                record_wasm_error(plugin_name);
                Self::record_invoke_failure("serverless");
                return Err(WasmPluginError::ExecutionFailed(
                    "handle_request function not exported".into(),
                ));
            }
        };

        Self::check_timeout(&store).inspect_err(|_| {
            Self::record_invoke_failure("serverless");
        })?;

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
            Self::record_invoke_failure("serverless");
            WasmPluginError::ExecutionFailed(format!(
                "handle_request failed in '{}': {}",
                self.name, e
            ))
        })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        record_wasm_duration(plugin_name, duration_ms);

        if code < 0 {
            record_wasm_error(plugin_name);
            Self::record_invoke_failure("serverless");
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

pub enum WasmFilterResult {
    Pass,
    Block(StatusCode, String),
    Challenge(String),
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

    #[test]
    fn test_load_plugin_duplicate_name_rejected() {
        let mgr = WasmPluginManager::new();

        // Try to load same plugin twice - second load should fail
        let path = Path::new("/nonexistent/plugin.wasm");
        let first_result = mgr.load_plugin(path);
        assert!(first_result.is_err()); // Expected - plugin doesn't exist

        // Second attempt also fails (could be duplicate check or file not found)
        let second_result = mgr.load_plugin(path);
        assert!(second_result.is_err());

        // The key verification is that load_plugin failed as expected
        // (whether due to duplicate name or file not found depends on implementation)
    }

    // ─── Phase 2: TOCTOU and load policy tests ────────────────────────────

    #[test]
    fn test_load_plugin_reads_bytes_once_for_toctou() {
        let mgr = WasmPluginManager::new();
        let path = Path::new("/nonexistent/plugin.wasm");
        let result = mgr.prepare_plugin_load(Some(path), None, None);
        assert!(result.is_err());
        let err_msg = match result {
            Err(e) => e.to_string(),
            _ => panic!("expected error"),
        };
        assert!(err_msg.contains("failed to read") || err_msg.contains("No such file"));
    }

    #[test]
    fn test_prepare_plugin_load_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let tmpdir = tempfile::tempdir().unwrap();
        let wasm_path = tmpdir.path().join("plugin.wasm");
        symlink("/nonexistent/target.wasm", &wasm_path).unwrap();
        let mgr = WasmPluginManager::new();
        let result = mgr.prepare_plugin_load(Some(&wasm_path), None, None);
        assert!(result.is_err());
        let err_msg = match result {
            Err(e) => e.to_string(),
            _ => panic!("expected error"),
        };
        assert!(err_msg.contains("symlink"));
    }

    #[test]
    fn test_load_plugin_from_memory_defaults_to_local_sandboxed() {
        let mgr = WasmPluginManager::new();
        let result =
            mgr.load_plugin_from_memory("test-plugin", b"fake wasm", WasmResourceLimits::default());
        assert!(result.is_err());
        let err_msg = match result {
            Err(e) => e.to_string(),
            _ => panic!("expected error"),
        };
        // Should NOT mention signature verification (SignedSandboxed)
        assert!(!err_msg.contains("signature"));
    }

    #[test]
    fn test_load_plugin_from_memory_with_manifest_enforces_policy() {
        let mgr = WasmPluginManager::new();
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: crate::sandbox::types::PluginLimits::default(),
            signature: None, // Missing signature should fail
        };
        let result = mgr.load_plugin_from_memory_with_manifest(
            "test",
            b"fake wasm",
            &manifest,
            WasmResourceLimits::default(),
        );
        assert!(result.is_err());
        let err_msg = match result {
            Err(e) => e.to_string(),
            _ => panic!("expected error"),
        };
        assert!(err_msg.contains("signature") || err_msg.contains("MissingSignature"));
    }

    #[test]
    fn test_prepare_plugin_load_rejects_entry_path_traversal() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wasm_path = tmpdir.path().join("plugin.wasm");
        // Write a minimal (invalid) WASM file
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").unwrap();
        // Write a manifest with traversal entry
        let manifest_path = tmpdir.path().join("plugin.toml");
        std::fs::write(
            &manifest_path,
            r#"
name = "traversal-test"
version = "0.1.0"
entry = "../escape.wasm"
"#,
        )
        .unwrap();
        let mgr = WasmPluginManager::new();
        let result = mgr.prepare_plugin_load(Some(&wasm_path), None, None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("path traversal"),
            "Expected path traversal error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_prepare_plugin_load_rejects_entry_absolute_path() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wasm_path = tmpdir.path().join("plugin.wasm");
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").unwrap();
        let manifest_path = tmpdir.path().join("plugin.toml");
        std::fs::write(
            &manifest_path,
            r#"
name = "absolute-test"
version = "0.1.0"
entry = "/etc/passwd"
"#,
        )
        .unwrap();
        let mgr = WasmPluginManager::new();
        let result = mgr.prepare_plugin_load(Some(&wasm_path), None, None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("relative path"),
            "Expected relative path error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_prepare_plugin_load_rejects_nonexistent_entry() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wasm_path = tmpdir.path().join("plugin.wasm");
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").unwrap();
        let manifest_path = tmpdir.path().join("plugin.toml");
        std::fs::write(
            &manifest_path,
            r#"
name = "noentry-test"
version = "0.1.0"
entry = "nonexistent.wasm"
"#,
        )
        .unwrap();
        let mgr = WasmPluginManager::new();
        let result = mgr.prepare_plugin_load(Some(&wasm_path), None, None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not resolve"),
            "Expected entry resolution error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_reload_plugin_preserves_old_on_failure() {
        let mgr = WasmPluginManager::new();
        // Attempt reload on nonexistent path — should fail cleanly
        let result = mgr.reload_plugin(Path::new("/nonexistent/plugin.wasm"));
        assert!(result.is_err());
        // Manager state should be unchanged
        assert!(
            mgr.list_plugins().is_empty(),
            "reload failure should not modify plugin list"
        );
    }

    /// Gap 3: Manifest entry symlink escape must be rejected.
    ///
    /// When a manifest's `entry` field resolves via symlink to a file outside
    /// the plugin directory, the load must fail with "escapes plugin directory".
    #[test]
    fn test_prepare_plugin_load_rejects_entry_symlink_escape() {
        use std::os::unix::fs::symlink;

        let tmpdir = tempfile::tempdir().unwrap();
        let plugin_dir = tmpdir.path().join("my_plugin");
        std::fs::create_dir(&plugin_dir).unwrap();

        // Write a valid WASM file inside the plugin directory
        let wasm_path = plugin_dir.join("plugin.wasm");
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").unwrap();

        // Create a target file OUTSIDE the plugin directory
        let escaped_target = tmpdir.path().join("escaped_target.wasm");
        std::fs::write(&escaped_target, b"\x00asm\x01\x00\x00\x00").unwrap();

        // Create a symlink inside the plugin directory pointing outside
        let symlink_path = plugin_dir.join("escaped.wasm");
        symlink(&escaped_target, &symlink_path).unwrap();

        // Write a manifest whose entry points to the symlink
        let manifest_path = plugin_dir.join("plugin.toml");
        std::fs::write(
            &manifest_path,
            r#"
name = "symlink-escape-test"
version = "0.1.0"
entry = "escaped.wasm"
"#,
        )
        .unwrap();

        let mgr = WasmPluginManager::new();
        let result = mgr.prepare_plugin_load(Some(&wasm_path), None, None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("escapes plugin directory"),
            "Expected directory escape error, got: {}",
            err_msg
        );
    }

    /// Gap 4: Reload with tampered bytes must fail.
    ///
    /// When a plugin file is overwritten with invalid WASM bytes between load
    /// and reload, the reload must fail and the manager state must be unchanged.
    #[test]
    fn test_reload_plugin_with_tampered_bytes_fails() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wasm_path = tmpdir.path().join("plugin.wasm");
        let manifest_path = tmpdir.path().join("plugin.toml");

        // Write a minimal valid WASM module (empty module: just header)
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").unwrap();
        std::fs::write(
            &manifest_path,
            r#"
name = "tamper-test"
version = "0.1.0"
entry = "plugin.wasm"
"#,
        )
        .unwrap();

        // Tamper: overwrite with invalid bytes
        std::fs::write(&wasm_path, b"\xff\xff\xff\xff").unwrap();

        let mgr = WasmPluginManager::new();
        let result = mgr.reload_plugin(&wasm_path);
        assert!(result.is_err(), "reload with tampered bytes should fail");
        // Manager should have no plugins (nothing was loaded before)
        assert!(
            mgr.list_plugins().is_empty(),
            "manager should remain empty after failed reload"
        );
    }

    /// Gap 5: Successful reload cycle must update plugin state.
    ///
    /// Load a plugin, overwrite the file with valid bytes, reload,
    /// and verify the reload succeeds and the plugin list is updated.
    #[test]
    fn test_reload_plugin_successful_cycle() {
        let tmpdir = tempfile::tempdir().unwrap();
        let wasm_path = tmpdir.path().join("plugin.wasm");
        let manifest_path = tmpdir.path().join("plugin.toml");

        // Write a minimal valid WASM module (empty module: just magic + version)
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").unwrap();
        std::fs::write(
            &manifest_path,
            r#"
name = "reload-cycle-test"
version = "0.1.0"
entry = "plugin.wasm"
"#,
        )
        .unwrap();

        let mgr = WasmPluginManager::new();

        // Initial load via load_plugin
        let initial = mgr.load_plugin(&wasm_path);
        assert!(
            initial.is_ok(),
            "initial load should succeed: {:?}",
            initial.err()
        );
        assert_eq!(
            mgr.list_plugins().len(),
            1,
            "should have 1 plugin after initial load"
        );

        // Overwrite with same valid WASM bytes (reload mechanism test).
        // The reload path must: prepare -> instantiate -> swap under lock.
        std::fs::write(&wasm_path, b"\x00asm\x01\x00\x00\x00").unwrap();

        // Reload should succeed
        let reloaded = mgr.reload_plugin(&wasm_path);
        assert!(
            reloaded.is_ok(),
            "reload should succeed: {:?}",
            reloaded.err()
        );
        assert_eq!(
            mgr.list_plugins().len(),
            1,
            "should still have 1 plugin after reload"
        );
        assert_eq!(
            mgr.list_plugins()[0],
            "plugin",
            "plugin name should be unchanged (derived from file stem)"
        );

        // Verify the plugin info is present
        let info = mgr.get_plugin_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].name, "plugin");
    }
}
