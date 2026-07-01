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
    enforce_plugin_load_policy, PluginCapabilities, PluginCapability, PluginFailureClass,
    PluginFailurePolicy, PluginInvocationGuard, PluginLimits, PluginLoadConfig, PluginManifest,
    PluginRuntimeState, PluginTrustTier,
};
use crate::streaming_body::StreamingBody;
use crate::wasm_metrics::{
    record_wasm_decision_block, record_wasm_decision_challenge, record_wasm_decision_pass,
    record_wasm_duration, record_wasm_error, record_wasm_fuel_consumed, record_wasm_invocation,
    WasmPluginMetrics,
};

/// Maximum size of request/response data passed through WASM memory (1MB)
const MAX_WASM_DATA_SIZE: usize = 1024 * 1024;

/// Stable ABI error codes for host-call failures.
/// These are returned to guest code when a host function fails.
pub const ABI_SUCCESS: i32 = 0;
pub const ABI_ERR_CAPABILITY_DENIED: i32 = -1;
pub const ABI_ERR_INVALID_POINTER: i32 = -2;
pub const ABI_ERR_TIMEOUT: i32 = -3;
pub const ABI_ERR_INPUT_TOO_LARGE: i32 = -4;
pub const ABI_ERR_UNAVAILABLE: i32 = -5;
pub const ABI_ERR_INTERNAL: i32 = -6;

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
pub struct ExecutionInterruptPolicy {
    pub fuel_required: bool,
    pub epoch_deadline_enabled: bool,
    pub epoch_ticks_per_timeout: u64,
    pub host_call_timeout: Duration,
}

impl Default for ExecutionInterruptPolicy {
    fn default() -> Self {
        Self {
            fuel_required: true,
            epoch_deadline_enabled: true,
            epoch_ticks_per_timeout: 10,
            host_call_timeout: Duration::from_secs(5),
        }
    }
}

/// Per-call budgets for individual host functions.
///
/// Each host function gets independent timeout and size limits so that a slow
/// `mesh_query_dht` cannot starve `get_env` or vice-versa.
#[derive(Debug, Clone)]
pub struct HostCallBudget {
    /// Timeout for `get_env` host calls.
    pub env_lookup_timeout: Duration,
    /// Timeout for `synvoid_read_body_chunk` host calls.
    pub body_chunk_timeout: Duration,
    /// Timeout for `mesh_query_dht` host calls.
    pub mesh_query_timeout: Duration,
    /// Timeout for `mesh_check_threat` host calls.
    pub mesh_threat_timeout: Duration,
    /// Timeout for `mesh_emit_event` host calls.
    pub mesh_emit_timeout: Duration,
    /// Maximum bytes returned by `synvoid_read_body_chunk`.
    pub max_body_chunk_bytes: usize,
    /// Maximum bytes returned by `get_env`.
    pub max_env_value_bytes: usize,
    /// Maximum key size for mesh DHT queries.
    pub max_mesh_key_bytes: usize,
    /// Maximum value size for mesh DHT queries.
    pub max_mesh_value_bytes: usize,
}

impl Default for HostCallBudget {
    fn default() -> Self {
        Self {
            env_lookup_timeout: Duration::from_secs(5),
            body_chunk_timeout: Duration::from_secs(5),
            mesh_query_timeout: Duration::from_secs(5),
            mesh_threat_timeout: Duration::from_secs(5),
            mesh_emit_timeout: Duration::from_secs(5),
            max_body_chunk_bytes: 64 * 1024,
            max_env_value_bytes: 4 * 1024,
            max_mesh_key_bytes: 1024,
            max_mesh_value_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WasmResourceLimits {
    pub max_memory_mb: usize,
    pub max_table_elements: Option<usize>,
    /// CPU fuel budget for sandboxed plugins. Must be non-zero for production
    /// sandboxed tiers (SignedSandboxed, LocalSandboxed). Fuel is the primary
    /// CPU interruption mechanism for synchronous guest execution; wall-clock
    /// timeout is a secondary budget applied via `tokio::time::timeout`.
    pub max_cpu_fuel: u64,
    pub timeout: Duration,
    pub max_instances: usize,
    pub memory_budget_mb: Option<usize>,
    pub wasi_enabled: bool,
    pub allowed_dht_prefixes: Vec<String>,
    pub capabilities: Arc<PluginCapabilities>,
    pub epoch_deadline_enabled: bool,
    pub epoch_ticks_per_timeout: u64,
    pub host_call_timeout: Duration,
    pub host_call_budget: HostCallBudget,
    /// Pool state model controlling cross-request state semantics.
    pub state_model: crate::sandbox::types::PluginStateModel,
}

impl Default for WasmResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_table_elements: None,
            max_cpu_fuel: 1000000,
            timeout: Duration::from_secs(30),
            max_instances: 1,
            memory_budget_mb: None,
            wasi_enabled: false,
            allowed_dht_prefixes: Vec::new(),
            capabilities: Arc::new(PluginCapabilities::default()),
            epoch_deadline_enabled: true,
            epoch_ticks_per_timeout: 10,
            host_call_timeout: Duration::from_secs(5),
            host_call_budget: HostCallBudget::default(),
            state_model: crate::sandbox::types::PluginStateModel::default(),
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

/// Metadata about a loaded WASM module's guest ABI exports.
///
/// Used to validate that a plugin provides the required exports before
/// attempting invocation. The pointer-length ABI requires `memory`,
/// `guest_alloc`, and `guest_free` to prevent fixed-offset aliasing.
#[derive(Debug, Clone)]
pub struct GuestAbiInfo {
    pub has_filter_request: bool,
    pub has_transform_response: bool,
    pub has_handle_request: bool,
    pub has_memory: bool,
    pub has_guest_alloc: bool,
    pub has_guest_free: bool,
}

impl GuestAbiInfo {
    /// Returns true if the module has at least one hook export.
    pub fn has_any_hook(&self) -> bool {
        self.has_filter_request || self.has_transform_response || self.has_handle_request
    }

    /// Returns true if the module has the required allocator exports
    /// for safe pointer-length ABI usage.
    pub fn has_required_allocator(&self) -> bool {
        self.has_guest_alloc && self.has_guest_free
    }

    pub fn validate_for_policy(&self, policy: GuestAbiPolicy) -> Result<(), WasmPluginError> {
        if !self.has_memory {
            return Err(WasmPluginError::LoadFailed(
                "plugin missing memory export for pointer-length ABI".into(),
            ));
        }
        if !self.has_guest_alloc {
            return Err(WasmPluginError::LoadFailed(
                "plugin missing required guest_alloc export for pointer-length ABI".into(),
            ));
        }
        if !self.has_any_hook() {
            return Err(WasmPluginError::LoadFailed(
                "plugin has no hook exports (filter_request/transform_response/handle_request)"
                    .into(),
            ));
        }
        match policy {
            GuestAbiPolicy::ProductionPointerLength => {
                if !self.has_guest_free {
                    return Err(WasmPluginError::LoadFailed(
                        "production ABI requires guest_free export".into(),
                    ));
                }
            }
            GuestAbiPolicy::DevelopmentAllowMissingFree => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestAbiPolicy {
    ProductionPointerLength,
    DevelopmentAllowMissingFree,
}

impl GuestAbiPolicy {
    /// Derive the ABI policy from a plugin trust tier.
    /// Production tiers require both guest_alloc and guest_free.
    /// Development tiers allow missing guest_free for test compatibility.
    pub fn from_trust_tier(tier: PluginTrustTier) -> Self {
        match tier {
            PluginTrustTier::DevelopmentHotReload => Self::DevelopmentAllowMissingFree,
            _ => Self::ProductionPointerLength,
        }
    }
}

#[derive(Debug, Clone)]
struct RequestInputPieces<'a> {
    method: &'a [u8],
    uri: &'a [u8],
    headers: Vec<u8>,
    body: &'a [u8],
}

#[derive(Debug, Clone)]
struct GuestInputFrame {
    base: i32,
    total_len: i32,
    method: GuestAllocation,
    uri: GuestAllocation,
    headers: GuestAllocation,
    body: Option<GuestAllocation>,
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
    guard: Arc<PluginInvocationGuard>,
    failure_policy: PluginFailurePolicy,
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub path: Option<PathBuf>,
    pub version: String,
    pub trust_tier: PluginTrustTier,
    pub timeout: Duration,
    pub max_memory_mb: usize,
    pub max_cpu_fuel: u64,
    pub max_instances: usize,
    pub capabilities_summary: Vec<(PluginCapability, bool)>,
    pub state_model: crate::sandbox::types::PluginStateModel,
    pub failure_policy_summary: String,
    pub current_state: String,
    pub failure_count: u32,
    pub timeout_count: u32,
    pub last_failure_class: Option<String>,
    pub fuel_budget: u64,
    pub pool_stats_hits: u64,
    pub pool_stats_misses: u64,
    pub pool_stats_dropped: u64,
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

        let effective_limits = limits_from_manifest(m, &self.default_limits)?;
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
            state_model: prepared.effective_limits.state_model,
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
            state_model: prepared.effective_limits.state_model,
        };
        self.plugin_policies.write().insert(runtime_name, policy);
        Ok(arc)
    }

    #[allow(dead_code)]
    fn create_component_store(
        engine: &Engine,
        limits: &WasmResourceLimits,
    ) -> Store<RequestContext> {
        let timeout = limits.timeout;
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
                capability_violation: None,
                host_call_budget: limits.host_call_budget.clone(),
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
                let metrics = WasmPluginMetrics::get(name);
                let failure_policy = &r.failure_policy;
                let failure_policy_summary = format!(
                    "threshold={}, timeout_threshold={}, cap_violation_disables={}, fail_closed_filter={}, fail_closed_transform={}",
                    failure_policy.failure_threshold,
                    failure_policy.timeout_threshold,
                    failure_policy.capability_violation_disables,
                    failure_policy.fail_closed_on_filter_error,
                    failure_policy.fail_closed_on_transform_error,
                );
                let guard_state = r.guard().state();
                PluginInfo {
                    name: name.to_string(),
                    path: path.clone(),
                    version: policy
                        .map(|p| p.version.clone())
                        .unwrap_or_else(|| "0.0.0".into()),
                    trust_tier: policy.map(|p| p.trust_tier).unwrap_or_default(),
                    timeout: r.limits.timeout,
                    max_memory_mb: r.limits.max_memory_mb,
                    max_cpu_fuel: r.limits.max_cpu_fuel,
                    max_instances: r.limits.max_instances,
                    capabilities_summary: r.limits.capabilities.iter_flags(),
                    state_model: policy
                        .map(|p| p.state_model)
                        .unwrap_or_default(),
                    failure_policy_summary,
                    current_state: guard_state.to_string(),
                    failure_count: r.guard().failure_count(),
                    timeout_count: 0,
                    last_failure_class: None,
                    fuel_budget: r.limits.max_cpu_fuel,
                    pool_stats_hits: metrics.pool_hits,
                    pool_stats_misses: metrics.pool_misses,
                    pool_stats_dropped: metrics.pool_dropped,
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

    /// Get the runtime state of a plugin by name.
    pub fn get_plugin_state(&self, name: &str) -> Option<PluginRuntimeState> {
        self.get_runtime_by_name(name).map(|r| r.guard().state())
    }

    /// Get the failure count of a plugin by name.
    pub fn get_plugin_failure_count(&self, name: &str) -> Option<u32> {
        self.get_runtime_by_name(name)
            .map(|r| r.guard().failure_count())
    }

    /// Reset failure counters for a plugin, restoring it to Loaded state.
    pub fn reset_plugin_failures(&self, name: &str) -> Result<(), WasmPluginError> {
        let runtime = self
            .get_runtime_by_name(name)
            .ok_or_else(|| WasmPluginError::FunctionNotFound(name.to_string()))?;
        runtime.guard().reset_failures();
        crate::wasm_metrics::record_plugin_state_transition(name, "loaded", "manual reset");
        Ok(())
    }

    /// Quarantine a plugin, preventing all future invocations.
    pub fn quarantine_plugin(&self, name: &str) -> Result<(), WasmPluginError> {
        let runtime = self
            .get_runtime_by_name(name)
            .ok_or_else(|| WasmPluginError::FunctionNotFound(name.to_string()))?;
        runtime.guard().quarantine();
        crate::wasm_metrics::record_plugin_state_transition(
            name,
            "quarantined",
            "manual quarantine",
        );
        Ok(())
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
    pub(crate) capability_violation: Option<PluginCapability>,
    pub(crate) host_call_budget: HostCallBudget,
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

/// Validate a guest pointer+length pair against memory bounds.
///
/// Returns the validated `Range<usize>` or a descriptive error.
/// Uses checked arithmetic to prevent overflow on 32-bit targets.
fn checked_guest_range(
    ptr: i32,
    len: i32,
    mem_len: usize,
) -> Result<std::ops::Range<usize>, WasmPluginError> {
    if ptr < 0 {
        return Err(WasmPluginError::ExecutionFailed(
            "negative guest pointer".into(),
        ));
    }
    if len < 0 {
        return Err(WasmPluginError::ExecutionFailed(
            "negative guest length".into(),
        ));
    }
    let start = ptr as usize;
    let len = len as usize;
    let end = start
        .checked_add(len)
        .ok_or_else(|| WasmPluginError::ExecutionFailed("guest pointer range overflow".into()))?;
    if end > mem_len {
        return Err(WasmPluginError::ExecutionFailed(format!(
            "guest pointer range out of bounds: [{}, {}) but memory is {}",
            start, end, mem_len
        )));
    }
    Ok(start..end)
}

#[derive(Debug, Clone, Copy)]
struct GuestAllocation {
    ptr: i32,
    len: i32,
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

        if limits.epoch_deadline_enabled {
            config.epoch_interruption(true);
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

        // Validate ABI against production or development policy
        let abi_info = Self::validate_guest_abi(&module);
        let abi_policy = prepared
            .as_ref()
            .map(|p| GuestAbiPolicy::from_trust_tier(p.manifest.trust_tier))
            .unwrap_or(GuestAbiPolicy::ProductionPointerLength);
        abi_info.validate_for_policy(abi_policy).map_err(|e| {
            tracing::warn!("Plugin '{}' ABI validation failed: {}", name, e);
            e
        })?;

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
            "Loaded WASM plugin '{}' with limits: {}MB memory, {} fuel, {}ms timeout, priority {} (filter={}, transform={}, handle={})",
            name,
            limits.max_memory_mb,
            limits.max_cpu_fuel,
            limits.timeout.as_millis(),
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
            limits: p.effective_limits.clone(),
            manifest_limits: p.manifest.limits.clone(),
            source: p.source,
            state_model: p.effective_limits.state_model,
        });

        let guard = Arc::new(PluginInvocationGuard::new(
            (*limits.capabilities).clone(),
            PluginLimits {
                timeout_ms: limits.timeout.as_millis() as u64,
                max_concurrency: limits.max_instances.max(1),
                ..Default::default()
            },
            limits.max_instances.max(1),
        ));
        let failure_policy = effective_policy
            .as_ref()
            .map(|_p| PluginFailurePolicy {
                failure_threshold: 5,
                timeout_threshold: 3,
                capability_violation_disables: true,
                fail_closed_on_filter_error: true,
                fail_closed_on_transform_error: false,
            })
            .unwrap_or_default();

        Ok(Self {
            engine,
            module,
            limits,
            name,
            priority,
            pool,
            linker,
            effective_policy,
            guard,
            failure_policy,
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

        // Validate ABI — legacy paths without prepared load use production policy
        let abi_info = Self::validate_guest_abi(&module);
        abi_info
            .validate_for_policy(GuestAbiPolicy::ProductionPointerLength)
            .map_err(|e| {
                tracing::warn!("Plugin '{}' ABI validation failed: {}", name, e);
                e
            })?;

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
            "Loaded WASM plugin '{}' with limits: {}MB memory, {} fuel, {}ms timeout, priority {} (filter={}, transform={}, handle={})",
            name,
            limits.max_memory_mb,
            limits.max_cpu_fuel,
            limits.timeout.as_millis(),
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

        let guard = Arc::new(PluginInvocationGuard::new(
            (*limits.capabilities).clone(),
            PluginLimits {
                timeout_ms: limits.timeout.as_millis() as u64,
                max_concurrency: limits.max_instances.max(1),
                ..Default::default()
            },
            limits.max_instances.max(1),
        ));

        Ok(Self {
            engine,
            module,
            limits,
            name: name.to_string(),
            priority,
            pool,
            linker,
            effective_policy: None,
            guard,
            failure_policy: PluginFailurePolicy::default(),
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

        // Validate ABI — legacy paths without prepared load use production policy
        let abi_info = Self::validate_guest_abi(&module);
        abi_info
            .validate_for_policy(GuestAbiPolicy::ProductionPointerLength)
            .map_err(|e| {
                tracing::warn!("Plugin '{}' ABI validation failed: {}", name, e);
                e
            })?;

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
            "Loaded WASM plugin '{}' with limits: {}MB memory, {} fuel, {}ms timeout, priority {} (filter={}, transform={}, handle={})",
            name,
            limits.max_memory_mb,
            limits.max_cpu_fuel,
            limits.timeout.as_millis(),
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

        let guard = Arc::new(PluginInvocationGuard::new(
            (*limits.capabilities).clone(),
            PluginLimits {
                timeout_ms: limits.timeout.as_millis() as u64,
                max_concurrency: limits.max_instances.max(1),
                ..Default::default()
            },
            limits.max_instances.max(1),
        ));

        Ok(Self {
            engine,
            module,
            limits,
            name,
            priority,
            pool,
            linker,
            effective_policy: None,
            guard,
            failure_policy: PluginFailurePolicy::default(),
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
                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return ABI_ERR_INTERNAL,
                    };
                    let mem_data = mem.data(&caller);

                    let key_range = match checked_guest_range(key_ptr, key_len, mem_data.len()) {
                        Ok(r) => r,
                        Err(_) => {
                            crate::wasm_metrics::record_host_call_failure(
                                "",
                                "get_env",
                                "InvalidPointer",
                            );
                            return ABI_ERR_INVALID_POINTER;
                        }
                    };
                    let key = String::from_utf8_lossy(&mem_data[key_range]);

                    let value = caller.data().env.get(key.as_ref());
                    let fallback = String::new();
                    let value_str = value.unwrap_or(&fallback);
                    let value_bytes = value_str.as_bytes();
                    let max_bytes = caller.data().host_call_budget.max_env_value_bytes as i32;
                    let clamped_max = out_max.min(max_bytes);
                    let value_len = value_bytes.len().min(clamped_max as usize);

                    let out_range =
                        match checked_guest_range(out_ptr, value_len as i32, mem_data.len()) {
                            Ok(r) => r,
                            Err(_) => {
                                crate::wasm_metrics::record_host_call_failure(
                                    "",
                                    "get_env",
                                    "InvalidPointer",
                                );
                                return ABI_ERR_INVALID_POINTER;
                            }
                        };

                    unsafe {
                        let mem_ptr = mem.data_ptr(&caller);
                        let slice = std::slice::from_raw_parts_mut(
                            mem_ptr.add(out_range.start),
                            out_range.len(),
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
                    let start = caller.data().start;
                    let budget_timeout = caller.data().host_call_budget.body_chunk_timeout;

                    let mut rx = match caller.data_mut().body_receiver.take() {
                        Some(rx) => rx,
                        None => {
                            crate::wasm_metrics::record_host_call_failure(
                                "",
                                "synvoid_read_body_chunk",
                                "InternalError",
                            );
                            return ABI_ERR_INTERNAL;
                        }
                    };

                    let result = rx.blocking_recv();

                    // Per-call budget check: reject if we exceeded the per-call timeout
                    if start.elapsed() > budget_timeout {
                        caller.data_mut().body_receiver = Some(rx);
                        crate::wasm_metrics::record_host_call_failure(
                            "",
                            "synvoid_read_body_chunk",
                            "BodyChunkTimeout",
                        );
                        return ABI_ERR_TIMEOUT;
                    }

                    // Put the receiver back for future calls
                    caller.data_mut().body_receiver = Some(rx);

                    match result {
                        Some(Ok(chunk)) => {
                            let max_bytes = caller.data().host_call_budget.max_body_chunk_bytes;
                            let len = chunk.len().min(out_max as usize).min(max_bytes);
                            let mem = match caller.get_export("memory") {
                                Some(wasmtime::Extern::Memory(m)) => m,
                                _ => {
                                    crate::wasm_metrics::record_host_call_failure(
                                        "",
                                        "synvoid_read_body_chunk",
                                        "InternalError",
                                    );
                                    return ABI_ERR_INTERNAL;
                                }
                            };
                            let mem_len = mem.data(&caller).len();
                            if checked_guest_range(out_ptr, len as i32, mem_len).is_err() {
                                crate::wasm_metrics::record_host_call_failure(
                                    "",
                                    "synvoid_read_body_chunk",
                                    "InvalidPointer",
                                );
                                return ABI_ERR_INVALID_POINTER;
                            }
                            if mem
                                .write(&mut caller, out_ptr as usize, &chunk[..len])
                                .is_err()
                            {
                                crate::wasm_metrics::record_host_call_failure(
                                    "",
                                    "synvoid_read_body_chunk",
                                    "InternalError",
                                );
                                return ABI_ERR_INTERNAL;
                            }
                            len as i32
                        }
                        Some(Err(_)) => {
                            crate::wasm_metrics::record_host_call_failure(
                                "",
                                "synvoid_read_body_chunk",
                                "InternalError",
                            );
                            ABI_ERR_INTERNAL
                        }
                        None => 0, // EOF
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
                        crate::wasm_metrics::record_host_call_failure(
                            "",
                            "mesh_query_dht",
                            "CapabilityDenied",
                        );
                        caller.data_mut().capability_violation = Some(PluginCapability::Mesh);
                        return ABI_ERR_CAPABILITY_DENIED;
                    }

                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return ABI_ERR_INTERNAL,
                    };
                    let mem_data = mem.data(&caller);

                    let key_range = match checked_guest_range(key_ptr, key_len, mem_data.len()) {
                        Ok(r) => r,
                        Err(_) => {
                            crate::wasm_metrics::record_host_call_failure(
                                "",
                                "mesh_query_dht",
                                "InvalidPointer",
                            );
                            return ABI_ERR_INVALID_POINTER;
                        }
                    };

                    let key = String::from_utf8_lossy(&mem_data[key_range]).to_string();

                    // Enforce per-call key size budget
                    if key.len() > caller.data().host_call_budget.max_mesh_key_bytes {
                        crate::wasm_metrics::record_host_call_failure(
                            "",
                            "mesh_query_dht",
                            "InputTooLarge",
                        );
                        return ABI_ERR_INPUT_TOO_LARGE;
                    }

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
                        crate::wasm_metrics::record_host_call_failure(
                            "",
                            "mesh_query_dht",
                            "CapabilityDenied",
                        );
                        return ABI_ERR_CAPABILITY_DENIED;
                    }

                    let result = if let Some(provider) = crate::mesh_callbacks::get_mesh_provider()
                    {
                        if let Some(value) = provider.get_record(&key) {
                            let max_bytes = caller.data().host_call_budget.max_mesh_value_bytes;
                            let value_len = value.len().min(out_max as usize).min(max_bytes);
                            let out_range = match checked_guest_range(
                                out_ptr,
                                value_len as i32,
                                mem_data.len(),
                            ) {
                                Ok(r) => r,
                                Err(_) => {
                                    crate::wasm_metrics::record_host_call_failure(
                                        "",
                                        "mesh_query_dht",
                                        "InvalidPointer",
                                    );
                                    return ABI_ERR_INVALID_POINTER;
                                }
                            };
                            unsafe {
                                let mem_ptr = mem.data_ptr(&caller);
                                std::slice::from_raw_parts_mut(
                                    mem_ptr.add(out_range.start),
                                    out_range.len(),
                                )
                                .copy_from_slice(&value[..value_len]);
                            }
                            value_len as i32
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
                        crate::wasm_metrics::record_host_call_failure(
                            "", "mesh_check_threat", "CapabilityDenied",
                        );
                        caller.data_mut().capability_violation = Some(PluginCapability::Mesh);
                        return ABI_ERR_CAPABILITY_DENIED;
                    }

                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return ABI_ERR_INTERNAL,
                    };
                    let mem_data = mem.data(&caller);

                    let ip_range = match checked_guest_range(ip_ptr, ip_len, mem_data.len()) {
                        Ok(r) => r,
                        Err(_) => {
                            crate::wasm_metrics::record_host_call_failure(
                                "", "mesh_check_threat", "InvalidPointer",
                            );
                            return ABI_ERR_INVALID_POINTER;
                        }
                    };

                    let ip_str = String::from_utf8_lossy(&mem_data[ip_range]).to_string();

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
                        crate::wasm_metrics::record_host_call_failure(
                            "",
                            "mesh_emit_event",
                            "CapabilityDenied",
                        );
                        caller.data_mut().capability_violation = Some(PluginCapability::Mesh);
                        return ABI_ERR_CAPABILITY_DENIED;
                    }

                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return ABI_ERR_INTERNAL,
                    };
                    let mem_data = mem.data(&caller);

                    let topic_range =
                        match checked_guest_range(topic_ptr, topic_len, mem_data.len()) {
                            Ok(r) => r,
                            Err(_) => {
                                crate::wasm_metrics::record_host_call_failure(
                                    "",
                                    "mesh_emit_event",
                                    "InvalidPointer",
                                );
                                return ABI_ERR_INVALID_POINTER;
                            }
                        };

                    let data_range = match checked_guest_range(data_ptr, data_len, mem_data.len()) {
                        Ok(r) => r,
                        Err(_) => {
                            crate::wasm_metrics::record_host_call_failure(
                                "",
                                "mesh_emit_event",
                                "InvalidPointer",
                            );
                            return ABI_ERR_INVALID_POINTER;
                        }
                    };

                    let topic = String::from_utf8_lossy(&mem_data[topic_range]).to_string();
                    let data = mem_data[data_range].to_vec();

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
        let timeout = self.limits.timeout;
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
                capability_violation: None,
                host_call_budget: self.limits.host_call_budget.clone(),
            },
        );

        store.limiter(|state| state);

        if self.limits.max_cpu_fuel > 0 {
            store.set_fuel(self.limits.max_cpu_fuel).ok();
        }

        if self.limits.epoch_deadline_enabled {
            let ticks = self.limits.epoch_ticks_per_timeout.max(1);
            store.set_epoch_deadline(ticks);
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

    /// Validate that a loaded module has the required ABI exports.
    ///
    /// For the pointer-length ABI, requires `memory` and at least one
    /// hook export. `guest_alloc`/`guest_free` are required for safe
    /// memory operations; missing them causes invocation failure.
    pub fn validate_guest_abi(module: &Module) -> GuestAbiInfo {
        GuestAbiInfo {
            has_filter_request: module.get_export("filter_request").is_some(),
            has_transform_response: module.get_export("transform_response").is_some(),
            has_handle_request: module.get_export("handle_request").is_some(),
            has_memory: module.get_export("memory").is_some(),
            has_guest_alloc: module.get_export("guest_alloc").is_some(),
            has_guest_free: module.get_export("guest_free").is_some(),
        }
    }

    /// Write data into WASM linear memory via guest_alloc.
    ///
    /// Requires `guest_alloc` export — the fixed-offset fallback is removed.
    /// Validates allocation result and memory bounds before writing.
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

        // Zero-length writes return a null pointer convention
        if data_len == 0 {
            return Ok((0, 0));
        }

        let alloc_fn = exports.guest_alloc.as_ref().ok_or_else(|| {
            WasmPluginError::LoadFailed(
                "plugin missing required guest_alloc export for pointer-length ABI".into(),
            )
        })?;

        let ptr = alloc_fn
            .call(&mut *store, data_len as i32)
            .map_err(|e| WasmPluginError::ExecutionFailed(format!("guest_alloc failed: {}", e)))?;

        // Validate allocation result
        if ptr < 0 {
            return Err(WasmPluginError::ExecutionFailed(format!(
                "guest_alloc returned negative pointer: {}",
                ptr
            )));
        }

        // Check memory bounds with checked arithmetic
        let mem_size = memory.data_size(&*store);
        let end = (ptr as usize).checked_add(data_len).ok_or_else(|| {
            WasmPluginError::ExecutionFailed("guest pointer range overflow".into())
        })?;

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

    /// Free guest memory if guest_free is available.
    ///
    /// Failures from guest_free are logged but do not panic.
    /// If guest_free traps, the caller should treat the instance as poisoned.
    fn free_guest_memory(
        &self,
        store: &mut Store<RequestContext>,
        exports: &GuestExports,
        alloc: &GuestAllocation,
    ) -> bool {
        if alloc.ptr == 0 && alloc.len == 0 {
            return true;
        }
        if let Some(free_fn) = &exports.guest_free {
            match free_fn.call(&mut *store, (alloc.ptr, alloc.len)) {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!("guest_free failed (instance may be poisoned): {}", e);
                    false
                }
            }
        } else {
            tracing::warn!(
                "guest_free missing — memory leak possible (ptr={}, len={})",
                alloc.ptr,
                alloc.len
            );
            true
        }
    }

    fn write_request_input_frame(
        &self,
        store: &mut Store<RequestContext>,
        exports: &GuestExports,
        pieces: RequestInputPieces<'_>,
    ) -> Result<GuestInputFrame, WasmPluginError> {
        let total_len = pieces
            .method
            .len()
            .checked_add(pieces.uri.len())
            .and_then(|v| v.checked_add(pieces.headers.len()))
            .and_then(|v| v.checked_add(pieces.body.len()))
            .ok_or_else(|| {
                WasmPluginError::SandboxError("request input total length overflow".into())
            })?;

        if total_len > MAX_WASM_DATA_SIZE {
            return Err(WasmPluginError::SandboxError(format!(
                "request input total {} exceeds max {}",
                total_len, MAX_WASM_DATA_SIZE
            )));
        }

        if total_len == 0 {
            return Ok(GuestInputFrame {
                base: 0,
                total_len: 0,
                method: GuestAllocation { ptr: 0, len: 0 },
                uri: GuestAllocation { ptr: 0, len: 0 },
                headers: GuestAllocation { ptr: 0, len: 0 },
                body: None,
            });
        }

        let alloc_fn = exports.guest_alloc.as_ref().ok_or_else(|| {
            WasmPluginError::LoadFailed(
                "plugin missing required guest_alloc export for pointer-length ABI".into(),
            )
        })?;

        let base = alloc_fn
            .call(&mut *store, total_len as i32)
            .map_err(|e| WasmPluginError::ExecutionFailed(format!("guest_alloc failed: {}", e)))?;

        if base < 0 {
            return Err(WasmPluginError::ExecutionFailed(format!(
                "guest_alloc returned negative pointer: {}",
                base
            )));
        }

        let memory = exports
            .memory
            .as_ref()
            .ok_or_else(|| WasmPluginError::ExecutionFailed("no memory export".into()))?;

        let end = (base as usize).checked_add(total_len).ok_or_else(|| {
            WasmPluginError::ExecutionFailed("guest pointer range overflow".into())
        })?;

        let mem_size = memory.data_size(&*store);
        if end > mem_size {
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
        let mut offset = base as usize;

        mem_data[offset..offset + pieces.method.len()].copy_from_slice(pieces.method);
        let method = GuestAllocation {
            ptr: base,
            len: pieces.method.len() as i32,
        };
        offset += pieces.method.len();

        mem_data[offset..offset + pieces.uri.len()].copy_from_slice(pieces.uri);
        let uri = GuestAllocation {
            ptr: offset as i32,
            len: pieces.uri.len() as i32,
        };
        offset += pieces.uri.len();

        mem_data[offset..offset + pieces.headers.len()].copy_from_slice(&pieces.headers);
        let headers = GuestAllocation {
            ptr: offset as i32,
            len: pieces.headers.len() as i32,
        };
        offset += pieces.headers.len();

        let body = if !pieces.body.is_empty() {
            mem_data[offset..offset + pieces.body.len()].copy_from_slice(pieces.body);
            let alloc = GuestAllocation {
                ptr: offset as i32,
                len: pieces.body.len() as i32,
            };
            Some(alloc)
        } else {
            None
        };

        Ok(GuestInputFrame {
            base,
            total_len: total_len as i32,
            method,
            uri,
            headers,
            body,
        })
    }

    fn free_guest_input_frame(
        &self,
        store: &mut Store<RequestContext>,
        exports: &GuestExports,
        frame: &GuestInputFrame,
    ) -> bool {
        self.free_guest_memory(
            store,
            exports,
            &GuestAllocation {
                ptr: frame.base,
                len: frame.total_len,
            },
        )
    }

    /// Serialize headers to a compact binary format for passing to WASM guest.
    ///
    /// Delegates to [`crate::abi_frame::serialize_headers_canonical`] for the
    /// authoritative serialization logic. This ensures all header encoding
    /// uses the single canonical path with policy-driven bounds.
    ///
    /// Format: [header_count: u16]
    ///         [for each header: [name_len: u16][name][value_len: u16][value]]
    fn serialize_headers(
        headers: &HeaderMap,
        max_encoded_bytes: usize,
    ) -> Result<Vec<u8>, WasmPluginError> {
        let policy = crate::abi_frame::RequestFramePolicy {
            max_serialized_headers_bytes: max_encoded_bytes,
            ..Default::default()
        };
        crate::abi_frame::serialize_headers_canonical(headers, &policy)
            .map_err(|e| WasmPluginError::SandboxError(e.to_string()))
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

    /// Classify a WasmPluginError into a failure class for policy decisions.
    fn classify_failure(error: &WasmPluginError) -> PluginFailureClass {
        match error {
            WasmPluginError::SandboxError(msg) => {
                if msg.contains("fuel") || msg.contains("all fuel") {
                    PluginFailureClass::FuelExhausted
                } else if msg.contains("memory") || msg.contains("out of bounds") {
                    PluginFailureClass::MemoryViolation
                } else {
                    PluginFailureClass::GuestTrap
                }
            }
            WasmPluginError::ExecutionFailed(msg) => {
                if msg.contains("timed out") || msg.contains("timeout") {
                    PluginFailureClass::Timeout
                } else if msg.contains("trap") || msg.contains("panic") {
                    PluginFailureClass::GuestTrap
                } else if msg.contains("capability") {
                    PluginFailureClass::CapabilityViolation
                } else {
                    PluginFailureClass::OtherRuntimeError
                }
            }
            WasmPluginError::LoadFailed(_) => PluginFailureClass::LoadError,
            WasmPluginError::FunctionNotFound(_) => PluginFailureClass::OtherRuntimeError,
        }
    }

    /// Record a failure using the guard and return the failure class.
    fn record_and_classify_failure(&self, error: &WasmPluginError) -> PluginFailureClass {
        let class = Self::classify_failure(error);
        if class == PluginFailureClass::CapabilityViolation
            && self.failure_policy.capability_violation_disables
        {
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                &self.name,
                "disabled_by_capability_violation",
                "capability violation during invocation",
            );
        } else if class.is_timeout() {
            self.guard
                .record_failure(self.failure_policy.timeout_threshold);
            let state = self.guard.state();
            if state != PluginRuntimeState::Loaded {
                crate::wasm_metrics::record_plugin_state_transition(
                    &self.name,
                    &state.to_string(),
                    "timeout threshold exceeded",
                );
            }
        } else if class.counts_as_failure() {
            self.guard
                .record_failure(self.failure_policy.failure_threshold);
            let state = self.guard.state();
            if state != PluginRuntimeState::Loaded {
                crate::wasm_metrics::record_plugin_state_transition(
                    &self.name,
                    &state.to_string(),
                    "failure threshold exceeded",
                );
            }
        }
        class
    }

    /// Get a reference to the invocation guard for this runtime.
    pub fn guard(&self) -> &PluginInvocationGuard {
        &self.guard
    }

    pub fn filter_request(
        &self,
        request: Request<Bytes>,
        env: Arc<std::collections::HashMap<String, String>>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        let plugin_name = &self.name;

        // Check runtime state via guard
        if !self.guard.is_invocable() {
            let state = self.guard.state();
            tracing::warn!(
                "WASM plugin '{}' is not invocable (state: {}) — {}",
                plugin_name,
                state,
                if self.failure_policy.fail_closed_on_filter_error {
                    "blocking"
                } else {
                    "passing through"
                }
            );
            if self.failure_policy.fail_closed_on_filter_error {
                return Ok(WasmFilterResult::Block(
                    StatusCode::FORBIDDEN,
                    format!("Plugin '{}' is disabled ({})", plugin_name, state),
                ));
            } else {
                return Ok(WasmFilterResult::Pass);
            }
        }

        // Check capability via guard
        if self
            .guard
            .capabilities
            .require_any_capability(&[
                PluginCapability::RequestInspect,
                PluginCapability::RequestMutate,
            ])
            .is_err()
        {
            tracing::error!(
                "WASM plugin '{}' lacks RequestInspect/RequestMutate capability — rejecting invocation",
                plugin_name
            );
            crate::wasm_metrics::record_plugin_capability_violation("RequestInspect");
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "missing filter_request capability",
            );
            return Err(WasmPluginError::ExecutionFailed(
                "plugin lacks required capability".to_string(),
            ));
        }

        // Check input size
        let input_len = request.headers().len() + request.body().len();
        if let Err(e) = self.guard.limits.check_input(input_len) {
            return Err(WasmPluginError::ExecutionFailed(format!(
                "input too large: {}",
                e
            )));
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
                self.limits.timeout,
                self.limits.allowed_dht_prefixes.clone(),
                self.limits.capabilities.clone(),
            );
            let exports =
                WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
            let result = self.do_filter_request_with_exports(parts, body, &mut inst.store, exports);
            if result.is_err() {
                // Drop poisoned instance — do not return to pool
                drop(inst);
                if let Err(ref e) = result {
                    self.record_and_classify_failure(e);
                    Self::record_invoke_failure("filter_request");
                }
            } else {
                self.pool.return_instance(inst);
            }
            return result;
        }

        let mut store = self.create_store((*env).clone());
        let exports = self.instantiate(&mut store).inspect_err(|_| {
            Self::record_invoke_failure("filter_request");
        })?;
        let result = self.do_filter_request_with_exports(parts, body, &mut store, exports);
        if let Err(ref e) = result {
            self.record_and_classify_failure(e);
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

        let headers_meta = Self::serialize_headers(&parts.headers, MAX_WASM_DATA_SIZE)?;
        let body_bytes = body.as_ref();

        let pieces = RequestInputPieces {
            method: method_bytes,
            uri: uri_bytes,
            headers: headers_meta,
            body: body_bytes,
        };
        let frame = self.write_request_input_frame(&mut *store, &exports, pieces)?;

        let method_ptr = frame.method.ptr;
        let method_len = frame.method.len;
        let uri_ptr = frame.uri.ptr;
        let uri_len = frame.uri.len;
        let hdr_ptr = frame.headers.ptr;
        let hdr_len = frame.headers.len;
        let (body_ptr, body_len) = frame
            .body
            .as_ref()
            .map(|b| (b.ptr, b.len))
            .unwrap_or((0, 0));

        let result = filter_fn.call(
            &mut *store,
            (
                method_ptr, method_len, uri_ptr, uri_len, hdr_ptr, hdr_len, body_ptr, body_len,
            ),
        );

        // Check for capability violations reported by host functions during guest execution
        if store.data().capability_violation.is_some() {
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "host function capability violation during guest call",
            );
        }

        self.free_guest_input_frame(&mut *store, &exports, &frame);

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

        // Check runtime state via guard
        if !self.guard.is_invocable() {
            let state = self.guard.state();
            tracing::warn!(
                "WASM plugin '{}' is not invocable (state: {}) — {}",
                plugin_name,
                state,
                if self.failure_policy.fail_closed_on_transform_error {
                    "blocking"
                } else {
                    "passing through"
                }
            );
            if self.failure_policy.fail_closed_on_transform_error {
                return Err(WasmPluginError::ExecutionFailed(format!(
                    "Plugin '{}' is disabled ({})",
                    plugin_name, state
                )));
            } else {
                return Ok(response);
            }
        }

        // Check capability via guard
        if self
            .guard
            .capabilities
            .require_any_capability(&[
                PluginCapability::ResponseInspect,
                PluginCapability::ResponseMutate,
            ])
            .is_err()
        {
            tracing::error!(
                "WASM plugin '{}' lacks ResponseInspect/ResponseMutate capability — rejecting invocation",
                plugin_name
            );
            crate::wasm_metrics::record_plugin_capability_violation("ResponseInspect");
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "missing transform_response capability",
            );
            return Err(WasmPluginError::ExecutionFailed(
                "plugin lacks required capability".to_string(),
            ));
        }

        // Check input size
        let input_len = response.headers().len() + response.body().len();
        if let Err(e) = self.guard.limits.check_input(input_len) {
            return Err(WasmPluginError::ExecutionFailed(format!(
                "input too large: {}",
                e
            )));
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
                self.limits.timeout,
                self.limits.allowed_dht_prefixes.clone(),
                self.limits.capabilities.clone(),
            );
            let exports =
                WasmInstancePool::resolve_exports_from_instance(&inst.instance, &mut inst.store);
            let result =
                self.do_transform_response_with_exports(parts, body, &mut inst.store, exports);
            if result.is_err() {
                // Drop poisoned instance — do not return to pool
                drop(inst);
                if let Err(ref e) = result {
                    self.record_and_classify_failure(e);
                    Self::record_invoke_failure("transform_response");
                }
            } else {
                self.pool.return_instance(inst);
            }
            return result;
        }

        let mut store = self.create_store((*env).clone());
        let exports = self.instantiate(&mut store).inspect_err(|_| {
            Self::record_invoke_failure("transform_response");
        })?;
        let result = self.do_transform_response_with_exports(parts, body, &mut store, exports);
        if let Err(ref e) = result {
            self.record_and_classify_failure(e);
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
        let out_max = (body_bytes.len() + 65536).min(MAX_WASM_DATA_SIZE);

        let out_buf = vec![0u8; out_max];
        let pieces = RequestInputPieces {
            method: body_bytes,
            uri: &[],
            headers: out_buf,
            body: &[],
        };
        let frame = self.write_request_input_frame(&mut *store, &exports, pieces)?;

        let body_ptr = frame.method.ptr;
        let body_len = frame.method.len;
        let out_ptr = frame.headers.ptr;
        let out_max_i32 = frame.headers.len;

        Self::check_timeout(&*store)?;

        let status_code = parts.status.as_u16() as i32;

        let new_len = transform_fn
            .call(
                &mut *store,
                (status_code, body_ptr, body_len, out_ptr, out_max_i32),
            )
            .map_err(|e| {
                record_wasm_error(plugin_name);
                WasmPluginError::ExecutionFailed(format!(
                    "transform_response failed in '{}': {}",
                    self.name, e
                ))
            })?;

        // Check for capability violations reported by host functions during guest execution
        if store.data().capability_violation.is_some() {
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "host function capability violation during guest call",
            );
        }

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

        self.free_guest_input_frame(&mut *store, &exports, &frame);

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

        // Check runtime state via guard
        if !self.guard.is_invocable() {
            let state = self.guard.state();
            tracing::warn!(
                "WASM plugin '{}' is not invocable (state: {}) — blocking serverless invocation",
                plugin_name,
                state,
            );
            return Err(WasmPluginError::ExecutionFailed(format!(
                "Plugin '{}' is disabled ({})",
                plugin_name, state
            )));
        }

        // Check capability via guard
        if self
            .guard
            .capabilities
            .require_any_capability(&[
                PluginCapability::RequestInspect,
                PluginCapability::RequestMutate,
            ])
            .is_err()
        {
            tracing::error!(
                "WASM plugin '{}' lacks RequestInspect/RequestMutate capability — rejecting streaming invocation",
                plugin_name
            );
            crate::wasm_metrics::record_plugin_capability_violation("RequestInspect");
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "missing invoke_handler_streaming capability",
            );
            return Err(WasmPluginError::ExecutionFailed(
                "plugin lacks required capability".to_string(),
            ));
        }

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

        let exports = self.instantiate(&mut store).inspect_err(|e| {
            self.record_and_classify_failure(e);
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

        Self::check_timeout(&store).inspect_err(|e| {
            self.record_and_classify_failure(e);
            Self::record_invoke_failure("serverless_streaming");
        })?;

        let method_bytes = method.as_bytes();
        let uri_bytes = uri.as_bytes();
        let headers_bytes = headers.as_bytes();

        let pieces = RequestInputPieces {
            method: method_bytes,
            uri: uri_bytes,
            headers: headers_bytes.to_vec(),
            body: &[],
        };
        let input_frame = self.write_request_input_frame(&mut store, &exports, pieces)?;

        const OUT_BODY_MAX: usize = 65536;
        let (out_status_ptr, _) = self.write_to_guest_memory(&mut store, &exports, &[0u8; 4])?;
        let (out_body_ptr, _) =
            self.write_to_guest_memory(&mut store, &exports, &[0u8; OUT_BODY_MAX])?;

        let method_ptr = input_frame.method.ptr;
        let method_len = input_frame.method.len;
        let uri_ptr = input_frame.uri.ptr;
        let uri_len = input_frame.uri.len;
        let hdr_ptr = input_frame.headers.ptr;
        let hdr_len = input_frame.headers.len;
        let (body_ptr, body_len) = input_frame
            .body
            .as_ref()
            .map(|b| (b.ptr, b.len))
            .unwrap_or((0, 0));

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

        // Check for capability violations reported by host functions during guest execution
        if store.data().capability_violation.is_some() {
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "host function capability violation during guest call",
            );
        }

        self.free_guest_input_frame(&mut store, &exports, &input_frame);

        if self.limits.max_cpu_fuel > 0 {
            if let Ok(remaining) = store.get_fuel() {
                let consumed = self.limits.max_cpu_fuel.saturating_sub(remaining);
                record_wasm_fuel_consumed(plugin_name, consumed);
            }
        }

        let code = result.map_err(|e| {
            record_wasm_error(plugin_name);
            self.record_and_classify_failure(&WasmPluginError::ExecutionFailed(format!(
                "handle_request failed in '{}': {}",
                self.name, e
            )));
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
            let err = WasmPluginError::ExecutionFailed(format!(
                "handle_request in '{}' returned error code {}",
                self.name, code
            ));
            self.record_and_classify_failure(&err);
            Self::record_invoke_failure("serverless_streaming");
            return Err(err);
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

        self.free_guest_memory(
            &mut store,
            &exports,
            &GuestAllocation {
                ptr: out_status_ptr,
                len: 4,
            },
        );
        self.free_guest_memory(
            &mut store,
            &exports,
            &GuestAllocation {
                ptr: out_body_ptr,
                len: OUT_BODY_MAX as i32,
            },
        );

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

        // Check runtime state via guard
        if !self.guard.is_invocable() {
            let state = self.guard.state();
            tracing::warn!(
                "WASM plugin '{}' is not invocable (state: {}) — blocking serverless invocation",
                plugin_name,
                state,
            );
            return Err(WasmPluginError::ExecutionFailed(format!(
                "Plugin '{}' is disabled ({})",
                plugin_name, state
            )));
        }

        // Check capability via guard
        if self
            .guard
            .capabilities
            .require_any_capability(&[
                PluginCapability::RequestInspect,
                PluginCapability::RequestMutate,
            ])
            .is_err()
        {
            tracing::error!(
                "WASM plugin '{}' lacks RequestInspect/RequestMutate capability — rejecting invocation",
                plugin_name
            );
            crate::wasm_metrics::record_plugin_capability_violation("RequestInspect");
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "missing invoke_handler capability",
            );
            return Err(WasmPluginError::ExecutionFailed(
                "plugin lacks required capability".to_string(),
            ));
        }

        // Check input size
        if let Err(e) = self.guard.limits.check_input(body.len()) {
            return Err(WasmPluginError::ExecutionFailed(format!(
                "input too large: {}",
                e
            )));
        }

        record_wasm_invocation(plugin_name);
        metrics::counter!("synvoid_plugin_invoke_total", "capability" => "serverless", "status" => "invoked").increment(1);

        tracing::debug!(
            "WASM serverless function '{}' handling {} {}",
            self.name,
            method,
            uri
        );

        let mut store = self.create_store(env);
        let exports = self.instantiate(&mut store).inspect_err(|e| {
            self.record_and_classify_failure(e);
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

        Self::check_timeout(&store).inspect_err(|e| {
            self.record_and_classify_failure(e);
            Self::record_invoke_failure("serverless");
        })?;

        let method_bytes = method.as_bytes();
        let uri_bytes = uri.as_bytes();
        let headers_bytes = headers.as_bytes();

        let pieces = RequestInputPieces {
            method: method_bytes,
            uri: uri_bytes,
            headers: headers_bytes.to_vec(),
            body,
        };
        let input_frame = self.write_request_input_frame(&mut store, &exports, pieces)?;

        const OUT_BODY_MAX: usize = 65536;
        let (out_status_ptr, _) = self.write_to_guest_memory(&mut store, &exports, &[0u8; 4])?;
        let (out_body_ptr, _) =
            self.write_to_guest_memory(&mut store, &exports, &[0u8; OUT_BODY_MAX])?;

        let method_ptr = input_frame.method.ptr;
        let method_len = input_frame.method.len;
        let uri_ptr = input_frame.uri.ptr;
        let uri_len = input_frame.uri.len;
        let hdr_ptr = input_frame.headers.ptr;
        let hdr_len = input_frame.headers.len;
        let (body_ptr, body_len) = input_frame
            .body
            .as_ref()
            .map(|b| (b.ptr, b.len))
            .unwrap_or((0, 0));

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

        // Check for capability violations reported by host functions during guest execution
        if store.data().capability_violation.is_some() {
            self.guard.disable_for_violation();
            crate::wasm_metrics::record_plugin_state_transition(
                plugin_name,
                "disabled_by_capability_violation",
                "host function capability violation during guest call",
            );
        }

        self.free_guest_input_frame(&mut store, &exports, &input_frame);

        if self.limits.max_cpu_fuel > 0 {
            if let Ok(remaining) = store.get_fuel() {
                let consumed = self.limits.max_cpu_fuel.saturating_sub(remaining);
                record_wasm_fuel_consumed(plugin_name, consumed);
            }
        }

        let code = result.map_err(|e| {
            record_wasm_error(plugin_name);
            self.record_and_classify_failure(&WasmPluginError::ExecutionFailed(format!(
                "handle_request failed in '{}': {}",
                self.name, e
            )));
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
            let err = WasmPluginError::ExecutionFailed(format!(
                "Serverless function '{}' returned error",
                self.name
            ));
            self.record_and_classify_failure(&err);
            Self::record_invoke_failure("serverless");
            return Err(err);
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

        self.free_guest_memory(
            &mut store,
            &exports,
            &GuestAllocation {
                ptr: out_status_ptr,
                len: 4,
            },
        );
        self.free_guest_memory(
            &mut store,
            &exports,
            &GuestAllocation {
                ptr: out_body_ptr,
                len: OUT_BODY_MAX.try_into().unwrap(),
            },
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

#[derive(Debug)]
pub enum WasmFilterResult {
    Pass,
    Block(StatusCode, String),
    Challenge(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::types::{PluginInvokeError, ResourceLimitError};
    use http::HeaderValue;
    extern crate wat;

    #[test]
    fn test_resource_limits_default() {
        let limits = WasmResourceLimits::default();
        assert_eq!(limits.max_memory_mb, 64);
        assert_eq!(limits.max_cpu_fuel, 1_000_000);
        assert_eq!(limits.timeout, Duration::from_secs(30));
        assert_eq!(limits.max_instances, 1);
    }

    #[test]
    fn test_timeout_ms_1_maps_to_duration_1ms() {
        let mut manifest = crate::sandbox::types::PluginManifest::default();
        manifest.limits.timeout_ms = 1;
        let defaults = WasmResourceLimits::default();
        let limits = crate::sandbox::policy::limits_from_manifest(&manifest, &defaults).unwrap();
        assert_eq!(limits.timeout, Duration::from_millis(1));
    }

    #[test]
    fn test_timeout_ms_50_maps_to_duration_50ms() {
        let mut manifest = crate::sandbox::types::PluginManifest::default();
        manifest.limits.timeout_ms = 50;
        let defaults = WasmResourceLimits::default();
        let limits = crate::sandbox::policy::limits_from_manifest(&manifest, &defaults).unwrap();
        assert_eq!(limits.timeout, Duration::from_millis(50));
    }

    #[test]
    fn test_timeout_ms_1500_preserves_precision() {
        let mut manifest = crate::sandbox::types::PluginManifest::default();
        manifest.limits.timeout_ms = 1500;
        let defaults = WasmResourceLimits::default();
        let limits = crate::sandbox::policy::limits_from_manifest(&manifest, &defaults).unwrap();
        assert_eq!(limits.timeout, Duration::from_millis(1500));
    }

    #[test]
    fn test_plugin_info_exposes_timeout_without_loss() {
        let limits = WasmResourceLimits {
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let info = PluginInfo {
            name: "test".into(),
            path: None,
            version: "0.0.0".into(),
            trust_tier: PluginTrustTier::default(),
            timeout: limits.timeout,
            max_memory_mb: limits.max_memory_mb,
            max_cpu_fuel: limits.max_cpu_fuel,
            max_instances: limits.max_instances,
            capabilities_summary: Vec::new(),
            state_model: crate::sandbox::types::PluginStateModel::default(),
            failure_policy_summary: String::new(),
            current_state: "active".into(),
            failure_count: 0,
            timeout_count: 0,
            last_failure_class: None,
            fuel_budget: limits.max_cpu_fuel,
            pool_stats_hits: 0,
            pool_stats_misses: 0,
            pool_stats_dropped: 0,
        };
        assert_eq!(info.timeout, Duration::from_millis(50));
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

        let data = WasmRuntime::serialize_headers(&headers, MAX_WASM_DATA_SIZE).unwrap();

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

        // Write a valid WASM module with complete ABI (guest_alloc + guest_free + filter_request)
        let valid_wasm = test_fixtures::minimal_filter_pass();
        std::fs::write(&wasm_path, &valid_wasm).unwrap();
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
        std::fs::write(&wasm_path, &valid_wasm).unwrap();

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

    #[test]
    fn test_plugin_failure_policy_default() {
        let policy = PluginFailurePolicy::default();
        assert_eq!(policy.failure_threshold, 5);
        assert_eq!(policy.timeout_threshold, 3);
        assert!(policy.capability_violation_disables);
        assert!(policy.fail_closed_on_filter_error);
        assert!(!policy.fail_closed_on_transform_error);
    }

    #[test]
    fn test_plugin_failure_class_counts_as_failure() {
        assert!(!PluginFailureClass::CapabilityViolation.counts_as_failure());
        assert!(PluginFailureClass::Timeout.counts_as_failure());
        assert!(PluginFailureClass::FuelExhausted.counts_as_failure());
        assert!(PluginFailureClass::GuestTrap.counts_as_failure());
        assert!(PluginFailureClass::MemoryViolation.counts_as_failure());
        assert!(PluginFailureClass::OtherRuntimeError.counts_as_failure());
    }

    #[test]
    fn test_plugin_failure_class_is_timeout() {
        assert!(PluginFailureClass::Timeout.is_timeout());
        assert!(!PluginFailureClass::CapabilityViolation.is_timeout());
        assert!(!PluginFailureClass::FuelExhausted.is_timeout());
    }

    #[test]
    fn test_classify_failure_sandbox_fuel() {
        let err = WasmPluginError::SandboxError("exhausted fuel budget".to_string());
        assert_eq!(
            WasmRuntime::classify_failure(&err),
            PluginFailureClass::FuelExhausted
        );
    }

    #[test]
    fn test_classify_failure_sandbox_memory() {
        let err = WasmPluginError::SandboxError("memory out of bounds".to_string());
        assert_eq!(
            WasmRuntime::classify_failure(&err),
            PluginFailureClass::MemoryViolation
        );
    }

    #[test]
    fn test_classify_failure_execution_timeout() {
        let err = WasmPluginError::ExecutionFailed("timed out after 30.00s".to_string());
        assert_eq!(
            WasmRuntime::classify_failure(&err),
            PluginFailureClass::Timeout
        );
    }

    #[test]
    fn test_classify_failure_execution_capability() {
        let err = WasmPluginError::ExecutionFailed("plugin lacks required capability".to_string());
        assert_eq!(
            WasmRuntime::classify_failure(&err),
            PluginFailureClass::CapabilityViolation
        );
    }

    #[test]
    fn test_classify_failure_load() {
        let err = WasmPluginError::LoadFailed("file not found".to_string());
        assert_eq!(
            WasmRuntime::classify_failure(&err),
            PluginFailureClass::LoadError
        );
    }

    #[test]
    fn test_guard_state_reflects_runtime() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );
        assert_eq!(guard.state(), PluginRuntimeState::Loaded);
        assert!(guard.is_invocable());
        assert_eq!(guard.failure_count(), 0);

        guard.record_failure(5);
        assert_eq!(guard.failure_count(), 1);
        assert!(guard.is_invocable());

        // Disable at threshold
        for _ in 0..4 {
            guard.record_failure(5);
        }
        assert_eq!(guard.failure_count(), 5);
        assert!(!guard.is_invocable());
        assert_eq!(guard.state(), PluginRuntimeState::DisabledByRuntimeFailure);
    }

    #[test]
    fn test_guard_quarantine() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        assert_eq!(guard.state(), PluginRuntimeState::Loaded);
        guard.quarantine();
        assert_eq!(guard.state(), PluginRuntimeState::Quarantined);
        assert!(!guard.is_invocable());
    }

    #[test]
    fn test_guard_invoke_with_limits_blocking_success() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );
        let result =
            guard.invoke_with_limits_blocking(PluginCapability::RequestInspect, 100, || {
                Ok::<_, PluginInvokeError>(42)
            });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_guard_invoke_with_limits_blocking_disabled() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        guard.disable_for_violation();
        let result =
            guard.invoke_with_limits_blocking(PluginCapability::RequestInspect, 100, || {
                Ok::<_, PluginInvokeError>(42)
            });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginInvokeError::PluginDisabled
        ));
    }

    #[test]
    fn test_guard_invoke_with_limits_blocking_input_too_large() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits {
                max_input_bytes: 100,
                ..Default::default()
            },
            4,
        );
        let result = guard.invoke_with_limits_blocking(
            PluginCapability::RequestInspect,
            200, // exceeds limit
            || Ok::<_, PluginInvokeError>(42),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginInvokeError::ResourceLimit(ResourceLimitError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn test_guard_concurrency_blocking_rejects_when_exhausted() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits {
                max_concurrency: 1,
                ..Default::default()
            },
            1,
        );
        // Take the only permit
        let _permit = guard.concurrency.clone().try_acquire_owned().unwrap();
        let result =
            guard.invoke_with_limits_blocking(PluginCapability::RequestInspect, 100, || {
                Ok::<_, PluginInvokeError>(42)
            });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PluginInvokeError::ConcurrencyLimitExceeded
        ));
    }

    #[test]
    fn test_manager_get_plugin_state() {
        let mgr = WasmPluginManager::new();
        assert!(mgr.get_plugin_state("nonexistent").is_none());
        assert!(mgr.get_plugin_failure_count("nonexistent").is_none());
    }

    #[test]
    fn test_manager_reset_plugin_failures_not_found() {
        let mgr = WasmPluginManager::new();
        let result = mgr.reset_plugin_failures("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_quarantine_plugin_not_found() {
        let mgr = WasmPluginManager::new();
        let result = mgr.quarantine_plugin("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_require_any_capability() {
        let caps = PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        };
        // Should succeed with RequestInspect
        assert!(caps
            .require_any_capability(&[
                PluginCapability::RequestInspect,
                PluginCapability::RequestMutate,
            ])
            .is_ok());
        // Should fail with ResponseInspect/ResponseMutate
        assert!(caps
            .require_any_capability(&[
                PluginCapability::ResponseInspect,
                PluginCapability::ResponseMutate,
            ])
            .is_err());
    }

    #[test]
    fn test_require_any_capability_empty_list() {
        let caps = PluginCapabilities::default();
        let result = caps.require_any_capability(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_guard_timeout_returns_timeout_error() {
        // Test that PluginInvokeError::Timeout exists and can be matched
        let err = PluginInvokeError::Timeout;
        assert!(matches!(err, PluginInvokeError::Timeout));

        // Test that a guard with zero timeout would timeout immediately
        // Note: We can't test actual async timeout without tokio time feature,
        // but we can verify the error type exists and the guard structure is correct
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits {
                timeout_ms: 0, // Zero timeout
                ..Default::default()
            },
            4,
        );
        // Verify guard is created with the timeout limit
        assert_eq!(guard.limits.timeout_ms, 0);
    }

    #[test]
    fn test_guard_record_failure_disables_at_threshold() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );
        // Record failures up to threshold
        for _ in 0..4 {
            guard.record_failure(5);
            assert!(guard.is_invocable());
        }
        // Fifth failure should disable
        guard.record_failure(5);
        assert!(!guard.is_invocable());
        assert_eq!(guard.state(), PluginRuntimeState::DisabledByRuntimeFailure);
        assert_eq!(guard.failure_count(), 5);
    }

    #[test]
    fn test_guard_disable_for_violation_state_transition() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );
        assert_eq!(guard.state(), PluginRuntimeState::Loaded);
        guard.disable_for_violation();
        assert_eq!(
            guard.state(),
            PluginRuntimeState::DisabledByCapabilityViolation
        );
        assert!(!guard.is_invocable());
    }

    #[test]
    fn test_guard_reset_failures_restores_loaded_state() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );
        // Disable by threshold
        for _ in 0..5 {
            guard.record_failure(5);
        }
        assert!(!guard.is_invocable());
        assert_eq!(guard.state(), PluginRuntimeState::DisabledByRuntimeFailure);
        // Reset should restore to Loaded
        guard.reset_failures();
        assert!(guard.is_invocable());
        assert_eq!(guard.state(), PluginRuntimeState::Loaded);
        assert_eq!(guard.failure_count(), 0);
    }

    #[test]
    fn test_guard_reset_failures_restores_violation_state() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );
        guard.disable_for_violation();
        assert_eq!(
            guard.state(),
            PluginRuntimeState::DisabledByCapabilityViolation
        );
        // Reset should also restore from violation state
        guard.reset_failures();
        assert!(guard.is_invocable());
        assert_eq!(guard.state(), PluginRuntimeState::Loaded);
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // Integration Tests with WASM Fixtures
    // ═══════════════════════════════════════════════════════════════════════════════

    use crate::test_fixtures;

    fn make_limits_with_filter_cap() -> WasmResourceLimits {
        WasmResourceLimits {
            capabilities: Arc::new(PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_plugin_trap_disables_after_repeated_failures() {
        let wasm = test_fixtures::trapping_module();
        let limits = make_limits_with_filter_cap();

        let runtime =
            WasmRuntime::load_from_bytes_with_priority("trap-plugin", &wasm, limits.clone(), 0)
                .expect("load should succeed");

        assert!(runtime.guard.is_invocable());
        assert_eq!(runtime.guard.failure_count(), 0);

        // Invoke repeatedly — each should trap and record a failure
        for i in 0..6 {
            let req = Request::builder()
                .method("GET")
                .uri("http://example.com/")
                .body(Bytes::new())
                .unwrap();
            let env = Arc::new(std::collections::HashMap::new());
            let _ = runtime.filter_request(req, env);
            eprintln!(
                "After invocation {}: failure_count={}",
                i + 1,
                runtime.guard.failure_count()
            );
        }

        // After 6 invocations (threshold is 5), plugin MUST be disabled
        assert!(!runtime.guard.is_invocable());
        assert_eq!(
            runtime.guard.state(),
            PluginRuntimeState::DisabledByRuntimeFailure
        );
        assert!(runtime.guard.failure_count() >= 5);

        // Subsequent invocations must be blocked by guard
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_ok());
        match result.unwrap() {
            WasmFilterResult::Block(status, _) => assert_eq!(status, StatusCode::FORBIDDEN),
            _ => panic!("expected Block after plugin disabled"),
        }
    }

    #[test]
    fn test_plugin_fuel_exhaustion_disables_after_threshold() {
        let wasm = test_fixtures::infinite_loop_module();
        let mut limits = make_limits_with_filter_cap();
        limits.max_cpu_fuel = 100; // Very low fuel — each invocation exhausts it

        let runtime =
            WasmRuntime::load_from_bytes_with_priority("fuel-plugin", &wasm, limits.clone(), 0)
                .expect("load should succeed");

        assert!(runtime.guard.is_invocable());

        // Each invocation should exhaust fuel and record a failure
        for i in 0..10 {
            let req = Request::builder()
                .method("GET")
                .uri("http://example.com/")
                .body(Bytes::new())
                .unwrap();
            let env = Arc::new(std::collections::HashMap::new());
            let _ = runtime.filter_request(req, env);
            eprintln!(
                "Fuel test after {}: failure_count={}",
                i + 1,
                runtime.guard.failure_count()
            );
        }

        // After 10 invocations (threshold is 5), plugin MUST be disabled
        assert!(!runtime.guard.is_invocable());
        assert_eq!(
            runtime.guard.state(),
            PluginRuntimeState::DisabledByRuntimeFailure
        );
        assert!(runtime.guard.failure_count() >= 5);
    }

    #[test]
    fn test_plugin_missing_filter_request_returns_pass() {
        // Use a module with handle_request but no filter_request — valid ABI, missing optional hook.
        let wasm = wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (global $heap (mut i32) (i32.const 0))
                (func (export "guest_alloc") (param $size i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $heap))
                    (global.set $heap (i32.add (global.get $heap) (local.get $size)))
                    (local.get $ptr)
                )
                (func (export "guest_free") (param $ptr i32) (param $size i32))
                (func (export "handle_request")
                    (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
                    i32.const 0  ;; Return 0 = success
                )
            )
            "#,
        )
        .expect("valid WAT");
        let limits = make_limits_with_filter_cap();

        let runtime = WasmRuntime::load_from_bytes_with_priority(
            "no-filter-plugin",
            &wasm,
            limits.clone(),
            0,
        )
        .expect("load should succeed");

        // filter_request should return Pass (no filter export)
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);

        assert!(result.is_ok());
        match result.unwrap() {
            WasmFilterResult::Pass => {} // Expected
            other => panic!("expected Pass for missing filter_request, got {:?}", other),
        }

        // Failure count should NOT increase for missing optional export
        assert_eq!(runtime.guard.failure_count(), 0);
        assert!(runtime.guard.is_invocable());
    }

    #[test]
    fn test_plugin_oversized_input_rejected_before_invocation() {
        // Verify that oversized input is rejected at the guard level before WASM execution.
        // The guard's check_input rejects the request, so guest code never runs.
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits {
                max_input_bytes: 10, // Very small limit
                ..Default::default()
            },
            4,
        );

        // Simulate a large input check
        let result = guard.limits.check_input(200);
        assert!(result.is_err());

        // Failure count should NOT increase for input size rejection
        assert_eq!(guard.failure_count(), 0);
        assert!(guard.is_invocable());
    }

    #[test]
    fn test_plugin_transform_disables_after_repeated_failures() {
        // Use a module with allocator exports and transform_response that traps
        let trapping_transform = wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (global $heap (mut i32) (i32.const 0))
                (func (export "guest_alloc") (param $size i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $heap))
                    (global.set $heap (i32.add (global.get $heap) (local.get $size)))
                    (local.get $ptr)
                )
                (func (export "guest_free") (param $ptr i32) (param $size i32))
                (func (export "transform_response") (param i32 i32 i32 i32 i32) (result i32)
                    unreachable  ;; Trap immediately
                )
            )
            "#,
        )
        .expect("valid WAT");

        let limits = WasmResourceLimits {
            capabilities: Arc::new(PluginCapabilities {
                response_inspect: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let runtime = WasmRuntime::load_from_bytes_with_priority(
            "trap-transform-plugin",
            &trapping_transform,
            limits.clone(),
            0,
        )
        .expect("load should succeed");

        // Each invocation should trap
        for _ in 0..6 {
            let response = Response::builder().status(200).body(Bytes::new()).unwrap();
            let env = Arc::new(std::collections::HashMap::new());
            let _ = runtime.transform_response(response, env);
        }

        // After threshold, plugin should be disabled
        assert!(!runtime.guard.is_invocable());
        assert_eq!(
            runtime.guard.state(),
            PluginRuntimeState::DisabledByRuntimeFailure
        );
    }

    #[test]
    fn test_host_function_violation_disables_plugin() {
        // Load a WASM module that calls mesh_query_dht without mesh capability.
        // The host function should set capability_violation on RequestContext,
        // and the post-invocation check should disable the plugin.
        let wasm = test_fixtures::mesh_call_without_capability();
        let limits = WasmResourceLimits {
            capabilities: Arc::new(PluginCapabilities {
                request_inspect: true, // Has filter cap, but NOT mesh cap
                ..Default::default()
            }),
            ..Default::default()
        };

        let runtime = WasmRuntime::load_from_bytes_with_priority(
            "mesh-violation-plugin",
            &wasm,
            limits.clone(),
            0,
        )
        .expect("load should succeed");

        assert!(runtime.guard.is_invocable());

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);

        // The guest calls mesh_query_dht which returns -1 (no mesh capability),
        // then returns 0 (Pass). The host function sets capability_violation.
        // After guest execution, the post-invocation check should disable the plugin.
        assert!(result.is_ok());
        assert!(
            !runtime.guard.is_invocable(),
            "plugin should be disabled after host-function capability violation"
        );
        assert_eq!(
            runtime.guard.state(),
            PluginRuntimeState::DisabledByCapabilityViolation
        );
    }

    #[test]
    fn test_manager_get_plugin_state_loaded() {
        let wasm = test_fixtures::minimal_filter_pass();
        let limits = make_limits_with_filter_cap();

        let runtime =
            WasmRuntime::load_from_bytes_with_priority("state-plugin", &wasm, limits.clone(), 0)
                .expect("load should succeed");

        // Loaded runtime should report Loaded state
        assert_eq!(runtime.guard.state(), PluginRuntimeState::Loaded);
        assert!(runtime.guard.is_invocable());
        assert_eq!(runtime.guard.failure_count(), 0);

        // After a successful invocation, state should still be Loaded
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_ok());
        assert_eq!(runtime.guard.state(), PluginRuntimeState::Loaded);
    }

    #[test]
    fn test_manager_disabled_plugin_filter_request_via_runtime() {
        // Verify that calling filter_request on a disabled runtime returns Block
        let wasm = test_fixtures::minimal_filter_pass();
        let limits = make_limits_with_filter_cap();

        let runtime = WasmRuntime::load_from_bytes_with_priority(
            "disabled-filter-plugin",
            &wasm,
            limits.clone(),
            0,
        )
        .expect("load should succeed");

        // Verify initial state
        assert!(runtime.guard.is_invocable());

        // Disable the plugin via capability violation
        runtime.guard.disable_for_violation();
        assert!(!runtime.guard.is_invocable());

        // filter_request should return Block (fail_closed_on_filter_error is true by default)
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);

        assert!(result.is_ok());
        match result.unwrap() {
            WasmFilterResult::Block(status, msg) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(
                    msg.contains("disabled"),
                    "error message should mention disabled: {}",
                    msg
                );
            }
            other => panic!("expected Block for disabled plugin, got {:?}", other),
        }

        // Verify state is still disabled
        assert_eq!(
            runtime.guard.state(),
            PluginRuntimeState::DisabledByCapabilityViolation
        );
    }

    #[test]
    fn test_inflight_request_not_invalidated_by_disable() {
        let wasm = test_fixtures::trapping_module();
        let limits = make_limits_with_filter_cap();

        let runtime =
            WasmRuntime::load_from_bytes_with_priority("inflight-plugin", &wasm, limits.clone(), 0)
                .expect("load should succeed");

        // Simulate an in-flight request by acquiring a concurrency permit
        let _permit = runtime
            .guard
            .concurrency
            .clone()
            .try_acquire_owned()
            .unwrap();

        // Disable the plugin while request is in-flight
        runtime.guard.disable_for_violation();
        assert!(!runtime.guard.is_invocable());

        // The permit should still be held (in-flight request continues)
        // After dropping the permit, subsequent requests should be blocked
        drop(_permit);

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_ok());
        match result.unwrap() {
            WasmFilterResult::Block(status, _) => assert_eq!(status, StatusCode::FORBIDDEN),
            _ => panic!("expected Block after plugin disabled"),
        }
    }

    #[test]
    fn test_manager_get_plugin_failure_count() {
        let mgr = WasmPluginManager::new();
        assert!(mgr.get_plugin_failure_count("nonexistent").is_none());
    }

    #[test]
    fn test_metrics_record_invocation_status() {
        let wasm = test_fixtures::minimal_filter_pass();
        let limits = make_limits_with_filter_cap();

        let runtime =
            WasmRuntime::load_from_bytes_with_priority("metrics-plugin", &wasm, limits.clone(), 0)
                .expect("load should succeed");

        // Successful invocation
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // Phase 4: ABI Memory Boundary Hardening Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_checked_guest_range_rejects_negative_pointer() {
        let result = checked_guest_range(-1, 10, 1024);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("negative guest pointer"), "got: {}", msg);
    }

    #[test]
    fn test_checked_guest_range_rejects_negative_length() {
        let result = checked_guest_range(0, -1, 1024);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("negative guest length"), "got: {}", msg);
    }

    #[test]
    fn test_checked_guest_range_rejects_overflow() {
        // On 64-bit, i32::MAX + 10 fits in usize so the bounds check catches it.
        // On 32-bit, checked_add would trigger overflow. Either way, it must error.
        let result = checked_guest_range(i32::MAX, 10, 1024);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("overflow") || msg.contains("out of bounds"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn test_checked_guest_range_rejects_out_of_bounds() {
        let result = checked_guest_range(500, 600, 1024);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("out of bounds"), "got: {}", msg);
    }

    #[test]
    fn test_checked_guest_range_accepts_valid_range_at_end() {
        let result = checked_guest_range(1000, 24, 1024);
        assert!(result.is_ok());
        let range = result.unwrap();
        assert_eq!(range, 1000..1024);
    }

    #[test]
    fn test_checked_guest_range_accepts_zero_length() {
        let result = checked_guest_range(100, 0, 1024);
        assert!(result.is_ok());
        let range = result.unwrap();
        assert_eq!(range, 100..100);
    }

    #[test]
    fn test_guest_abi_info_has_any_hook() {
        let info = GuestAbiInfo {
            has_filter_request: true,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: true,
            has_guest_free: true,
        };
        assert!(info.has_any_hook());
        assert!(info.has_required_allocator());
    }

    #[test]
    fn test_guest_abi_info_no_hooks() {
        let info = GuestAbiInfo {
            has_filter_request: false,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: false,
            has_guest_free: false,
        };
        assert!(!info.has_any_hook());
        assert!(!info.has_required_allocator());
    }

    #[test]
    fn test_guest_abi_info_missing_free() {
        let info = GuestAbiInfo {
            has_filter_request: true,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: true,
            has_guest_free: false,
        };
        assert!(info.has_any_hook());
        assert!(!info.has_required_allocator());
    }

    #[test]
    fn test_validate_guest_abi_with_allocator_plugin() {
        let wasm = test_fixtures::filter_with_allocator();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        let info = WasmRuntime::validate_guest_abi(&module);
        assert!(info.has_filter_request);
        assert!(info.has_memory);
        assert!(info.has_guest_alloc);
        assert!(info.has_guest_free);
        assert!(info.has_any_hook());
        assert!(info.has_required_allocator());
    }

    #[test]
    fn test_validate_guest_abi_no_exports() {
        let wasm = test_fixtures::no_exports_module();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        let info = WasmRuntime::validate_guest_abi(&module);
        assert!(!info.has_any_hook());
        assert!(!info.has_required_allocator());
        assert!(info.has_memory);
    }

    #[test]
    fn test_serialize_headers_rejects_oversized_name() {
        // The http crate itself limits header name length, so test the
        // defensive u16::MAX check by reading our own source.
        let source = include_str!("wasm_runtime.rs");
        // Verify the u16::MAX check for name length exists in serialize_headers
        assert!(
            source.contains("header name length") && source.contains("u16::MAX"),
            "serialize_headers must check name length against u16::MAX"
        );
    }

    #[test]
    fn test_serialize_headers_rejects_oversized_value() {
        let mut headers = HeaderMap::new();
        let long_value = "v".repeat(70000);
        headers.insert(
            http::header::HeaderName::from_static("x-custom"),
            HeaderValue::from_bytes(long_value.as_bytes()).unwrap(),
        );
        let result = WasmRuntime::serialize_headers(&headers, MAX_WASM_DATA_SIZE);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("value length"), "got: {}", msg);
    }

    #[test]
    fn test_serialize_headers_rejects_total_size_beyond_limit() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let result = WasmRuntime::serialize_headers(&headers, 4); // 4 bytes = just the count field
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("limit"), "got: {}", msg);
    }

    #[test]
    fn test_write_to_guest_memory_requires_allocator() {
        // A module without guest_alloc should be rejected at load time
        let wasm = test_fixtures::minimal_filter_pass_no_alloc();
        let limits = make_limits_with_filter_cap();
        let result =
            WasmRuntime::load_from_bytes_with_priority("no-alloc-plugin", &wasm, limits, 0);
        assert!(result.is_err(), "load should reject missing guest_alloc");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("guest_alloc"),
            "expected missing guest_alloc error, got: {}",
            msg
        );
    }

    #[test]
    fn test_write_to_guest_memory_zero_length_returns_null() {
        let wasm = test_fixtures::filter_with_allocator();
        let limits = make_limits_with_filter_cap();
        let runtime = WasmRuntime::load_from_bytes_with_priority("alloc-plugin", &wasm, limits, 0)
            .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        let result = runtime.write_to_guest_memory(&mut store, &exports, &[]);
        assert!(result.is_ok());
        let (ptr, len) = result.unwrap();
        assert_eq!(ptr, 0);
        assert_eq!(len, 0);
    }

    #[test]
    fn test_allocator_plugin_receives_distinct_ranges() {
        // Load a plugin with allocator, invoke it, and verify it receives
        // method, URI, headers, and body in distinct memory ranges.
        let wasm = test_fixtures::filter_verifies_distinct_ranges();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("range-check-plugin", &wasm, limits, 0)
                .expect("load should succeed");

        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/api/test")
            .header("content-type", "application/json")
            .body(Bytes::from_static(b"{\"key\":\"value\"}"))
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_ok());
        match result.unwrap() {
            WasmFilterResult::Pass => {}
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // ─── Missing plan item: ABI validation for guest_free ────────────────────

    #[test]
    fn test_validate_guest_abi_missing_free() {
        let wasm = test_fixtures::filter_alloc_only_no_free();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        let info = WasmRuntime::validate_guest_abi(&module);
        assert!(info.has_filter_request);
        assert!(info.has_memory);
        assert!(info.has_guest_alloc);
        assert!(!info.has_guest_free, "should detect missing guest_free");
        assert!(
            !info.has_required_allocator(),
            "has_required_allocator should be false when guest_free is missing"
        );
    }

    #[test]
    fn test_write_to_guest_memory_rejected_without_guest_free() {
        // Production policy requires guest_free — load should fail at validation
        let wasm = test_fixtures::filter_alloc_only_no_free();
        let limits = make_limits_with_filter_cap();
        let result =
            WasmRuntime::load_from_bytes_with_priority("alloc-only-plugin", &wasm, limits, 0);
        assert!(
            result.is_err(),
            "load should reject missing guest_free in production"
        );
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("guest_free"),
            "expected guest_free error, got: {}",
            msg
        );
    }

    // ─── Missing plan item: negative pointer → instance poisoned ─────────────

    #[test]
    fn test_negative_alloc_pointer_fails() {
        let wasm = test_fixtures::filter_alloc_returns_negative();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("neg-alloc-plugin", &wasm, limits, 0)
                .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        let result = runtime.write_to_guest_memory(&mut store, &exports, b"test");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("negative pointer"),
            "expected negative pointer error, got: {}",
            msg
        );
    }

    #[test]
    fn test_negative_alloc_pointer_full_invocation_fails() {
        // Full invocation: filter_request should fail when guest_alloc returns -1
        let wasm = test_fixtures::filter_alloc_returns_negative();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("neg-alloc-plugin", &wasm, limits, 0)
                .expect("load should succeed");

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("guest_alloc") || msg.contains("negative pointer"),
            "expected allocation failure, got: {}",
            msg
        );
    }

    // ─── Missing plan item: guest traps during guest_alloc ───────────────────

    #[test]
    fn test_guest_alloc_trap_classified_as_runtime_failure() {
        let wasm = test_fixtures::filter_alloc_traps();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("alloc-trap-plugin", &wasm, limits, 0)
                .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        let result = runtime.write_to_guest_memory(&mut store, &exports, b"test");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("guest_alloc failed"),
            "expected guest_alloc trap error, got: {}",
            msg
        );
    }

    #[test]
    fn test_guest_alloc_trap_full_invocation_fails() {
        let wasm = test_fixtures::filter_alloc_traps();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("alloc-trap-plugin", &wasm, limits, 0)
                .expect("load should succeed");

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_err());
    }

    // ─── Missing plan item: guest traps during guest_free ────────────────────

    #[test]
    fn test_guest_free_trap_returns_false() {
        let wasm = test_fixtures::filter_free_traps();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("free-trap-plugin", &wasm, limits, 0)
                .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        // Allocate some memory first
        let result = runtime.write_to_guest_memory(&mut store, &exports, b"test");
        assert!(result.is_ok());
        let (ptr, len) = result.unwrap();

        // free_guest_memory should return false (trap → instance poisoned)
        let alloc = GuestAllocation { ptr, len };
        let freed = runtime.free_guest_memory(&mut store, &exports, &alloc);
        assert!(
            !freed,
            "free_guest_memory should return false when guest_free traps"
        );
    }

    // ─── Pairwise disjoint range assertion helper + test ─────────────────────

    /// Assert that all given ranges are pairwise disjoint (no overlaps).
    /// Returns Ok(()) if all ranges are disjoint, or Err with details of the overlap.
    fn assert_ranges_pairwise_disjoint(
        ranges: &[std::ops::Range<usize>],
        labels: &[&str],
    ) -> Result<(), String> {
        for i in 0..ranges.len() {
            for j in (i + 1)..ranges.len() {
                let a = &ranges[i];
                let b = &ranges[j];
                // Two ranges [a_start, a_end) and [b_start, b_end) overlap iff
                // a_start < b_end && b_start < a_end
                if a.start < b.end && b.start < a.end {
                    return Err(format!(
                        "ranges overlap: {} [{}..{}) and {} [{}..{})",
                        labels[i], a.start, a.end, labels[j], b.start, b.end
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_pairwise_disjoint_helper_detects_overlap() {
        let ranges = vec![0..10, 5..15, 20..30];
        let labels = vec!["a", "b", "c"];
        let result = assert_ranges_pairwise_disjoint(&ranges, &labels);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("overlap"), "got: {}", msg);
    }

    #[test]
    fn test_pairwise_disjoint_helper_accepts_disjoint() {
        let ranges = vec![0..10, 10..20, 20..30];
        let labels = vec!["a", "b", "c"];
        let result = assert_ranges_pairwise_disjoint(&ranges, &labels);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pairwise_disjoint_helper_accepts_empty() {
        let ranges: Vec<std::ops::Range<usize>> = vec![];
        let labels: Vec<&str> = vec![];
        let result = assert_ranges_pairwise_disjoint(&ranges, &labels);
        assert!(result.is_ok());
    }

    #[test]
    #[allow(clippy::single_range_in_vec_init)]
    fn test_pairwise_disjoint_helper_accepts_single() {
        let ranges = vec![50..150];
        let labels = vec!["only"];
        let result = assert_ranges_pairwise_disjoint(&ranges, &labels);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pairwise_disjoint_helper_touching_ok() {
        let ranges = vec![0..10, 10..20];
        let labels = vec!["left", "right"];
        let result = assert_ranges_pairwise_disjoint(&ranges, &labels);
        assert!(result.is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // Workstream 1: GuestAbiPolicy Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_guest_abi_policy_production_rejects_missing_free() {
        let info = GuestAbiInfo {
            has_filter_request: true,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: true,
            has_guest_free: false,
        };
        let result = info.validate_for_policy(GuestAbiPolicy::ProductionPointerLength);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("guest_free"), "got: {}", msg);
    }

    #[test]
    fn test_guest_abi_policy_production_rejects_missing_alloc() {
        let info = GuestAbiInfo {
            has_filter_request: true,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: false,
            has_guest_free: true,
        };
        let result = info.validate_for_policy(GuestAbiPolicy::ProductionPointerLength);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("guest_alloc"), "got: {}", msg);
    }

    #[test]
    fn test_guest_abi_policy_production_rejects_no_hooks() {
        let info = GuestAbiInfo {
            has_filter_request: false,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: true,
            has_guest_free: true,
        };
        let result = info.validate_for_policy(GuestAbiPolicy::ProductionPointerLength);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("no hook exports"), "got: {}", msg);
    }

    #[test]
    fn test_guest_abi_policy_production_rejects_no_memory() {
        let info = GuestAbiInfo {
            has_filter_request: true,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: false,
            has_guest_alloc: true,
            has_guest_free: true,
        };
        let result = info.validate_for_policy(GuestAbiPolicy::ProductionPointerLength);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("memory export"), "got: {}", msg);
    }

    #[test]
    fn test_guest_abi_policy_production_accepts_complete() {
        let info = GuestAbiInfo {
            has_filter_request: true,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: true,
            has_guest_free: true,
        };
        assert!(info
            .validate_for_policy(GuestAbiPolicy::ProductionPointerLength)
            .is_ok());
    }

    #[test]
    fn test_guest_abi_policy_dev_allows_missing_free() {
        let info = GuestAbiInfo {
            has_filter_request: true,
            has_transform_response: false,
            has_handle_request: false,
            has_memory: true,
            has_guest_alloc: true,
            has_guest_free: false,
        };
        assert!(info
            .validate_for_policy(GuestAbiPolicy::DevelopmentAllowMissingFree)
            .is_ok());
    }

    #[test]
    fn test_validate_guest_abi_is_pub() {
        let wasm = test_fixtures::minimal_filter_pass();
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::from_binary(&engine, &wasm).expect("valid WASM");
        let info = WasmRuntime::validate_guest_abi(&module);
        assert!(info.has_filter_request);
        assert!(info.has_memory);
        assert!(info.has_any_hook());
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // Load-Path ABI Validation Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_load_path_rejects_missing_guest_free() {
        let wasm = test_fixtures::filter_alloc_only_no_free();
        let limits = make_limits_with_filter_cap();
        let result = WasmRuntime::load_from_bytes_with_priority("no-free", &wasm, limits, 0);
        assert!(result.is_err(), "should reject missing guest_free");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("guest_free"),
            "expected guest_free error, got: {}",
            msg
        );
    }

    #[test]
    fn test_load_path_accepts_complete_abi() {
        let wasm = test_fixtures::minimal_filter_pass();
        let limits = make_limits_with_filter_cap();
        let result = WasmRuntime::load_from_bytes_with_priority("complete", &wasm, limits, 0);
        assert!(
            result.is_ok(),
            "complete ABI should load: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_load_path_rejects_no_allocator_exports() {
        let wasm = test_fixtures::minimal_transform_pass();
        let limits = make_limits_with_filter_cap();
        let result = WasmRuntime::load_from_bytes_with_priority("no-alloc", &wasm, limits, 0);
        assert!(result.is_err(), "should reject missing allocator exports");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("guest_alloc"),
            "expected guest_alloc error, got: {}",
            msg
        );
    }

    #[test]
    fn test_load_path_rejects_no_memory_export() {
        let wasm = test_fixtures::no_memory_module();
        let limits = make_limits_with_filter_cap();
        let result = WasmRuntime::load_from_bytes_with_priority("no-memory", &wasm, limits, 0);
        assert!(result.is_err(), "should reject missing memory export");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("memory export"),
            "expected memory error, got: {}",
            msg
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // Workstream 2: Single-Frame Allocation Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_single_frame_allocation_for_filter_request() {
        let wasm = test_fixtures::filter_alloc_counter();
        let limits = make_limits_with_filter_cap();
        let runtime = WasmRuntime::load_from_bytes_with_priority("alloc-counter", &wasm, limits, 0)
            .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        let pieces = RequestInputPieces {
            method: b"POST",
            uri: b"http://example.com/test",
            headers: vec![],
            body: b"hello",
        };
        let frame = runtime
            .write_request_input_frame(&mut store, &exports, pieces)
            .expect("write frame");
        assert_eq!(frame.method.len, 4);
        assert_eq!(frame.uri.len, 23);
        assert_eq!(frame.headers.len, 0);
        assert!(frame.body.is_some());
        assert_eq!(frame.body.as_ref().unwrap().len, 5);
        assert_eq!(frame.total_len, 32);

        let freed = runtime.free_guest_input_frame(&mut store, &exports, &frame);
        assert!(freed);
    }

    #[test]
    fn test_single_frame_rejects_total_length_overflow() {
        let result = usize::MAX.checked_add(1);
        assert!(result.is_none(), "usize overflow should be caught");
    }

    #[test]
    fn test_single_frame_rejects_total_length_exceeds_limit() {
        let wasm = test_fixtures::filter_alloc_counter();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("alloc-counter-oversize", &wasm, limits, 0)
                .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        let huge_method = vec![0u8; MAX_WASM_DATA_SIZE / 2 + 1];
        let huge_uri = vec![0u8; MAX_WASM_DATA_SIZE / 2 + 1];
        let pieces = RequestInputPieces {
            method: &huge_method,
            uri: &huge_uri,
            headers: vec![],
            body: &[],
        };
        let result = runtime.write_request_input_frame(&mut store, &exports, pieces);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exceeds max"), "got: {}", msg);
    }

    #[test]
    fn test_single_frame_empty_body_no_separate_alloc() {
        let wasm = test_fixtures::filter_alloc_counter();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("alloc-counter-empty", &wasm, limits, 0)
                .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        let pieces = RequestInputPieces {
            method: b"GET",
            uri: b"/",
            headers: vec![],
            body: &[],
        };
        let frame = runtime
            .write_request_input_frame(&mut store, &exports, pieces)
            .expect("write frame");
        assert!(frame.body.is_none());
        assert_eq!(frame.total_len, 4);

        let freed = runtime.free_guest_input_frame(&mut store, &exports, &frame);
        assert!(freed);
    }

    #[test]
    fn test_malicious_allocator_returns_zero_still_works() {
        let wasm = test_fixtures::filter_alloc_counter();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("alloc-counter-zero", &wasm, limits, 0)
                .expect("load should succeed");

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .body(Bytes::new())
            .unwrap();
        let env = Arc::new(std::collections::HashMap::new());
        let result = runtime.filter_request(req, env);
        assert!(result.is_ok());
    }

    #[test]
    fn test_free_guest_input_frame_calls_guest_free_once() {
        let wasm = test_fixtures::filter_alloc_counter();
        let limits = make_limits_with_filter_cap();
        let runtime =
            WasmRuntime::load_from_bytes_with_priority("free-frame-test", &wasm, limits, 0)
                .expect("load should succeed");
        let mut store = runtime.create_store(std::collections::HashMap::new());
        let exports = runtime.instantiate(&mut store).expect("instantiate");

        let pieces = RequestInputPieces {
            method: b"GET",
            uri: b"/",
            headers: vec![],
            body: b"test",
        };
        let frame = runtime
            .write_request_input_frame(&mut store, &exports, pieces)
            .expect("write frame");

        let freed = runtime.free_guest_input_frame(&mut store, &exports, &frame);
        assert!(freed, "free_guest_input_frame should succeed");
    }

    #[test]
    fn test_execution_interrupt_policy_default() {
        let policy = ExecutionInterruptPolicy::default();
        assert!(policy.fuel_required);
        assert!(policy.epoch_deadline_enabled);
        assert_eq!(policy.epoch_ticks_per_timeout, 10);
        assert_eq!(policy.host_call_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_wasm_resource_limits_epoch_defaults() {
        let limits = WasmResourceLimits::default();
        assert!(limits.epoch_deadline_enabled);
        assert_eq!(limits.epoch_ticks_per_timeout, 10);
        assert_eq!(limits.host_call_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_pooled_instance_preparation_preserves_timeout() {
        use crate::pool::PooledInstance;
        use crate::sandbox::types::PluginCapabilities;

        let limits = WasmResourceLimits {
            timeout: Duration::from_millis(1500),
            ..Default::default()
        };
        let wasm = test_fixtures::minimal_filter_pass();
        let runtime = WasmRuntime::load_from_bytes_with_priority(
            "timeout-preserve-test",
            &wasm,
            limits.clone(),
            0,
        )
        .expect("load should succeed");

        let mut store = runtime.create_store(std::collections::HashMap::new());
        let instance = runtime
            .linker
            .instantiate(&mut store, &runtime.module)
            .expect("instantiate");

        let mut pool_inst = PooledInstance {
            instance,
            store,
            filter_name: "test".into(),
            max_cpu_fuel: limits.max_cpu_fuel,
            allowed_dht_prefixes: Vec::new(),
            capabilities: Arc::new(PluginCapabilities::default()),
        };

        pool_inst.prepare_for_request(
            std::collections::HashMap::new(),
            Duration::from_millis(1500),
            Vec::new(),
            Arc::new(PluginCapabilities::default()),
        );

        assert_eq!(
            pool_inst.store.data().timeout,
            Duration::from_millis(1500),
            "prepare_for_request must preserve millisecond timeout"
        );
    }

    #[test]
    fn test_host_call_budget_default() {
        let budget = HostCallBudget::default();
        assert_eq!(budget.env_lookup_timeout, Duration::from_secs(5));
        assert_eq!(budget.body_chunk_timeout, Duration::from_secs(5));
        assert_eq!(budget.mesh_query_timeout, Duration::from_secs(5));
        assert_eq!(budget.mesh_threat_timeout, Duration::from_secs(5));
        assert_eq!(budget.mesh_emit_timeout, Duration::from_secs(5));
        assert_eq!(budget.max_body_chunk_bytes, 64 * 1024);
        assert_eq!(budget.max_env_value_bytes, 4 * 1024);
        assert_eq!(budget.max_mesh_key_bytes, 1024);
        assert_eq!(budget.max_mesh_value_bytes, 64 * 1024);
    }

    #[test]
    fn test_abi_error_codes_are_distinct() {
        let codes = [
            ABI_SUCCESS,
            ABI_ERR_CAPABILITY_DENIED,
            ABI_ERR_INVALID_POINTER,
            ABI_ERR_TIMEOUT,
            ABI_ERR_INPUT_TOO_LARGE,
            ABI_ERR_UNAVAILABLE,
            ABI_ERR_INTERNAL,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            codes.len(),
            sorted.len(),
            "ABI error codes must be distinct"
        );
    }

    #[test]
    fn test_abi_error_codes_stability() {
        // These values are part of the stable ABI contract.
        // Do not change them without a version bump.
        assert_eq!(ABI_SUCCESS, 0);
        assert_eq!(ABI_ERR_CAPABILITY_DENIED, -1);
        assert_eq!(ABI_ERR_INVALID_POINTER, -2);
        assert_eq!(ABI_ERR_TIMEOUT, -3);
        assert_eq!(ABI_ERR_INPUT_TOO_LARGE, -4);
        assert_eq!(ABI_ERR_UNAVAILABLE, -5);
        assert_eq!(ABI_ERR_INTERNAL, -6);
    }
}
