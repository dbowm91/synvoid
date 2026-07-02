use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Configuration for unsafe native extension plugins.
///
/// Native extensions run with full Synvoid process authority: memory access,
/// arbitrary syscalls, panic/UB potential, allocator interaction, and thread
/// spawning. They are NOT sandboxed and must only be loaded from trusted sources.
#[derive(Debug, Default, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UnsafeNativePluginConfig {
    /// Enable loading of unsafe native extensions. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Allow loading in production mode. Default: false.
    #[serde(default)]
    pub allow_in_production: bool,
    /// Exact risk acknowledgement string required in production.
    #[serde(default)]
    pub risk_acknowledgement: Option<String>,
    /// Directories from which native extensions may be loaded.
    #[serde(default)]
    pub allowed_dirs: Vec<String>,
    /// Whether hot-reload is enabled for native extensions (separate from WASM hot-reload).
    #[serde(default)]
    pub hot_reload_enabled: bool,
    /// Explicit library allowlist with optional hash verification.
    #[serde(default)]
    pub allowed_libraries: Vec<UnsafeNativeAllowedLibrary>,
}

/// An explicitly allowed native library with optional SHA-256 hash verification.
#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UnsafeNativeAllowedLibrary {
    /// Absolute path to the shared library.
    pub path: String,
    /// Expected SHA-256 hex digest. If provided, the library hash must match before loading.
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct PluginConfig {
    #[serde(default)]
    pub wasm: WasmPluginGlobalConfig,
    #[serde(default)]
    pub unsafe_native: UnsafeNativePluginConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct WasmPluginGlobalConfig {
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: usize,
    #[serde(default = "default_max_cpu_fuel")]
    pub max_cpu_fuel: u64,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub plugins: Vec<WasmPluginInstanceConfig>,
}

impl Default for WasmPluginGlobalConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 64,
            max_cpu_fuel: 1_000_000,
            timeout_seconds: 30,
            plugins: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct WasmPluginInstanceConfig {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub max_memory_mb: Option<usize>,
    #[serde(default)]
    pub max_cpu_fuel: Option<u64>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub on_error: Option<super::site::WasmOnError>,
    #[serde(default)]
    pub allowed_dht_prefixes: Vec<String>,
}

fn default_max_memory_mb() -> usize {
    64
}
fn default_max_cpu_fuel() -> u64 {
    1_000_000
}
fn default_timeout_seconds() -> u64 {
    30
}
