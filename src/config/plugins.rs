use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct PluginConfig {
    #[serde(default)]
    pub wasm: WasmPluginGlobalConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
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

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
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
