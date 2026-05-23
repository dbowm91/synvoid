use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct ServerlessConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub functions: Vec<FunctionDefinition>,
    #[serde(default = "default_memory_mb")]
    pub default_memory_mb: usize,
    #[serde(default = "default_cpu_fuel")]
    pub default_cpu_fuel: u64,
    #[serde(default = "default_timeout_seconds")]
    pub default_timeout_seconds: u64,
    #[serde(default = "default_waf_mode")]
    pub waf_mode: ServerlessWafMode,
}

fn default_memory_mb() -> usize {
    64
}

fn default_cpu_fuel() -> u64 {
    1000000
}

fn default_timeout_seconds() -> u64 {
    30
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct FunctionDefinition {
    pub name: String,
    pub path: String,
    #[serde(default = "default_handler_name")]
    pub handler: String,
    #[serde(default)]
    pub memory_mb: Option<usize>,
    #[serde(default)]
    pub cpu_fuel: Option<u64>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub pre_warm_instances: Option<usize>,
    #[serde(default)]
    pub min_instances: Option<usize>,
    #[serde(default)]
    pub max_instances: Option<usize>,
    #[serde(default)]
    pub idle_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub routes: Option<Vec<String>>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
    #[serde(default)]
    pub event_subscriptions: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_callers: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_orgs: Option<Vec<String>>,
    #[serde(default)]
    pub require_trusted_caller: bool,
    #[serde(default)]
    pub min_tier_level: Option<u32>,
    #[serde(default)]
    pub public_function: Option<bool>,
    #[serde(default)]
    pub allowed_dht_prefixes: Vec<String>,
}

fn default_handler_name() -> String {
    "handle_request".to_string()
}

#[derive(
    Debug, Deserialize, Serialize, Clone, Copy, Default, JsonSchema, ToSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum ServerlessWafMode {
    #[default]
    Enforce,
    Log,
    Off,
}

fn default_waf_mode() -> ServerlessWafMode {
    ServerlessWafMode::Enforce
}
