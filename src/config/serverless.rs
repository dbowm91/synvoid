use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct ServerlessConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub functions: Vec<FunctionDefinition>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
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
}

fn default_handler_name() -> String {
    "handle_request".to_string()
}
