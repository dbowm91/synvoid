use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct UpgradeConfig {
    #[serde(default = "default_health_check_path")]
    pub health_check_path: String,
    #[serde(default = "default_health_check_timeout")]
    pub health_check_timeout_secs: u64,
    #[serde(default = "default_validation_retries")]
    pub validation_retries: u32,
    #[serde(default = "default_validation_interval")]
    pub validation_interval_secs: u64,
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
    #[serde(default = "default_drain_check_interval")]
    pub drain_check_interval_ms: u64,
    #[serde(default = "default_port_swap_timeout")]
    pub port_swap_cutover_timeout_ms: u64,
    #[serde(default = "default_keep_old_versions")]
    pub keep_old_versions: usize,
    #[serde(default)]
    pub staged_dir: Option<String>,
    #[serde(default)]
    pub bin_dir: Option<String>,
    #[serde(default)]
    pub force_mode: Option<String>,
}

fn default_health_check_path() -> String {
    "/health".to_string()
}
fn default_health_check_timeout() -> u64 {
    5
}
fn default_validation_retries() -> u32 {
    3
}
fn default_validation_interval() -> u64 {
    5
}
fn default_drain_timeout() -> u64 {
    30
}
fn default_drain_check_interval() -> u64 {
    100
}
fn default_port_swap_timeout() -> u64 {
    500
}
fn default_keep_old_versions() -> usize {
    2
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            health_check_path: default_health_check_path(),
            health_check_timeout_secs: default_health_check_timeout(),
            validation_retries: default_validation_retries(),
            validation_interval_secs: default_validation_interval(),
            drain_timeout_secs: default_drain_timeout(),
            drain_check_interval_ms: default_drain_check_interval(),
            port_swap_cutover_timeout_ms: default_port_swap_timeout(),
            keep_old_versions: default_keep_old_versions(),
            staged_dir: None,
            bin_dir: None,
            force_mode: None,
        }
    }
}
