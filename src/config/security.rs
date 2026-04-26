use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

fn default_ipc_enforce_signing() -> bool {
    true
}

fn default_global_security_headers() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct MainSecurityConfig {
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default = "default_sanitize_forwarded")]
    pub sanitize_forwarded_headers: bool,
    #[serde(default = "default_global_security_headers")]
    pub global_security_headers: bool,
    #[serde(default = "default_ipc_enforce_signing")]
    pub ipc_enforce_signing: bool,
    #[serde(default)]
    pub ipc_session_key_env: Option<String>,
    #[serde(default)]
    pub allow_insecure_ipc_key: bool,
}

fn default_sanitize_forwarded() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct MainStaticConfig {
    #[serde(default = "default_static_worker_enabled")]
    pub enabled: Option<bool>,
    #[serde(default = "default_watch_interval_ms")]
    pub watch_interval_ms: Option<u64>,
    #[serde(default = "default_preload_on_startup")]
    pub preload_on_startup: Option<bool>,
    #[serde(default = "default_minified_base_dir")]
    pub minified_base_dir: Option<String>,
}

fn default_static_worker_enabled() -> Option<bool> {
    Some(true)
}

fn default_watch_interval_ms() -> Option<u64> {
    Some(5000)
}

fn default_preload_on_startup() -> Option<bool> {
    Some(true)
}

fn default_minified_base_dir() -> Option<String> {
    Some("/var/cache/maluwaf/minified".to_string())
}
