use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MainSecurityConfig {
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default = "default_sanitize_forwarded")]
    pub sanitize_forwarded_headers: bool,
    #[serde(default)]
    pub global_security_headers: bool,
    #[serde(default)]
    pub ipc_enforce_signing: bool,
    #[serde(default)]
    pub ipc_session_key_env: Option<String>,
}

fn default_sanitize_forwarded() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
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
