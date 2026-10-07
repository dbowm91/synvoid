use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

fn default_ipc_enforce_signing() -> bool {
    true
}

fn default_global_security_headers() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
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
    #[serde(default)]
    pub strict_tls_passthrough_policy: bool,
}

impl Default for MainSecurityConfig {
    /// Hand-written so the struct default matches the serde field defaults.
    ///
    /// The derive produced `false` for `ipc_enforce_signing`,
    /// `sanitize_forwarded_headers` and `global_security_headers` where TOML
    /// parsing produced `true` — a fail-open default on an authentication
    /// boundary for any construction path that used `default()` instead of a
    /// parsed file.
    fn default() -> Self {
        Self {
            more_clear_headers: Vec::new(),
            sanitize_forwarded_headers: default_sanitize_forwarded(),
            global_security_headers: default_global_security_headers(),
            ipc_enforce_signing: default_ipc_enforce_signing(),
            ipc_session_key_env: None,
            allow_insecure_ipc_key: false,
            strict_tls_passthrough_policy: false,
        }
    }
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
    Some("/var/cache/synvoid/minified".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_tls_passthrough_policy_default_is_false() {
        assert!(!MainSecurityConfig::default().strict_tls_passthrough_policy);
    }

    #[test]
    fn strict_tls_passthrough_policy_backward_compat_missing_field() {
        let toml_str = r#"
more_clear_headers = ["X-Request-Id"]
sanitize_forwarded_headers = true
"#;
        let config: MainSecurityConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.strict_tls_passthrough_policy);
    }

    #[test]
    fn strict_tls_passthrough_policy_explicit_true() {
        let toml_str = r#"
strict_tls_passthrough_policy = true
"#;
        let config: MainSecurityConfig = toml::from_str(toml_str).unwrap();
        assert!(config.strict_tls_passthrough_policy);
    }
}
