use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Configuration for unsafe native extension plugins.
///
/// Native extensions run with full Synvoid process authority: memory access,
/// arbitrary syscalls, panic/UB potential, allocator interaction, and thread
/// spawning. They are NOT sandboxed and must only be loaded from trusted sources.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, JsonSchema, ToSchema)]
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
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, JsonSchema, ToSchema)]
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
    /// Main native extension config.
    #[serde(default)]
    pub unsafe_native: UnsafeNativePluginConfig,
    /// Deprecated alias for `unsafe_native`. If set, the value is migrated to `unsafe_native`
    /// and a deprecation warning is logged at startup.
    #[serde(default, alias = "native_plugins")]
    pub native_plugins_compat: Option<UnsafeNativePluginConfig>,
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

impl PluginConfig {
    /// Migrate deprecated `native_plugins_compat` into `unsafe_native` if set.
    ///
    /// Returns `true` if migration occurred (caller should log a deprecation warning).
    pub fn migrate_deprecated_native_plugins(&mut self) -> bool {
        if let Some(legacy) = self.native_plugins_compat.take() {
            tracing::warn!(
                "DEPRECATION: [plugins.native_plugins] is deprecated. \
                 Use [plugins.unsafe_native] instead."
            );
            // Only overwrite if the new section is at defaults (not explicitly configured)
            if self.unsafe_native == UnsafeNativePluginConfig::default() {
                self.unsafe_native = legacy;
            }
            true
        } else {
            false
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults_disabled() {
        let config = UnsafeNativePluginConfig::default();
        assert!(!config.enabled);
        assert!(!config.allow_in_production);
        assert!(!config.hot_reload_enabled);
        assert!(config.risk_acknowledgement.is_none());
        assert!(config.allowed_dirs.is_empty());
        assert!(config.allowed_libraries.is_empty());
    }

    #[test]
    fn test_deprecated_config_key_maps_to_new_key() {
        let toml = r#"
[native_plugins]
enabled = true
allow_in_production = true
risk_acknowledgement = "I understand native extensions run with full Synvoid process authority"
allowed_dirs = ["/opt/native"]
hot_reload_enabled = true
"#;
        let mut config: PluginConfig = toml::from_str(toml).unwrap();
        assert!(config.native_plugins_compat.is_some());
        assert!(!config.unsafe_native.enabled);

        let migrated = config.migrate_deprecated_native_plugins();
        assert!(
            migrated,
            "migration should return true when compat key is present"
        );
        assert!(config.native_plugins_compat.is_none());
        assert!(config.unsafe_native.enabled);
        assert!(config.unsafe_native.allow_in_production);
        assert!(config.unsafe_native.hot_reload_enabled);
        assert_eq!(
            config.unsafe_native.risk_acknowledgement.as_deref(),
            Some("I understand native extensions run with full Synvoid process authority")
        );
        assert_eq!(config.unsafe_native.allowed_dirs, vec!["/opt/native"]);
    }

    #[test]
    fn test_deprecated_config_does_not_overwrite_explicit_new_config() {
        let toml = r#"
[unsafe_native]
enabled = true
allow_in_production = true

[native_plugins]
enabled = false
"#;
        let mut config: PluginConfig = toml::from_str(toml).unwrap();
        let migrated = config.migrate_deprecated_native_plugins();
        assert!(migrated);
        // Should NOT overwrite because unsafe_native was explicitly configured (non-default)
        assert!(config.unsafe_native.enabled);
        assert!(config.unsafe_native.allow_in_production);
    }

    #[test]
    fn test_no_deprecated_key_no_migration() {
        let toml = r#"
[unsafe_native]
enabled = true
"#;
        let mut config: PluginConfig = toml::from_str(toml).unwrap();
        let migrated = config.migrate_deprecated_native_plugins();
        assert!(
            !migrated,
            "migration should return false when no compat key"
        );
        assert!(config.unsafe_native.enabled);
    }
}
