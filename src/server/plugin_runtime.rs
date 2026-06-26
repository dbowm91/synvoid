use std::path::Path;
use std::sync::Arc;

use crate::plugin::{PluginManager, PluginManagerLifecycle};

/// Owns the plugin manager and its optional lifecycle (file-watcher).
///
/// Replaces the `std::mem::forget(lifecycle)` pattern with proper RAII
/// ownership so the watcher is dropped when the server shuts down.
pub struct PluginRuntimeOwner {
    manager: Arc<PluginManager>,
    lifecycle: Option<PluginManagerLifecycle>,
}

impl PluginRuntimeOwner {
    pub fn new(manager: Arc<PluginManager>) -> Self {
        Self {
            manager,
            lifecycle: None,
        }
    }

    pub fn manager(&self) -> &Arc<PluginManager> {
        &self.manager
    }

    /// Load all WASM plugins declared in the config.
    pub fn load_configured_plugins(
        &mut self,
        plugin_configs: &[crate::config::plugins::WasmPluginInstanceConfig],
    ) -> PluginRuntimeReport {
        let mut loaded = 0;
        let mut failed = 0;
        for plugin_cfg in plugin_configs {
            let limits = crate::plugin::WasmResourceLimits {
                max_memory_mb: plugin_cfg.max_memory_mb.unwrap_or(256),
                max_cpu_fuel: plugin_cfg.max_cpu_fuel.unwrap_or(1_000_000),
                timeout_seconds: plugin_cfg.timeout_seconds.unwrap_or(30),
                allowed_dht_prefixes: plugin_cfg.allowed_dht_prefixes.clone(),
                ..Default::default()
            };
            let path = Path::new(&plugin_cfg.path);
            match self
                .manager
                .wasm_manager()
                .load_plugin_with_limits(path, limits)
            {
                Ok(_) => {
                    loaded += 1;
                    tracing::info!("Loaded WASM plugin: {}", plugin_cfg.name);
                }
                Err(e) => {
                    failed += 1;
                    tracing::error!("Failed to load WASM plugin {}: {}", plugin_cfg.name, e);
                }
            }
        }
        PluginRuntimeReport { loaded, failed }
    }

    /// Enable hot-reload for the given plugin directory.
    ///
    /// Loads any existing plugins from the directory, then starts a file watcher
    /// that automatically reloads modified `.wasm`/`.wat` files. The watcher is
    /// owned by `self` and will be stopped when the `PluginRuntimeOwner` is
    /// dropped.
    pub fn enable_hot_reload_if_configured(&mut self, plugin_dir: &Path) -> Result<(), String> {
        if !plugin_dir.is_dir() {
            return Err(format!(
                "plugin directory does not exist: {}",
                plugin_dir.display()
            ));
        }
        let mut lifecycle = PluginManagerLifecycle::new(self.manager.clone());
        match lifecycle.load_plugins_from_dir(plugin_dir) {
            Ok(count) if count > 0 => {
                tracing::info!(
                    "Auto-loaded {} WASM plugins from {}",
                    count,
                    plugin_dir.display()
                );
            }
            _ => {}
        }
        lifecycle.enable_hot_reload(plugin_dir)?;
        self.lifecycle = Some(lifecycle);
        Ok(())
    }
}

#[derive(Debug)]
pub struct PluginRuntimeReport {
    pub loaded: usize,
    pub failed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_owner_has_no_lifecycle() {
        let mgr = Arc::new(PluginManager::new());
        let owner = PluginRuntimeOwner::new(mgr);
        assert!(owner.lifecycle.is_none());
    }

    #[test]
    fn load_empty_config_returns_zero_counts() {
        let mgr = Arc::new(PluginManager::new());
        let mut owner = PluginRuntimeOwner::new(mgr);
        let report = owner.load_configured_plugins(&[]);
        assert_eq!(report.loaded, 0);
        assert_eq!(report.failed, 0);
    }
}
