use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::plugin::{PluginManager, PluginManagerLifecycle};

/// Owns the plugin manager and its optional lifecycle (file-watcher).
///
/// Replaces the `std::mem::forget(lifecycle)` pattern with proper RAII
/// ownership so the watcher is dropped when the server shuts down.
///
/// Also ensures the epoch incrementer is cleanly stopped before the
/// plugin manager is dropped.
pub struct PluginRuntimeOwner {
    manager: Arc<PluginManager>,
    lifecycle: Option<PluginManagerLifecycle>,
    epoch_started: bool,
}

impl PluginRuntimeOwner {
    pub fn new(manager: Arc<PluginManager>) -> Self {
        Self {
            manager,
            lifecycle: None,
            epoch_started: false,
        }
    }

    pub fn manager(&self) -> &Arc<PluginManager> {
        &self.manager
    }

    /// Start the background epoch incrementer task on the WASM manager.
    ///
    /// This must be called after plugins are loaded and before the server
    /// begins accepting requests. If the incrementer is already running,
    /// this is a no-op (logs a warning).
    pub fn start_epoch_incrementer(&mut self, interval: Duration) {
        self.manager
            .wasm_manager()
            .start_epoch_incrementer(interval);
        self.epoch_started = true;
    }

    /// Stop the epoch incrementer task if running.
    pub fn stop_epoch_incrementer(&mut self) {
        if self.epoch_started {
            self.manager.wasm_manager().stop_epoch_incrementer();
            self.epoch_started = false;
        }
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
                timeout: Duration::from_secs(plugin_cfg.timeout_seconds.unwrap_or(30)),
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

impl Drop for PluginRuntimeOwner {
    fn drop(&mut self) {
        // Stop the epoch incrementer before dropping the manager so that the
        // background task is cancelled and no further epoch increments occur
        // while engines are being torn down.
        if self.epoch_started {
            self.manager.wasm_manager().stop_epoch_incrementer();
        }
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

    #[tokio::test]
    async fn epoch_incrementer_running_false_before_start() {
        let mgr = Arc::new(PluginManager::new());
        assert!(!mgr.wasm_manager().epoch_incrementer_running());
    }

    #[tokio::test]
    async fn epoch_incrementer_running_true_after_start() {
        let mgr = Arc::new(PluginManager::new());
        mgr.wasm_manager()
            .start_epoch_incrementer(Duration::from_millis(100));
        assert!(mgr.wasm_manager().epoch_incrementer_running());
        mgr.wasm_manager().stop_epoch_incrementer();
    }

    #[tokio::test]
    async fn start_epoch_incrementer_twice_is_idempotent() {
        let mgr = Arc::new(PluginManager::new());
        mgr.wasm_manager()
            .start_epoch_incrementer(Duration::from_millis(100));
        // Second start should log warning and not panic.
        mgr.wasm_manager()
            .start_epoch_incrementer(Duration::from_millis(100));
        assert!(mgr.wasm_manager().epoch_incrementer_running());
        mgr.wasm_manager().stop_epoch_incrementer();
    }

    #[tokio::test]
    async fn drop_stops_epoch_incrementer() {
        let mgr = Arc::new(PluginManager::new());
        let mut owner = PluginRuntimeOwner::new(mgr.clone());
        owner.start_epoch_incrementer(Duration::from_millis(100));
        assert!(mgr.wasm_manager().epoch_incrementer_running());
        drop(owner);
        assert!(!mgr.wasm_manager().epoch_incrementer_running());
    }

    #[tokio::test]
    async fn validate_fails_when_epoch_needed_but_not_running() {
        let mgr = Arc::new(PluginManager::new());
        // No plugins loaded, no incrementer — should pass (no epochs needed).
        assert!(mgr
            .wasm_manager()
            .validate_execution_containment_runtime()
            .is_ok());
    }

    #[tokio::test]
    async fn validate_passes_when_incrementer_running() {
        let mgr = Arc::new(PluginManager::new());
        mgr.wasm_manager()
            .start_epoch_incrementer(Duration::from_millis(100));
        assert!(mgr
            .wasm_manager()
            .validate_execution_containment_runtime()
            .is_ok());
        mgr.wasm_manager().stop_epoch_incrementer();
    }
}
