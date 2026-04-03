use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;

pub mod axum_loader;
pub mod instance_pool;
pub mod wasm_metrics;
pub mod wasm_runtime;

pub use wasm_runtime::{PluginInfo, WasmPluginManager, WasmResourceLimits, WasmRuntime};

pub enum WasmFilterResult {
    Pass,
    Block(StatusCode, String),
    Challenge(String),
}

#[derive(Debug, thiserror::Error)]
pub enum WasmPluginError {
    #[error("Failed to load WASM module: {0}")]
    LoadFailed(String),
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Sandbox error: {0}")]
    SandboxError(String),
}

// ─── PluginManager (public API) ──────────────────────────────────────────────

pub struct PluginManager {
    wasm_manager: Arc<WasmPluginManager>,
    axum_plugins: RwLock<Vec<Arc<AxumPluginWrapper>>>,
}

struct AxumPluginWrapper {
    router: Arc<axum::Router<()>>,
    name: String,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new()),
            axum_plugins: RwLock::new(Vec::new()),
        }
    }

    pub fn with_wasm_limits(limits: WasmResourceLimits) -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new().with_limits(limits)),
            axum_plugins: RwLock::new(Vec::new()),
        }
    }

    pub fn load_wasm_plugin(&self, path: &Path) -> Result<(), WasmPluginError> {
        if let Some(name) = path.file_stem() {
            if let Some(name_str) = name.to_str() {
                if let Some(wasm_dist) = crate::mesh::get_global_wasm_dist_manager() {
                    if let Some(data) = wasm_dist
                        .get_module_data(name_str, crate::mesh::protocol::WasmModuleType::Plugin)
                    {
                        tracing::debug!("Loading plugin '{}' from mesh WASM store", name_str);
                        self.wasm_manager.load_plugin_from_memory(name_str, &data)?;
                        return Ok(());
                    }
                }
            }
        }
        self.wasm_manager.load_plugin(path)?;
        Ok(())
    }

    pub fn load_axum_plugin(&self, path: &Path) -> Result<Arc<Router>, AxumPluginError> {
        let (router, wrapper_name) = axum_loader::load_plugin(path)?;

        let shared_router = Arc::new(router);
        let wrapper = AxumPluginWrapper {
            router: shared_router.clone(),
            name: wrapper_name.clone(),
        };

        self.axum_plugins.write().push(Arc::new(wrapper));
        tracing::info!("Loaded Axum plugin: {}", wrapper_name);

        Ok(shared_router)
    }

    /// Get the first loaded Axum plugin router, if any
    pub fn get_axum_router(&self) -> Option<Arc<Router>> {
        self.axum_plugins.read().first().map(|w| w.router.clone())
    }

    /// Get all loaded Axum plugin routers
    pub fn get_axum_routers(&self) -> Vec<Arc<Router>> {
        self.axum_plugins
            .read()
            .iter()
            .map(|w| w.router.clone())
            .collect()
    }

    /// Remove an Axum plugin by name. Returns true if found and removed.
    /// The old router stays in memory until all references are dropped.
    pub fn unload_axum_plugin(&self, name: &str) -> bool {
        let mut plugins = self.axum_plugins.write();
        let before = plugins.len();
        plugins.retain(|w| w.name != name);
        plugins.len() < before
    }

    pub fn apply_wasm_filters(
        &self,
        request: Request<Bytes>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        self.wasm_manager.filter_request(request, env)
    }

    pub fn apply_wasm_filters_with_plugins(
        &self,
        request: Request<Bytes>,
        plugin_names: &[String],
        env: std::collections::HashMap<String, String>,
    ) -> Result<WasmFilterResult, WasmPluginError> {
        self.wasm_manager
            .filter_request_with_plugins(request, plugin_names, env)
    }

    pub fn apply_wasm_response_transforms(
        &self,
        response: Response<Bytes>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        self.wasm_manager.transform_response(response, env)
    }

    pub fn apply_wasm_response_transforms_with_plugins(
        &self,
        response: Response<Bytes>,
        plugin_names: &[String],
        env: std::collections::HashMap<String, String>,
    ) -> Result<Response<Bytes>, WasmPluginError> {
        self.wasm_manager
            .transform_response_with_plugins(response, plugin_names, env)
    }

    /// Get the underlying WASM plugin manager
    pub fn wasm_manager(&self) -> &Arc<WasmPluginManager> {
        &self.wasm_manager
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AxumPluginError {
    #[error("Failed to load plugin: {0}")]
    LoadFailed(String),
    #[error("Plugin ABI version {plugin} does not match expected version {expected}")]
    AbiMismatch { plugin: String, expected: String },
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PluginAppManager (lifecycle management) ─────────────────────────────────

/// Manages plugin lifecycle: load, unload, reload, and hot-reload via file watching.
pub struct PluginManagerLifecycle {
    plugin_manager: Arc<PluginManager>,
    watch_dir: Option<PathBuf>,
    _watcher: Option<RecommendedWatcher>,
    plugin_dir: Option<PathBuf>,
}

impl PluginManagerLifecycle {
    pub fn new(plugin_manager: Arc<PluginManager>) -> Self {
        Self {
            plugin_manager,
            watch_dir: None,
            _watcher: None,
            plugin_dir: None,
        }
    }

    /// Load all WASM plugins from a directory
    pub fn load_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, WasmPluginError> {
        if !dir.is_dir() {
            return Err(WasmPluginError::LoadFailed(format!(
                "plugin directory does not exist: {}",
                dir.display()
            )));
        }

        self.plugin_dir = Some(dir.to_path_buf());

        let mut loaded = 0;
        let entries = std::fs::read_dir(dir)
            .map_err(|e| WasmPluginError::LoadFailed(format!("failed to read dir: {}", e)))?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("Failed to read plugin directory entry: {}", e);
                    continue;
                }
            };
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "wasm" || ext == "wat" {
                    match self.plugin_manager.load_wasm_plugin(&path) {
                        Ok(()) => {
                            loaded += 1;
                            tracing::info!("Loaded plugin: {}", path.display());
                        }
                        Err(e) => {
                            tracing::error!("Failed to load plugin {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Load all Axum plugins (.so/.dylib/.dll) from a directory
    pub fn load_axum_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, AxumPluginError> {
        if !dir.is_dir() {
            return Err(AxumPluginError::LoadFailed(format!(
                "plugin directory does not exist: {}",
                dir.display()
            )));
        }

        let mut loaded = 0;
        let entries = std::fs::read_dir(dir)
            .map_err(|e| AxumPluginError::LoadFailed(format!("failed to read dir: {}", e)))?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("Failed to read plugin directory entry: {}", e);
                    continue;
                }
            };
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "so" || ext == "dylib" || ext == "dll" {
                    match self.plugin_manager.load_axum_plugin(&path) {
                        Ok(_) => {
                            loaded += 1;
                        }
                        Err(e) => {
                            tracing::error!("Failed to load Axum plugin {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Enable hot-reload watching on a directory.
    /// When `.wasm`, `.wat`, `.so`, `.dylib`, or `.dll` files change, plugins are reloaded.
    pub fn enable_hot_reload(&mut self, dir: &Path) -> Result<(), String> {
        let dir = dir.to_path_buf();
        if !dir.is_dir() {
            return Err(format!(
                "hot-reload directory does not exist: {}",
                dir.display()
            ));
        }

        let plugin_manager = self.plugin_manager.clone();
        let _watch_dir = dir.clone();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
                Ok(event) => {
                    if !matches!(event.kind, notify::EventKind::Modify(_)) {
                        return;
                    }
                    for path in &event.paths {
                        if let Some(ext) = path.extension() {
                            match ext.to_str() {
                                Some("wasm") | Some("wat") => {
                                    tracing::info!("Hot-reloading WASM plugin: {}", path.display());
                                    match plugin_manager.wasm_manager().reload_plugin(path) {
                                        Ok(_) => {
                                            tracing::info!(
                                                "Successfully hot-reloaded: {}",
                                                path.display()
                                            );
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Hot-reload failed for {}: {}",
                                                path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                                Some("so") | Some("dylib") | Some("dll") => {
                                    tracing::info!("Hot-reloading Axum plugin: {}", path.display());
                                    // Remove old plugin entry by name (library stays loaded
                                    // until all in-flight request references are dropped)
                                    let name = path
                                        .file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    plugin_manager.unload_axum_plugin(&name);
                                    match plugin_manager.load_axum_plugin(path) {
                                        Ok(_) => {
                                            tracing::info!(
                                                "Successfully hot-reloaded: {}",
                                                path.display()
                                            );
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Hot-reload failed for {}: {}",
                                                path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Hot-reload watch error: {}", e);
                }
            }
        })
        .map_err(|e| format!("failed to create file watcher: {}", e))?;

        watcher
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(|e| format!("failed to watch directory {}: {}", dir.display(), e))?;

        // Keep watcher alive by storing it
        self._watcher = Some(watcher);
        self.watch_dir = Some(dir.clone());

        tracing::info!("Hot-reload enabled for plugin directory: {}", dir.display());
        Ok(())
    }

    /// Reload a specific plugin by path
    pub fn reload_plugin(&self, path: &Path) -> Result<(), WasmPluginError> {
        if let Some(ext) = path.extension() {
            match ext.to_str() {
                Some("wasm") | Some("wat") => {
                    self.plugin_manager.wasm_manager().reload_plugin(path)?;
                }
                Some("so") | Some("dylib") | Some("dll") => {
                    self.plugin_manager
                        .load_axum_plugin(path)
                        .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;
                }
                _ => {
                    return Err(WasmPluginError::LoadFailed(format!(
                        "unsupported plugin extension: {}",
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Unload all plugins and clean up
    pub fn shutdown(&self) {
        // The watcher is dropped when self._watcher is dropped,
        // which stops the file watching thread.
        tracing::info!("Plugin lifecycle manager shutting down");
    }

    pub fn plugin_manager(&self) -> &Arc<PluginManager> {
        &self.plugin_manager
    }
}
