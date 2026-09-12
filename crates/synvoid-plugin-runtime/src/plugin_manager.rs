use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use bytes::Bytes;
use http::{Request, Response};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;

use crate::sandbox::types::PluginLoadConfig;
#[cfg(not(feature = "unsafe-native-extensions"))]
use crate::unsafe_native_loader::UnsafeNativeExtensionConfig;
use crate::unsafe_native_loader::UnsafeNativeExtensionStatus;
pub use crate::unsafe_native_loader::{AxumPluginError, UnsafeNativePluginError};
use crate::wasm_runtime::{
    WasmFilterResult, WasmPluginError, WasmPluginManager, WasmResourceLimits,
};

#[cfg(feature = "unsafe-native-extensions")]
use synvoid_native_extension::{InProcessNativeBackend, NativeExtensionBackend};

// ─── PluginManager (public API) ──────────────────────────────────────────────

pub struct PluginManager {
    wasm_manager: Arc<WasmPluginManager>,
    /// Narrow native-extension backend (Phase 28).
    ///
    /// The manager never owns concrete shared-library handles: with the
    /// `unsafe-native-extensions` feature it delegates to an in-process
    /// backend through [`NativeExtensionBackend`]; without the feature there
    /// is no native state at all and every load reports `Unsupported`.
    #[cfg(feature = "unsafe-native-extensions")]
    native_backend: Arc<dyn NativeExtensionBackend>,
    /// Tracks the last error from a native extension load attempt.
    last_native_load_error: RwLock<Option<String>>,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new()),
            #[cfg(feature = "unsafe-native-extensions")]
            native_backend: Arc::new(InProcessNativeBackend::new()),
            last_native_load_error: RwLock::new(None),
        }
    }

    pub fn with_wasm_limits(limits: WasmResourceLimits) -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new().with_limits(limits)),
            #[cfg(feature = "unsafe-native-extensions")]
            native_backend: Arc::new(InProcessNativeBackend::new()),
            last_native_load_error: RwLock::new(None),
        }
    }

    pub fn with_load_config(config: PluginLoadConfig) -> Self {
        PluginManager {
            wasm_manager: Arc::new(WasmPluginManager::new().with_load_config(config)),
            #[cfg(feature = "unsafe-native-extensions")]
            native_backend: Arc::new(InProcessNativeBackend::new()),
            last_native_load_error: RwLock::new(None),
        }
    }

    /// Inject a narrow native-extension backend (composition-root wiring).
    ///
    /// Only available with the `unsafe-native-extensions` feature. Lets the
    /// root composition choose the backend implementation while request-path
    /// code stays on the narrow [`NativeExtensionBackend`] interface.
    #[cfg(feature = "unsafe-native-extensions")]
    pub fn with_native_backend(mut self, backend: Arc<dyn NativeExtensionBackend>) -> Self {
        self.native_backend = backend;
        self
    }

    pub fn set_load_config(&self, config: PluginLoadConfig) {
        self.wasm_manager.set_load_config(config);
    }

    /// Load a WASM plugin from a file path (no mesh dependency).
    pub fn load_wasm_plugin(&self, path: &Path) -> Result<(), WasmPluginError> {
        self.wasm_manager.load_plugin(path)?;
        Ok(())
    }

    /// Load a WASM plugin from pre-fetched bytes.
    /// The caller is responsible for mesh resolution (e.g. fetching from global_wasm_dist_manager).
    pub fn load_wasm_plugin_from_bytes(
        &self,
        name: &str,
        bytes: Vec<u8>,
    ) -> Result<(), WasmPluginError> {
        self.wasm_manager.load_plugin_from_memory(
            name,
            &bytes,
            self.wasm_manager.get_default_limits(),
        )?;
        Ok(())
    }

    pub fn load_unsafe_native_extension(
        &self,
        path: &Path,
        allowed_dirs: &[String],
        expected_hash: Option<&str>,
    ) -> Result<Arc<Router>, UnsafeNativePluginError> {
        #[cfg(feature = "unsafe-native-extensions")]
        {
            match self.native_backend.load(path, allowed_dirs, expected_hash) {
                Ok(handle) => {
                    *self.last_native_load_error.write() = None;
                    Ok(handle.router)
                }
                Err(e) => {
                    *self.last_native_load_error.write() = Some(e.to_string());
                    Err(e)
                }
            }
        }
        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            let _ = path;
            let _ = expected_hash;
            let config = crate::unsafe_native_loader::get_global_unsafe_native_config();
            if let Err(gate) = config.validate_for_load(allowed_dirs) {
                *self.last_native_load_error.write() = Some(gate.to_string());
                return Err(gate);
            }
            let err = UnsafeNativePluginError::Unsupported;
            *self.last_native_load_error.write() = Some(err.to_string());
            Err(err)
        }
    }

    /// Backward-compatible wrapper for loading an unsafe native extension.
    pub fn load_axum_plugin(&self, path: &Path) -> Result<Arc<Router>, UnsafeNativePluginError> {
        self.load_unsafe_native_extension(path, &[], None)
    }

    /// Get the first loaded unsafe native extension router, if any
    pub fn get_axum_router(&self) -> Option<Arc<Router>> {
        #[cfg(feature = "unsafe-native-extensions")]
        {
            self.native_backend.first_router()
        }
        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            None
        }
    }

    /// Get an unsafe native extension router by name
    pub fn get_axum_router_by_name(&self, name: &str) -> Option<Arc<Router>> {
        #[cfg(feature = "unsafe-native-extensions")]
        {
            self.native_backend.router(name)
        }
        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            let _ = name;
            None
        }
    }

    /// Get all loaded unsafe native extension routers
    pub fn get_axum_routers(&self) -> Vec<Arc<Router>> {
        #[cfg(feature = "unsafe-native-extensions")]
        {
            self.native_backend.routers()
        }
        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            Vec::new()
        }
    }

    /// Remove an unsafe native extension by name. Returns true if found and removed.
    /// The old generation stays mapped until all outstanding handles/routers are dropped.
    pub fn unload_axum_plugin(&self, name: &str) -> bool {
        #[cfg(feature = "unsafe-native-extensions")]
        {
            self.native_backend.unload(name)
        }
        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            let _ = name;
            false
        }
    }

    /// Returns status information for all loaded unsafe native extensions.
    pub fn unsafe_native_status(&self) -> Vec<UnsafeNativeExtensionStatus> {
        #[cfg(feature = "unsafe-native-extensions")]
        {
            self.native_backend.status()
        }
        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            Vec::new()
        }
    }

    /// Returns global status of the unsafe native extension subsystem,
    /// combining configuration state with per-extension status.
    pub fn unsafe_native_global_status(
        &self,
    ) -> crate::unsafe_native_loader::UnsafeNativeGlobalStatus {
        #[cfg(feature = "unsafe-native-extensions")]
        {
            let mut status = self.native_backend.global_status();
            // Prefer the manager-observed error so direct backend use and
            // manager-mediated loads report consistently.
            if status.last_load_error.is_none() {
                status.last_load_error = self.last_native_load_error.read().clone();
            }
            status
        }
        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            let config: UnsafeNativeExtensionConfig =
                crate::unsafe_native_loader::get_global_unsafe_native_config();
            crate::unsafe_native_loader::UnsafeNativeGlobalStatus {
                enabled: config.enabled,
                production_mode: config.is_production(),
                allow_in_production: config.allow_in_production,
                hot_reload_enabled: config.hot_reload_enabled,
                loaded_count: 0,
                last_load_error: self.last_native_load_error.read().clone(),
                extensions: Vec::new(),
            }
        }
    }

    /// Returns the last error from a failed native extension load attempt.
    pub fn last_native_load_error(&self) -> Option<String> {
        self.last_native_load_error.read().clone()
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

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PluginManagerLifecycle ──────────────────────────────────────────────────

/// Per-stem resolver returning mesh-distributed (or otherwise externally
/// sourced) WASM bytes for a plugin file stem.
///
/// Mesh-agnostic hook: the application composition root passes a closure that
/// resolves bytes from its own store, so the runtime crate never imports root
/// mesh types. See `PluginManagerLifecycle::load_plugins_from_dir_with_resolver`.
pub type PluginBytesResolver = dyn Fn(&str) -> Option<Vec<u8>>;

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

    /// Load all WASM plugins from a directory, with no external byte resolver.
    pub fn load_plugins_from_dir(&mut self, dir: &Path) -> Result<usize, WasmPluginError> {
        self.load_plugins_from_dir_with_resolver(dir, None)
    }

    /// Load all WASM plugins from a directory.
    ///
    /// When `resolver` is provided, it is consulted first per plugin file stem:
    /// a returned byte vector is loaded via `load_wasm_plugin_from_bytes`
    /// instead of the on-disk file. This mesh-agnostic hook lets the root
    /// application composition prefer mesh-distributed modules without the
    /// runtime crate importing root mesh types.
    pub fn load_plugins_from_dir_with_resolver(
        &mut self,
        dir: &Path,
        resolver: Option<&PluginBytesResolver>,
    ) -> Result<usize, WasmPluginError> {
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
                    if let Some(resolver) = resolver {
                        let stem = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or_default()
                            .to_string();
                        if let Some(data) = resolver(&stem) {
                            match self.plugin_manager.load_wasm_plugin_from_bytes(&stem, data) {
                                Ok(()) => {
                                    loaded += 1;
                                    crate::wasm_metrics::record_plugin_load("unknown", "loaded");
                                    tracing::info!("Loaded plugin: {}", path.display());
                                }
                                Err(e) => {
                                    crate::wasm_metrics::record_plugin_load("unknown", "failed");
                                    tracing::error!(
                                        "Failed to load plugin {}: {}",
                                        path.display(),
                                        e
                                    );
                                }
                            }
                            continue;
                        }
                    }
                    match self.plugin_manager.load_wasm_plugin(&path) {
                        Ok(()) => {
                            loaded += 1;
                            crate::wasm_metrics::record_plugin_load("unknown", "loaded");
                            tracing::info!("Loaded plugin: {}", path.display());
                        }
                        Err(e) => {
                            crate::wasm_metrics::record_plugin_load("unknown", "failed");
                            tracing::error!("Failed to load plugin {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Load all unsafe native extensions (.so/.dylib/.dll) from a directory.
    ///
    /// Without the `unsafe-native-extensions` feature this reports
    /// `Unsupported` when the directory contains any native artifact instead
    /// of silently loading nothing.
    pub fn load_axum_plugins_from_dir(
        &mut self,
        dir: &Path,
    ) -> Result<usize, UnsafeNativePluginError> {
        if !dir.is_dir() {
            return Err(UnsafeNativePluginError::LoadFailed(format!(
                "plugin directory does not exist: {}",
                dir.display()
            )));
        }

        #[cfg(not(feature = "unsafe-native-extensions"))]
        {
            let has_native_artifact = std::fs::read_dir(dir)
                .map(|entries| {
                    entries.flatten().any(|e| {
                        e.path()
                            .extension()
                            .and_then(|x| x.to_str())
                            .is_some_and(|x| x == "so" || x == "dylib" || x == "dll")
                    })
                })
                .unwrap_or(false);
            if has_native_artifact {
                return Err(UnsafeNativePluginError::Unsupported);
            }
            Ok(0)
        }

        #[cfg(feature = "unsafe-native-extensions")]
        {
            let mut loaded = 0;
            let entries = std::fs::read_dir(dir).map_err(|e| {
                UnsafeNativePluginError::LoadFailed(format!("failed to read dir: {}", e))
            })?;

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
                                tracing::error!(
                                    "Failed to load unsafe native extension {}: {}",
                                    path.display(),
                                    e
                                );
                            }
                        }
                    }
                }
            }

            Ok(loaded)
        }
    }

    /// Enable hot-reload watching on a directory.
    /// When `.wasm`/`.wat` files change, plugins are reloaded.
    /// `.so`/`.dylib`/`.dll` files are only hot-reloaded when native hot-reload is enabled.
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
                                    let native_config =
                                        crate::unsafe_native_loader::get_global_unsafe_native_config();
                                    if !native_config.hot_reload_enabled {
                                        tracing::debug!(
                                            "Skipping native hot-reload (hot_reload_enabled=false): {}",
                                            path.display()
                                        );
                                        return;
                                    }
                                    tracing::info!(
                                        "Hot-reloading unsafe native extension: {}",
                                        path.display()
                                    );
                                    // Remove old extension entry by name (library stays loaded
                                    // until all in-flight request references are dropped)
                                    let name = path
                                        .file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                    plugin_manager.unload_axum_plugin(&name);
                                    match plugin_manager.load_axum_plugin(path) {
                                        Ok(_) => {
                                            crate::wasm_metrics::record_unsafe_native_extension_reloaded(&name);
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
                    crate::wasm_metrics::record_plugin_hot_reload("success");
                }
                Some("so") | Some("dylib") | Some("dll") => {
                    self.plugin_manager
                        .load_axum_plugin(path)
                        .map_err(|e| WasmPluginError::LoadFailed(e.to_string()))?;
                    crate::wasm_metrics::record_plugin_hot_reload("success");
                }
                _ => {
                    crate::wasm_metrics::record_plugin_hot_reload("failed");
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
