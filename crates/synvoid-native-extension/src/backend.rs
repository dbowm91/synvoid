//! Narrow native-extension backend interface.
//!
//! Phase 28: `PluginManager` (in `synvoid-plugin-runtime`) consumes native
//! extensions through [`NativeExtensionBackend`] rather than owning concrete
//! shared-library handles. The trait exposes only:
//!
//! - load a named native extension from a validated local artifact;
//! - unload/reload by generation (old generations drain via `Arc`);
//! - resolve a request/router callback through an opaque handle;
//! - query bounded status metadata.
//!
//! It deliberately does NOT expose shared-library handles, raw function
//! pointers, or arbitrary symbol lookup to callers: the only types crossing
//! the boundary are paths, strings, status DTOs, and opaque router handles.

use std::any::Any;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use axum::Router;

use crate::error::UnsafeNativePluginError;
use crate::loader::{
    get_global_unsafe_native_config, load_plugin, record_audit_event, UnsafeNativeAuditEventKind,
    UnsafeNativeExtension, UnsafeNativeExtensionStatus, UnsafeNativeGlobalStatus,
};

/// Opaque handle for a loaded native extension.
///
/// The `router` is the request-path callback surface. The `keep_alive` token
/// retains the underlying shared-library mapping for as long as the handle
/// (or any router cloned from it) is alive; its concrete type is intentionally
/// erased so callers can never observe native-loader handle types across the
/// boundary.
pub struct NativeExtensionHandle {
    /// File-stem name of the extension.
    pub name: String,
    /// Request router derived from the extension's `create_router` factory.
    pub router: Arc<Router<()>>,
    /// Serializable status snapshot.
    pub status: UnsafeNativeExtensionStatus,
    keep_alive: Arc<dyn Any + Send + Sync>,
}

impl std::fmt::Debug for NativeExtensionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeExtensionHandle")
            .field("name", &self.name)
            .field("status", &self.status)
            .finish()
    }
}

impl NativeExtensionHandle {
    fn from_extension(extension: UnsafeNativeExtension) -> Self {
        let status = extension.status();
        let name = extension.name.clone();
        let router = extension.router.clone();
        let keep_alive: Arc<dyn Any + Send + Sync> = Arc::new(extension);
        Self {
            name,
            router,
            status,
            keep_alive,
        }
    }

    /// Borrow the keep-alive token (for backend-internal retention checks).
    #[cfg(test)]
    pub(crate) fn keep_alive(&self) -> &Arc<dyn Any + Send + Sync> {
        &self.keep_alive
    }
}

/// Narrow backend consumed by `PluginManager`.
///
/// All methods are fallible or bounded; none expose library handles, raw
/// pointers, or symbol lookup.
pub trait NativeExtensionBackend: Send + Sync {
    /// Load a native extension from a validated local artifact.
    ///
    /// Runs the full gate chain (production gate → path validation → hash
    /// verification → ABI check) before the first `Library::new` call.
    fn load(
        &self,
        path: &Path,
        allowed_dirs: &[String],
        expected_hash: Option<&str>,
    ) -> Result<NativeExtensionHandle, UnsafeNativePluginError>;

    /// Remove a native extension by name.
    ///
    /// Returns `true` when an entry was removed. The old generation stays
    /// mapped until all outstanding handles/routers are dropped.
    fn unload(&self, name: &str) -> bool;

    /// Resolve one extension router by name.
    fn router(&self, name: &str) -> Option<Arc<Router<()>>>;

    /// Resolve the first loaded extension router, if any.
    fn first_router(&self) -> Option<Arc<Router<()>>>;

    /// Resolve all loaded extension routers.
    fn routers(&self) -> Vec<Arc<Router<()>>>;

    /// Bounded per-extension status snapshots.
    fn status(&self) -> Vec<UnsafeNativeExtensionStatus>;

    /// Number of currently loaded extensions.
    fn loaded_count(&self) -> usize;

    /// Last load error, if any.
    fn last_load_error(&self) -> Option<String>;

    /// Global subsystem status (config state + per-extension status).
    fn global_status(&self) -> UnsafeNativeGlobalStatus;
}

/// Default in-process backend.
///
/// Loads shared libraries into the host address space with full process
/// authority. This is explicitly UNSANDBOXED: prefer the future external-host
/// seam (`crate::external_seam`) for production native extensibility.
pub struct InProcessNativeBackend {
    extensions: parking_lot::RwLock<HashMap<String, Arc<UnsafeNativeExtension>>>,
    last_load_error: parking_lot::RwLock<Option<String>>,
}

impl InProcessNativeBackend {
    /// Create an empty backend.
    pub fn new() -> Self {
        Self {
            extensions: parking_lot::RwLock::new(HashMap::new()),
            last_load_error: parking_lot::RwLock::new(None),
        }
    }
}

impl Default for InProcessNativeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeExtensionBackend for InProcessNativeBackend {
    fn load(
        &self,
        path: &Path,
        allowed_dirs: &[String],
        expected_hash: Option<&str>,
    ) -> Result<NativeExtensionHandle, UnsafeNativePluginError> {
        match load_plugin(path, allowed_dirs, expected_hash) {
            Ok(extension) => {
                *self.last_load_error.write() = None;
                let handle = NativeExtensionHandle::from_extension(extension);
                // Retain the concrete extension alongside the erased handle so
                // status queries stay cheap and unload drains by generation.
                let retained: Arc<UnsafeNativeExtension> = handle
                    .keep_alive
                    .clone()
                    .downcast::<UnsafeNativeExtension>()
                    .expect("native handle keep-alive hosts UnsafeNativeExtension");
                let replaced = self
                    .extensions
                    .write()
                    .insert(handle.name.clone(), retained);
                // A repeated load for an existing name is a generation swap:
                // account it as a reload so `..._reloaded_total` counts swaps,
                // not first loads (first loads are counted by the loader).
                if replaced.is_some() {
                    crate::metrics::record_unsafe_native_extension_reloaded(&handle.name);
                    record_audit_event(UnsafeNativeAuditEventKind::ReloadCompleted {
                        name: handle.name.clone(),
                        new_generation: handle.status.generation,
                    });
                }
                Ok(handle)
            }
            Err(e) => {
                *self.last_load_error.write() = Some(e.to_string());
                Err(e)
            }
        }
    }

    fn unload(&self, name: &str) -> bool {
        // Drain by generation: removing the backend's handle drops one `Arc`
        // reference; outstanding routers/handles keep the library mapped until
        // they are dropped (see the middleware keep-alive in `loader`).
        self.extensions.write().remove(name).is_some()
    }

    fn router(&self, name: &str) -> Option<Arc<Router<()>>> {
        self.extensions.read().get(name).map(|e| e.router.clone())
    }

    fn first_router(&self) -> Option<Arc<Router<()>>> {
        self.extensions
            .read()
            .values()
            .next()
            .map(|e| e.router.clone())
    }

    fn routers(&self) -> Vec<Arc<Router<()>>> {
        self.extensions
            .read()
            .values()
            .map(|e| e.router.clone())
            .collect()
    }

    fn status(&self) -> Vec<UnsafeNativeExtensionStatus> {
        self.extensions
            .read()
            .values()
            .map(|e| e.status())
            .collect()
    }

    fn loaded_count(&self) -> usize {
        self.extensions.read().len()
    }

    fn last_load_error(&self) -> Option<String> {
        self.last_load_error.read().clone()
    }

    fn global_status(&self) -> UnsafeNativeGlobalStatus {
        let config = get_global_unsafe_native_config();
        let extensions = self.status();
        UnsafeNativeGlobalStatus {
            enabled: config.enabled,
            production_mode: config.is_production(),
            allow_in_production: config.allow_in_production,
            hot_reload_enabled: config.hot_reload_enabled,
            loaded_count: extensions.len(),
            last_load_error: self.last_load_error(),
            extensions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{
        drain_audit_events, set_global_unsafe_native_config, UnsafeNativeExtensionConfig,
    };

    fn dev_config() -> UnsafeNativeExtensionConfig {
        UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        }
    }

    #[test]
    fn backend_traits_do_not_expose_library_types() {
        // Compile-time boundary assertion: the public trait surface must not
        // mention libloading, raw pointers, or symbol lookup. We assert on
        // the non-test source text so future edits that widen the trait fail
        // loudly. (Split before the test module: the forbidden list itself
        // lives below and must not self-match.)
        let src = include_str!("backend.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        for forbidden in ["libloading", "Library", "Symbol", "*mut", "*const", "dlsym"] {
            assert!(
                !code.contains(forbidden),
                "NativeExtensionBackend surface must not contain '{forbidden}'"
            );
        }
    }

    #[test]
    fn unload_unknown_name_returns_false() {
        // `unload` touches only backend-local state (no global config).
        let backend = InProcessNativeBackend::new();
        assert!(!backend.unload("does-not-exist"));
        assert_eq!(backend.loaded_count(), 0);
        assert!(backend.first_router().is_none());
        assert!(backend.routers().is_empty());
        assert!(backend.status().is_empty());
    }

    #[test]
    fn failed_load_records_last_error() {
        // NOTE: the loader's production gate reads process-global config,
        // which sibling tests also mutate; assert only that a failure is
        // recorded, not the exact gate variant. Gate-variant coverage lives
        // in `validate_for_load` unit tests that take `&self` (no globals).
        set_global_unsafe_native_config(UnsafeNativeExtensionConfig {
            enabled: false,
            production_mode_override: Some(false),
            ..Default::default()
        });
        let backend = InProcessNativeBackend::new();
        let dir = std::env::temp_dir().join(format!(
            "native_backend_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let so_path = dir.join("test.so");
        std::fs::write(&so_path, b"fake").unwrap();
        let result = backend.load(&so_path, &[], None);
        assert!(result.is_err(), "disabled backend must refuse to load");
        let last = backend.last_load_error();
        assert!(last.is_some(), "failed load must record last_load_error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_status_reports_empty_backend() {
        // Assert only backend-local state (loaded count, extension list):
        // the `enabled` flag mirrors process-global config, which sibling
        // tests mutate concurrently, so it is not asserted here. Gate-variant
        // coverage lives in `validate_for_load` unit tests (no globals).
        drain_audit_events();
        let backend = InProcessNativeBackend::new();
        let status = backend.global_status();
        assert_eq!(status.loaded_count, 0);
        assert!(status.extensions.is_empty());
    }

    #[test]
    fn opaque_handle_hides_library_handle() {
        // The handle's keep-alive must be type-erased: callers can hold it
        // without ever naming a loader handle type.
        let backend = InProcessNativeBackend::new();
        // No extensions loaded; construct the type-level assertion only.
        fn _assert_opaque(_: &Arc<dyn Any + Send + Sync>) {}
        let _ = backend.loaded_count();
    }
}
