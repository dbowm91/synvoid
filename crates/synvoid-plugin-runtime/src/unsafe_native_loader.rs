//! Compatibility facade over `synvoid-native-extension` (Phase 28).
//!
//! Capability isolation: the sandboxed WASM plugin runtime no longer links a
//! shared-library loader unconditionally.
//!
//! - With the `unsafe-native-extensions` feature enabled, this module
//!   re-exports the canonical loader from `synvoid-native-extension` and
//!   `load_plugin` executes the full gate chain before `Library::new`.
//! - Without the feature, this module exposes compatible stubs whose load
//!   path always returns [`UnsafeNativePluginError::Unsupported`] (after
//!   still enforcing the production gate, so misconfiguration is explicit
//!   rather than silent). There is no `Library::new` code path in that build.

#[cfg(feature = "unsafe-native-extensions")]
pub use synvoid_native_extension::{
    create_plugin_library_example, current_generation, drain_audit_events,
    get_global_unsafe_native_config, is_production_env, load_plugin, peek_audit_events,
    record_audit_event, set_global_unsafe_native_config, AxumPluginError, UnsafeNativeAuditEvent,
    UnsafeNativeAuditEventKind, UnsafeNativeExtension, UnsafeNativeExtensionConfig,
    UnsafeNativeExtensionStatus, UnsafeNativeGlobalStatus, UnsafeNativePluginError,
    RISK_ACKNOWLEDGEMENT,
};

#[cfg(not(feature = "unsafe-native-extensions"))]
mod disabled {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, LazyLock};
    use std::time::SystemTime;

    use axum::Router;

    /// Exact risk-acknowledgement string required in production mode.
    ///
    /// Must stay identical to `synvoid_native_extension::RISK_ACKNOWLEDGEMENT`.
    pub const RISK_ACKNOWLEDGEMENT: &str =
        "I understand native extensions run with full Synvoid process authority";

    /// Errors from unsafe native extension loading and validation.
    ///
    /// Feature-disabled stub mirroring the canonical
    /// `synvoid_native_extension::UnsafeNativePluginError` (which additionally
    /// documents the loader). `Unsupported` is returned by every load attempt
    /// in builds without compiled native support.
    #[derive(Debug, thiserror::Error)]
    pub enum UnsafeNativePluginError {
        #[error("Failed to load unsafe native extension: {0}")]
        LoadFailed(String),
        #[error(
            "Unsafe native extension ABI version {plugin} does not match expected version {expected}"
        )]
        AbiMismatch { plugin: String, expected: String },
        #[error("Symbol not found: {0}")]
        SymbolNotFound(String),
        #[error("Unsafe native extension not allowed in production mode")]
        ProductionDenied,
        #[error("Risk acknowledgement missing or incorrect")]
        RiskAcknowledgementRequired,
        #[error("No allowed directories configured for unsafe native extensions")]
        NoAllowedDirs,
        #[error(
            "Unsafe native extensions are not compiled into this binary \
             (enable the `unsafe-native-extensions` feature and set \
             [plugins.unsafe_native] at runtime)"
        )]
        Unsupported,
    }

    /// Backward-compatible alias.
    pub type AxumPluginError = UnsafeNativePluginError;

    /// Returns `true` when `SYNVOID_ENV` is set to `"production"`.
    pub fn is_production_env() -> bool {
        std::env::var("SYNVOID_ENV")
            .map(|v| v.eq_ignore_ascii_case("production"))
            .unwrap_or(false)
    }

    /// Runtime configuration for the unsafe native extension loader.
    ///
    /// Feature-disabled stub mirroring the canonical config shape so
    /// `validate_for_load` gate semantics stay testable without compiled
    /// native support. Validation logic must stay identical to the canonical
    /// implementation in `synvoid-native-extension`.
    #[derive(Debug, Clone, Default)]
    pub struct UnsafeNativeExtensionConfig {
        /// Master switch — must be `true` for any native extension to load.
        pub enabled: bool,
        /// If `true`, native extensions may be loaded when `is_production_env()` is true.
        pub allow_in_production: bool,
        /// Exact acknowledgement string required in production mode.
        pub risk_acknowledgement: Option<String>,
        /// Directories from which native extensions may be loaded.
        pub allowed_dirs: Vec<String>,
        /// Whether hot-reload is enabled for native extensions.
        pub hot_reload_enabled: bool,
        /// Runtime override; when `None`, `is_production_env()` is used.
        pub production_mode_override: Option<bool>,
    }

    impl UnsafeNativeExtensionConfig {
        /// Returns `true` if the current environment is considered production.
        pub fn is_production(&self) -> bool {
            self.production_mode_override
                .unwrap_or_else(is_production_env)
        }

        /// Validate that the config permits loading in the current environment.
        pub fn validate_for_load(
            &self,
            allowed_dirs_from_caller: &[String],
        ) -> Result<(), UnsafeNativePluginError> {
            if !self.enabled {
                return Err(UnsafeNativePluginError::LoadFailed(
                    "Unsafe native extensions are disabled (set plugins.unsafe_native.enabled = true)"
                        .to_string(),
                ));
            }

            if self.is_production() {
                if !self.allow_in_production {
                    return Err(UnsafeNativePluginError::ProductionDenied);
                }

                match &self.risk_acknowledgement {
                    Some(ack) if ack == RISK_ACKNOWLEDGEMENT => {}
                    _ => return Err(UnsafeNativePluginError::RiskAcknowledgementRequired),
                }

                let effective_dirs = if allowed_dirs_from_caller.is_empty() {
                    &self.allowed_dirs
                } else {
                    allowed_dirs_from_caller
                };
                if effective_dirs.is_empty() {
                    return Err(UnsafeNativePluginError::NoAllowedDirs);
                }
            }

            Ok(())
        }
    }

    static GLOBAL_UNSAFE_NATIVE_CONFIG: LazyLock<parking_lot::Mutex<UnsafeNativeExtensionConfig>> =
        LazyLock::new(|| parking_lot::Mutex::new(UnsafeNativeExtensionConfig::default()));

    /// Set the global unsafe native extension configuration.
    ///
    /// Stored even in disabled builds so operator status keeps reporting the
    /// configured intent; loading still returns `Unsupported`.
    pub fn set_global_unsafe_native_config(config: UnsafeNativeExtensionConfig) {
        *GLOBAL_UNSAFE_NATIVE_CONFIG.lock() = config;
    }

    /// Get a snapshot of the current global configuration.
    pub fn get_global_unsafe_native_config() -> UnsafeNativeExtensionConfig {
        GLOBAL_UNSAFE_NATIVE_CONFIG.lock().clone()
    }

    /// Generation counter stub: disabled builds never load, so this is always 0.
    pub fn current_generation() -> u64 {
        0
    }

    /// Opaque loaded-extension type for disabled builds.
    ///
    /// Never constructed successfully (every load returns `Unsupported`), but
    /// the type must exist so facades compiling against this module keep
    /// working. Mirrors the canonical field surface minus the retained
    /// shared-library handle, which does not exist in this build.
    pub struct UnsafeNativeExtension {
        pub name: String,
        pub path: PathBuf,
        pub canonical_path: PathBuf,
        pub router: Arc<Router<()>>,
        pub abi_version: String,
        pub loaded_at: SystemTime,
        pub sha256: String,
        pub generation: u64,
    }

    impl std::fmt::Debug for UnsafeNativeExtension {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UnsafeNativeExtension")
                .field("name", &self.name)
                .field("path", &self.path)
                .field("canonical_path", &self.canonical_path)
                .field("abi_version", &self.abi_version)
                .field("loaded_at", &self.loaded_at)
                .field("sha256", &self.sha256)
                .field("generation", &self.generation)
                .finish()
        }
    }

    impl UnsafeNativeExtension {
        pub fn status(&self) -> UnsafeNativeExtensionStatus {
            UnsafeNativeExtensionStatus {
                name: self.name.clone(),
                path: self.canonical_path.display().to_string(),
                sha256: self.sha256.clone(),
                abi_version: self.abi_version.clone(),
                loaded_at: self
                    .loaded_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                generation: self.generation,
            }
        }
    }

    /// Serializable status snapshot of a loaded unsafe native extension.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct UnsafeNativeExtensionStatus {
        pub name: String,
        pub path: String,
        pub sha256: String,
        pub abi_version: String,
        pub loaded_at: u64,
        pub generation: u64,
    }

    /// Global status of unsafe native extension subsystem.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct UnsafeNativeGlobalStatus {
        pub enabled: bool,
        pub production_mode: bool,
        pub allow_in_production: bool,
        pub hot_reload_enabled: bool,
        pub loaded_count: usize,
        pub last_load_error: Option<String>,
        pub extensions: Vec<UnsafeNativeExtensionStatus>,
    }

    /// Structured audit event for unsafe native extension operations.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct UnsafeNativeAuditEvent {
        pub timestamp: u64,
        pub kind: UnsafeNativeAuditEventKind,
    }

    /// Classification of audit events for the unsafe native extension subsystem.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    pub enum UnsafeNativeAuditEventKind {
        LoadAccepted {
            name: String,
            path: String,
            sha256: String,
            generation: u64,
        },
        LoadRejectedGate {
            reason: String,
        },
        LoadRejectedPath {
            path: String,
            reason: String,
        },
        HashMismatch {
            path: String,
            expected: String,
            actual: String,
        },
        AbiMismatch {
            name: String,
            plugin_version: String,
            expected_version: String,
        },
        FactoryPanic {
            name: String,
            message: String,
        },
        ReloadStarted {
            name: String,
            old_generation: u64,
        },
        ReloadCompleted {
            name: String,
            new_generation: u64,
        },
        ReloadFailed {
            name: String,
            reason: String,
        },
    }

    /// No-op in disabled builds (no loads occur, so no events are produced).
    pub fn record_audit_event(_kind: UnsafeNativeAuditEventKind) {}

    /// Always empty in disabled builds.
    pub fn drain_audit_events() -> Vec<UnsafeNativeAuditEvent> {
        Vec::new()
    }

    /// Always empty in disabled builds.
    pub fn peek_audit_events() -> Vec<UnsafeNativeAuditEvent> {
        Vec::new()
    }

    /// Load stub: enforces the production gate, then reports `Unsupported`.
    ///
    /// There is no shared-library load path in this build. Gate rejections
    /// surface the specific gate error; everything else is explicitly
    /// `Unsupported` rather than a silent success.
    pub fn load_plugin(
        _path: &Path,
        allowed_dirs: &[String],
        _expected_hash: Option<&str>,
    ) -> Result<UnsafeNativeExtension, UnsafeNativePluginError> {
        let config = get_global_unsafe_native_config();
        config.validate_for_load(allowed_dirs)?;
        Err(UnsafeNativePluginError::Unsupported)
    }

    /// Static example source for authoring a native extension crate.
    pub fn create_plugin_library_example() -> &'static str {
        r#"
use axum::{Router, routing::get};

#[no_mangle]
pub static synvoid_abi_version: *const std::ffi::c_char = concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::ffi::c_char;

#[no_mangle]
pub extern "C" fn create_router() -> *mut Router<()> {
    let router = Router::new()
        .route("/", get(|| async { "Hello from plugin!" }));
    Box::into_raw(Box::new(router))
}
"#
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn disabled_stub_reports_unsupported_after_gate() {
            set_global_unsafe_native_config(UnsafeNativeExtensionConfig {
                enabled: true,
                production_mode_override: Some(false),
                ..Default::default()
            });
            let err = load_plugin(Path::new("/tmp/x.so"), &[], None).unwrap_err();
            assert!(matches!(err, UnsafeNativePluginError::Unsupported));
        }

        #[test]
        fn disabled_stub_still_enforces_production_gate() {
            set_global_unsafe_native_config(UnsafeNativeExtensionConfig {
                enabled: false,
                production_mode_override: Some(false),
                ..Default::default()
            });
            let err = load_plugin(Path::new("/tmp/x.so"), &[], None).unwrap_err();
            assert!(matches!(err, UnsafeNativePluginError::LoadFailed(_)));
        }

        #[test]
        fn disabled_audit_buffer_stays_empty() {
            record_audit_event(UnsafeNativeAuditEventKind::LoadRejectedGate {
                reason: "test".to_string(),
            });
            assert!(drain_audit_events().is_empty());
            assert!(peek_audit_events().is_empty());
        }
    }
}

#[cfg(not(feature = "unsafe-native-extensions"))]
pub use disabled::{
    create_plugin_library_example, current_generation, drain_audit_events,
    get_global_unsafe_native_config, is_production_env, load_plugin, peek_audit_events,
    record_audit_event, set_global_unsafe_native_config, AxumPluginError, UnsafeNativeAuditEvent,
    UnsafeNativeAuditEventKind, UnsafeNativeExtension, UnsafeNativeExtensionConfig,
    UnsafeNativeExtensionStatus, UnsafeNativeGlobalStatus, UnsafeNativePluginError,
    RISK_ACKNOWLEDGEMENT,
};
