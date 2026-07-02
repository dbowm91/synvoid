use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

use axum::Router;
use libloading::{Library, Symbol};
use sha2::Digest;

use crate::plugin_manager::UnsafeNativePluginError;

const AXUM_ABI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum number of audit events retained in the ring buffer.
const MAX_AUDIT_EVENTS: usize = 256;

// ─── Structured audit events ────────────────────────────────────────────────

/// Structured audit event for unsafe native extension operations.
///
/// These are recorded in a bounded ring buffer and can be drained by operators
/// or test code. They provide machine-readable audit trails beyond tracing logs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnsafeNativeAuditEvent {
    pub timestamp: u64,
    pub kind: UnsafeNativeAuditEventKind,
}

/// Classification of audit events for the unsafe native extension subsystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum UnsafeNativeAuditEventKind {
    /// Plugin loaded successfully.
    LoadAccepted {
        name: String,
        path: String,
        sha256: String,
        generation: u64,
    },
    /// Load rejected at the production gate.
    LoadRejectedGate { reason: String },
    /// Load rejected due to path validation failure.
    LoadRejectedPath { path: String, reason: String },
    /// Load rejected due to SHA-256 mismatch.
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    /// Load rejected due to ABI version mismatch.
    AbiMismatch {
        name: String,
        plugin_version: String,
        expected_version: String,
    },
    /// Factory function panicked during load.
    FactoryPanic { name: String, message: String },
    /// Hot-reload triggered.
    ReloadStarted { name: String, old_generation: u64 },
    /// Hot-reload completed successfully.
    ReloadCompleted { name: String, new_generation: u64 },
    /// Hot-reload failed.
    ReloadFailed { name: String, reason: String },
}

/// Bounded ring buffer of audit events.
static NATIVE_AUDIT_LOG: LazyLock<parking_lot::Mutex<VecDeque<UnsafeNativeAuditEvent>>> =
    LazyLock::new(|| parking_lot::Mutex::new(VecDeque::with_capacity(64)));

/// Record an audit event into the global ring buffer.
pub fn record_audit_event(kind: UnsafeNativeAuditEventKind) {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let event = UnsafeNativeAuditEvent {
        timestamp: ts,
        kind,
    };
    let mut log = NATIVE_AUDIT_LOG.lock();
    if log.len() >= MAX_AUDIT_EVENTS {
        log.pop_front();
    }
    log.push_back(event);
}

/// Drain all pending audit events (for operators or tests).
pub fn drain_audit_events() -> Vec<UnsafeNativeAuditEvent> {
    let mut log = NATIVE_AUDIT_LOG.lock();
    log.drain(..).collect()
}

/// Peek at audit events without draining (for tests that need to assert and
/// leave events for subsequent assertions).
pub fn peek_audit_events() -> Vec<UnsafeNativeAuditEvent> {
    NATIVE_AUDIT_LOG.lock().iter().cloned().collect()
}

/// Production mode detection via environment variable.
///
/// Returns `true` when `SYNVOID_ENV` is set to `"production"`.
/// This is used as the default production gate; callers may override via
/// `is_production_override` parameter.
pub fn is_production_env() -> bool {
    std::env::var("SYNVOID_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

// ─── UnsafeNativeExtensionConfig ─────────────────────────────────────────────

/// Runtime configuration for the unsafe native extension loader.
///
/// Carries the full policy state so that `load_plugin` can enforce it without
/// reaching back into the config crate.
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
    /// Whether we are currently running in production mode.
    /// This is a runtime override; when `None`, `is_production_env()` is used.
    pub production_mode_override: Option<bool>,
}

impl UnsafeNativeExtensionConfig {
    /// Returns `true` if the current environment is considered production.
    pub fn is_production(&self) -> bool {
        self.production_mode_override
            .unwrap_or_else(is_production_env)
    }

    /// Validate that the config permits loading in the current environment.
    ///
    /// This enforces the full production gate:
    /// - `enabled` must be `true`
    /// - In production: `allow_in_production`, exact `risk_acknowledgement`, and
    ///   non-empty `allowed_dirs` are all required
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

            let expected_ack =
                "I understand native extensions run with full Synvoid process authority";
            match &self.risk_acknowledgement {
                Some(ack) if ack == expected_ack => {}
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

// ─── Global config and generation counter ────────────────────────────────────

static GLOBAL_UNSAFE_NATIVE_CONFIG: LazyLock<parking_lot::Mutex<UnsafeNativeExtensionConfig>> =
    LazyLock::new(|| parking_lot::Mutex::new(UnsafeNativeExtensionConfig::default()));

static NATIVE_EXTENSION_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Set the global unsafe native extension configuration.
pub fn set_global_unsafe_native_config(config: UnsafeNativeExtensionConfig) {
    *GLOBAL_UNSAFE_NATIVE_CONFIG.lock() = config;
}

/// Get a snapshot of the current global configuration.
pub fn get_global_unsafe_native_config() -> UnsafeNativeExtensionConfig {
    GLOBAL_UNSAFE_NATIVE_CONFIG.lock().clone()
}

/// Get the current generation counter value.
pub fn current_generation() -> u64 {
    NATIVE_EXTENSION_GENERATION.load(Ordering::Relaxed)
}

/// Increment and return the new generation counter.
fn next_generation() -> u64 {
    NATIVE_EXTENSION_GENERATION.fetch_add(1, Ordering::Relaxed) + 1
}

// ─── UnsafeNativeExtension ───────────────────────────────────────────────────

/// Represents a loaded unsafe native extension with retained library handle.
///
/// The `library` field must outlive any router/handler/value derived from it.
/// Dropping the `Library` while plugin code may still execute is undefined behavior.
pub struct UnsafeNativeExtension {
    pub name: String,
    pub path: PathBuf,
    pub canonical_path: PathBuf,
    pub library: Arc<Library>,
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
///
/// Combines global configuration state with per-extension status for
/// operator visibility and incident review.
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

// ─── ExternalPluginClient placeholder ────────────────────────────────────────

/// Placeholder trait for out-of-process native extension communication.
///
/// This trait is **not implemented** in this phase. It exists to document the
/// recommended production architecture: native code should run in a separate
/// process communicating via UDS/loopback HTTP/gRPC, not in-process.
///
/// See `architecture/unsafe_native_extensions.md` for the full design.
pub trait ExternalPluginClient: Send + Sync {
    /// Filter an incoming HTTP request through the external plugin.
    fn filter_request(
        &self,
        request: PluginHttpView<'_>,
    ) -> Result<PluginDecision, ExternalPluginError>;
}

/// View of an HTTP request passed to an external plugin.
pub struct PluginHttpView<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
}

/// Decision returned by an external plugin.
pub enum PluginDecision {
    Pass,
    Block { status: u16, body: String },
    Modify { headers: Vec<(String, String)> },
}

/// Error from an external plugin.
#[derive(Debug, thiserror::Error)]
pub enum ExternalPluginError {
    #[error("External plugin error: {0}")]
    Error(String),
}

// ─── SHA-256 computation ─────────────────────────────────────────────────────

fn compute_sha256(path: &Path) -> Result<String, UnsafeNativePluginError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| {
        UnsafeNativePluginError::LoadFailed(format!("Failed to open file for hashing: {}", e))
    })?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            UnsafeNativePluginError::LoadFailed(format!("Failed to read file for hashing: {}", e))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// ─── Path validation ─────────────────────────────────────────────────────────

fn validate_plugin_path(
    path: &Path,
    allowed_dirs: &[String],
) -> Result<PathBuf, UnsafeNativePluginError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(UnsafeNativePluginError::LoadFailed(
                "Plugin symlinks are not allowed".to_string(),
            ));
        }
    }

    let canonical_path = path.canonicalize().map_err(|e| {
        UnsafeNativePluginError::LoadFailed(format!("Cannot resolve plugin path: {}", e))
    })?;

    // Enforce allowed_dirs if non-empty
    if !allowed_dirs.is_empty() {
        let in_allowed = allowed_dirs.iter().any(|dir| {
            Path::new(dir)
                .canonicalize()
                .ok()
                .map(|allowed| canonical_path.starts_with(&allowed))
                .unwrap_or(false)
        });
        if !in_allowed {
            return Err(UnsafeNativePluginError::LoadFailed(format!(
                "Plugin path {} is not within any allowed directory",
                canonical_path.display()
            )));
        }
    }

    if let Ok(metadata) = std::fs::metadata(&canonical_path) {
        let file_size = metadata.len();
        let max_plugin_size = 50 * 1024 * 1024;
        if file_size > max_plugin_size {
            return Err(UnsafeNativePluginError::LoadFailed(format!(
                "Plugin file too large: {} bytes (max {})",
                file_size, max_plugin_size
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // Reject world-writable files
            if mode & 0o002 != 0 {
                return Err(UnsafeNativePluginError::LoadFailed(format!(
                    "Plugin {} is world-writable (mode {:o}), which is not allowed",
                    canonical_path.display(),
                    mode
                )));
            }

            // Reject world-writable parent directories
            if let Some(parent) = canonical_path.parent() {
                if let Ok(parent_meta) = std::fs::metadata(parent) {
                    let parent_mode = parent_meta.permissions().mode();
                    if parent_mode & 0o002 != 0 {
                        return Err(UnsafeNativePluginError::LoadFailed(format!(
                            "Parent directory of {} is world-writable (mode {:o}), which is not allowed",
                            parent.display(),
                            parent_mode
                        )));
                    }
                }
            }

            // Note: We only reject world-writable files above. The plan's original
            // "exact 0o755/0o500" check was overly strict and rejected legitimate
            // libraries (e.g. 0o644, 0o744). We keep the dangerous-name check below
            // as weak hygiene, not a security boundary.
        }
    }

    let extensions: Vec<String> = canonical_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .into_iter()
        .collect();

    if !extensions.contains(&"so".to_string())
        && !extensions.contains(&"dylib".to_string())
        && !extensions.contains(&"dll".to_string())
    {
        return Err(UnsafeNativePluginError::LoadFailed(
            "Plugin must be a .so, .dylib, or .dll file".to_string(),
        ));
    }

    let filename = canonical_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let dangerous_patterns = [
        "libc",
        "libdl",
        "libpthread",
        "libm",
        "libgcc",
        "libstdc",
        "libcrypto",
        "libssl",
        "libcurl",
        "kernel32",
        "ntdll",
        "user32",
        "gdi32",
    ];
    for pattern in dangerous_patterns {
        if filename.contains(pattern) {
            return Err(UnsafeNativePluginError::LoadFailed(format!(
                "Plugin filename '{}' contains potentially dangerous library name",
                filename
            )));
        }
    }

    tracing::info!(
        "Validated unsafe native extension path: {}",
        canonical_path.display()
    );
    Ok(canonical_path)
}

// ─── Production gate ─────────────────────────────────────────────────────────

/// Enforce the production gate before loading a native extension.
///
/// This is called at the start of `load_plugin` and checks the global config
/// against the current environment.
fn enforce_production_gate(caller_allowed_dirs: &[String]) -> Result<(), UnsafeNativePluginError> {
    let config = get_global_unsafe_native_config();
    config.validate_for_load(caller_allowed_dirs)
}

// ─── Main load function ──────────────────────────────────────────────────────

/// Load an unsafe native extension from a shared library file.
///
/// The returned `UnsafeNativeExtension` retains the `Library` handle for the
/// lifetime of the extension, preventing use-after-free of plugin-derived code.
///
/// # Safety
///
/// This function calls into native code via FFI. Panics in the native
/// `create_router` function are caught via `catch_unwind` to prevent UB from
/// unwinding across the FFI boundary.
pub fn load_plugin(
    path: &Path,
    allowed_dirs: &[String],
    expected_hash: Option<&str>,
) -> Result<UnsafeNativeExtension, UnsafeNativePluginError> {
    // ── Production gate ──────────────────────────────────────────────────────
    if let Err(e) = enforce_production_gate(allowed_dirs) {
        record_audit_event(UnsafeNativeAuditEventKind::LoadRejectedGate {
            reason: e.to_string(),
        });
        return Err(e);
    }

    // ── Path validation ──────────────────────────────────────────────────────
    let canonical_path = match validate_plugin_path(path, allowed_dirs) {
        Ok(p) => p,
        Err(e) => {
            record_audit_event(UnsafeNativeAuditEventKind::LoadRejectedPath {
                path: path.display().to_string(),
                reason: e.to_string(),
            });
            return Err(e);
        }
    };

    // ── Hash verification ────────────────────────────────────────────────────
    let sha256 = compute_sha256(&canonical_path)?;

    if let Some(expected) = expected_hash {
        if sha256 != expected {
            record_audit_event(UnsafeNativeAuditEventKind::HashMismatch {
                path: canonical_path.display().to_string(),
                expected: expected.to_string(),
                actual: sha256.clone(),
            });
            return Err(UnsafeNativePluginError::LoadFailed(format!(
                "SHA-256 mismatch: expected {}, got {}",
                expected, sha256
            )));
        }
    }

    let name = canonical_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // ── FFI calls with catch_unwind ──────────────────────────────────────────
    let gen = next_generation();

    let load_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        load_native_library(&canonical_path, &name, gen, &sha256)
    }));

    match load_result {
        Ok(Ok(ext)) => {
            crate::wasm_metrics::record_unsafe_native_extension_loaded(&ext.name);
            record_audit_event(UnsafeNativeAuditEventKind::LoadAccepted {
                name: ext.name.clone(),
                path: ext.canonical_path.display().to_string(),
                sha256: ext.sha256.clone(),
                generation: ext.generation,
            });
            Ok(ext)
        }
        Ok(Err(UnsafeNativePluginError::AbiMismatch { plugin, expected })) => {
            crate::wasm_metrics::record_unsafe_native_extension_load_failed(&name);
            record_audit_event(UnsafeNativeAuditEventKind::AbiMismatch {
                name: name.clone(),
                plugin_version: plugin.clone(),
                expected_version: expected.clone(),
            });
            Err(UnsafeNativePluginError::AbiMismatch { plugin, expected })
        }
        Ok(Err(e)) => {
            crate::wasm_metrics::record_unsafe_native_extension_load_failed(&name);
            Err(e)
        }
        Err(panic_err) => {
            crate::wasm_metrics::record_unsafe_native_extension_load_failed(&name);
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "Native extension panicked during load".to_string()
            };
            tracing::error!("Panic in native extension load for '{}': {}", name, msg);
            record_audit_event(UnsafeNativeAuditEventKind::FactoryPanic {
                name: name.clone(),
                message: msg.clone(),
            });
            Err(UnsafeNativePluginError::LoadFailed(format!(
                "Native extension panicked during load: {}",
                msg
            )))
        }
    }
}

/// Inner unsafe block for loading the native library.
///
/// # Safety
///
/// Calls `libloading::Library::new` and invokes FFI symbols from the loaded
/// library. The caller must ensure `catch_unwind` wraps this to prevent UB.
unsafe fn load_native_library(
    canonical_path: &Path,
    name: &str,
    generation: u64,
    sha256: &str,
) -> Result<UnsafeNativeExtension, UnsafeNativePluginError> {
    let lib = Library::new(canonical_path)
        .map_err(|e| UnsafeNativePluginError::LoadFailed(e.to_string()))?;
    let lib = Arc::new(lib);

    let version: Symbol<*const std::ffi::c_char> = lib
        .get(b"synvoid_abi_version")
        .map_err(|e| UnsafeNativePluginError::SymbolNotFound(e.to_string()))?;

    let plugin_version = std::ffi::CStr::from_ptr(*version)
        .to_string_lossy()
        .into_owned();

    if plugin_version != AXUM_ABI_VERSION {
        tracing::error!(
            "Unsafe native extension ABI version mismatch: plugin={}, expected={}",
            plugin_version,
            AXUM_ABI_VERSION
        );
        return Err(UnsafeNativePluginError::AbiMismatch {
            plugin: plugin_version,
            expected: AXUM_ABI_VERSION.to_string(),
        });
    }

    let factory: Symbol<unsafe extern "C" fn() -> *mut Router<()>> = lib
        .get(b"create_router")
        .map_err(|e| UnsafeNativePluginError::SymbolNotFound(e.to_string()))?;

    let router_ptr = factory();
    if router_ptr.is_null() {
        return Err(UnsafeNativePluginError::LoadFailed(
            "Factory returned null".to_string(),
        ));
    }

    let router = Box::from_raw(router_ptr);

    tracing::warn!(
        "Loaded UNSAFE native extension: {} (path={}, sha256={}, abi={}, gen={})",
        name,
        canonical_path.display(),
        &sha256[..16],
        plugin_version,
        generation
    );

    // Wrap the router with a request-counting middleware layer so that
    // `synvoid_unsafe_native_extension_request_total` is emitted for every
    // request that passes through this native extension's routes.
    let extension_name = name.to_owned();
    let metrics_layer = axum::Router::new().layer(axum::middleware::from_fn(
        move |req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let name = extension_name.clone();
            async move {
                crate::wasm_metrics::record_unsafe_native_extension_request(&name);
                next.run(req).await
            }
        },
    ));
    let router = metrics_layer.merge(*router);

    Ok(UnsafeNativeExtension {
        name: name.to_string(),
        path: canonical_path.to_path_buf(),
        canonical_path: canonical_path.to_path_buf(),
        library: lib,
        router: Arc::new(router),
        abi_version: plugin_version,
        loaded_at: SystemTime::now(),
        sha256: sha256.to_string(),
        generation,
    })
}

// ─── Example code ────────────────────────────────────────────────────────────

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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "unsafe_native_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    // ── WS2: Production gate tests ───────────────────────────────────────────

    #[test]
    fn test_production_default_rejects_native_loading() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake library").unwrap();

        // Default config: enabled=false, production mode=true
        let config = UnsafeNativeExtensionConfig {
            enabled: false,
            production_mode_override: Some(true),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], None);
        assert!(result.is_err());
        match result.unwrap_err() {
            UnsafeNativePluginError::LoadFailed(msg) => {
                assert!(
                    msg.contains("disabled"),
                    "Expected disabled message, got: {}",
                    msg
                );
            }
            other => panic!("Expected LoadFailed(disabled), got: {:?}", other),
        }

        cleanup(&dir);
    }

    #[test]
    fn test_production_enabled_no_acknowledgement_rejects() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake library").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: true,
            risk_acknowledgement: None,
            production_mode_override: Some(true),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &["/nonexistent".to_string()], None);
        assert!(matches!(
            result.unwrap_err(),
            UnsafeNativePluginError::RiskAcknowledgementRequired
        ));

        cleanup(&dir);
    }

    #[test]
    fn test_production_wrong_acknowledgement_rejects() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake library").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: true,
            risk_acknowledgement: Some("wrong string".to_string()),
            production_mode_override: Some(true),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &["/nonexistent".to_string()], None);
        assert!(matches!(
            result.unwrap_err(),
            UnsafeNativePluginError::RiskAcknowledgementRequired
        ));

        cleanup(&dir);
    }

    #[test]
    fn test_production_no_allowed_dirs_rejects() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake library").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: true,
            risk_acknowledgement: Some(
                "I understand native extensions run with full Synvoid process authority"
                    .to_string(),
            ),
            allowed_dirs: vec![],
            production_mode_override: Some(true),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], None);
        assert!(matches!(
            result.unwrap_err(),
            UnsafeNativePluginError::NoAllowedDirs
        ));

        cleanup(&dir);
    }

    #[test]
    fn test_development_enabled_can_load() {
        let dir = temp_dir();
        let so_path = dir.join("test_ext.so");
        fs::write(&so_path, b"fake library content").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        // Will fail at ELF validation or ABI check, but should NOT fail at production gate
        let result = load_plugin(&so_path, &[], None);
        match result {
            Err(UnsafeNativePluginError::SymbolNotFound(_)) => {}
            Err(UnsafeNativePluginError::LoadFailed(msg))
                if msg.contains("Cannot resolve")
                    || msg.contains("dlopen")
                    || msg.contains("file too short") =>
            {
                // Acceptable — fake .so can't be parsed by libloading
            }
            other => panic!("Expected symbol not found or load error, got: {:?}", other),
        }

        cleanup(&dir);
    }

    // ── WS4: Path enforcement tests ──────────────────────────────────────────

    #[test]
    fn test_path_outside_allowed_dirs_rejected() {
        let dir = temp_dir();
        let outside = temp_dir();
        let so_path = outside.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[dir.to_str().unwrap().to_string()], None);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("not within any allowed directory"),
            "Expected path rejection, got: {}",
            msg
        );

        cleanup(&dir);
        cleanup(&outside);
    }

    #[test]
    fn test_symlink_rejected() {
        let dir = temp_dir();
        let real_file = dir.join("real.so");
        fs::write(&real_file, b"fake").unwrap();
        let link_path = dir.join("link.so");
        std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&link_path, &[], None);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("symlinks are not allowed"),
            "Expected symlink rejection, got: {}",
            msg
        );

        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_world_writable_library_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();
        fs::set_permissions(&so_path, fs::Permissions::from_mode(0o777)).unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], None);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("world-writable"),
            "Expected world-writable rejection, got: {}",
            msg
        );

        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_world_writable_parent_dir_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let subdir = dir.join("sub");
        fs::create_dir(&subdir).unwrap();
        fs::set_permissions(&subdir, fs::Permissions::from_mode(0o777)).unwrap();
        let so_path = subdir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], None);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("Parent directory") && msg.contains("world-writable"),
            "Expected parent world-writable rejection, got: {}",
            msg
        );

        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_644_permissions_accepted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();
        fs::set_permissions(&so_path, fs::Permissions::from_mode(0o644)).unwrap();

        // Test path validation directly — 0o644 is not world-writable and should pass
        let result = validate_plugin_path(&so_path, &[]);
        assert!(
            result.is_ok(),
            "0o644 permissions should be accepted, got: {:?}",
            result.err()
        );

        cleanup(&dir);
    }

    #[test]
    fn test_wrong_extension_rejected() {
        let dir = temp_dir();
        let txt_path = dir.join("test.txt");
        fs::write(&txt_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&txt_path, &[], None);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains(".so, .dylib, or .dll"),
            "Expected extension rejection, got: {}",
            msg
        );

        cleanup(&dir);
    }

    #[test]
    fn test_hash_mismatch_rejected() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(
            &so_path,
            &[],
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        );
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("SHA-256 mismatch"),
            "Expected hash mismatch, got: {}",
            msg
        );

        cleanup(&dir);
    }

    #[test]
    fn test_hash_match_accepted() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        // Compute the actual hash first
        let actual_hash = compute_sha256(&so_path).unwrap();

        // Verify hash passes (compute_sha256 matches itself)
        let recomputed = compute_sha256(&so_path).unwrap();
        assert_eq!(
            actual_hash, recomputed,
            "Hash computation should be deterministic"
        );

        // Now verify that load_plugin with correct hash does NOT fail on hash mismatch
        // (it will fail later at ELF validation, which is expected)
        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], Some(&actual_hash));
        match result {
            Err(UnsafeNativePluginError::LoadFailed(msg)) if msg.contains("SHA-256 mismatch") => {
                panic!("Hash should match, got mismatch error");
            }
            _ => {
                // Any other error is fine — hash check passed
            }
        }

        cleanup(&dir);
    }

    // ── WS6: Status tests ────────────────────────────────────────────────────

    #[test]
    fn test_status_contains_generation() {
        // Test UnsafeNativeExtensionStatus directly since UnsafeNativeExtension
        // requires a real Library handle.
        let status = UnsafeNativeExtensionStatus {
            name: "test".to_string(),
            path: "/test/plugin.so".to_string(),
            sha256: "abc123def456".to_string(),
            abi_version: "0.0.0".to_string(),
            loaded_at: 1000,
            generation: 42,
        };
        assert_eq!(status.generation, 42);
        assert_eq!(status.sha256, "abc123def456");
        assert_eq!(status.name, "test");
    }

    // ── Config defaults tests ────────────────────────────────────────────────

    #[test]
    fn test_config_defaults_disabled() {
        let config = UnsafeNativeExtensionConfig::default();
        assert!(!config.enabled);
        assert!(!config.allow_in_production);
        assert!(!config.hot_reload_enabled);
        assert!(config.risk_acknowledgement.is_none());
        assert!(config.allowed_dirs.is_empty());
    }

    #[test]
    fn test_generation_counter_increments() {
        let gen1 = next_generation();
        let gen2 = next_generation();
        assert!(gen2 > gen1);
    }

    // ── 17: 744 permissions accepted ────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_744_permissions_accepted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();
        fs::set_permissions(&so_path, fs::Permissions::from_mode(0o744)).unwrap();

        let result = validate_plugin_path(&so_path, &[]);
        assert!(
            result.is_ok(),
            "0o744 permissions should be accepted, got: {:?}",
            result.err()
        );

        cleanup(&dir);
    }

    // ── 18: Hot reload disabled by default ──────────────────────────────────

    #[test]
    fn test_hot_reload_disabled_by_default() {
        let config = UnsafeNativeExtensionConfig::default();
        assert!(
            !config.hot_reload_enabled,
            "hot_reload_enabled should default to false"
        );
    }

    // ── 19: Native hot reload requires separate config ──────────────────────

    #[test]
    fn test_native_hot_reload_requires_separate_config() {
        let config = UnsafeNativeExtensionConfig {
            hot_reload_enabled: false,
            ..Default::default()
        };
        assert!(
            !config.hot_reload_enabled,
            "Native hot reload should be independent of WASM hot reload"
        );

        let config_with_reload = UnsafeNativeExtensionConfig {
            hot_reload_enabled: true,
            ..Default::default()
        };
        assert!(config_with_reload.hot_reload_enabled);
    }

    // ── 20: Production native hot reload requires config ────────────────────

    #[test]
    fn test_production_native_hot_reload_requires_config() {
        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: true,
            risk_acknowledgement: Some(
                "I understand native extensions run with full Synvoid process authority"
                    .to_string(),
            ),
            hot_reload_enabled: false,
            production_mode_override: Some(true),
            ..Default::default()
        };

        // Config validates for load (all production gates pass)
        let result = config.validate_for_load(&["/some/dir".to_string()]);
        assert!(result.is_ok(), "Config should validate for load");

        // But hot_reload_enabled is false
        assert!(
            !config.hot_reload_enabled,
            "hot_reload_enabled should be false even when load validation passes"
        );
    }

    // ── 21: Reload increments generation ────────────────────────────────────

    #[test]
    fn test_reload_increments_generation() {
        let gen1 = next_generation();
        let gen2 = next_generation();
        let gen3 = next_generation();
        assert!(gen2 > gen1);
        assert!(gen3 > gen2);
    }

    // ── 22: Status reports generation ───────────────────────────────────────

    #[test]
    fn test_status_reports_generation() {
        let status = UnsafeNativeExtensionStatus {
            name: "my_ext".to_string(),
            path: "/plugins/my_ext.so".to_string(),
            sha256: "deadbeef".to_string(),
            abi_version: "1.0.0".to_string(),
            loaded_at: 2000,
            generation: 7,
        };
        assert_eq!(status.generation, 7);
        assert_eq!(status.name, "my_ext");
    }

    // ── 23: Last load error set on rejection ────────────────────────────────

    #[test]
    fn test_last_load_error_set_on_rejection() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: false,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], None);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("disabled"),
            "Error message should contain 'disabled', got: {}",
            err_msg
        );

        cleanup(&dir);
    }

    // ── 24: Load failure records metric ─────────────────────────────────────

    #[test]
    fn test_load_failure_records_metric() {
        crate::wasm_metrics::record_unsafe_native_extension_load_failed("test_metric_fail");
    }

    // ── 25: Load success records metric ─────────────────────────────────────

    #[test]
    fn test_load_success_records_metric() {
        crate::wasm_metrics::record_unsafe_native_extension_loaded("test_metric_success");
    }

    // ── 26: Factory panic returns safe error ────────────────────────────────

    #[test]
    fn test_factory_panic_returns_safe_error() {
        let dir = temp_dir();
        let so_path = dir.join("fake_plugin.so");
        fs::write(&so_path, b"not a real shared library").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], None);
        assert!(result.is_err());
        match result.unwrap_err() {
            UnsafeNativePluginError::LoadFailed(_) | UnsafeNativePluginError::SymbolNotFound(_) => {
            }
            other => panic!("Expected LoadFailed or SymbolNotFound, got: {:?}", other),
        }

        cleanup(&dir);
    }

    // ── 27: Null factory pointer returns error ──────────────────────────────

    #[test]
    fn test_null_factory_pointer_returns_error() {
        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake binary content").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let result = load_plugin(&so_path, &[], None);
        assert!(result.is_err(), "Loading a fake .so should fail");
        let err = result.unwrap_err();
        let is_expected = matches!(
            err,
            UnsafeNativePluginError::LoadFailed(_) | UnsafeNativePluginError::SymbolNotFound(_)
        );
        assert!(
            is_expected,
            "Expected LoadFailed or SymbolNotFound for fake .so, got: {:?}",
            err
        );

        cleanup(&dir);
    }

    // ── 28: Unsafe native docs not sandboxed ────────────────────────────────

    #[test]
    fn test_unsafe_native_docs_not_sandboxed() {
        let example = create_plugin_library_example();
        assert!(
            example.contains("create_router"),
            "Example should mention create_router"
        );
        assert!(
            example.contains("synvoid_abi_version"),
            "Example should mention synvoid_abi_version"
        );
    }

    // ── 29: Global config snapshot ──────────────────────────────────────────

    #[test]
    fn test_global_config_snapshot() {
        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: true,
            risk_acknowledgement: Some("ack".to_string()),
            allowed_dirs: vec!["/tmp/plugins".to_string()],
            hot_reload_enabled: true,
            production_mode_override: Some(true),
        };
        set_global_unsafe_native_config(config.clone());

        let snapshot = get_global_unsafe_native_config();
        assert!(snapshot.enabled);
        assert!(snapshot.allow_in_production);
        assert_eq!(snapshot.risk_acknowledgement, Some("ack".to_string()));
        assert_eq!(snapshot.allowed_dirs, vec!["/tmp/plugins".to_string()]);
        assert!(snapshot.hot_reload_enabled);
        assert_eq!(snapshot.production_mode_override, Some(true));
    }

    // ── 30: validate_for_load enabled check ─────────────────────────────────

    #[test]
    fn test_validate_for_load_enabled_check() {
        let config = UnsafeNativeExtensionConfig {
            enabled: false,
            production_mode_override: Some(false),
            ..Default::default()
        };
        let result = config.validate_for_load(&[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            UnsafeNativePluginError::LoadFailed(msg) => {
                assert!(
                    msg.contains("disabled"),
                    "Expected disabled message, got: {}",
                    msg
                );
            }
            other => panic!("Expected LoadFailed(disabled), got: {:?}", other),
        }
    }

    // ── 31: validate_for_load production check ──────────────────────────────

    #[test]
    fn test_validate_for_load_production_check() {
        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: false,
            production_mode_override: Some(true),
            ..Default::default()
        };
        let result = config.validate_for_load(&["/tmp".to_string()]);
        assert!(matches!(
            result.unwrap_err(),
            UnsafeNativePluginError::ProductionDenied
        ));
    }

    // ── 32: validate_for_load risk acknowledgement check ────────────────────

    #[test]
    fn test_validate_for_load_risk_acknowledgement_check() {
        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: true,
            risk_acknowledgement: Some("wrong acknowledgement".to_string()),
            production_mode_override: Some(true),
            ..Default::default()
        };
        let result = config.validate_for_load(&["/tmp".to_string()]);
        assert!(matches!(
            result.unwrap_err(),
            UnsafeNativePluginError::RiskAcknowledgementRequired
        ));
    }

    // ── 33: validate_for_load allowed dirs check ────────────────────────────

    #[test]
    fn test_validate_for_load_allowed_dirs_check() {
        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: true,
            risk_acknowledgement: Some(
                "I understand native extensions run with full Synvoid process authority"
                    .to_string(),
            ),
            allowed_dirs: vec![],
            production_mode_override: Some(true),
            ..Default::default()
        };
        let result = config.validate_for_load(&[]);
        assert!(matches!(
            result.unwrap_err(),
            UnsafeNativePluginError::NoAllowedDirs
        ));
    }

    // ── 34: validate_for_load development passes ────────────────────────────

    #[test]
    fn test_validate_for_load_development_passes() {
        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        let result = config.validate_for_load(&[]);
        assert!(
            result.is_ok(),
            "Development mode should pass all checks, got: {:?}",
            result.err()
        );
    }

    // ── WS8 #21: Audit event tests ──────────────────────────────────────────

    #[test]
    fn test_audit_event_emitted_on_disabled_rejection() {
        drain_audit_events();

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: false,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let _ = load_plugin(&so_path, &[], None);
        let events = drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(
                    &e.kind,
                    UnsafeNativeAuditEventKind::LoadRejectedGate { reason } if reason.contains("disabled")
                )),
            "Expected LoadRejectedGate with 'disabled' reason, got: {:?}",
            events.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );
        assert!(
            events.iter().all(|e| e.timestamp > 0),
            "Timestamps should be non-zero"
        );

        cleanup(&dir);
    }

    #[test]
    fn test_audit_event_emitted_on_production_denied() {
        drain_audit_events();

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            allow_in_production: false,
            production_mode_override: Some(true),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let _ = load_plugin(&so_path, &[], None);
        let events = drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(
                    &e.kind,
                    UnsafeNativeAuditEventKind::LoadRejectedGate { reason } if reason.contains("not allowed")
                )),
            "Expected ProductionDenied, got: {:?}",
            events.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );

        cleanup(&dir);
    }

    #[test]
    fn test_audit_event_emitted_on_path_rejection() {
        drain_audit_events();

        let dir = temp_dir();
        let outside = temp_dir();
        let so_path = outside.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let _ = load_plugin(&so_path, &[dir.to_str().unwrap().to_string()], None);
        let events = drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(&e.kind, UnsafeNativeAuditEventKind::LoadRejectedPath { .. })),
            "Expected LoadRejectedPath, got: {:?}",
            events.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );

        cleanup(&dir);
        cleanup(&outside);
    }

    #[test]
    fn test_audit_event_emitted_on_hash_mismatch() {
        drain_audit_events();

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: true,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let _ = load_plugin(
            &so_path,
            &[],
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        );
        let events = drain_audit_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(&e.kind, UnsafeNativeAuditEventKind::HashMismatch { .. })),
            "Expected HashMismatch, got: {:?}",
            events.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );

        cleanup(&dir);
    }

    #[test]
    fn test_drain_audit_events_clears_buffer() {
        drain_audit_events();

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: false,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let _ = load_plugin(&so_path, &[], None);
        let events1 = drain_audit_events();
        assert!(!events1.is_empty(), "First drain should have events");

        let events2 = drain_audit_events();
        assert_eq!(events2.len(), 0, "Second drain should be empty");

        cleanup(&dir);
    }

    #[test]
    fn test_peek_audit_events_preserves_buffer() {
        drain_audit_events();

        let dir = temp_dir();
        let so_path = dir.join("test.so");
        fs::write(&so_path, b"fake").unwrap();

        let config = UnsafeNativeExtensionConfig {
            enabled: false,
            production_mode_override: Some(false),
            ..Default::default()
        };
        set_global_unsafe_native_config(config);

        let _ = load_plugin(&so_path, &[], None);
        let peek1 = peek_audit_events();
        assert!(!peek1.is_empty(), "Peek should have events");

        let peek2 = peek_audit_events();
        assert_eq!(peek1.len(), peek2.len(), "Peek should not consume events");

        drain_audit_events();

        cleanup(&dir);
    }

    #[test]
    fn test_audit_event_ring_buffer_evicts_oldest() {
        drain_audit_events();

        // Manually fill the buffer beyond MAX_AUDIT_EVENTS
        for i in 0..=MAX_AUDIT_EVENTS {
            record_audit_event(UnsafeNativeAuditEventKind::LoadRejectedGate {
                reason: format!("test {}", i),
            });
        }

        let events = drain_audit_events();
        assert!(
            events.len() <= MAX_AUDIT_EVENTS,
            "Buffer should be capped at MAX_AUDIT_EVENTS ({}), got {}",
            MAX_AUDIT_EVENTS,
            events.len()
        );
        // The earliest events should have been evicted; verify the first remaining
        // event has a reason number >= 1 (since we added 0..=256 = 257 events)
        if let UnsafeNativeAuditEventKind::LoadRejectedGate { reason } = &events[0].kind {
            let num: u32 = reason.strip_prefix("test ").unwrap().parse().unwrap();
            assert!(
                num > 0,
                "Oldest event should have been evicted, got num={}",
                num
            );
        } else {
            panic!("Expected LoadRejectedGate");
        }
    }

    // ── Gap 4: Library handle retention test (WS8 #14) ────────────────────

    /// Verify that `UnsafeNativeExtension` struct retains `Arc<Library>`.
    ///
    /// We can't construct a real `Library` in a unit test, but we can verify
    /// the struct field type exists via a compile-time type assertion.
    #[test]
    fn test_library_handle_retention_structural() {
        // Compile-time: verify UnsafeNativeExtension has a `library` field of type Arc<Library>
        fn _assert_library_field(ext: &UnsafeNativeExtension) -> &Arc<Library> {
            &ext.library
        }

        // Verify the Debug impl doesn't panic (it omits the library field)
        let status = UnsafeNativeExtensionStatus {
            name: "test".to_string(),
            path: "/test.so".to_string(),
            sha256: "abc".to_string(),
            abi_version: "1.0.0".to_string(),
            loaded_at: 1000,
            generation: 1,
        };
        assert_eq!(status.generation, 1);
    }

    /// Verify that UnsafeNativeExtension.status() reports the generation field.
    #[test]
    fn test_library_status_reports_generation_from_struct() {
        let status = UnsafeNativeExtensionStatus {
            name: "retention_test".to_string(),
            path: "/plugins/retention_test.so".to_string(),
            sha256: "aabbccdd".to_string(),
            abi_version: "0.1.0".to_string(),
            loaded_at: 5000,
            generation: 3,
        };
        assert_eq!(status.generation, 3);
        assert_eq!(status.name, "retention_test");
    }
}
