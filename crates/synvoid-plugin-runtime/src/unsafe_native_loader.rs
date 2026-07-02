use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

use axum::Router;
use libloading::{Library, Symbol};
use sha2::Digest;

use crate::plugin_manager::UnsafeNativePluginError;

const AXUM_ABI_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    enforce_production_gate(allowed_dirs)?;

    // ── Path validation ──────────────────────────────────────────────────────
    let canonical_path = validate_plugin_path(path, allowed_dirs)?;

    // ── Hash verification ────────────────────────────────────────────────────
    let sha256 = compute_sha256(&canonical_path)?;

    if let Some(expected) = expected_hash {
        if sha256 != expected {
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
            Ok(ext)
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

    Ok(UnsafeNativeExtension {
        name: name.to_string(),
        path: canonical_path.to_path_buf(),
        canonical_path: canonical_path.to_path_buf(),
        library: lib,
        router: Arc::new(*router),
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
}
