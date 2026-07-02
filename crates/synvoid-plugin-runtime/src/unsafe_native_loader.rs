use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use libloading::{Library, Symbol};
use sha2::Digest;

use crate::plugin_manager::UnsafeNativePluginError;

const AXUM_ABI_VERSION: &str = env!("CARGO_PKG_VERSION");

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
}

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

            if mode & 0o777 != 0o755 && mode & 0o777 != 0o500 {
                return Err(UnsafeNativePluginError::LoadFailed(format!(
                    "Plugin {} has insecure permissions {:o}, must be 755 or 500",
                    canonical_path.display(),
                    mode & 0o777
                )));
            }
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

/// Load an unsafe native extension from a shared library file.
///
/// The returned `UnsafeNativeExtension` retains the `Library` handle for the
/// lifetime of the extension, preventing use-after-free of plugin-derived code.
pub fn load_plugin(
    path: &Path,
    allowed_dirs: &[String],
    expected_hash: Option<&str>,
) -> Result<UnsafeNativeExtension, UnsafeNativePluginError> {
    let canonical_path = validate_plugin_path(path, allowed_dirs)?;

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

    unsafe {
        let lib = Library::new(&canonical_path)
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
            "Loaded UNSAFE native extension: {} (path={}, sha256={}, abi={})",
            name,
            canonical_path.display(),
            &sha256[..16],
            plugin_version
        );

        Ok(UnsafeNativeExtension {
            name,
            path: path.to_path_buf(),
            canonical_path,
            library: lib,
            router: Arc::new(*router),
            abi_version: plugin_version,
            loaded_at: SystemTime::now(),
            sha256,
        })
    }
}

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
