use std::path::Path;
use std::sync::Arc;

use axum::Router;
use libloading::{Library, Symbol};

use super::AxumPluginError;

const AXUM_ABI_VERSION: &str = env!("CARGO_PKG_VERSION");

fn validate_plugin_path(path: &Path) -> Result<(), AxumPluginError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(AxumPluginError::LoadFailed(
                "Plugin symlinks are not allowed".to_string(),
            ));
        }
    }

    let canonical_path = path
        .canonicalize()
        .map_err(|e| AxumPluginError::LoadFailed(format!("Cannot resolve plugin path: {}", e)))?;

    if let Ok(metadata) = std::fs::metadata(&canonical_path) {
        let file_size = metadata.len();
        let max_plugin_size = 50 * 1024 * 1024;
        if file_size > max_plugin_size {
            return Err(AxumPluginError::LoadFailed(format!(
                "Plugin file too large: {} bytes (max {})",
                file_size, max_plugin_size
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            if mode & 0o777 != 0o755 && mode & 0o777 != 0o500 {
                return Err(AxumPluginError::LoadFailed(format!(
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
        return Err(AxumPluginError::LoadFailed(
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
            return Err(AxumPluginError::LoadFailed(format!(
                "Plugin filename '{}' contains potentially dangerous library name",
                filename
            )));
        }
    }

    tracing::info!("Validated plugin path: {}", canonical_path.display());
    Ok(())
}

pub fn load_plugin(path: &Path) -> Result<(Arc<Router<()>>, String), AxumPluginError> {
    validate_plugin_path(path)?;

    unsafe {
        let lib = Library::new(path).map_err(|e| AxumPluginError::LoadFailed(e.to_string()))?;

        let version: Symbol<*const std::ffi::c_char> = lib
            .get(b"maluwaf_abi_version")
            .map_err(|e| AxumPluginError::SymbolNotFound(e.to_string()))?;

        let plugin_version = std::ffi::CStr::from_ptr(*version)
            .to_string_lossy()
            .into_owned();

        if plugin_version != AXUM_ABI_VERSION {
            tracing::error!(
                "Plugin ABI version mismatch: plugin={}, expected={}",
                plugin_version,
                AXUM_ABI_VERSION
            );
            return Err(AxumPluginError::AbiMismatch {
                plugin: plugin_version,
                expected: AXUM_ABI_VERSION.to_string(),
            });
        }

        let factory: Symbol<unsafe extern "C" fn() -> *mut Router<()>> = lib
            .get(b"create_router")
            .map_err(|e| AxumPluginError::SymbolNotFound(e.to_string()))?;

        let router_ptr = factory();
        if router_ptr.is_null() {
            return Err(AxumPluginError::LoadFailed(
                "Factory returned null".to_string(),
            ));
        }

        let router = Box::from_raw(router_ptr);

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok((Arc::new(*router), name))
    }
}

pub fn create_plugin_library_example() -> &'static str {
    r#"
use axum::{Router, routing::get};

#[no_mangle]
pub static maluwaf_abi_version: *const std::ffi::c_char = concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::ffi::c_char;

#[no_mangle]
pub extern "C" fn create_router() -> *mut Router<()> {
    let router = Router::new()
        .route("/", get(|| async { "Hello from plugin!" }));
    Box::into_raw(Box::new(router))
}
"#
}
