use std::path::Path;

use axum::Router;
use libloading::{Library, Symbol};

use super::AxumPluginError;

const AXUM_ABI_VERSION: &str = env!("CARGO_PKG_VERSION");
const REQUIRED_AXUM_VERSION: &str = "0.8";
const REQUIRED_YEW_VERSION: &str = "0.21";

pub type AxumFactory = unsafe extern "C" fn() -> *mut Router<()>;

pub fn load_plugin(path: &Path) -> Result<(axum::Router<()>, String), AxumPluginError> {
    unsafe {
        let lib = Library::new(path).map_err(|e| AxumPluginError::LoadFailed(e.to_string()))?;

        let version: Symbol<*const std::ffi::c_char> = lib
            .get(b"rustwaf_abi_version")
            .map_err(|e| AxumPluginError::SymbolNotFound(e.to_string()))?;

        let plugin_version = std::ffi::CStr::from_ptr(*version)
            .to_string_lossy()
            .into_owned();

        if plugin_version != AXUM_ABI_VERSION {
            tracing::warn!(
                "Plugin ABI version {} does not match rustwaf axum version {}. \
                For best stability, recompile plugin against rustwaf {}. \
                Required: axum {}, yew {}",
                plugin_version,
                AXUM_ABI_VERSION,
                AXUM_ABI_VERSION,
                REQUIRED_AXUM_VERSION,
                REQUIRED_YEW_VERSION
            );
        }

        let factory: Symbol<AxumFactory> = lib
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

        Ok((*router, name))
    }
}

pub fn create_plugin_library_example() -> &'static str {
    r#"
use axum::{Router, routing::get};

#[no_mangle]
pub static rustwaf_abi_version: *const std::ffi::c_char = concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const std::ffi::c_char;

#[no_mangle]
pub extern "C" fn create_router() -> *mut Router<()> {
    let router = Router::new()
        .route("/", get(|| async { "Hello from plugin!" }));
    Box::into_raw(Box::new(router))
}
"#
}
