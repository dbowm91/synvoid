//
// Dynamic Axum Plugin for synvoid
//
// This example shows how to build an Axum app as a shared library
// that can be loaded at runtime by synvoid.
//
// IMPORTANT: The ABI version must match synvoid's version for stability.
// synvoid will log a warning if versions don't match.
//
// Required exports:
// - synvoid_abi_version: C string pointer with version
// - create_router: Function that returns pointer to Router
//

use axum::{routing::get, Router};

#[repr(transparent)]
pub struct AbiVersion(*const std::ffi::c_char);

unsafe impl Sync for AbiVersion {}

#[no_mangle]
pub static synvoid_abi_version: AbiVersion = {
    let version = concat!(env!("CARGO_PKG_VERSION"), "\0");
    AbiVersion(version.as_ptr() as *const std::ffi::c_char)
};

#[no_mangle]
pub extern "C" fn create_router() -> *mut Router<()> {
    let router = Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/data", get(data))
        .fallback(fallback);

    Box::into_raw(Box::new(router))
}

#[no_mangle]
// SAFETY: FFI boundary — caller guarantees `router` is a valid pointer from `create_router`.
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI: caller-owned pointer, validity is contract
pub extern "C" fn destroy_router(router: *mut Router<()>) {
    if !router.is_null() {
        unsafe {
            drop(Box::from_raw(router));
        }
    }
}

async fn index() -> &'static str {
    "Hello from dynamic Axum plugin!"
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "plugin": "myapp",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn data() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "message": "Dynamic content from plugin",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn fallback(uri: axum::http::Uri) -> (axum::http::StatusCode, String) {
    (
        axum::http::StatusCode::NOT_FOUND,
        format!("Not found: {}", uri),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_plugin() {
        unsafe {
            let router = create_router();
            assert!(!router.is_null());

            let app = &*router;
            let response = app
                .clone()
                .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);

            destroy_router(router);
        }
    }
}
