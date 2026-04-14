//
// Example: Building RustWAF with embedded Axum application
//
// This example shows how to create a custom WAF binary that includes
// your Axum/Yew application directly compiled in.
//
// For compile-time integration (maximum performance):
// --------------------------------------------------
// 1. Add this crate as a dependency in your app's Cargo.toml:
//
// [dependencies]
// rustwaf = { path = "/path/to/rustwaf", features = ["axum-embedded"] }
// myapp = { path = "./myapp" }
//
// 2. Create your app router in myapp/src/lib.rs:
//
// use axum::{Router, routing::get};
//
// pub fn app() -> Router {
//     Router::new()
//         .route("/", get(|| async { "Hello from embedded app!" }))
// }
//
// 3. Build the combined binary:
//
// cargo build --release
//
// For dynamic loading (convenience):
// --------------------------------------------------
// Use axum-dynamic backend type in your site config:
//
// [site]
// domains = ["myapp.example.com"]
//
// [site.backend]
// type = "axum-dynamic"
// plugin = "/opt/myapp/libmyapp.so"
// socket = "/run/rustwaf/app.sock"
//
// Build your app as a shared library:
// cargo build --release -C rustflags="-C link-args=-shared" -p myapp
//

use axum::{routing::get, Router};

pub fn create_app() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/data", get(data))
        .fallback(fallback)
}

async fn index() -> &'static str {
    "Hello from RustWAF with embedded Axum app!"
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "rustwaf-app"
    }))
}

async fn data() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "message": "Your dynamic content here",
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
    async fn test_index() {
        let app = create_app();
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health() {
        let app = create_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fallback() {
        let app = create_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
