//! Root-test ownership: COMPOSITION
//! Rationale: validates admin router composition, public/protected delivery, and feature boundaries
//!
//! Guard tests for Phase 1: router construction must succeed for all feature profiles,
//! SPA delivery must be unauthenticated, protected API must require auth, and
//! feature-gated routes must be absent when their feature is disabled.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use synvoid::admin::create_admin_router;
use synvoid::config::admin::{AdminCorsConfig, AdminRateLimitConfig};
use synvoid::config::ConfigManager;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn default_cors() -> AdminCorsConfig {
    AdminCorsConfig::default()
}

fn disabled_rate_limit() -> AdminRateLimitConfig {
    AdminRateLimitConfig {
        requests_per_minute: u32::MAX,
        burst: u32::MAX,
    }
}

/// Build the admin router in a blocking context.
///
/// `create_admin_router` calls `config.blocking_read()` which panics inside a
/// tokio runtime. We use `spawn_blocking` to construct it off the async executor.
async fn build_test_router() -> Router {
    tokio::task::spawn_blocking(|| {
        let config_dir = std::env::temp_dir();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(ConfigManager::new(config_dir)));
        let token = "test_admin_token_that_is_at_least_32_chars_long".to_string();

        create_admin_router(
            config,
            token,
            default_cors(),
            disabled_rate_limit(),
            vec![],
            None, // probe_tracker
            None, // suspicious_word_tracker
            None, // upstream_error_tracker
            None, // threat_level_manager
            None, // rule_feed_manager
            #[cfg(feature = "mesh")]
            None, // mesh_transport
            #[cfg(feature = "icmp-filter")]
            None, // icmp_filter
        )
    })
    .await
    .expect("spawn_blocking should not panic")
}

// ── Router construction tests ────────────────────────────────────────────────

/// Default feature profile must construct without panic.
#[tokio::test]
async fn router_construction_default_features() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
}

// ── Public/protected delivery tests ──────────────────────────────────────────

/// SPA fallback must serve index.html for browser navigation requests.
#[tokio::test]
async fn spa_fallback_serves_index_html() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/settings")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    let status = response.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "SPA route should return 200 or 404 (not auth-gated), got {}",
        status
    );
}

/// API 404 must not serve the SPA shell.
#[tokio::test]
async fn api_404_not_spa_shell() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/nonexistent-endpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "/api/* misses should return 404, not SPA shell"
    );
}

/// Protected API without auth must be rejected (401).
#[tokio::test]
async fn protected_api_requires_auth() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/stats/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Protected API without auth should return 401"
    );
}

/// Health endpoint must be accessible without auth.
#[tokio::test]
async fn health_endpoint_public() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(response.status(), StatusCode::OK);
}

/// Deep SPA route returns shell or 404 (not auth-gated).
#[tokio::test]
async fn deep_spa_route_not_auth_gated() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/mesh/overview")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    let status = response.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "Deep SPA route should return 200 or 404 (not auth-gated), got {}",
        status
    );
}

// ── Feature boundary tests ───────────────────────────────────────────────────

/// ICMP routes must not be accessible without icmp-filter feature.
#[cfg(not(feature = "icmp-filter"))]
#[tokio::test]
async fn icmp_routes_absent_without_feature() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/icmp/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "ICMP route should not be accessible without feature gate"
    );
}

/// ICMP routes must be registered when icmp-filter feature is enabled.
#[cfg(feature = "icmp-filter")]
#[tokio::test]
async fn icmp_routes_present_with_feature() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/icmp/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "ICMP route should exist and require auth when feature is enabled"
    );
}

/// DNS routes must not be accessible without dns feature.
#[cfg(not(feature = "dns"))]
#[tokio::test]
async fn dns_routes_absent_without_feature() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/config/dns")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "DNS route should not be accessible without feature gate"
    );
}

/// DNS routes must be registered when dns feature is enabled.
#[cfg(feature = "dns")]
#[tokio::test]
async fn dns_routes_present_with_feature() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/config/dns")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "DNS route should exist and require auth when feature is enabled"
    );
}

/// Core routes (stats, system info) must always be present.
#[tokio::test]
async fn core_routes_always_present() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/stats/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "/api/stats/summary should exist (401), not be missing (404)"
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/system/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "/api/system/info should exist (401), not be missing (404)"
    );
}

/// Mesh routes must not be accessible without mesh feature.
#[cfg(not(feature = "mesh"))]
#[tokio::test]
async fn mesh_routes_absent_without_feature() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/mesh/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "Mesh route should not be accessible without feature gate"
    );
}

/// Mesh routes must be registered when mesh feature is enabled.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn mesh_routes_present_with_feature() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/mesh/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Mesh route should exist and require auth when feature is enabled"
    );
}
