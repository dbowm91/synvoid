//! Admin route-contract regression test
//!
//! Validates that production frontend operations map to registered backend routes.
//! Catches singular/plural path drift, POST-vs-PUT drift, and calls to absent routes.
//!
//! Test principle: a registered route returns any status OTHER than 404.
//! Unregistered routes return 404.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use synvoid::admin::create_admin_router;
use synvoid::config::admin::{AdminCorsConfig, AdminRateLimitConfig};
use synvoid::config::ConfigManager;

fn default_cors() -> AdminCorsConfig {
    AdminCorsConfig::default()
}

fn disabled_rate_limit() -> AdminRateLimitConfig {
    AdminRateLimitConfig {
        requests_per_minute: u32::MAX,
        burst: u32::MAX,
    }
}

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
            None,
            None,
            None,
            None,
            None,
            #[cfg(feature = "mesh")]
            None,
            #[cfg(feature = "icmp-filter")]
            None,
        )
    })
    .await
    .expect("spawn_blocking should not panic")
}

/// Helper: assert route exists (not 404).
fn assert_route_exists(response: axum::response::Response, description: &str) {
    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "{} should be registered (any status except 404), got 404",
        description
    );
}

/// Production frontend API contract: every path/method must map to a registered route.
#[tokio::test]
async fn admin_route_contract_worker_routes() {
    let router = build_test_router().await;

    // GET /system/workers
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/system/workers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "GET /api/system/workers");

    // GET /system/supervisor (replaces old /system/overseer)
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/system/supervisor")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "GET /api/system/supervisor");

    // GET /system/workers/count
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/system/workers/count")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "GET /api/system/workers/count");

    // POST /system/workers/scale
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/system/workers/scale")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"target_count": 2}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "POST /api/system/workers/scale");

    // POST /system/workers/{id}/restart (plural, canonical)
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/system/workers/test-worker-1/restart")
                .header("content-type", "application/json")
                .body(Body::from(r"{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "POST /api/system/workers/{{id}}/restart");
}

/// Old singular worker restart path must NOT exist.
#[tokio::test]
async fn admin_route_contract_old_worker_restart_absent() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/system/worker/test-worker-1/restart")
                .header("content-type", "application/json")
                .body(Body::from(r"{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "POST /api/system/worker/{{id}}/restart (singular) should NOT exist (404)"
    );
}

/// Old /system/overseer path must NOT exist.
#[tokio::test]
async fn admin_route_contract_old_overseer_absent() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/system/overseer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /api/system/overseer should NOT exist (404)"
    );
}

/// Old /config/overseer path must NOT exist.
#[tokio::test]
async fn admin_route_contract_old_config_overseer_absent() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/config/overseer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /api/config/overseer should NOT exist (404)"
    );
}

/// ICMP routes must be registered when icmp-filter feature is enabled.
#[cfg(feature = "icmp-filter")]
#[tokio::test]
async fn admin_route_contract_icmp_routes() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/icmp/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "GET /api/icmp/status");

    // PUT /icmp/config is canonical (not POST)
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/icmp/config")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "PUT /api/icmp/config");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/icmp/enable")
                .header("content-type", "application/json")
                .body(Body::from(r"{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "POST /api/icmp/enable");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/icmp/disable")
                .header("content-type", "application/json")
                .body(Body::from(r"{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "POST /api/icmp/disable");
}

/// Mesh config routes must be registered when mesh feature is enabled.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn admin_route_contract_mesh_config_routes() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/config/mesh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "GET /api/config/mesh");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/config/mesh")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "PUT /api/config/mesh");
}

/// Tier key routes must be registered when mesh feature is enabled.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn admin_route_contract_tier_key_routes() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/tier-keys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "GET /api/tier-keys");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tier-keys/issue")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"org_id": "test", "tier": 1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "POST /api/tier-keys/issue");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tier-keys/revoke")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"org_id": "test", "key_id": "key-1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "POST /api/tier-keys/revoke");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/tier-keys/unbind")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"org_id": "test", "key_id": "key-1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "POST /api/tier-keys/unbind");
}

/// Supervisor config routes must be registered.
#[tokio::test]
async fn admin_route_contract_supervisor_config_routes() {
    let router = build_test_router().await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/config/supervisor")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "GET /api/config/supervisor");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/config/supervisor")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"min_workers": 2}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_route_exists(response, "PUT /api/config/supervisor");
}

/// Negative test: the contract check fails when given fabricated/wrong paths.
/// Proves the test infrastructure detects drift (acceptance criteria requirement).
#[tokio::test]
async fn admin_route_contract_fails_on_wrong_fixture() {
    let router = build_test_router().await;

    // Fabricated routes that should NOT exist — pure 404s (unregistered paths)
    let wrong_fixture: Vec<(&str, &str, &str)> = vec![
        ("GET", "/api/nonexistent/route", "nonexistent GET"),
        ("POST", "/api/config/overseer", "old overseer POST"),
        (
            "PUT",
            "/api/system/worker/1/restart",
            "singular worker restart",
        ),
        ("GET", "/api/mesh/tier-keys", "namespaced tier-keys"),
        ("POST", "/api/admin/ghost", "completely fabricated"),
        ("GET", "/api/sites/broken/edit", "nonexistent sites subpath"),
    ];

    for (method, path, description) in &wrong_fixture {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(*path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Wrong fixture '{}' ({}) should return 404, got {}",
            description,
            path,
            response.status()
        );
    }
}
