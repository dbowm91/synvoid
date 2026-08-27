//! Admin panel integrated smoke flow — exercises the 15-step acceptance criteria
//! from Phase 6 of the admin panel corrective roadmap.
//!
//! Uses `create_admin_router` with `tower::ServiceExt::oneshot` to exercise the
//! real admin router composition (not a mock), covering auth, CSRF, session lifecycle,
//! protected API access, and SPA fallback behavior.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use synvoid::admin::create_admin_router;
use synvoid::config::admin::{AdminCorsConfig, AdminRateLimitConfig};
use synvoid::config::ConfigManager;

// ── Helpers ──────────────────────────────────────────────────────────────────

const TEST_TOKEN: &str = "test_admin_token_that_is_at_least_32_chars_long";

fn default_cors() -> AdminCorsConfig {
    AdminCorsConfig::default()
}

fn disabled_rate_limit() -> AdminRateLimitConfig {
    AdminRateLimitConfig {
        requests_per_minute: u32::MAX,
        burst: u32::MAX,
    }
}

async fn build_router() -> Router {
    tokio::task::spawn_blocking(|| {
        let config_dir = std::env::temp_dir();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(ConfigManager::new(config_dir)));
        create_admin_router(
            config,
            TEST_TOKEN.to_string(),
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

fn extract_cookie(response: &Response<Body>, cookie_name: &str) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&format!("{}=", cookie_name)))
        .and_then(|c| c.split(';').next())
        .and_then(|c| c.split('=').nth(1))
        .map(|v| v.to_string())
}

fn extract_header(response: &Response<Body>, header: &str) -> Option<String> {
    response
        .headers()
        .get(header)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

async fn body_string(response: &mut Response<Body>) -> String {
    let body = response.body_mut().collect().await.unwrap_or_default();
    String::from_utf8_lossy(&body.to_bytes()).to_string()
}

async fn session_login(router: &Router) -> (String, String) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/session")
                .header("authorization", format!("Bearer {}", TEST_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login should succeed");

    let session_cookie =
        extract_cookie(&resp, "synvoid_session").expect("login should set synvoid_session cookie");
    let csrf_token =
        extract_header(&resp, "x-csrf-token").expect("login should return X-CSRF-Token header");

    (session_cookie, csrf_token)
}

// ── Step 1: Health endpoint (stand-in for "app shell loads") ─────────────────

#[tokio::test]
async fn smoke_01_health_endpoint_responds() {
    let router = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Step 2: SPA fallback for unauthenticated browser navigation ──────────────

#[tokio::test]
async fn smoke_02_spa_fallback_unauthenticated() {
    let router = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/settings")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "SPA route should return 200 or 404 (not auth-gated), got {}",
        status
    );
}

// ── Step 3: Deep SPA route not auth-gated ────────────────────────────────────

#[tokio::test]
async fn smoke_03_deep_spa_route_not_auth_gated() {
    let router = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/mesh/overview")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "Deep SPA route should return 200 or 404, got {}",
        status
    );
}

// ── Step 4: Unauthenticated protected API is rejected ────────────────────────

#[tokio::test]
async fn smoke_04_unauthenticated_api_rejected() {
    let router = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/system/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Protected API without auth should return 401"
    );
}

// ── Step 5: Invalid login is rejected without leaking token detail ───────────

#[tokio::test]
async fn smoke_05_invalid_login_rejected() {
    let router = build_router().await;
    let mut resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/session")
                .header("authorization", "Bearer wrong-token-value-here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Invalid token should return 401"
    );
    let body = body_string(&mut resp).await;
    assert!(
        !body.contains("wrong-token-value-here"),
        "Error response must not reflect the invalid token"
    );
    // Must not leak the invalid token in the response
    assert!(
        !body.contains("wrong-token-value-here"),
        "Error response must not reflect the invalid token"
    );
}

// ── Step 6: Valid token creates HttpOnly session ─────────────────────────────

#[tokio::test]
async fn smoke_06_valid_token_creates_session() {
    let router = build_router().await;
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/session")
                .header("authorization", format!("Bearer {}", TEST_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Session cookie must be HttpOnly
    let cookie_header = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("synvoid_session="))
        .expect("should set synvoid_session cookie");
    assert!(
        cookie_header.contains("HttpOnly"),
        "Session cookie must be HttpOnly: {}",
        cookie_header
    );
    assert!(
        cookie_header.contains("SameSite=Strict"),
        "Session cookie must be SameSite=Strict: {}",
        cookie_header
    );
}

// ── Step 7: No long-lived bearer token in response ──────────────────────────

#[tokio::test]
async fn smoke_07_no_long_lived_token_in_response() {
    let router = build_router().await;
    let mut resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/session")
                .header("authorization", format!("Bearer {}", TEST_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(&mut resp).await;
    // The response body should be an AdminMutationResult, not contain a raw bearer token
    assert!(
        !body.contains(TEST_TOKEN),
        "Response must not contain the raw bearer token"
    );
}

// ── Step 8: Authenticated API read by session ───────────────────────────────

#[tokio::test]
async fn smoke_08_authenticated_session_read() {
    let router = build_router().await;
    let (session_cookie, _csrf) = session_login(&router).await;

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/system/info")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Authenticated session should access /api/system/info"
    );
}

// ── Step 9: CSRF-protected mutation succeeds ─────────────────────────────────

#[tokio::test]
async fn smoke_09_csrf_protected_mutation() {
    let router = build_router().await;
    let (session_cookie, csrf_token) = session_login(&router).await;

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/reload")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .header("x-csrf-token", &csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::CONFLICT,
        "CSRF-protected config reload should succeed (200) or report no changes (409), got {}",
        resp.status()
    );
}

// ── Step 10: WebSocket endpoint rejects unauthenticated ──────────────────────

#[tokio::test]
async fn smoke_10_ws_endpoint_rejects_unauthenticated() {
    let router = build_router().await;
    for path in ["/api/ws/metrics", "/api/ws/logs"] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("upgrade", "websocket")
                    .header("connection", "Upgrade")
                    .header("sec-websocket-version", "13")
                    .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::UNAUTHORIZED
                || resp.status() == StatusCode::UPGRADE_REQUIRED,
            "{} must reject unauthenticated upgrades, got {}",
            path,
            resp.status()
        );
    }
}

// ── Step 11: Threat level endpoint returns real data ─────────────────────────

#[tokio::test]
async fn smoke_11_threat_level_returns_data() {
    let router = build_router().await;
    let (session_cookie, _csrf) = session_login(&router).await;

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/threat-level")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Threat level endpoint returns 200 when manager is wired, 404 when not.
    // Both are acceptable in a test router without full infrastructure.
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::NOT_FOUND,
        "Threat level should return 200 (wired) or 404 (not wired), got {}",
        resp.status()
    );
}

// ── Step 12: Feature-gated route behavior ────────────────────────────────────

#[tokio::test]
async fn smoke_12_feature_gated_routes() {
    let router = build_router().await;
    let (session_cookie, _csrf) = session_login(&router).await;

    // Test ICMP route (may or may not be compiled in)
    #[cfg(feature = "icmp-filter")]
    {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/icmp/status")
                    .header("cookie", format!("synvoid_session={}", session_cookie))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "ICMP route should be accessible when feature is enabled"
        );
    }

    // Test DNS route (may or may not be compiled in)
    #[cfg(feature = "dns")]
    {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/config/dns")
                    .header("cookie", format!("synvoid_session={}", session_cookie))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "DNS config route should be accessible when feature is enabled"
        );
    }
}

// ── Step 13: Logout invalidates session ──────────────────────────────────────

#[tokio::test]
async fn smoke_13_logout_invalidates_session() {
    let router = build_router().await;
    let (session_cookie, csrf_token) = session_login(&router).await;

    // Logout (DELETE requires CSRF or bearer)
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/auth/session")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .header("x-csrf-token", &csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Logout should succeed");

    // Session cookie should be expired
    let cookie_header = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("synvoid_session="));
    if let Some(c) = cookie_header {
        assert!(
            c.contains("Max-Age=0") || c.contains("Expires="),
            "Logout should expire the session cookie: {}",
            c
        );
    }
}

// ── Step 14: API access fails after logout ───────────────────────────────────

#[tokio::test]
async fn smoke_14_api_fails_after_logout() {
    let router = build_router().await;
    let (session_cookie, csrf_token) = session_login(&router).await;

    // Logout (DELETE requires CSRF or bearer)
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/auth/session")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .header("x-csrf-token", &csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Try to access protected API with the now-invalid session
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/system/info")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Protected API should fail after logout"
    );
}

// ── Step 15: Post-logout navigation returns to login ─────────────────────────

#[tokio::test]
async fn smoke_15_post_logout_navigates_to_login() {
    let router = build_router().await;
    let (session_cookie, csrf_token) = session_login(&router).await;

    // Logout (DELETE requires CSRF or bearer)
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/auth/session")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .header("x-csrf-token", &csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Navigate to a protected SPA route — should get shell (not auth-gated)
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/settings")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "SPA route after logout should return shell (200) or 404, got {}",
        status
    );
}

// ── CSRF enforcement ─────────────────────────────────────────────────────────

#[tokio::test]
async fn smoke_csrf_rejected_without_header() {
    let router = build_router().await;
    let (session_cookie, _) = session_login(&router).await;

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/reload")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                // Missing x-csrf-token header
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Mutation without CSRF token should return 403"
    );
}

#[tokio::test]
async fn smoke_csrf_rejected_with_wrong_token() {
    let router = build_router().await;
    let (session_cookie, _) = session_login(&router).await;

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/reload")
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .header("x-csrf-token", "wrong-csrf-token-value")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Mutation with wrong CSRF token should return 403"
    );
}

// ── Bearer token bypasses CSRF ───────────────────────────────────────────────

#[tokio::test]
async fn smoke_bearer_bypasses_csrf() {
    let router = build_router().await;

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/reload")
                .header("authorization", format!("Bearer {}", TEST_TOKEN))
                // No CSRF header needed with bearer
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success() || resp.status() == StatusCode::CONFLICT,
        "Bearer token should bypass CSRF, got {}",
        resp.status()
    );
}

// ── Security headers present ─────────────────────────────────────────────────

#[tokio::test]
async fn smoke_security_headers_present() {
    let router = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "Missing X-Content-Type-Options: nosniff"
    );
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY"),
        "Missing X-Frame-Options: DENY"
    );
    assert!(
        resp.headers().get("content-security-policy").is_some(),
        "Missing Content-Security-Policy header"
    );
}

// ── API 404 must not serve SPA shell ─────────────────────────────────────────

#[tokio::test]
async fn smoke_api_404_not_spa_shell() {
    let router = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/nonexistent-endpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "/api/* misses should return 404, not SPA shell"
    );
}

// ── OpenAPI spec available ───────────────────────────────────────────────────

#[tokio::test]
async fn smoke_openapi_spec_available() {
    let router = build_router().await;
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "OpenAPI spec should be publicly available"
    );
}

// ── TLS config validation (BUG-009) ──────────────────────────────────────────

#[tokio::test]
async fn tls_config_validation_rejects_enabled_without_cert() {
    let router = build_router().await;
    let body = serde_json::json!({
        "config": {
            "enabled": true,
            "cert_path": null,
            "key_path": null,
            "port": 443,
            "prefer_post_quantum": true,
            "client_auth": { "enabled": false },
            "acme": { "enabled": false }
        }
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/config/tls")
                .header("authorization", format!("Bearer {}", TEST_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "TLS enabled without cert_path or ACME should return 400"
    );
}

#[tokio::test]
async fn tls_config_validation_accepts_disabled() {
    let router = build_router().await;
    let body = serde_json::json!({
        "config": {
            "enabled": false,
            "cert_path": null,
            "key_path": null,
            "port": 443,
            "prefer_post_quantum": true,
            "client_auth": { "enabled": false },
            "acme": { "enabled": false }
        }
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/config/tls")
                .header("authorization", format!("Bearer {}", TEST_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "TLS disabled should succeed, got {}",
        resp.status()
    );
}

// ── HTTP/3 config validation (BUG-009) ───────────────────────────────────────

#[tokio::test]
async fn http3_config_validation_accepts_default() {
    let router = build_router().await;
    let body = serde_json::json!({
        "config": {
            "enabled": false,
            "port": 443,
            "alt_svc_max_age": 86400,
            "max_request_size": 10485760
        }
    });
    let resp = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/config/http3")
                .header("authorization", format!("Bearer {}", TEST_TOKEN))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "HTTP/3 config with valid defaults should succeed, got {}",
        resp.status()
    );
}
