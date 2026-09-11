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

// ── Probe-IP helper (Phase 05) ────────────────────────────────────────────
// `oneshot` requests carry no TCP peer, so the client-IP middleware keys them
// all as `"unknown"` in the global auth limiter — bursts of unauthenticated
// probes would trip the 5-failure lockout (429) and flake exact-status
// assertions under `cargo test`'s shared-process threads. Stamping a unique
// direct-peer IP per probe gives each its own limiter bucket (≤2 failures),
// keeping 401-registered / 404-absent signals exact under both `cargo test`
// and nextest process isolation. Session/bearer validity never depends on IP.
static PROBE_IP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

fn with_probe_ip(mut req: Request<Body>) -> Request<Body> {
    let n = PROBE_IP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let addr: std::net::SocketAddr = format!("10.255.{}.{}:4311", (n >> 8) & 0xFF, n & 0xFF)
        .parse()
        .expect("probe addr");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    req
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
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/stats/summary")
                .body(Body::empty())
                .unwrap(),
        ))
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
        .clone()
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/icmp/status")
                .body(Body::empty())
                .unwrap(),
        ))
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
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/config/dns")
                .body(Body::empty())
                .unwrap(),
        ))
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
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/stats/summary")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "/api/stats/summary should exist (401), not be missing (404)"
    );

    let response = router
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/system/info")
                .body(Body::empty())
                .unwrap(),
        ))
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
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/mesh/status")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Mesh route should exist and require auth when feature is enabled"
    );
}

// ── Phase 05: capability ↔ route-family cross-check ─────────────────────────
// For each capability surfaced by `/system/capabilities`, exactly one holds:
// - capability true  + canonical route family registered, or
// - capability false + feature route family absent.
// Capability flags must never be maintained independently from compiled
// route availability.

const TEST_BEARER: &str = "test_admin_token_that_is_at_least_32_chars_long";

async fn fetch_capabilities(router: &Router) -> serde_json::Value {
    use http_body_util::BodyExt;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/system/capabilities")
                .header("authorization", format!("Bearer {}", TEST_BEARER))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/api/system/capabilities must be reachable with bearer auth"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).expect("capabilities must be JSON")
}

#[tokio::test]
async fn capabilities_match_compiled_route_families() {
    let router = build_test_router().await;
    let cap = fetch_capabilities(&router).await;

    let mesh_admin = cap
        .get("mesh_admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dns_admin = cap
        .get("dns_admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let icmp_admin = cap
        .get("icmp_admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let honeypot = cap
        .get("honeypot")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let process_manager = cap
        .get("process_manager")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Flags must track compile-time features — never drift independently.
    assert_eq!(
        mesh_admin,
        cfg!(feature = "mesh"),
        "mesh_admin must track mesh feature"
    );
    assert_eq!(
        dns_admin,
        cfg!(feature = "dns"),
        "dns_admin must track dns feature"
    );
    assert_eq!(
        icmp_admin,
        cfg!(feature = "icmp-filter"),
        "icmp_admin must track icmp-filter feature"
    );
    // Always-available families report true unconditionally.
    assert!(
        honeypot,
        "honeypot capability must be true (always-available family)"
    );
    assert!(
        process_manager,
        "process_manager capability must be true (always-available family)"
    );

    // Capability true → canonical route family registered (401 unauthenticated).
    // Capability false → feature family absent (404). Unauthenticated probes
    // observe middleware status only, never handler-level domain 404s, and
    // each carries a unique probe IP so the auth limiter cannot interfere.
    async fn family_status(router: &Router, uri: &str) -> StatusCode {
        let response = router
            .clone()
            .oneshot(with_probe_ip(
                Request::builder().uri(uri).body(Body::empty()).unwrap(),
            ))
            .await
            .expect("router should handle request");
        response.status()
    }

    for (capable, uri) in [
        (mesh_admin, "/api/mesh/status"),
        (dns_admin, "/api/config/dns"),
        (icmp_admin, "/api/icmp/status"),
        (mesh_admin, "/api/tier-keys"),
    ] {
        let status = family_status(&router, uri).await;
        if capable {
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "capability=true requires registered {} (got {})",
                uri,
                status
            );
        } else {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "capability=false requires absent {} (got {})",
                uri,
                status
            );
        }
    }

    // Always-available families are always registered.
    for uri in [
        "/api/honeypot/status",
        "/api/system/workers",
        "/api/system/info",
    ] {
        let status = family_status(&router, uri).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{} must always be registered (got {})",
            uri,
            status
        );
    }
}

// ── Phase 05: API discovery / OpenAPI consistency ───────────────────────────
// Operator-facing REST inventory must not drift from real registration.
// WebSockets are documented separately (not modeled as ordinary HTTP).

#[tokio::test]
async fn api_discovery_lists_registered_operator_endpoints() {
    use http_body_util::BodyExt;
    let router = build_test_router().await;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api")
                .header("authorization", format!("Bearer {}", TEST_BEARER))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /api discovery must succeed with auth"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let discovery: serde_json::Value = serde_json::from_slice(&body).expect("discovery JSON");

    // Spot-check operator-facing categories exist.
    let categories = discovery
        .get("categories")
        .and_then(|v| v.as_array())
        .expect("discovery must have categories");
    let names: Vec<&str> = categories
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();
    for expected in [
        "stats",
        "sites",
        "config",
        "system",
        "probes",
        "threat_level",
        "logs",
    ] {
        assert!(
            names.contains(&expected),
            "discovery must list '{}' category",
            expected
        );
    }

    // Every sampled discovery endpoint must be registered with its method.
    // (Full per-endpoint sweep lives in admin_route_contract; here we prove
    // discovery itself tracks registration.) Unauthenticated probes observe
    // middleware status only: 401 proves registration without reaching
    // handler-level domain 404s (e.g. unwired managers in the test router).
    // POST without bearer is refused by CSRF (403) before auth — registered,
    // never missing.
    for (method, path) in [
        ("GET", "/api/stats/summary"),
        ("GET", "/api/sites"),
        ("GET", "/api/config/main"),
        ("POST", "/api/config/reload"),
        ("GET", "/api/system/info"),
        ("GET", "/api/system/capabilities"),
        ("GET", "/api/threat-level"),
        ("GET", "/api/logs"),
    ] {
        let mut builder = Request::builder().method(method).uri(path);
        if matches!(method, "POST" | "PUT" | "PATCH") {
            builder = builder.header("content-type", "application/json");
        }
        let mut req = builder.body(Body::empty()).unwrap();
        req.extensions_mut().insert({
            let n = PROBE_IP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            axum::extract::ConnectInfo(
                format!("10.255.{}.{}:4311", (n >> 8) & 0xFF, n & 0xFF)
                    .parse::<std::net::SocketAddr>()
                    .expect("probe addr"),
            )
        });
        let resp = router.clone().oneshot(req).await.unwrap();
        if method == "GET" {
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "discovery endpoint {} {} must be registered",
                method,
                path
            );
        } else {
            assert_ne!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "discovery endpoint {} {} must be registered",
                method,
                path
            );
        }
    }
}

#[tokio::test]
async fn openapi_spec_covers_operator_rest_surface() {
    use http_body_util::BodyExt;
    let router = build_test_router().await;
    // OpenAPI JSON is intentionally public (no auth) — smoke_covered.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router should handle request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "OpenAPI spec must be public"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let spec: serde_json::Value = serde_json::from_slice(&body).expect("OpenAPI JSON");
    let paths = spec
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("paths object");
    for expected in ["/system/info", "/stats/summary", "/sites", "/config/main"] {
        assert!(
            paths.keys().any(|k| k.contains(expected)),
            "OpenAPI must document '{}'",
            expected
        );
    }
    // WebSockets must NOT be modeled as ordinary HTTP paths.
    assert!(
        !paths
            .keys()
            .any(|k| k.contains("/ws/metrics") || k.contains("/ws/logs")),
        "WebSocket paths must be documented separately, not as HTTP OpenAPI paths"
    );
}

// ── Phase 05: auth / middleware classification ─────────────────────────────
// Public, session-bootstrap, protected, CSRF, and WebSocket classes must not
// drift silently; middleware exclusions must be exact, never broad prefixes.

#[tokio::test]
async fn public_routes_bypass_auth() {
    let router = build_test_router().await;
    // Root health is public.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // OpenAPI + docs are public.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn session_bootstrap_endpoints_have_intended_semantics() {
    let router = build_test_router().await;
    // Session creation without any credential is rejected (never 404).
    // CSRF middleware runs outermost, so a credential-less POST is refused
    // with 403 (missing session/CSRF) before auth returns 401; either way the
    // route is registered and stays closed without the bearer token.
    let resp = router
        .clone()
        .oneshot(with_probe_ip(
            Request::builder()
                .method("POST")
                .uri("/api/auth/session")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "credential-less session creation must be refused, not missing"
    );
    // CSRF bootstrap without a session cookie is 401 (not 404).
    let resp = router
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/auth/csrf")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_rest_routes_require_auth() {
    let router = build_test_router().await;
    for uri in [
        "/api/system/info",
        "/api/stats/summary",
        "/api/sites",
        "/api/config/main",
    ] {
        let resp = router
            .clone()
            .oneshot(with_probe_ip(
                Request::builder().uri(uri).body(Body::empty()).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{} must require auth",
            uri
        );
    }
}

#[tokio::test]
async fn bearer_bypasses_csrf_but_session_requires_it() {
    // Login to get a session cookie + CSRF token.
    let router = build_test_router().await;
    let login = router
        .clone()
        .oneshot(with_probe_ip(
            Request::builder()
                .method("POST")
                .uri("/api/auth/session")
                .header("authorization", format!("Bearer {}", TEST_BEARER))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("synvoid_session="))
        .and_then(|c| c.split(';').next().map(str::to_string))
        .expect("session cookie");
    let csrf = login
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(!csrf.is_empty());

    // Session mutation WITHOUT CSRF → 403.
    let session_id = cookie["synvoid_session=".len()..].to_string();
    let resp = router
        .clone()
        .oneshot(with_probe_ip(
            Request::builder()
                .method("POST")
                .uri("/api/config/reload")
                .header("cookie", format!("synvoid_session={}", session_id))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Same mutation WITH CSRF → not 403 (200 or domain-level conflict).
    let resp = router
        .clone()
        .oneshot(with_probe_ip(
            Request::builder()
                .method("POST")
                .uri("/api/config/reload")
                .header("cookie", format!("synvoid_session={}", session_id))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);

    // Bearer mutation WITHOUT CSRF → bypasses CSRF (not 403).
    let resp = router
        .oneshot(with_probe_ip(
            Request::builder()
                .method("POST")
                .uri("/api/config/reload")
                .header("authorization", format!("Bearer {}", TEST_BEARER))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn websocket_auth_is_per_connection_not_middleware_bypass() {
    let router = build_test_router().await;
    // Unauthenticated WS upgrades are rejected per-connection (401), proving
    // the handlers enforce auth even though blanket REST middleware skips the
    // two canonical upgrade paths.
    for path in ["/api/ws/metrics", "/api/ws/logs"] {
        let resp = router
            .clone()
            .oneshot(with_probe_ip(
                Request::builder()
                    .uri(path)
                    .header("upgrade", "websocket")
                    .header("connection", "Upgrade")
                    .header("sec-websocket-version", "13")
                    .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                    .body(Body::empty())
                    .unwrap(),
            ))
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
    // Non-canonical WS-looking paths are NOT covered by the exclusion: they
    // fall through to auth (401) or 404 — never an accidental public bypass.
    let resp = router
        .oneshot(with_probe_ip(
            Request::builder()
                .uri("/api/ws/evil")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::UNAUTHORIZED,
        "/api/ws/evil must not be publicly exposed, got {}",
        resp.status()
    );
}
