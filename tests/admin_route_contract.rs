//! Admin route-contract regression test (Phase 05).
//!
//! Mechanical frontend/backend contract guard: every endpoint consumed by the
//! admin UI must map to a registered backend route with the expected method,
//! under the appropriate feature profile.
//!
//! Test principle: a registered route returns any status OTHER than 404.
//! Unregistered routes return 404. Protected routes return 401 without auth,
//! which still proves registration.
//!
//! Canonical sources of truth:
//! - backend route families: `src/admin/routes.rs`
//!   (composition in `src/admin/mod.rs`)
//! - canonical WebSocket paths: `src/admin/ws/mod.rs`
//!   (`WS_METRICS_PATH` / `WS_LOGS_PATH`)
//! - frontend client: `admin-ui/src/services/api.rs` (`ApiService`)
//! - capability gating: `/api/system/capabilities` + sidebar visibility
//!
//! Rejection criteria enforced here: no second hand-maintained giant route
//! list without mechanical comparison — every entry below is checked against
//! the real Axum router via `oneshot`, so drift fails the test.

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

fn json_body() -> Body {
    Body::from(r#"{}"#)
}

/// Drive a (method, uri) pair through the real router and assert registration.
///
/// Probes are intentionally UNAUTHENTICATED: matched protected routes return
/// 401 from the auth middleware (proving registration without reaching
/// handler-level domain 404s for missing resources), while absent routes fall
/// through to the 404 fallback. Each probe carries a unique direct-peer IP so
/// the global per-IP auth limiter never trips its 5-failure lockout (429)
/// within one shared-process `cargo test` run; under nextest's process
/// isolation the same helper is a harmless no-op.
static PROBE_IP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

const CONTRACT_BEARER: &str = "test_admin_token_that_is_at_least_32_chars_long";

fn probe_request(method: &str, uri: &str, has_body: bool) -> Request<Body> {
    let n = PROBE_IP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let addr: std::net::SocketAddr = format!("10.255.{}.{}:4311", (n >> 8) & 0xFF, n & 0xFF)
        .parse()
        .expect("probe addr");
    let mut builder = Request::builder().method(method).uri(uri);
    if has_body {
        builder = builder.header("content-type", "application/json");
    }
    let mut req = builder
        .body(if has_body { json_body() } else { Body::empty() })
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    req
}

async fn assert_registered(router: &Router, method: &str, uri: &str) {
    let has_body = matches!(method, "POST" | "PUT" | "PATCH");
    let req = probe_request(method, uri, has_body);
    let response = router.clone().oneshot(req).await.unwrap();
    assert_route_exists(response, &format!("{} {}", method, uri));
}

async fn assert_all_registered(router: &Router, cases: &[(&str, &str)]) {
    for (method, uri) in cases {
        assert_registered(router, method, uri).await;
    }
}

/// Always-available frontend-consumed surface: auth session lifecycle.
const AUTH_ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/auth/session"),
    ("DELETE", "/api/auth/session"),
    ("GET", "/api/auth/csrf"),
];

/// Always-available stats/dashboard surface consumed by dashboard,
/// realtime header, request-logs, and site-detail pages.
const STATS_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/stats/summary"),
    ("GET", "/api/stats/sites"),
    ("GET", "/api/stats/history"),
    ("GET", "/api/stats/history?seconds=60"),
    ("GET", "/api/stats/attacks"),
    ("GET", "/api/stats/cache"),
    ("GET", "/api/stats/bandwidth"),
    ("GET", "/api/stats/requests"),
    ("GET", "/api/stats/requests?site_id=example.com&limit=20"),
];

/// Sites + upstreams + logs surface.
const SITES_UPSTREAMS_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/sites"),
    ("POST", "/api/sites"),
    ("GET", "/api/sites/example.com"),
    ("PUT", "/api/sites/example.com"),
    ("DELETE", "/api/sites/example.com"),
    ("GET", "/api/sites/example.com/theme"),
    ("PUT", "/api/sites/example.com/theme"),
    ("GET", "/api/sites/example.com/bot-detection"),
    ("PUT", "/api/sites/example.com/bot-detection"),
    ("GET", "/api/sites/example.com/error-pages"),
    ("PUT", "/api/sites/example.com/error-pages"),
    ("GET", "/api/upstreams"),
    ("GET", "/api/upstreams/example.com"),
    ("POST", "/api/upstreams/example.com/check"),
    ("GET", "/api/logs"),
    ("GET", "/api/logs?limit=200"),
    ("GET", "/api/logs?level=info&limit=200"),
    ("GET", "/api/audit-logs"),
    ("GET", "/api/error-pages"),
    ("GET", "/api/error-pages/404"),
    ("PUT", "/api/error-pages/404"),
];

/// Core config read/write families used by settings pages.
const CONFIG_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/config/main"),
    ("PUT", "/api/config/main"),
    ("GET", "/api/config/schema"),
    ("POST", "/api/config/reload"),
    ("GET", "/api/config/log-level"),
    ("PUT", "/api/config/log-level"),
    ("GET", "/api/config/export"),
    ("POST", "/api/config/import"),
    ("POST", "/api/config/check-regex"),
    ("GET", "/api/config/supervisor"),
    ("PUT", "/api/config/supervisor"),
    ("GET", "/api/config/tls"),
    ("PUT", "/api/config/tls"),
    ("GET", "/api/config/http"),
    ("PUT", "/api/config/http"),
    ("GET", "/api/config/acme"),
    ("PUT", "/api/config/acme"),
    ("GET", "/api/config/http3"),
    ("PUT", "/api/config/http3"),
    ("GET", "/api/config/security"),
    ("PUT", "/api/config/security"),
    ("GET", "/api/config/static"),
    ("PUT", "/api/config/static"),
    ("GET", "/api/config/tunnel"),
    ("PUT", "/api/config/tunnel"),
    ("GET", "/api/config/plugins"),
    ("PUT", "/api/config/plugins"),
    ("GET", "/api/config/logging"),
    ("PUT", "/api/config/logging"),
    ("GET", "/api/config/metrics"),
    ("PUT", "/api/config/metrics"),
    ("GET", "/api/config/tokio"),
    ("PUT", "/api/config/tokio"),
    ("GET", "/api/config/traffic-shaping"),
    ("PUT", "/api/config/traffic-shaping"),
    ("GET", "/api/config/rate-limits"),
    ("PUT", "/api/config/rate-limits"),
    ("GET", "/api/config/bot-detection"),
    ("PUT", "/api/config/bot-detection"),
    ("GET", "/api/config/threat-level"),
    ("PUT", "/api/config/threat-level"),
    ("GET", "/api/config/ip-feeds"),
    ("PUT", "/api/config/ip-feeds"),
    ("GET", "/api/config/mime-types"),
    ("PUT", "/api/config/mime-types"),
    ("GET", "/api/config/tcp-udp-defaults"),
    ("PUT", "/api/config/tcp-udp-defaults"),
    ("GET", "/api/config/fallback"),
    ("PUT", "/api/config/fallback"),
    ("GET", "/api/config/upgrade"),
    ("PUT", "/api/config/upgrade"),
    ("GET", "/api/config/rule-feed"),
    ("PUT", "/api/config/rule-feed"),
    ("GET", "/api/config/yara-feed"),
    ("PUT", "/api/config/yara-feed"),
    ("POST", "/api/config/validate"),
    ("GET", "/api/config/versions"),
    ("GET", "/api/config/versions/v1"),
    ("POST", "/api/config/rollback/v1"),
    ("GET", "/api/config/diff"),
    ("GET", "/api/config/bundle"),
    ("PUT", "/api/config/bundle"),
    ("GET", "/api/config/process-manager"),
    ("PUT", "/api/config/process-manager"),
    ("GET", "/api/config/defaults/honeypot"),
    ("PUT", "/api/config/defaults/honeypot"),
    ("GET", "/api/config/defaults/honeypot-probe"),
    ("PUT", "/api/config/defaults/honeypot-probe"),
    ("GET", "/api/config/defaults/blocked"),
    ("PUT", "/api/config/defaults/blocked"),
    ("GET", "/api/config/defaults/suspicious-words"),
    ("PUT", "/api/config/defaults/suspicious-words"),
    ("GET", "/api/config/defaults/upstream-errors"),
    ("PUT", "/api/config/defaults/upstream-errors"),
    ("GET", "/api/config/defaults/error-pages"),
    ("PUT", "/api/config/defaults/error-pages"),
    ("GET", "/api/config/defaults/css-challenge"),
    ("PUT", "/api/config/defaults/css-challenge"),
    ("GET", "/api/config/defaults/pow-challenge"),
    ("PUT", "/api/config/defaults/pow-challenge"),
    ("GET", "/api/config/defaults/challenge"),
    ("PUT", "/api/config/defaults/challenge"),
    ("GET", "/api/config/defaults/auth"),
    ("PUT", "/api/config/defaults/auth"),
    ("GET", "/api/config/defaults/worker-pool"),
    ("PUT", "/api/config/defaults/worker-pool"),
    ("GET", "/api/config/defaults/persistence"),
    ("PUT", "/api/config/defaults/persistence"),
    ("GET", "/api/config/defaults/tarpit"),
    ("PUT", "/api/config/defaults/tarpit"),
    ("GET", "/api/config/defaults/upload"),
    ("PUT", "/api/config/defaults/upload"),
    ("GET", "/api/config/defaults/traffic-shaping"),
    ("PUT", "/api/config/defaults/traffic-shaping"),
    ("GET", "/api/config/defaults/asn-scraping"),
    ("PUT", "/api/config/defaults/asn-scraping"),
];

/// TCP/UDP listeners, probes, threat-level, and rule-feed surface.
const INFRA_PROBES_THREAT_RULES_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/tcp-udp/listeners"),
    ("POST", "/api/tcp-udp/listeners"),
    ("DELETE", "/api/tcp-udp/listeners/listener-1"),
    ("GET", "/api/tcp-udp/protocols"),
    ("GET", "/api/probes"),
    ("GET", "/api/probes/stats"),
    ("POST", "/api/probes/block"),
    ("GET", "/api/probes/1.2.3.4"),
    ("DELETE", "/api/probes/1.2.3.4"),
    ("GET", "/api/probes/words"),
    ("GET", "/api/probes/words/stats"),
    ("DELETE", "/api/probes/words/1.2.3.4"),
    ("GET", "/api/probes/upstream"),
    ("GET", "/api/probes/upstream/stats"),
    ("DELETE", "/api/probes/upstream/1.2.3.4"),
    ("GET", "/api/threat-level"),
    ("GET", "/api/threat-level/history"),
    ("GET", "/api/threat-level/history/stats"),
    ("POST", "/api/threat-level/history/backup"),
    ("GET", "/api/threat-level/history/backups"),
    ("DELETE", "/api/threat-level/history/backups"),
    ("POST", "/api/threat-level/history/prune"),
    ("GET", "/api/threat-level/baseline"),
    ("POST", "/api/threat-level/reset"),
    ("POST", "/api/threat-level/set/2"),
    ("POST", "/api/threat-level/auto"),
    ("GET", "/api/rules/status"),
    ("POST", "/api/rules/check"),
    ("POST", "/api/rules/apply"),
    ("POST", "/api/rules/discard"),
];

/// System/process/auth/theme/alerting/honeypot/observability surface.
const SYSTEM_PROCESS_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/system/info"),
    ("GET", "/api/system/capabilities"),
    ("GET", "/api/system/supervisor"),
    ("GET", "/api/system/workers"),
    ("GET", "/api/system/workers/count"),
    ("POST", "/api/system/workers/scale"),
    ("POST", "/api/system/workers/test-worker-1/restart"),
    ("POST", "/api/system/workers/batch-restart"),
    ("GET", "/api/system/app-servers/example.com/logs"),
    ("GET", "/api/system/php-pools"),
    ("POST", "/api/system/php-pools/reload"),
    ("GET", "/api/alerts/config"),
    ("PUT", "/api/alerts/config"),
    ("POST", "/api/alerts/test-webhook"),
    ("GET", "/api/theme"),
    ("PUT", "/api/theme"),
    ("GET", "/api/theme/css"),
    ("GET", "/api/theme/presets"),
    ("GET", "/api/honeypot/status"),
    ("POST", "/api/honeypot/control"),
    ("GET", "/api/honeypot/config"),
    ("PUT", "/api/honeypot/config"),
    ("GET", "/api/observability/security-summary"),
    ("GET", "/api/observability/tasks"),
    ("GET", "/api/observability/blocklist-health"),
    ("GET", "/api/observability/plugins"),
    ("GET", "/api/observability/features"),
    ("GET", "/api/observability/threat-intel"),
    ("GET", "/api"),
];

/// Canonical WebSocket upgrade paths (must match `ws::CANONICAL_WS_PATHS`).
const WS_ROUTES: &[(&str, &str)] = &[("GET", "/api/ws/metrics"), ("GET", "/api/ws/logs")];

/// Paths that must NEVER exist: historical aliases, singular/plural typos,
/// missing `/api` namespace, stale feature gates, frontend-only routes, and
/// the removed `/system/master` + `/api/logs/realtime` drifts.
const ABSENT_ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/system/worker/test-worker-1/restart"),
    ("PUT", "/api/system/worker/1/restart"),
    ("GET", "/api/system/overseer"),
    ("GET", "/api/config/overseer"),
    ("POST", "/api/config/overseer"),
    ("GET", "/api/system/master"),
    ("GET", "/system/master"),
    ("GET", "/api/logs/realtime"),
    ("GET", "/api/mesh/tier-keys"),
    ("GET", "/api/nonexistent/route"),
    ("POST", "/api/admin/ghost"),
    ("GET", "/api/sites/broken/edit"),
    ("GET", "/api/ws/evil"),
    ("GET", "/api/ws/metricsExtra"),
    ("GET", "/api/ws/logs/extra"),
    ("GET", "/api/system/workersExtra"),
];

/// Production frontend API contract: every path/method must map to a registered route.
#[tokio::test]
async fn admin_route_contract_worker_routes() {
    let router = build_test_router().await;
    // Canonical worker/supervisor surface (replaces old /system/overseer).
    // Uses the shared probe helper so the global auth limiter is never
    // tripped by raw unauthenticated bursts in a shared test process.
    assert_all_registered(
        &router,
        &[
            ("GET", "/api/system/workers"),
            ("GET", "/api/system/supervisor"),
            ("GET", "/api/system/workers/count"),
            ("POST", "/api/system/workers/scale"),
            ("POST", "/api/system/workers/test-worker-1/restart"),
        ],
    )
    .await;
}

/// Exhaustive always-available UI coverage: auth lifecycle.
#[tokio::test]
async fn admin_route_contract_auth_session_lifecycle() {
    let router = build_test_router().await;
    assert_all_registered(&router, AUTH_ROUTES).await;
}

/// Exhaustive always-available UI coverage: stats/dashboard families.
#[tokio::test]
async fn admin_route_contract_stats_families() {
    let router = build_test_router().await;
    assert_all_registered(&router, STATS_ROUTES).await;
}

/// Exhaustive always-available UI coverage: sites, upstreams, logs.
#[tokio::test]
async fn admin_route_contract_sites_upstreams_logs() {
    let router = build_test_router().await;
    assert_all_registered(&router, SITES_UPSTREAMS_ROUTES).await;
}

/// Exhaustive always-available UI coverage: config read/write families.
#[tokio::test]
async fn admin_route_contract_config_families() {
    let router = build_test_router().await;
    assert_all_registered(&router, CONFIG_ROUTES).await;
}

/// Exhaustive always-available UI coverage: TCP/UDP, probes, threat, rules.
#[tokio::test]
async fn admin_route_contract_infra_probes_threat_rules() {
    let router = build_test_router().await;
    assert_all_registered(&router, INFRA_PROBES_THREAT_RULES_ROUTES).await;
}

/// Exhaustive always-available UI coverage: system/process/alerts/theme/
/// honeypot/observability/discovery, including the capability endpoint.
#[tokio::test]
async fn admin_route_contract_system_process_families() {
    let router = build_test_router().await;
    assert_all_registered(&router, SYSTEM_PROCESS_ROUTES).await;
}

/// Canonical WebSocket paths are covered by the same contract guard.
#[tokio::test]
async fn admin_route_contract_canonical_websocket_paths() {
    let router = build_test_router().await;
    assert_all_registered(&router, WS_ROUTES).await;

    // Exact-match enforcement: near-miss WS paths must NOT exist.
    for (method, path) in [
        ("GET", "/api/ws/evil"),
        ("GET", "/api/ws/metricsExtra"),
        ("GET", "/api/ws/logs/extra"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{} {} must be 404 (exact WS matching)",
            method,
            path
        );
    }
}

/// Stale aliases, typos, and frontend-only routes must stay absent.
#[tokio::test]
async fn admin_route_contract_stale_paths_absent() {
    let router = build_test_router().await;
    for (method, path) in ABSENT_ROUTES {
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
            "{} {} should NOT exist (404)",
            method,
            path
        );
    }
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

/// Removed `/system/master` must NOT exist (frontend uses `/system/supervisor`).
#[tokio::test]
async fn admin_route_contract_old_master_absent() {
    let router = build_test_router().await;
    for path in ["/api/system/master", "/system/master"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "GET {} should NOT exist (404)",
            path
        );
    }
}

/// Stale `/api/logs/realtime` must NOT exist (canonical: `/api/ws/logs`).
#[tokio::test]
async fn admin_route_contract_old_logs_realtime_absent() {
    let router = build_test_router().await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/logs/realtime")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /api/logs/realtime should NOT exist (404)"
    );
}

/// ICMP routes must be registered when icmp-filter feature is enabled.
#[cfg(feature = "icmp-filter")]
#[tokio::test]
async fn admin_route_contract_icmp_routes() {
    let router = build_test_router().await;
    assert_all_registered(
        &router,
        &[
            ("GET", "/api/icmp/status"),
            ("GET", "/api/icmp/config"),
            ("PUT", "/api/icmp/config"),
            ("POST", "/api/icmp/enable"),
            ("POST", "/api/icmp/disable"),
            ("GET", "/api/icmp/backends"),
        ],
    )
    .await;
}

/// Mesh config routes must be registered when mesh feature is enabled.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn admin_route_contract_mesh_config_routes() {
    let router = build_test_router().await;
    assert_all_registered(
        &router,
        &[("GET", "/api/config/mesh"), ("PUT", "/api/config/mesh")],
    )
    .await;
}

/// Mesh operational families (YARA, mesh status/topology, plugins,
/// serverless, spin) when compiled.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn admin_route_contract_mesh_operational_routes() {
    let router = build_test_router().await;
    assert_all_registered(
        &router,
        &[
            ("GET", "/api/yara/status"),
            ("GET", "/api/yara/submissions"),
            ("GET", "/api/yara/submissions/sub-1"),
            ("POST", "/api/yara/submissions/sub-1/approve"),
            ("POST", "/api/yara/submissions/sub-1/reject"),
            ("POST", "/api/yara/broadcast"),
            ("POST", "/api/yara/sync"),
            ("POST", "/api/yara/submit"),
            ("POST", "/api/yara/apply"),
            ("DELETE", "/api/yara/submissions/sub-1"),
            ("GET", "/api/mesh/status"),
            ("GET", "/api/mesh/raft/status"),
            ("GET", "/api/mesh/dht/stats"),
            ("POST", "/api/mesh/attest-capability"),
            ("GET", "/api/v1/mesh/raft/status"),
            ("GET", "/api/v1/mesh/dht/stats"),
            ("POST", "/api/mesh/derive-signing-key"),
            ("GET", "/api/mesh/nodes"),
            ("GET", "/api/mesh/nodes/node-1"),
            ("POST", "/api/mesh/organizations"),
            ("GET", "/api/mesh/organizations/org-1"),
            ("GET", "/api/mesh/organizations/org-1/public-key"),
            ("POST", "/api/mesh/ban/ip"),
            ("POST", "/api/mesh/ban/mesh-id"),
            ("DELETE", "/api/mesh/ban"),
            ("GET", "/api/mesh/bans"),
            ("GET", "/api/mesh/blocklist/catchup-stats"),
            ("GET", "/api/mesh/threat-intel/policy-shadow"),
            ("GET", "/api/mesh/threat-intel/policy-shadow/stats"),
            ("GET", "/api/mesh/topology"),
            ("GET", "/api/mesh/topology/graph"),
            ("GET", "/api/mesh/behavioral/stats"),
            ("GET", "/api/mesh/behavioral/config"),
            ("POST", "/api/mesh/audit/report"),
            ("POST", "/api/mesh/report/signature-failure"),
            ("GET", "/api/mesh/wasm-modules"),
            ("GET", "/api/plugins/metrics"),
            ("GET", "/api/plugins/metrics/test-plugin"),
            ("GET", "/api/plugins/status"),
            ("POST", "/api/plugins/test-plugin/reload"),
            ("GET", "/api/serverless/functions"),
            ("GET", "/api/serverless/functions/fn-1/stats"),
            ("GET", "/api/serverless/health"),
            ("GET", "/api/serverless/config"),
            ("PUT", "/api/serverless/config"),
            ("GET", "/api/spin/apps"),
            ("POST", "/api/spin/apps"),
            ("GET", "/api/spin/apps/app-1"),
            ("DELETE", "/api/spin/apps/app-1"),
            ("GET", "/api/spin/apps/app-1/instances"),
        ],
    )
    .await;
}

/// Tier key routes must be registered when mesh feature is enabled.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn admin_route_contract_tier_key_routes() {
    let router = build_test_router().await;
    assert_all_registered(
        &router,
        &[
            ("GET", "/api/tier-keys"),
            ("POST", "/api/tier-keys/issue"),
            ("POST", "/api/tier-keys/revoke"),
            ("POST", "/api/tier-keys/unbind"),
        ],
    )
    .await;
}

/// DNS config routes when compiled.
#[cfg(feature = "dns")]
#[tokio::test]
async fn admin_route_contract_dns_routes() {
    let router = build_test_router().await;
    assert_all_registered(
        &router,
        &[("GET", "/api/config/dns"), ("PUT", "/api/config/dns")],
    )
    .await;
}

/// Supervisor config routes must be registered.
#[tokio::test]
async fn admin_route_contract_supervisor_config_routes() {
    let router = build_test_router().await;
    assert_all_registered(
        &router,
        &[
            ("GET", "/api/config/supervisor"),
            ("PUT", "/api/config/supervisor"),
        ],
    )
    .await;
}

/// Method drift: canonical mutations reject the wrong method with 405, not 404.
/// A 405 proves the path is registered but the method is wrong — the contract
/// distinguishes "wrong method" (405) from "missing route" (404).
/// Uses bearer auth so the check observes routing status, not auth status.
#[tokio::test]
async fn admin_route_contract_wrong_method_is_405_not_404() {
    let router = build_test_router().await;
    // PUT on a POST-only route must not look like a missing route.
    let response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/system/workers/scale")
                .header("authorization", format!("Bearer {}", CONTRACT_BEARER))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"target_count": 2}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "PUT /api/system/workers/scale should be 405 (POST-only), got {}",
        response.status()
    );
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
