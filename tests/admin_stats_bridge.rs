//! Phase 04 bridge: the metrics publisher feed and the request-log sink must
//! reach the admin-visible state, or the dashboard graphs and the request-log
//! tab stay dead in every deployment mode.
//!
//! The router is built with `create_admin_router_with_state` so the test can
//! drive the same `Arc<AdminState>` the composition root hands to both the
//! router and the publisher, then observe the effect through the real API.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

use synvoid::admin::create_admin_router_with_state;
use synvoid::config::admin::{AdminCorsConfig, AdminRateLimitConfig};
use synvoid::config::ConfigManager;

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

async fn build_router_with_state() -> (Router, Arc<synvoid::admin::state::AdminState>) {
    tokio::task::spawn_blocking(|| {
        let config_dir = std::env::temp_dir();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(ConfigManager::new(config_dir)));
        // The `/api/stats/sites` endpoint iterates configured sites, so seed
        // the blog site the bridge tests observe.
        {
            let mut guard = config.blocking_write();
            let mut site = synvoid::config::SiteConfig::default_fallback_site(
                "http://127.0.0.1:5000".to_string(),
            );
            site.site.domains = vec!["127.0.0.1".to_string()];
            guard.sites.insert("blog".to_string(), site);
        }
        let (router, state) = create_admin_router_with_state(
            config,
            TEST_TOKEN.to_string(),
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
        );
        (router, state.expect("test router build must produce state"))
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

async fn authed_get(router: &Router, uri: &str) -> Response<Body> {
    let (session_cookie, csrf_token) = session_login(router).await;
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", format!("synvoid_session={}", session_cookie))
                .header("x-csrf-token", csrf_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(resp: Response<Body>) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("admin API must return JSON")
}

/// Recording N requests into a `WorkerMetrics` and running the publisher over
/// a `LocalMetricsFeed` must surface `total_requests == N` in
/// `GET /api/stats/summary` and a non-empty
/// `GET /api/stats/history?seconds=300` — the standalone path that was dead
/// because `start_metrics_publisher` had no production caller.
#[tokio::test]
async fn bridge_01_fed_metrics_reach_summary_and_history() {
    let (router, state) = build_router_with_state().await;

    let worker_metrics = Arc::new(synvoid::metrics::WorkerMetrics::default());
    // Record per-site, exactly as the production data plane does: nothing in
    // production writes the worker-top-level counters, so the publisher
    // derives its totals from the per-site map.
    for _ in 0..7 {
        worker_metrics.record_site_request_start("blog");
        worker_metrics.record_site_request_end("blog", 4);
    }

    let feed = Arc::new(synvoid::admin::metrics::LocalMetricsFeed {
        metrics: Some(worker_metrics),
        worker_id: synvoid::process::WorkerId(0),
    });
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let publisher = tokio::spawn({
        let state = state.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        async move {
            synvoid::admin::metrics::start_metrics_publisher(state, feed, None, shutdown_rx).await;
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let _ = shutdown_tx.send(());
    publisher.await.expect("publisher must drain on shutdown");

    let summary = body_json(authed_get(&router, "/api/stats/summary").await).await;
    assert_eq!(
        summary["total_requests"], 7,
        "fed requests must be visible in summary: {}",
        summary
    );
    assert!(
        summary["avg_latency_ms"].as_f64().unwrap_or(0.0) > 0.0,
        "fed latency must be visible in summary: {}",
        summary
    );
    assert!(
        summary["p50_latency_ms"].as_f64().unwrap_or(0.0) > 0.0,
        "fed latency percentiles must derive from the per-site map: {}",
        summary
    );

    let history = body_json(authed_get(&router, "/api/stats/history?seconds=300").await).await;
    let samples = history
        .as_array()
        .or_else(|| history.get("samples").and_then(|s| s.as_array()));
    match samples {
        Some(samples) => assert!(
            !samples.is_empty(),
            "history must contain the publisher ticks"
        ),
        None => panic!("history shape changed, inspect: {}", history),
    }
}

/// Emitting through the `RequestLogSink` seam must surface in
/// `GET /api/stats/requests` — the path that was dead because
/// `AdminState::add_request_log` had no production writer.
#[tokio::test]
async fn bridge_02_sink_records_reach_request_logs() {
    use synvoid_http::RequestLogSink;

    let (router, state) = build_router_with_state().await;

    state.emit(synvoid_http::RequestLogRecord {
        client_ip: "127.0.0.1".parse().unwrap(),
        method: "GET",
        path: "/probed",
        status: 200,
        latency_ms: 3,
        site_id: "blog",
        user_agent: None,
        is_internal: false,
    });

    let logs = body_json(authed_get(&router, "/api/stats/requests?limit=5").await).await;
    let entries = logs
        .get("entries")
        .and_then(|e| e.as_array())
        .expect("request logs must carry entries");
    assert!(
        entries.iter().any(|e| e["path"] == "/probed"),
        "emitted record must be listed: {}",
        logs
    );

    // The WAF-logs tab reads `/api/logs` (initial load) and streams
    // `/api/ws/logs` (same payload shape). Both must surface the record —
    // `get_logs` was a hardcoded-empty stub and the broadcaster had no
    // publisher.
    let waf_logs = body_json(authed_get(&router, "/api/logs?limit=200").await).await;
    let waf_entries = waf_logs
        .get("entries")
        .and_then(|e| e.as_array())
        .expect("waf logs must carry entries");
    let probed = waf_entries
        .iter()
        .find(|e| e["path"] == "/probed")
        .expect("emitted record must be listed in waf logs");
    assert_eq!(probed["status"], 200);
    assert_eq!(probed["level"], "info");
    assert!(probed["message"].as_str().unwrap_or("").contains("/probed"));
}

/// Standalone mode has no process manager: `/system/workers*` answer 404 by
/// design while `/system/supervisor` stays 200 with the mode the Workers page
/// keys its empty-state on. Pins the contract Phase 03 relies on.
#[tokio::test]
async fn bridge_03_standalone_workers_404_pinned() {
    let (router, _state) = build_router_with_state().await;

    for uri in ["/api/system/workers", "/api/system/workers/count"] {
        let resp = authed_get(&router, uri).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{} must stay 404 without a process manager",
            uri
        );
    }

    let resp = authed_get(&router, "/api/system/supervisor").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(
        body.get("mode").is_some(),
        "supervisor status must carry the mode the UI keys on: {}",
        body
    );
}

/// A site whose health was never reported serializes `"unknown"`, not a bool.
/// Pins the shape that broke the dashboard parse at column 470.
#[tokio::test]
async fn bridge_04_unknown_health_shape() {
    let (router, state) = build_router_with_state().await;

    let mut sites = HashMap::new();
    sites.insert(
        "blog".to_string(),
        synvoid::metrics::SiteMetricsPayload {
            total_requests: 0,
            blocked: 0,
            challenged: 0,
            proxied: 0,
            errors: 0,
            current_concurrent: 0,
            peak_concurrent: 0,
            avg_latency_ms: 0.0,
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            blocked_by_type: HashMap::new(),
            upstream_healthy: synvoid::metrics::HealthStatus::Unknown,
            proxy_cache_hits: 0,
            proxy_cache_misses: 0,
            static_cache_hits: 0,
            static_cache_misses: 0,
            bytes_received: 0,
            bytes_sent: 0,
            proxied_bytes_sent: 0,
            proxied_bytes_received: 0,
            mesh_bytes_sent: 0,
            mesh_bytes_received: 0,
            healthy_backends: 0,
            unhealthy_backends: 0,
            total_backends: 0,
            metrics_timestamp_ms: 0,
        },
    );
    state.update_site_metrics(sites);

    let sites_body = body_json(authed_get(&router, "/api/stats/sites").await).await;
    let entries = sites_body.as_array().expect("sites stats must be an array");
    let blog = entries
        .iter()
        .find(|e| e["site_id"] == "blog")
        .expect("seeded site must be listed");
    assert_eq!(
        blog["upstream_healthy"], "unknown",
        "health must serialize as the lowercase enum string: {}",
        blog
    );
}
