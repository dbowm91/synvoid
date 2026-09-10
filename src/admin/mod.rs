//! Admin dashboard and API for SynVoid.
//!
//! Exposes an HTTP/HTTPS management interface built on Axum, providing
//! site configuration, user management, metrics, alerting, WebSocket
//! broadcasting, and OpenAPI documentation. Handles authentication,
//! rate limiting, CSRF protection, and CORS via middleware layers.

pub mod alerting;
mod audit;
mod auth;
mod handlers;
pub mod metrics;
pub mod metrics_events;
mod middleware;
pub mod openapi;
mod prometheus_exporter;
pub use openapi::synvoidOpenApi;
mod rate_limit;
mod routes;
pub mod schema;
mod state;
#[allow(dead_code)]
mod ws;

pub use audit::{AuditLog, AuditState, ConfigVersion, ConfigVersionManager};
pub use auth::{hash_admin_token, hash_admin_token_with_cost, verify_admin_token};
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
pub use metrics::start_metrics_publisher;
pub use state::{
    get_cpu_memory_usage, get_current_connections, set_current_connections, AdminRateLimiter,
    AdminState, AggregatedMetrics, SystemResources, YaraRateLimiter, SESSION_COOKIE_NAME,
};
use tower_http::cors::CorsLayer;
#[allow(unused_imports)]
use utoipa::OpenApi;
#[cfg(feature = "swagger-ui")]
use utoipa_swagger_ui::SwaggerUi;

use crate::config::{AdminCorsConfig, ConfigManager};
use crate::waf::{
    ProbeTracker, RuleFeedManagerForWaf, SuspiciousWordTracker, ThreatLevelManager,
    UpstreamErrorTracker,
};

#[cfg(feature = "icmp-filter")]
use crate::icmp_filter::IcmpFilterManager;

fn create_cors_layer(cors_config: &AdminCorsConfig) -> CorsLayer {
    let mut cors = CorsLayer::new();

    if let Some(ref origin) = cors_config.allow_origin {
        if origin == "*" {
            if cfg!(debug_assertions) {
                tracing::warn!(
                    "CORS allow_origin='*' is insecure — only allowed in debug builds. \
                     Specify explicit origins for production."
                );
                cors = cors.allow_origin(axum::http::HeaderValue::from_static("*"));
            } else {
                tracing::error!(
                    "CORS allow_origin='*' is rejected in release builds for security. \
                     Set admin.cors.allow_origin to specific origins."
                );
            }
        } else {
            match origin.as_str().parse::<axum::http::HeaderValue>() {
                Ok(header_value) => {
                    cors = cors.allow_origin(header_value);
                }
                _ => {
                    tracing::warn!("Invalid CORS allow_origin: {}, using default", origin);
                }
            }
        }
    }

    if let Some(methods) = &cors_config.allow_methods {
        use axum::http::Method;
        let parsed_methods: Vec<Method> = methods.iter().filter_map(|m| m.parse().ok()).collect();
        if !parsed_methods.is_empty() {
            cors = cors.allow_methods(parsed_methods);
        }
    }

    if let Some(headers) = &cors_config.allow_headers {
        use axum::http::header;
        let parsed_headers: Vec<header::HeaderName> =
            headers.iter().filter_map(|h| h.parse().ok()).collect();
        if !parsed_headers.is_empty() {
            cors = cors.allow_headers(parsed_headers);
        }
    }

    cors
}

#[cfg(feature = "mesh")]
use crate::mesh::transport::MeshTransport;
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;

pub fn create_admin_router(
    config: Arc<TokioRwLock<ConfigManager>>,
    admin_token: String,
    admin_cors_config: AdminCorsConfig,
    admin_rate_limit_config: crate::config::admin::AdminRateLimitConfig,
    trusted_proxies: Vec<String>,
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
    rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    #[cfg(feature = "mesh")] mesh_transport: Option<Arc<MeshTransport>>,
    #[cfg(feature = "icmp-filter")] icmp_filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>,
) -> Router {
    let token_hash = match hash_admin_token(&admin_token) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash admin token: {}", e);
            return Router::new();
        }
    };

    let config_dir = config.blocking_read().config_dir.clone();
    let config_versions = ConfigVersionManager::new(config_dir);
    let secure_cookie = config.blocking_read().main.admin.secure_cookie;

    let state_builder = AdminState::new(config, token_hash)
        .with_config_versions(config_versions)
        .with_probe_tracker(probe_tracker)
        .with_suspicious_word_tracker(suspicious_word_tracker)
        .with_upstream_error_tracker(upstream_error_tracker)
        .with_threat_level_manager(threat_level_manager)
        .with_rule_feed_manager(rule_feed_manager)
        .with_secure_cookie(secure_cookie);

    #[cfg(feature = "mesh")]
    let state_builder = state_builder
        .with_mesh_transport(mesh_transport.clone())
        .with_org_key_manager(mesh_transport.as_ref().map(|m| m.get_org_key_manager()));

    #[cfg(feature = "icmp-filter")]
    let state_builder = state_builder.with_icmp_filter(icmp_filter);

    let state = Arc::new(state_builder);

    let router = build_router_from_state(
        state,
        admin_cors_config,
        admin_rate_limit_config,
        trusted_proxies.clone(),
    );
    middleware::set_trusted_proxies(trusted_proxies);
    router
}

/// Resolve the admin UI asset directory deterministically, independent of process CWD.
///
/// Priority:
/// 1. `SYNVOID_ADMIN_UI_DIR` environment variable
/// 2. `{exe_dir}/admin-ui/dist` (installed binary layout)
/// 3. `{CARGO_MANIFEST_DIR}/admin-ui/dist` (development, compile-time)
/// 4. `./admin-ui/dist` (last-resort fallback)
fn resolve_admin_ui_assets() -> std::path::PathBuf {
    // 1. Explicit env var override
    if let Ok(dir) = std::env::var("SYNVOID_ADMIN_UI_DIR") {
        let path = std::path::PathBuf::from(dir);
        if path.exists() {
            tracing::info!(
                "Admin UI assets resolved from SYNVOID_ADMIN_UI_DIR: {}",
                path.display()
            );
            return path;
        }
        tracing::warn!(
            "SYNVOID_ADMIN_UI_DIR set to {} but directory does not exist",
            path.display()
        );
    }

    // 2. Relative to the running executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let path = exe_dir.join("admin-ui").join("dist");
            if path.exists() {
                tracing::info!(
                    "Admin UI assets resolved relative to executable: {}",
                    path.display()
                );
                return path;
            }
        }
    }

    // 3. Compile-time manifest directory (development builds)
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("admin-ui").join("dist");
    if path.exists() {
        tracing::info!(
            "Admin UI assets resolved from CARGO_MANIFEST_DIR: {}",
            path.display()
        );
        return path;
    }

    // 4. CWD-relative fallback
    let path = std::path::PathBuf::from("admin-ui").join("dist");
    tracing::warn!(
        "Admin UI assets not found at any standard location. \
         Checked: SYNVOID_ADMIN_UI_DIR, executable dir, CARGO_MANIFEST_DIR ({}), CWD. \
         SPA will not be served until assets are available at: {}",
        manifest_dir.display(),
        path.display()
    );
    path
}

/// SPA fallback: serves `index.html` for browser navigation to non-existent paths.
/// Static assets that don't exist return 404 (no MIME confusion).
/// `/api/*` misses are handled by the API router's catch-all, not here.
async fn spa_fallback_handler(
    req: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    let asset_dir = resolve_admin_ui_assets();
    let uri_path = req.uri().path();

    // Try to serve the exact static file first
    let file_path = asset_dir.join(uri_path.trim_start_matches('/'));
    if file_path.is_file() {
        if let Ok(bytes) = tokio::fs::read(&file_path).await {
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();
            return axum::response::IntoResponse::into_response((
                [(axum::http::header::CONTENT_TYPE, mime)],
                bytes,
            ));
        }
    }

    // Not a static file — check if this is a browser navigation (Accept: text/html)
    let is_html_request = req
        .headers()
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false);

    if is_html_request {
        let index_path = asset_dir.join("index.html");
        match tokio::fs::read_to_string(&index_path).await {
            Ok(content) => axum::response::IntoResponse::into_response((
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                content,
            )),
            Err(_) => {
                tracing::warn!(
                    "SPA fallback: index.html not found at {}",
                    index_path.display()
                );
                axum::http::StatusCode::NOT_FOUND.into_response()
            }
        }
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

fn build_router_from_state(
    state: Arc<AdminState>,
    admin_cors_config: AdminCorsConfig,
    rate_limit_config: crate::config::admin::AdminRateLimitConfig,
    _trusted_proxies: Vec<String>,
) -> Router {
    let asset_dir = resolve_admin_ui_assets();
    if !asset_dir.join("index.html").exists() {
        tracing::warn!(
            "Admin UI index.html not found at {}. SPA deep links will not work.",
            asset_dir.join("index.html").display()
        );
    }

    // ── Phase 04: family routers merged in one visible order ──────────
    // Always-available families first, then feature-gated families. Each
    // family lives in `routes.rs`; this function only merges, nests under
    // `/api`, and applies middleware. No per-family state/middleware copies.
    #[allow(unused_mut)]
    let mut api_routes = Router::new()
        .merge(routes::observability_routes())
        .merge(routes::stats_routes())
        .merge(routes::sites_upstreams_routes())
        .merge(routes::config_routes())
        .merge(routes::infra_probes_threat_rules_routes())
        .merge(routes::system_process_routes())
        .merge(routes::honeypot_routes());

    // ── Feature-gated families (gate lives in `routes.rs`) ───────────
    #[cfg(feature = "dns")]
    {
        api_routes = api_routes.merge(routes::dns_routes());
    }
    #[cfg(feature = "mesh")]
    {
        api_routes = api_routes.merge(routes::mesh_config_routes());
        api_routes = api_routes.merge(routes::mesh_routes());
    }
    #[cfg(feature = "icmp-filter")]
    {
        api_routes = api_routes.merge(routes::icmp_routes());
    }

    let rate_limit_layer =
        rate_limit::AdminRateLimitLayer::from_config(rate_limit::AdminRateLimitConfig {
            requests_per_minute: rate_limit_config.requests_per_minute,
            requests_per_second: rate_limit_config.burst,
        });

    let yara_rate_limit_layer = axum::middleware::from_fn_with_state(
        state.clone(),
        middleware::yara_rate_limit::yara_rate_limit_middleware,
    );

    // ── Protected API router (auth + CSRF middleware) ──────────────────────
    #[allow(unused_mut)]
    let mut api_router = Router::new().nest("/api", api_routes);

    #[cfg(not(feature = "swagger-ui"))]
    {
        api_router = api_router.route("/api/openapi.json", get(openapi::get_openapi_json));
    }

    #[cfg(feature = "swagger-ui")]
    {
        api_router = api_router.merge(
            SwaggerUi::new("/api/docs")
                .url("/api/openapi.json", openapi::synvoidOpenApi::openapi()),
        );
    }

    let protected_api = api_router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware_with_state,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf_middleware,
        ));

    // ── WebSocket routes (session-authenticated upgrade, no blanket middleware) ──
    // Canonical paths: /api/ws/metrics and /api/ws/logs (matching frontend namespace)
    let ws_routes = Router::new()
        .route("/api/ws/metrics", get(ws::ws_metrics_handler))
        .route("/api/ws/logs", get(ws::ws_logs_handler));

    // ── Root health (public, no auth) ─────────────────────────────────────
    let health_route = Router::new().route("/health", get(health_check));

    // ── Combine: protected API + public routes + SPA fallback ──────────────
    Router::new()
        .merge(health_route)
        .merge(protected_api)
        .merge(ws_routes)
        .fallback_service(axum::routing::any(spa_fallback_handler))
        .layer(create_cors_layer(&admin_cors_config))
        .layer(axum::middleware::from_fn(
            middleware::security_headers_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::extract_client_ip_middleware,
        ))
        .layer(yara_rate_limit_layer)
        .layer(rate_limit_layer)
        .with_state(state)
}

async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok"
        })),
    )
}
