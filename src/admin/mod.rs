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
pub mod schema;
mod state;
#[allow(dead_code)]
mod ws;

pub use audit::{AuditLog, AuditState, ConfigVersion, ConfigVersionManager};
pub use auth::{hash_admin_token, hash_admin_token_with_cost, verify_admin_token};
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
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
    let admin_bind_address = config.blocking_read().main.admin.bind_address.clone();

    let state_builder = AdminState::new(config, token_hash)
        .with_config_versions(config_versions)
        .with_probe_tracker(probe_tracker)
        .with_suspicious_word_tracker(suspicious_word_tracker)
        .with_upstream_error_tracker(upstream_error_tracker)
        .with_threat_level_manager(threat_level_manager)
        .with_rule_feed_manager(rule_feed_manager)
        .with_secure_cookie(is_external_bind(&admin_bind_address));

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

    // ── Core API routes (always available regardless of feature flags) ──────
    let api_routes = Router::new()
        .route(
            "/observability/security-summary",
            get(handlers::observability::security_observability_summary),
        )
        .route(
            "/observability/tasks",
            get(handlers::observability::runtime_tasks_diagnostics),
        )
        .route(
            "/observability/blocklist-health",
            get(handlers::observability::blocklist_health_diagnostics),
        )
        .route(
            "/observability/plugins",
            get(handlers::observability::plugin_diagnostics),
        )
        .route(
            "/observability/features",
            get(handlers::observability::features_diagnostics),
        )
        .route(
            "/observability/threat-intel",
            get(handlers::observability::threat_intel_diagnostics),
        )
        .route("/stats/summary", get(handlers::stats::get_summary))
        .route("/stats/sites", get(handlers::stats::get_sites_stats))
        .route("/stats/history", get(handlers::stats::get_metrics_history))
        .route("/stats/attacks", get(handlers::stats::get_attack_stats))
        .route("/stats/cache", get(handlers::stats::get_cache_stats))
        .route("/stats/bandwidth", get(handlers::stats::get_bandwidth))
        .route("/stats/requests", get(handlers::stats::get_request_logs))
        .route(
            "/sites",
            get(handlers::sites::list_sites).post(handlers::sites::create_site),
        )
        .route(
            "/sites/{site_id}",
            get(handlers::sites::get_site)
                .put(handlers::sites::update_site)
                .delete(handlers::sites::delete_site),
        )
        .route(
            "/sites/{site_id}/theme",
            get(handlers::sites::get_site_theme).put(handlers::sites::update_site_theme),
        )
        .route(
            "/sites/{site_id}/bot-detection",
            get(handlers::sites::get_site_bot_detection)
                .put(handlers::sites::update_site_bot_detection),
        )
        .route(
            "/sites/{site_id}/error-pages",
            get(handlers::sites::get_site_error_pages)
                .put(handlers::sites::update_site_error_pages),
        )
        .route("/upstreams", get(handlers::upstreams::list_upstreams))
        .route(
            "/upstreams/{site_id}",
            get(handlers::upstreams::get_site_upstreams),
        )
        .route(
            "/upstreams/{site_id}/check",
            post(handlers::upstreams::trigger_health_check),
        )
        .route("/logs", get(handlers::logs::get_logs))
        .route("/audit-logs", get(handlers::logs::get_audit_logs))
        .route("/error-pages", get(handlers::logs::list_error_pages))
        .route(
            "/error-pages/{code}",
            get(handlers::logs::get_error_page).put(handlers::logs::update_error_page),
        )
        .route(
            "/config/main",
            get(handlers::config::get_main_config).put(handlers::config::update_main_config),
        )
        .route("/config/schema", get(handlers::config::get_config_schema))
        .route("/config/reload", post(handlers::config::reload_config))
        .route(
            "/config/log-level",
            get(handlers::config::get_log_level).put(handlers::config::set_log_level),
        )
        .route("/config/export", get(handlers::config::export_config))
        .route("/config/import", post(handlers::config::import_config))
        .route("/config/check-regex", post(handlers::config::check_regex))
        .route(
            "/config/supervisor",
            get(handlers::config::get_supervisor_config)
                .put(handlers::config::update_supervisor_config),
        )
        .route(
            "/config/tls",
            get(handlers::config::get_tls_config).put(handlers::config::update_tls_config),
        )
        .route(
            "/config/http",
            get(handlers::config::get_http_config).put(handlers::config::update_http_config),
        )
        .route(
            "/config/acme",
            get(handlers::config::get_acme_config).put(handlers::config::update_acme_config),
        )
        .route(
            "/config/http3",
            get(handlers::config::get_http3_config).put(handlers::config::update_http3_config),
        )
        .route(
            "/config/security",
            get(handlers::config::get_security_config)
                .put(handlers::config::update_security_config),
        )
        .route(
            "/config/static",
            get(handlers::config::get_static_config).put(handlers::config::update_static_config),
        )
        .route(
            "/config/tunnel",
            get(handlers::config::get_tunnel_config).put(handlers::config::update_tunnel_config),
        )
        .route(
            "/config/plugins",
            get(handlers::config::get_plugins_config).put(handlers::config::update_plugins_config),
        )
        .route(
            "/config/logging",
            get(handlers::config::get_logging_config).put(handlers::config::update_logging_config),
        )
        .route(
            "/config/metrics",
            get(handlers::config::get_metrics_config).put(handlers::config::update_metrics_config),
        )
        .route(
            "/config/tokio",
            get(handlers::config::get_tokio_config).put(handlers::config::update_tokio_config),
        )
        .route(
            "/config/traffic-shaping",
            get(handlers::config::get_traffic_shaping_config)
                .put(handlers::config::update_traffic_shaping_config),
        )
        .route(
            "/config/rate-limits",
            get(handlers::config::get_rate_limits_config)
                .put(handlers::config::update_rate_limits_config),
        )
        .route(
            "/config/bot-detection",
            get(handlers::config::get_bot_detection_config)
                .put(handlers::config::update_bot_detection_config),
        )
        .route(
            "/config/threat-level",
            get(handlers::config::get_threat_level_config)
                .put(handlers::config::update_threat_level_config),
        )
        .route(
            "/config/ip-feeds",
            get(handlers::config::get_ip_feeds_config)
                .put(handlers::config::update_ip_feeds_config),
        )
        .route(
            "/config/mime-types",
            get(handlers::config::get_mime_types_config)
                .put(handlers::config::update_mime_types_config),
        )
        .route(
            "/config/tcp-udp-defaults",
            get(handlers::config::get_tcp_udp_defaults_config)
                .put(handlers::config::update_tcp_udp_defaults_config),
        )
        .route(
            "/config/fallback",
            get(handlers::config::get_fallback_config)
                .put(handlers::config::update_fallback_config),
        )
        .route(
            "/config/upgrade",
            get(handlers::config::get_upgrade_config).put(handlers::config::update_upgrade_config),
        )
        .route(
            "/config/rule-feed",
            get(handlers::config::get_rule_feed_config)
                .put(handlers::config::update_rule_feed_config),
        )
        .route(
            "/config/yara-feed",
            get(handlers::config::get_yara_feed_config)
                .put(handlers::config::update_yara_feed_config),
        )
        .route("/config/validate", post(handlers::config::validate_config))
        .route(
            "/config/versions",
            get(handlers::config::list_config_versions),
        )
        .route(
            "/config/versions/{id}",
            get(handlers::config::get_config_version),
        )
        .route(
            "/config/rollback/{id}",
            post(handlers::config::rollback_config),
        )
        .route("/config/diff", get(handlers::config::diff_config_versions))
        .route(
            "/config/bundle",
            get(handlers::config::get_config_bundle).put(handlers::config::update_config_bundle),
        )
        .route(
            "/config/process-manager",
            get(handlers::config::get_process_manager_config)
                .put(handlers::config::update_process_manager_config),
        )
        .route(
            "/config/defaults/honeypot",
            get(handlers::config::get_honeypot_defaults)
                .put(handlers::config::update_honeypot_defaults),
        )
        .route(
            "/config/defaults/honeypot-probe",
            get(handlers::config::get_honeypot_probing_defaults)
                .put(handlers::config::update_honeypot_probing_defaults),
        )
        .route(
            "/config/defaults/blocked",
            get(handlers::config::get_blocked_defaults)
                .put(handlers::config::update_blocked_defaults),
        )
        .route(
            "/config/defaults/suspicious-words",
            get(handlers::config::get_suspicious_words_defaults)
                .put(handlers::config::update_suspicious_words_defaults),
        )
        .route(
            "/config/defaults/upstream-errors",
            get(handlers::config::get_upstream_errors_defaults)
                .put(handlers::config::update_upstream_errors_defaults),
        )
        .route(
            "/config/defaults/error-pages",
            get(handlers::config::get_error_pages_defaults)
                .put(handlers::config::update_error_pages_defaults),
        )
        .route(
            "/config/defaults/css-challenge",
            get(handlers::config::get_css_challenge_defaults)
                .put(handlers::config::update_css_challenge_defaults),
        )
        .route(
            "/config/defaults/pow-challenge",
            get(handlers::config::get_pow_challenge_defaults)
                .put(handlers::config::update_pow_challenge_defaults),
        )
        .route(
            "/config/defaults/challenge",
            get(handlers::config::get_challenge_defaults)
                .put(handlers::config::update_challenge_defaults),
        )
        .route(
            "/config/defaults/auth",
            get(handlers::config::get_auth_defaults).put(handlers::config::update_auth_defaults),
        )
        .route(
            "/config/defaults/worker-pool",
            get(handlers::config::get_worker_pool_defaults)
                .put(handlers::config::update_worker_pool_defaults),
        )
        .route(
            "/config/defaults/persistence",
            get(handlers::config::get_persistence_defaults)
                .put(handlers::config::update_persistence_defaults),
        )
        .route(
            "/config/defaults/tarpit",
            get(handlers::config::get_tarpit_defaults)
                .put(handlers::config::update_tarpit_defaults),
        )
        .route(
            "/config/defaults/upload",
            get(handlers::config::get_upload_defaults)
                .put(handlers::config::update_upload_defaults),
        )
        .route(
            "/config/defaults/traffic-shaping",
            get(handlers::config::get_traffic_shaping_sub_defaults)
                .put(handlers::config::update_traffic_shaping_sub_defaults),
        )
        .route(
            "/config/defaults/asn-scraping",
            get(handlers::config::get_asn_scraping_defaults)
                .put(handlers::config::update_asn_scraping_defaults),
        )
        .route(
            "/tcp-udp/listeners",
            get(handlers::tcp_udp::list_listeners).post(handlers::tcp_udp::create_listener),
        )
        .route(
            "/tcp-udp/listeners/{listener_id}",
            delete(handlers::tcp_udp::delete_listener),
        )
        .route("/tcp-udp/protocols", get(handlers::tcp_udp::list_protocols))
        .route("/probes", get(handlers::probes::list_probes))
        .route("/probes/stats", get(handlers::probes::get_probe_stats))
        .route("/probes/block", post(handlers::probes::block_probes))
        .route(
            "/probes/{ip}",
            get(handlers::probes::get_probe).delete(handlers::probes::delete_probe),
        )
        .route(
            "/probes/words",
            get(handlers::probes::list_suspicious_words),
        )
        .route(
            "/probes/words/stats",
            get(handlers::probes::get_suspicious_word_stats),
        )
        .route(
            "/probes/words/{ip}",
            delete(handlers::probes::delete_suspicious_word),
        )
        .route(
            "/probes/upstream",
            get(handlers::probes::list_upstream_errors),
        )
        .route(
            "/probes/upstream/stats",
            get(handlers::probes::get_upstream_error_stats),
        )
        .route(
            "/probes/upstream/{ip}",
            delete(handlers::probes::delete_upstream_error),
        )
        .route("/threat-level", get(handlers::threat_level::get_status))
        .route(
            "/threat-level/history",
            get(handlers::threat_level::get_history),
        )
        .route(
            "/threat-level/history/stats",
            get(handlers::threat_level::get_history_stats),
        )
        .route(
            "/threat-level/history/backup",
            post(handlers::threat_level::create_backup),
        )
        .route(
            "/threat-level/history/backups",
            get(handlers::threat_level::list_backups).delete(handlers::threat_level::delete_backup),
        )
        .route(
            "/threat-level/history/prune",
            post(handlers::threat_level::prune_history),
        )
        .route(
            "/threat-level/baseline",
            get(handlers::threat_level::get_baseline),
        )
        .route(
            "/threat-level/reset",
            post(handlers::threat_level::reset_baseline),
        )
        .route(
            "/threat-level/set/{level}",
            post(handlers::threat_level::set_level),
        )
        .route("/threat-level/auto", post(handlers::threat_level::set_auto))
        .route("/rules/status", get(handlers::rule_feed::get_status))
        .route("/rules/check", post(handlers::rule_feed::check_for_updates))
        .route("/rules/apply", post(handlers::rule_feed::apply_pending))
        .route("/rules/discard", post(handlers::rule_feed::discard_pending));

    // ── DNS-only routes ────────────────────────────────────────────────────
    #[cfg(feature = "dns")]
    let api_routes = api_routes.route(
        "/config/dns",
        get(handlers::config::get_dns_config).put(handlers::config::update_dns_config),
    );

    // ── Mesh-only config routes ────────────────────────────────────────────
    #[cfg(feature = "mesh")]
    let api_routes = api_routes.route(
        "/config/mesh",
        get(handlers::config::get_mesh_config).put(handlers::config::update_mesh_config),
    );

    // ── ICMP-filter routes (gated by icmp-filter, not mesh) ────────────────
    #[cfg(feature = "icmp-filter")]
    let api_routes = api_routes
        .route("/icmp/status", get(handlers::icmp::get_status))
        .route(
            "/icmp/config",
            get(handlers::icmp::get_config).put(handlers::icmp::update_config),
        )
        .route("/icmp/enable", post(handlers::icmp::enable))
        .route("/icmp/disable", post(handlers::icmp::disable))
        .route("/icmp/backends", get(handlers::icmp::list_backends));

    // ── Core system/auth/theme routes (always available, not mesh-gated) ───
    let api_routes = api_routes
        .route("/system/info", get(handlers::system::get_system_info))
        .route(
            "/system/capabilities",
            get(handlers::system::get_capabilities),
        )
        .route(
            "/system/supervisor",
            get(handlers::system::get_supervisor_status),
        )
        .route("/system/workers", get(handlers::system::get_workers))
        .route(
            "/system/workers/count",
            get(handlers::system::get_worker_count),
        )
        .route(
            "/system/workers/scale",
            post(handlers::system::scale_workers),
        )
        .route(
            "/system/workers/{worker_id}/restart",
            post(handlers::system::restart_worker),
        )
        .route(
            "/system/workers/batch-restart",
            post(handlers::system::batch_restart_workers),
        )
        .route(
            "/system/app-servers/{site_id}/logs",
            get(handlers::system::get_granian_logs),
        )
        .route("/system/php-pools", get(handlers::php::list_php_pools))
        .route(
            "/system/php-pools/reload",
            post(handlers::php::reload_php_pool),
        )
        .route(
            "/alerts/config",
            get(handlers::alerting::get_alert_config).put(handlers::alerting::update_alert_config),
        )
        .route(
            "/alerts/test-webhook",
            post(handlers::alerting::test_webhook),
        )
        .route(
            "/theme",
            get(handlers::theme::get_theme).put(handlers::theme::update_theme),
        )
        .route("/theme/css", get(handlers::theme::get_theme_css))
        .route("/theme/presets", get(handlers::theme::get_theme_presets))
        .route("/auth/session", post(handlers::auth::create_session))
        .route("/auth/csrf", get(handlers::auth::get_csrf_token))
        .route("/auth/session", delete(handlers::auth::delete_session))
        .route("/api", get(handlers::api_discovery::get_api_discovery));

    // ── Mesh-only routes ───────────────────────────────────────────────────
    #[cfg(feature = "mesh")]
    let api_routes = api_routes
        .route("/yara/status", get(handlers::yara_rules::get_status))
        .route(
            "/yara/submissions",
            get(handlers::yara_rules::list_submissions),
        )
        .route(
            "/yara/submissions/{submission_id}",
            get(handlers::yara_rules::get_submission),
        )
        .route(
            "/yara/submissions/{submission_id}/approve",
            post(handlers::yara_rules::approve_submission),
        )
        .route(
            "/yara/submissions/{submission_id}/reject",
            post(handlers::yara_rules::reject_submission),
        )
        .route(
            "/yara/broadcast",
            post(handlers::yara_rules::broadcast_rules),
        )
        .route("/yara/sync", post(handlers::yara_rules::sync_from_global))
        .route("/yara/submit", post(handlers::yara_rules::submit_rules))
        .route(
            "/yara/apply",
            post(handlers::yara_rules::apply_rules_direct),
        )
        .route(
            "/yara/submissions/{submission_id}",
            delete(handlers::yara_rules::delete_submission),
        )
        .route("/mesh/status", get(handlers::mesh_admin::get_mesh_status))
        .route(
            "/mesh/raft/status",
            get(handlers::mesh_admin::get_raft_status),
        )
        .route("/mesh/dht/stats", get(handlers::mesh_admin::get_dht_stats))
        .route(
            "/mesh/attest-capability",
            post(handlers::mesh_admin::attest_capability),
        )
        .route(
            "/v1/mesh/raft/status",
            get(handlers::mesh_admin::get_raft_status),
        )
        .route(
            "/v1/mesh/dht/stats",
            get(handlers::mesh_admin::get_dht_stats),
        )
        .route(
            "/mesh/derive-signing-key",
            post(handlers::mesh_admin::derive_signing_key),
        )
        .route("/mesh/nodes", get(handlers::mesh_admin::list_mesh_nodes))
        .route(
            "/mesh/nodes/{node_id}",
            get(handlers::mesh_admin::get_mesh_node),
        )
        .route(
            "/mesh/organizations",
            post(handlers::mesh_admin::create_organization),
        )
        .route(
            "/mesh/organizations/{org_id}",
            get(handlers::mesh_admin::get_organization),
        )
        .route(
            "/mesh/organizations/{org_id}/public-key",
            get(handlers::mesh_admin::get_org_public_key),
        )
        .route("/mesh/ban/ip", post(handlers::mesh_admin::ban_ip))
        .route("/mesh/ban/mesh-id", post(handlers::mesh_admin::ban_mesh_id))
        .route("/mesh/ban", delete(handlers::mesh_admin::unban))
        .route("/mesh/bans", get(handlers::mesh_admin::list_bans))
        .route(
            "/mesh/blocklist/catchup-stats",
            get(handlers::mesh_admin::get_blocklist_catchup_stats),
        )
        .route(
            "/mesh/threat-intel/policy-shadow",
            get(handlers::threat_intel_policy::get_policy_shadow),
        )
        .route(
            "/mesh/threat-intel/policy-shadow/stats",
            get(handlers::threat_intel_policy::get_policy_shadow_stats),
        )
        .route(
            "/mesh/topology",
            get(handlers::mesh_topology::get_mesh_topology),
        )
        .route(
            "/mesh/topology/graph",
            get(handlers::mesh_topology::get_topology_graph),
        )
        .route(
            "/mesh/behavioral/stats",
            get(handlers::behavioral_intel::get_behavioral_stats),
        )
        .route(
            "/mesh/behavioral/config",
            get(handlers::behavioral_intel::get_behavioral_config),
        )
        .route(
            "/mesh/audit/report",
            post(handlers::mesh_admin::submit_audit_report),
        )
        .route(
            "/mesh/report/signature-failure",
            post(handlers::mesh_admin::report_signature_failure),
        )
        .route(
            "/mesh/wasm-modules",
            get(handlers::plugins::get_mesh_wasm_modules),
        )
        .route(
            "/plugins/metrics",
            get(handlers::plugins::get_all_plugins_metrics),
        )
        .route(
            "/plugins/metrics/{name}",
            get(handlers::plugins::get_plugin_metrics),
        )
        .route(
            "/plugins/status",
            get(handlers::plugins::get_plugins_status),
        )
        .route(
            "/plugins/{name}/reload",
            post(handlers::plugins::reload_plugin),
        )
        .route(
            "/serverless/functions",
            get(handlers::serverless::list_functions),
        )
        .route(
            "/serverless/functions/{name}/stats",
            get(handlers::serverless::get_function_stats),
        )
        .route(
            "/serverless/health",
            get(handlers::serverless::get_serverless_health),
        )
        .route(
            "/serverless/config",
            get(handlers::serverless::get_serverless_config)
                .put(handlers::serverless::update_serverless_config),
        )
        .route("/spin/apps", get(handlers::spin::list_spin_apps))
        .route("/spin/apps", post(handlers::spin::create_spin_app))
        .route(
            "/spin/apps/{name}",
            get(handlers::spin::get_spin_app_manifest).delete(handlers::spin::delete_spin_app),
        )
        .route(
            "/spin/apps/{name}/instances",
            get(handlers::spin::get_spin_app_instances),
        )
        .route(
            "/honeypot/status",
            get(handlers::honeypot::get_honeypot_status),
        )
        .route(
            "/honeypot/control",
            post(handlers::honeypot::control_honeypot),
        )
        .route(
            "/honeypot/config",
            get(handlers::honeypot::get_honeypot_port_config)
                .put(handlers::honeypot::update_honeypot_port_config),
        )
        .route("/tier-keys", get(handlers::tier_keys::list_tier_keys))
        .route(
            "/tier-keys/issue",
            post(handlers::tier_keys::issue_tier_key),
        )
        .route(
            "/tier-keys/revoke",
            post(handlers::tier_keys::revoke_tier_key),
        )
        .route(
            "/tier-keys/unbind",
            post(handlers::tier_keys::unbind_tier_key),
        );

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

    // ── WebSocket routes (auth handled per-connection, not blanket) ────────
    let ws_routes = Router::new()
        .route("/ws/metrics", get(ws::ws_metrics_handler))
        .route("/ws/logs", get(ws::ws_logs_handler));

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

/// Returns true if the admin bind address is not a loopback address,
/// indicating the server is likely behind a TLS-terminating reverse proxy.
fn is_external_bind(bind_address: &str) -> bool {
    match bind_address.parse::<std::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        Err(_) => {
            // Non-IP hostnames like "0.0.0.0" are not loopback
            bind_address != "127.0.0.1" && bind_address != "::1" && bind_address != "localhost"
        }
    }
}

async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok"
        })),
    )
}
