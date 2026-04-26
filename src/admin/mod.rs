//! Admin dashboard and API for MaluWAF.
//!
//! Exposes an HTTP/HTTPS management interface built on Axum, providing
//! site configuration, user management, metrics, alerting, WebSocket
//! broadcasting, and OpenAPI documentation. Handles authentication,
//! rate limiting, CSRF protection, and CORS via middleware layers.

pub mod alerting;
mod audit;
mod auth;
mod handlers;
mod metrics;
mod middleware;
pub mod openapi;
pub use openapi::MaluWafOpenApi;
mod rate_limit;
mod state;
mod ws;

pub use audit::{AuditLog, AuditState};
pub use auth::{hash_admin_token, hash_admin_token_with_cost, verify_admin_token};
use axum::{
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
pub use metrics::start_metrics_publisher;
pub use state::{
    get_cpu_memory_usage, get_current_connections, set_current_connections, AdminRateLimiter,
    AdminState, AggregatedMetrics, SystemResources, YaraRateLimiter,
};
use tower_http::{cors::CorsLayer, services::ServeDir};

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
use crate::mesh::transport::MeshTransport;
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;

pub fn create_admin_router(
    config: Arc<TokioRwLock<ConfigManager>>,
    admin_token: String,
    admin_cors_config: AdminCorsConfig,
    admin_rate_limit_config: crate::config::admin::AdminRateLimitConfig,
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
    rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    mesh_transport: Option<Arc<MeshTransport>>,
    #[cfg(feature = "icmp-filter")] icmp_filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>,
) -> Router {
    let token_hash = match hash_admin_token(&admin_token) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash admin token: {}", e);
            return Router::new();
        }
    };
    let state_builder = AdminState::new(config, token_hash)
        .with_probe_tracker(probe_tracker)
        .with_suspicious_word_tracker(suspicious_word_tracker)
        .with_upstream_error_tracker(upstream_error_tracker)
        .with_threat_level_manager(threat_level_manager)
        .with_rule_feed_manager(rule_feed_manager)
        .with_mesh_transport(mesh_transport);

    #[cfg(feature = "icmp-filter")]
    {
        state_builder = state_builder.with_icmp_filter(icmp_filter);
    }

    let state = Arc::new(state_builder);

    build_router_from_state(state, admin_cors_config, admin_rate_limit_config)
}

pub async fn create_admin_router_with_state(state: Arc<AdminState>) -> Router {
    let cfg = state.process.config.read().await;
    let admin_cors_config = cfg.main.admin.cors.clone();
    let rate_limit_config = cfg.main.admin.rate_limit.clone();
    drop(cfg);
    build_router_from_state(state, admin_cors_config, rate_limit_config)
}

fn build_router_from_state(
    state: Arc<AdminState>,
    admin_cors_config: AdminCorsConfig,
    rate_limit_config: crate::config::admin::AdminRateLimitConfig,
) -> Router {
    let api_routes = Router::new()
        .route("/health", get(health_check))
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
            "/config/overseer",
            get(handlers::config::get_overseer_config)
                .put(handlers::config::update_overseer_config),
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
            "/config/mesh",
            get(handlers::config::get_mesh_config).put(handlers::config::update_mesh_config),
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
            "/config/bundle",
            get(handlers::config::get_config_bundle).put(handlers::config::update_config_bundle),
        )
        .route(
            "/config/process-manager",
            get(handlers::config::get_process_manager_config)
                .put(handlers::config::update_process_manager_config),
        )
        .route(
            "/config/supervisor",
            get(handlers::config::get_supervisor_config)
                .put(handlers::config::update_supervisor_config),
        )
        .route(
            "/tcp-udp/listeners",
            get(handlers::tcp_udp::list_listeners).post(handlers::tcp_udp::create_listener),
        )
        .route(
            "/tcp-udp/listeners/{listener_id}",
            delete(handlers::tcp_udp::delete_listener),
        )
        .route("/tcp-udp/protocols", get(handlers::tcp_udp::list_protocols));

    #[cfg(feature = "dns")]
    let api_routes = api_routes.route(
        "/config/dns",
        get(handlers::config::get_dns_config).put(handlers::config::update_dns_config),
    );

    let api_routes = api_routes
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
            get(handlers::threat_level::list_backups),
        )
        .route(
            "/threat-level/history/backups",
            delete(handlers::threat_level::delete_backup),
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
        .route("/rules/discard", post(handlers::rule_feed::discard_pending))
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
        .route("/icmp/status", get(handlers::icmp::get_status))
        .route(
            "/icmp/config",
            get(handlers::icmp::get_config).put(handlers::icmp::update_config),
        )
        .route("/icmp/enable", post(handlers::icmp::enable))
        .route("/icmp/disable", post(handlers::icmp::disable))
        .route("/icmp/backends", get(handlers::icmp::list_backends))
        .route("/system/info", get(handlers::system::get_system_info))
        .route("/system/master", get(handlers::system::get_master_status))
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
        .route("/system/overseer", get(handlers::system::get_overseer))
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
        .route("/mesh/status", get(handlers::mesh_admin::get_mesh_status))
        .route(
            "/mesh/attest-capability",
            post(handlers::mesh_admin::attest_capability),
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
        .route("/mesh/ban/ip", post(handlers::mesh_admin::ban_ip))
        .route("/mesh/ban/mesh-id", post(handlers::mesh_admin::ban_mesh_id))
        .route("/mesh/ban", delete(handlers::mesh_admin::unban))
        .route("/mesh/bans", get(handlers::mesh_admin::list_bans))
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
            "/honeypot/status",
            get(handlers::honeypot::get_honeypot_status),
        )
        .route(
            "/honeypot/control",
            post(handlers::honeypot::control_honeypot),
        )
        .route(
            "/theme",
            get(handlers::theme::get_theme).put(handlers::theme::update_theme),
        )
        .route("/theme/css", get(handlers::theme::get_theme_css))
        .route("/theme/presets", get(handlers::theme::get_theme_presets))
        .route("/ws/metrics", get(ws::ws_metrics_handler))
        .route("/ws/logs", get(ws::ws_logs_handler));

    let rate_limit_layer =
        rate_limit::AdminRateLimitLayer::from_config(rate_limit::AdminRateLimitConfig {
            requests_per_minute: rate_limit_config.requests_per_minute,
            requests_per_second: rate_limit_config.burst,
        });

    let yara_rate_limit_layer = axum::middleware::from_fn_with_state(
        state.clone(),
        middleware::yara_rate_limit::yara_rate_limit_middleware,
    );

    Router::new()
        .nest("/api", api_routes)
        .route("/api/openapi.json", get(openapi::get_openapi_json))
        .route("/health", get(health_check))
        .fallback_service(ServeDir::new("admin-ui/dist"))
        .layer(create_cors_layer(&admin_cors_config))
        .layer(axum::middleware::from_fn(
            middleware::extract_client_ip_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware_with_state,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf_middleware,
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

pub async fn start_admin_server(
    config: Arc<TokioRwLock<ConfigManager>>,
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
    rule_feed_manager: Option<Arc<RuleFeedManagerForWaf>>,
    yara_rules: Option<Arc<crate::mesh::yara_rules::YaraRulesManager>>,
    mesh_transport: Option<Arc<MeshTransport>>,
    #[cfg(feature = "icmp-filter")] icmp_filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>,
    process_manager: Option<Arc<crate::process::ProcessManager>>,
    plugin_manager: Option<Arc<crate::plugin::PluginManager>>,
) {
    let cfg = config.read().await.main.admin.clone();
    if !cfg.enabled {
        return;
    }

    let port = cfg.port;
    let token = match hash_admin_token_with_cost(&cfg.resolve_token(), cfg.bcrypt_cost) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash admin token: {}", e);
            return;
        }
    };
    let _cors_config = cfg.cors.clone();
    let rate_limit_config = cfg.rate_limit.clone();
    tracing::info!("Admin API token resolved from config/env var");

    let bind_addr = if cfg.bind_address.is_empty() {
        "127.0.0.1".to_string()
    } else {
        cfg.bind_address.clone()
    };

    let rate_limiter = if rate_limit_config.requests_per_minute > 0 {
        Some(Arc::new(AdminRateLimiter::new(
            rate_limit_config.requests_per_minute,
            rate_limit_config.burst,
        )))
    } else {
        None
    };

    let yara_rate_limiter = Some(Arc::new(YaraRateLimiter::default_for_yara()));
    if let Some(ref limiter) = yara_rate_limiter {
        limiter.clone().start_cleanup_task();
    }

    let addr: std::net::SocketAddr =
        format!("{}:{}", bind_addr, port)
            .parse()
            .unwrap_or_else(|_| {
                tracing::error!(
                    "Invalid admin bind address: {}, using 127.0.0.1:{}",
                    bind_addr,
                    port
                );
                std::net::SocketAddr::from(([127, 0, 0, 1], 8081))
            });

    tracing::info!("Admin API server starting on http://{}", addr);

    let admin_state_builder = AdminState::new(config, token.clone())
        .with_probe_tracker(probe_tracker)
        .with_suspicious_word_tracker(suspicious_word_tracker)
        .with_upstream_error_tracker(upstream_error_tracker)
        .with_threat_level_manager(threat_level_manager)
        .with_rule_feed_manager(rule_feed_manager)
        .with_yara_rules(yara_rules)
        .with_process_manager(process_manager.clone())
        .with_plugin_manager(plugin_manager)
        .with_mesh_transport(mesh_transport)
        .with_rate_limiter(rate_limiter)
        .with_yara_rate_limiter(yara_rate_limiter);

    #[cfg(feature = "icmp-filter")]
    {
        admin_state_builder = admin_state_builder.with_icmp_filter(icmp_filter);
    }

    let admin_state = Arc::new(admin_state_builder);

    admin_state.setup_site_config_sync().await;

    let app = create_admin_router_with_state(admin_state.clone()).await;

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind admin server: {}", e);
            return;
        }
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    if let Some(pm) = process_manager {
        let state_for_metrics = admin_state.clone();
        let alert_manager = admin_state.process.alert_manager.clone();
        tokio::spawn(async move {
            start_metrics_publisher(state_for_metrics, pm, alert_manager, shutdown_rx).await;
        });
    }

    let server = axum::serve(listener, app);

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!("Admin server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Admin server received Ctrl+C, shutting down");
            let _ = shutdown_tx.send(()).await;
        }
    }
}
