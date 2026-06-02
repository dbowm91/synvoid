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
mod ws;

pub use audit::{AuditLog, AuditState, ConfigVersion, ConfigVersionManager};
pub use auth::{hash_admin_token, hash_admin_token_with_cost, verify_admin_token};
use axum::{
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
pub use metrics::start_metrics_publisher;
pub use state::{
    get_cpu_memory_usage, get_current_connections, set_current_connections, AdminRateLimiter,
    AdminState, AggregatedMetrics, SystemResources, YaraRateLimiter, SESSION_COOKIE_NAME,
};
use tower_http::{cors::CorsLayer, services::ServeDir};
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

#[cfg(feature = "mesh")]
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

    let config_dir = config.blocking_read().config_dir.clone();
    let config_versions = ConfigVersionManager::new(config_dir);

    let state_builder = AdminState::new(config, token_hash)
        .with_config_versions(config_versions)
        .with_probe_tracker(probe_tracker)
        .with_suspicious_word_tracker(suspicious_word_tracker)
        .with_upstream_error_tracker(upstream_error_tracker)
        .with_threat_level_manager(threat_level_manager)
        .with_rule_feed_manager(rule_feed_manager)
        .with_mesh_transport(mesh_transport.clone())
        .with_org_key_manager(mesh_transport.map(|m| m.org_key_manager.clone()));

    #[cfg(feature = "icmp-filter")]
    {
        state_builder = state_builder.with_icmp_filter(icmp_filter);
    }

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

pub async fn create_admin_router_with_state(state: Arc<AdminState>) -> Router {
    let cfg = state.process.config.read().await;
    let admin_cors_config = cfg.main.admin.cors.clone();
    let rate_limit_config = cfg.main.admin.rate_limit.clone();
    let trusted_proxies = cfg.main.admin.trusted_proxies.clone();
    drop(cfg);
    let router = build_router_from_state(
        state,
        admin_cors_config,
        rate_limit_config,
        trusted_proxies.clone(),
    );
    middleware::set_trusted_proxies(trusted_proxies);
    router
}

fn build_router_from_state(
    state: Arc<AdminState>,
    admin_cors_config: AdminCorsConfig,
    rate_limit_config: crate::config::admin::AdminRateLimitConfig,
    _trusted_proxies: Vec<String>,
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
            "/config/supervisor",
            get(handlers::config::get_supervisor_config)
                .put(handlers::config::update_supervisor_config),
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
        .route("/rules/discard", post(handlers::rule_feed::discard_pending));

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
        .route("/icmp/status", get(handlers::icmp::get_status))
        .route(
            "/icmp/config",
            get(handlers::icmp::get_config).put(handlers::icmp::update_config),
        )
        .route("/icmp/enable", post(handlers::icmp::enable))
        .route("/icmp/disable", post(handlers::icmp::disable))
        .route("/icmp/backends", get(handlers::icmp::list_backends))
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
        .route("/system/supervisor", get(handlers::system::get_supervisor))
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
        );
    #[cfg(feature = "mesh")]
    let api_routes = api_routes
        .route("/mesh/status", get(handlers::mesh_admin::get_mesh_status))
        .route(
            "/mesh/raft/status",
            get(handlers::mesh_admin::get_raft_status),
        )
        .route("/mesh/dht/stats", get(handlers::mesh_admin::get_dht_stats))
        .route(
            "/mesh/attest-capability",
            post(handlers::mesh_admin::attest_capability),
        );

    #[cfg(feature = "mesh")]
    let api_routes = api_routes
        .route(
            "/v1/mesh/raft/status",
            get(handlers::mesh_admin::get_raft_status),
        )
        .route(
            "/v1/mesh/dht/stats",
            get(handlers::mesh_admin::get_dht_stats),
        )
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
        );

    #[cfg(feature = "mesh")]
    let api_routes = api_routes
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
        .route("/mesh/bans", get(handlers::mesh_admin::list_bans));

    #[cfg(feature = "mesh")]
    let api_routes = api_routes
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
        .route("/api", get(handlers::api_discovery::get_api_discovery))
        .route(
            "/theme",
            get(handlers::theme::get_theme).put(handlers::theme::update_theme),
        )
        .route("/theme/css", get(handlers::theme::get_theme_css))
        .route("/theme/presets", get(handlers::theme::get_theme_presets))
        .route("/auth/session", post(handlers::auth::create_session))
        .route("/auth/csrf", get(handlers::auth::get_csrf_token))
        .route("/auth/session", delete(handlers::auth::delete_session))
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

    let mut router = Router::new()
        .nest("/api", api_routes)
        .route("/api/openapi.json", get(openapi::get_openapi_json));

    #[cfg(feature = "swagger-ui")]
    {
        router = router.merge(
            SwaggerUi::new("/api/docs")
                .url("/api/openapi.json", openapi::synvoidOpenApi::openapi()),
        );
    }

    router
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
    #[cfg(feature = "mesh")] yara_rules: Option<Arc<crate::mesh::yara_rules::YaraRulesManager>>,
    #[cfg(feature = "mesh")] mesh_transport: Option<Arc<MeshTransport>>,
    #[cfg(feature = "icmp-filter")] icmp_filter: Option<Arc<TokioRwLock<IcmpFilterManager>>>,
    process_manager: Option<Arc<crate::process::ProcessManager>>,
    plugin_manager: Option<Arc<crate::plugin::PluginManager>>,
) {
    let cfg = config.read().await.main.admin.clone();
    if !cfg.enabled {
        return;
    }

    let metrics_config = config.read().await.main.metrics.clone();

    let port = cfg.port;
    let token = match hash_admin_token_with_cost(&cfg.resolve_token(), cfg.bcrypt_cost) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash admin token: {}", e);
            return;
        }
    };
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
        .with_process_manager(process_manager.clone())
        .with_plugin_manager(plugin_manager)
        .with_rate_limiter(rate_limiter)
        .with_yara_rate_limiter(yara_rate_limiter);

    #[cfg(feature = "mesh")]
    let admin_state_builder = admin_state_builder
        .with_yara_rules(yara_rules)
        .with_mesh_transport(mesh_transport.clone())
        .with_org_key_manager(mesh_transport.map(|m| m.org_key_manager.clone()));

    #[cfg(feature = "icmp-filter")]
    {
        admin_state_builder = admin_state_builder.with_icmp_filter(icmp_filter);
    }

    let admin_state = Arc::new(admin_state_builder);

    #[cfg(feature = "mesh")]
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

    {
        let metrics_cfg = metrics_config.clone();
        let (_metrics_shutdown_tx, metrics_shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        tokio::spawn(async move {
            crate::admin::prometheus_exporter::start_prometheus_exporter(
                &metrics_cfg,
                metrics_shutdown_rx,
            )
            .await;
        });
    }

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

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
