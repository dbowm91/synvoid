mod auth;
mod state;
mod ws;
mod handlers;
mod rate_limit;

pub use auth::constant_time_compare;
pub use state::AdminState;
pub use ws::broadcaster::Broadcaster;

use axum::{
    routing::{get, post, put, delete, patch},
    Router,
    http::StatusCode,
    Json,
};
use tower_http::{cors::CorsLayer, services::ServeDir};

use crate::config::ConfigManager;
use crate::waf::{ProbeTracker, SuspiciousWordTracker, UpstreamErrorTracker, ThreatLevelManager};

fn create_cors_layer() -> CorsLayer {
    CorsLayer::permissive()
}
use std::sync::Arc;
use tokio::sync::RwLock;

pub fn create_admin_router(
    config: Arc<RwLock<ConfigManager>>,
    admin_token: String,
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
) -> Router {
    let state = Arc::new(
        AdminState::new(config, admin_token)
            .with_probe_tracker(probe_tracker)
            .with_suspicious_word_tracker(suspicious_word_tracker)
            .with_upstream_error_tracker(upstream_error_tracker)
            .with_threat_level_manager(threat_level_manager)
    );
    
    let api_routes = Router::new()
        .route("/health", get(health_check))
        .route("/stats/summary", get(handlers::stats::get_summary))
        .route("/stats/sites", get(handlers::stats::get_sites_stats))
        .route("/sites", get(handlers::sites::list_sites).post(handlers::sites::create_site))
        .route("/sites/{site_id}", get(handlers::sites::get_site).delete(handlers::sites::delete_site))
        .route("/upstreams", get(handlers::upstreams::list_upstreams))
        .route("/upstreams/{site_id}", get(handlers::upstreams::get_site_upstreams))
        .route("/upstreams/{site_id}/check", post(handlers::upstreams::trigger_health_check))
        .route("/logs", get(handlers::logs::get_logs))
        .route("/error-pages", get(handlers::logs::list_error_pages))
        .route("/error-pages/{code}", get(handlers::logs::get_error_page))
        .route("/config/main", get(handlers::config::get_main_config).put(handlers::config::update_main_config))
        .route("/config/schema", get(handlers::config::get_config_schema))
        .route("/config/reload", post(handlers::config::reload_config))
        .route("/config/log-level", get(handlers::config::get_log_level).put(handlers::config::set_log_level))
        .route("/tcp-udp/listeners", get(handlers::tcp_udp::list_listeners).post(handlers::tcp_udp::create_listener))
        .route("/tcp-udp/listeners/{listener_id}", delete(handlers::tcp_udp::delete_listener))
        .route("/tcp-udp/protocols", get(handlers::tcp_udp::list_protocols))
        .route("/probes", get(handlers::probes::list_probes))
        .route("/probes/stats", get(handlers::probes::get_probe_stats))
        .route("/probes/block", post(handlers::probes::block_probes))
        .route("/probes/{ip}", get(handlers::probes::get_probe).delete(handlers::probes::delete_probe))
        .route("/probes/words", get(handlers::probes::list_suspicious_words))
        .route("/probes/words/stats", get(handlers::probes::get_suspicious_word_stats))
        .route("/probes/words/{ip}", delete(handlers::probes::delete_suspicious_word))
        .route("/probes/upstream", get(handlers::probes::list_upstream_errors))
        .route("/probes/upstream/stats", get(handlers::probes::get_upstream_error_stats))
        .route("/probes/upstream/{ip}", delete(handlers::probes::delete_upstream_error))
        .route("/threat-level", get(handlers::threat_level::get_status))
        .route("/threat-level/history", get(handlers::threat_level::get_history))
        .route("/threat-level/history/stats", get(handlers::threat_level::get_history_stats))
        .route("/threat-level/history/backup", post(handlers::threat_level::create_backup))
        .route("/threat-level/history/backups", get(handlers::threat_level::list_backups))
        .route("/threat-level/history/backups", delete(handlers::threat_level::delete_backup))
        .route("/threat-level/history/prune", post(handlers::threat_level::prune_history))
        .route("/threat-level/baseline", get(handlers::threat_level::get_baseline))
        .route("/threat-level/reset", post(handlers::threat_level::reset_baseline))
        .route("/threat-level/set/{level}", post(handlers::threat_level::set_level))
        .route("/threat-level/auto", post(handlers::threat_level::set_auto))
        .route("/ws/metrics", get(ws::ws_metrics_handler))
        .route("/ws/logs", get(ws::ws_logs_handler));

    let rate_limit_layer = rate_limit::AdminRateLimitLayer::new();

    Router::new()
        .nest("/api", api_routes)
        .route("/health", get(health_check))
        .fallback_service(ServeDir::new("admin-ui/dist"))
        .layer(create_cors_layer())
        .layer(rate_limit_layer)
        .with_state(state)
}

async fn health_check() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

pub async fn start_admin_server(
    config: Arc<RwLock<ConfigManager>>, 
    probe_tracker: Option<Arc<ProbeTracker>>,
    suspicious_word_tracker: Option<Arc<SuspiciousWordTracker>>,
    upstream_error_tracker: Option<Arc<UpstreamErrorTracker>>,
    threat_level_manager: Option<Arc<ThreatLevelManager>>,
) {
    let cfg = config.read().await.main.admin.clone();
    if !cfg.enabled {
        return;
    }

    let port = cfg.port;
    let token = cfg.token.clone();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    
    tracing::info!("Admin API server starting on http://{}", addr);
    
    let app = create_admin_router(config, token, probe_tracker, suspicious_word_tracker, upstream_error_tracker, threat_level_manager);
    
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind admin server: {}", e);
            return;
        }
    };
    
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Admin server error: {}", e);
    }
}

pub use crate::admin::legacy::*;
mod legacy;
