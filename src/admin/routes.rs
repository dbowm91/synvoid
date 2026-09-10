//! Phase 04: admin route families for `build_router_from_state`.
//!
//! Each `*_routes()` helper registers one coherent route family and returns a
//! narrow `Router<Arc<AdminState>>`. The final composition point in `mod.rs`
//! only merges families, nests under `/api`, and applies middleware in one
//! visible order. `AdminState` and middleware stacks are never duplicated per
//! family. Feature gates live inside the relevant family builder.

use std::sync::Arc;

use axum::{
    routing::{delete, get, post},
    Router,
};

use super::handlers;
use super::state::AdminState;

type AdminRouter = Router<Arc<AdminState>>;

/// Core observability/diagnostics (always available).
pub(crate) fn observability_routes() -> AdminRouter {
    Router::new()
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
}

/// Read-only stats/logs (always available).
pub(crate) fn stats_routes() -> AdminRouter {
    Router::new()
        .route("/stats/summary", get(handlers::stats::get_summary))
        .route("/stats/sites", get(handlers::stats::get_sites_stats))
        .route("/stats/history", get(handlers::stats::get_metrics_history))
        .route("/stats/attacks", get(handlers::stats::get_attack_stats))
        .route("/stats/cache", get(handlers::stats::get_cache_stats))
        .route("/stats/bandwidth", get(handlers::stats::get_bandwidth))
        .route("/stats/requests", get(handlers::stats::get_request_logs))
}

/// Sites + upstreams (always available).
pub(crate) fn sites_upstreams_routes() -> AdminRouter {
    Router::new()
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
}

/// Config get/put surface (always available; feature-gated config lives in
/// `dns_routes` / `mesh_config_routes`).
pub(crate) fn config_routes() -> AdminRouter {
    Router::new()
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
}

/// TCP/UDP listeners + probes/threat/rules (always available).
pub(crate) fn infra_probes_threat_rules_routes() -> AdminRouter {
    Router::new()
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
        .route("/rules/discard", post(handlers::rule_feed::discard_pending))
}

/// Core system/process/auth/theme routes (always available, not mesh-gated).
pub(crate) fn system_process_routes() -> AdminRouter {
    Router::new()
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
        .route("/", get(handlers::api_discovery::get_api_discovery))
}

/// Honeypot admin routes (not mesh-gated; controller availability is runtime).
pub(crate) fn honeypot_routes() -> AdminRouter {
    Router::new()
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
}

/// DNS-only routes. Empty router when the `dns` feature is disabled so the
/// top-level composition stays uniform and the gate is auditable here.
#[cfg(feature = "dns")]
pub(crate) fn dns_routes() -> AdminRouter {
    Router::new().route(
        "/config/dns",
        get(handlers::config::get_dns_config).put(handlers::config::update_dns_config),
    )
}

/// Mesh-only config route. Empty router when `mesh` is disabled.
#[cfg(feature = "mesh")]
pub(crate) fn mesh_config_routes() -> AdminRouter {
    Router::new().route(
        "/config/mesh",
        get(handlers::config::get_mesh_config).put(handlers::config::update_mesh_config),
    )
}

/// ICMP-filter routes, gated by `icmp-filter` (not mesh).
#[cfg(feature = "icmp-filter")]
pub(crate) fn icmp_routes() -> AdminRouter {
    Router::new()
        .route("/icmp/status", get(handlers::icmp::get_status))
        .route(
            "/icmp/config",
            get(handlers::icmp::get_config).put(handlers::icmp::update_config),
        )
        .route("/icmp/enable", post(handlers::icmp::enable))
        .route("/icmp/disable", post(handlers::icmp::disable))
        .route("/icmp/backends", get(handlers::icmp::list_backends))
}

/// Mesh-only operational routes (YARA, mesh status/topology, plugins,
/// serverless, spin, tier keys). Empty surface when `mesh` is disabled — the
/// gate lives here, not fragmented across the top-level lifecycle.
#[cfg(feature = "mesh")]
pub(crate) fn mesh_routes() -> AdminRouter {
    Router::new()
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
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_family_registers_security_summary() {
        // Construction must not panic; route presence is covered by
        // `tests/admin_router_composition.rs` characterization tests.
        let _ = observability_routes();
    }

    #[test]
    fn config_family_registers_main_route() {
        let _ = config_routes();
    }

    #[test]
    fn system_family_registers_health_surface() {
        let _ = system_process_routes();
    }

    #[test]
    fn honeypot_family_registers_status() {
        let _ = honeypot_routes();
    }

    #[cfg(feature = "dns")]
    #[test]
    fn dns_family_registers_dns_config() {
        let _ = dns_routes();
    }

    #[cfg(feature = "mesh")]
    #[test]
    fn mesh_family_registers_status() {
        let _ = mesh_routes();
        let _ = mesh_config_routes();
    }

    #[cfg(feature = "icmp-filter")]
    #[test]
    fn icmp_family_registers_status() {
        let _ = icmp_routes();
    }
}
