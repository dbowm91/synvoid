use axum::{routing::get, Json, Router};
use std::sync::Arc;
use utoipa::openapi;
use utoipa::OpenApi;

use crate::admin::state::AdminState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "MaluWAF Admin API",
        version = "1.0.0",
        description = "REST API for managing MaluWAF - Multi-Process Web Application Firewall",
        contact(
            name = "MaluWAF Support",
            url = "https://github.com/anomalyco/maluwaf"
        )
    ),
    paths(
        crate::admin::handlers::stats::get_summary,
        crate::admin::handlers::stats::get_sites_stats,
        crate::admin::handlers::stats::get_metrics_history,
        crate::admin::handlers::stats::get_attack_stats,
        crate::admin::handlers::stats::get_cache_stats,
        crate::admin::handlers::stats::get_bandwidth,
        crate::admin::handlers::stats::get_request_logs,
        crate::admin::handlers::sites::list_sites,
        crate::admin::handlers::sites::get_site,
        crate::admin::handlers::sites::create_site,
        crate::admin::handlers::sites::delete_site,
        crate::admin::handlers::sites::update_site,
        crate::admin::handlers::sites::get_site_theme,
        crate::admin::handlers::sites::update_site_theme,
        crate::admin::handlers::serverless::list_functions,
        crate::admin::handlers::serverless::get_serverless_health,
        crate::admin::handlers::serverless::get_function_stats,
        crate::admin::handlers::upstreams::list_upstreams,
        crate::admin::handlers::upstreams::get_site_upstreams,
        crate::admin::handlers::upstreams::trigger_health_check,
        crate::admin::handlers::system::get_master_status,
        crate::admin::handlers::system::get_system_info,
        crate::admin::handlers::system::get_workers,
        crate::admin::handlers::system::restart_worker,
        crate::admin::handlers::system::get_worker_count,
        crate::admin::handlers::system::scale_workers,
        crate::admin::handlers::system::get_overseer,
        crate::admin::handlers::logs::get_logs,
        crate::admin::handlers::logs::list_error_pages,
        crate::admin::handlers::logs::get_error_page,
        crate::admin::handlers::logs::update_error_page,
        crate::admin::handlers::logs::get_audit_logs,
        crate::admin::handlers::theme::get_theme,
        crate::admin::handlers::theme::update_theme,
        crate::admin::handlers::theme::get_theme_css,
        crate::admin::handlers::theme::get_theme_presets,
        crate::admin::handlers::mesh_admin::list_mesh_nodes,
        crate::admin::handlers::mesh_admin::get_mesh_node,
        crate::admin::handlers::mesh_admin::ban_ip,
        crate::admin::handlers::mesh_admin::ban_mesh_id,
        crate::admin::handlers::mesh_admin::unban,
        crate::admin::handlers::mesh_admin::list_bans,
        crate::admin::handlers::mesh_admin::get_mesh_status,
        crate::admin::handlers::mesh_admin::derive_signing_key,
        crate::admin::handlers::mesh_admin::submit_audit_report,
        crate::admin::handlers::mesh_admin::report_signature_failure,
        crate::admin::handlers::config::get_main_config,
        crate::admin::handlers::config::update_main_config,
        crate::admin::handlers::config::get_config_schema,
        crate::admin::handlers::config::reload_config,
        crate::admin::handlers::config::set_log_level,
        crate::admin::handlers::config::get_log_level,
        crate::admin::handlers::config::export_config,
        crate::admin::handlers::config::import_config,
        crate::admin::handlers::config::check_regex,
        crate::admin::handlers::config::get_overseer_config,
        crate::admin::handlers::config::update_overseer_config,
        crate::admin::handlers::config::get_process_manager_config,
        crate::admin::handlers::config::update_process_manager_config,
        crate::admin::handlers::config::get_supervisor_config,
        crate::admin::handlers::config::update_supervisor_config,
        crate::admin::handlers::config::get_tls_config,
        crate::admin::handlers::config::update_tls_config,
        crate::admin::handlers::config::get_http_config,
        crate::admin::handlers::config::update_http_config,
        crate::admin::handlers::config::get_acme_config,
        crate::admin::handlers::config::update_acme_config,
        crate::admin::handlers::config::get_http3_config,
        crate::admin::handlers::config::update_http3_config,
        crate::admin::handlers::config::get_security_config,
        crate::admin::handlers::config::update_security_config,
        crate::admin::handlers::config::get_tunnel_config,
        crate::admin::handlers::config::update_tunnel_config,
        crate::admin::handlers::config::get_plugins_config,
        crate::admin::handlers::config::update_plugins_config,
        crate::admin::handlers::config::get_logging_config,
        crate::admin::handlers::config::update_logging_config,
        crate::admin::handlers::config::get_traffic_shaping_config,
        crate::admin::handlers::config::update_traffic_shaping_config,
        crate::admin::handlers::config::get_threat_level_config,
        crate::admin::handlers::config::update_threat_level_config,
        crate::admin::handlers::config::get_ip_feeds_config,
        crate::admin::handlers::config::update_ip_feeds_config,
        crate::admin::handlers::config::get_dns_config,
        crate::admin::handlers::config::update_dns_config,
        crate::admin::handlers::config::get_rate_limits_config,
        crate::admin::handlers::config::update_rate_limits_config,
        crate::admin::handlers::config::get_bot_detection_config,
        crate::admin::handlers::config::update_bot_detection_config,
        crate::admin::handlers::config::get_mesh_config,
        crate::admin::handlers::config::update_mesh_config,
        crate::admin::handlers::config::validate_config,
        crate::admin::handlers::probes::list_probes,
        crate::admin::handlers::probes::get_probe,
        crate::admin::handlers::probes::get_probe_stats,
        crate::admin::handlers::probes::delete_probe,
        crate::admin::handlers::probes::block_probes,
        crate::admin::handlers::probes::list_suspicious_words,
        crate::admin::handlers::probes::get_suspicious_word_stats,
        crate::admin::handlers::probes::delete_suspicious_word,
        crate::admin::handlers::probes::list_upstream_errors,
        crate::admin::handlers::probes::get_upstream_error_stats,
        crate::admin::handlers::probes::delete_upstream_error,
        crate::admin::handlers::yara_rules::get_status,
        crate::admin::handlers::yara_rules::list_submissions,
        crate::admin::handlers::yara_rules::get_submission,
        crate::admin::handlers::yara_rules::approve_submission,
        crate::admin::handlers::yara_rules::reject_submission,
        crate::admin::handlers::yara_rules::broadcast_rules,
        crate::admin::handlers::yara_rules::sync_from_global,
        crate::admin::handlers::yara_rules::submit_rules,
        crate::admin::handlers::yara_rules::apply_rules_direct,
        crate::admin::handlers::yara_rules::delete_submission,
        crate::admin::handlers::threat_level::get_status,
        crate::admin::handlers::threat_level::get_history,
        crate::admin::handlers::threat_level::get_baseline,
        crate::admin::handlers::threat_level::reset_baseline,
        crate::admin::handlers::threat_level::set_level,
        crate::admin::handlers::threat_level::set_auto,
        crate::admin::handlers::threat_level::create_backup,
        crate::admin::handlers::threat_level::list_backups,
        crate::admin::handlers::threat_level::delete_backup,
        crate::admin::handlers::threat_level::prune_history,
        crate::admin::handlers::threat_level::get_history_stats,
        crate::admin::handlers::tcp_udp::list_listeners,
        crate::admin::handlers::tcp_udp::create_listener,
        crate::admin::handlers::tcp_udp::delete_listener,
        crate::admin::handlers::tcp_udp::list_protocols,
        crate::admin::handlers::plugins::get_all_plugins_metrics,
        crate::admin::handlers::plugins::get_plugin_metrics,
        crate::admin::handlers::plugins::get_plugins_status,
        crate::admin::handlers::plugins::reload_plugin,
        crate::admin::handlers::plugins::get_mesh_wasm_modules,
        crate::admin::handlers::rule_feed::get_status,
        crate::admin::handlers::rule_feed::check_for_updates,
        crate::admin::handlers::rule_feed::apply_pending,
        crate::admin::handlers::rule_feed::discard_pending,
        crate::admin::handlers::icmp::get_status,
        crate::admin::handlers::icmp::get_config,
        crate::admin::handlers::icmp::update_config,
        crate::admin::handlers::icmp::enable,
        crate::admin::handlers::icmp::disable,
        crate::admin::handlers::icmp::list_backends,
        crate::admin::handlers::alerting::get_alert_config,
        crate::admin::handlers::alerting::update_alert_config,
        crate::admin::handlers::alerting::test_webhook,
        crate::admin::handlers::honeypot::get_honeypot_status,
        crate::admin::handlers::honeypot::control_honeypot,
    ),
    components(
        schemas(
            crate::admin::handlers::stats::SystemStats,
            crate::admin::handlers::stats::SiteStats,
            crate::admin::handlers::stats::MetricsHistoryParams,
            crate::admin::handlers::stats::AttackStats,
            crate::admin::handlers::stats::CacheStats,
            crate::admin::handlers::stats::RequestLogResponse,
            crate::admin::handlers::stats::RequestLogsResponse,
            crate::admin::handlers::stats::RequestLogsQuery,
            crate::admin::handlers::sites::SiteInfo,
            crate::admin::handlers::sites::SiteDetail,
            crate::admin::handlers::sites::CreateSiteRequest,
            crate::admin::handlers::sites::UpdateSiteRequest,
            crate::admin::handlers::sites::SiteThemeResponse,
            crate::admin::handlers::sites::UpdateSiteThemeRequest,
            crate::admin::handlers::serverless::ServerlessStatus,
            crate::admin::handlers::serverless::ServerlessHealth,
            crate::admin::handlers::serverless::FunctionStatsResponse,
            crate::admin::handlers::upstreams::UpstreamStatus,
            crate::admin::handlers::upstreams::SiteUpstreams,
            crate::admin::handlers::upstreams::HealthCheckResponse,
            crate::admin::handlers::upstreams::TriggerHealthCheckRequest,
            crate::admin::handlers::system::MasterStatusResponse,
            crate::admin::handlers::system::MasterMetricsResponse,
            crate::admin::handlers::system::SystemInfoResponse,
            crate::admin::handlers::system::WorkerStatusResponse,
            crate::admin::handlers::system::ScaleWorkersRequest,
            crate::admin::handlers::system::ScaleWorkersResponse,
            crate::admin::handlers::system::WorkerCountResponse,
            crate::admin::handlers::system::OverseerStatusResponse,
            crate::admin::handlers::logs::LogsResponse,
            crate::admin::handlers::logs::LogEntry,
            crate::admin::handlers::logs::ErrorPageResponse,
            crate::admin::handlers::logs::AuditLogsResponse,
            crate::admin::handlers::theme::ThemeResponse,
            crate::admin::handlers::theme::ThemeColorsResponse,
            crate::admin::handlers::theme::DarkColors,
            crate::admin::handlers::theme::LightColors,
            crate::admin::handlers::theme::ThemePresetInfo,
            crate::admin::handlers::theme::UpdateThemeRequest,
            crate::admin::handlers::mesh_admin::MeshNodeListResponse,
            crate::admin::handlers::mesh_admin::MeshNodeInfo,
            crate::admin::handlers::mesh_admin::BanListResponse,
            crate::admin::handlers::mesh_admin::BanRecord,
            crate::admin::handlers::mesh_admin::MeshAdminStatusResponse,
            crate::admin::handlers::mesh_admin::DeriveSigningKeyRequest,
            crate::admin::handlers::mesh_admin::DeriveSigningKeyResponse,
            crate::admin::handlers::mesh_admin::AuditReportRequest,
            crate::admin::handlers::mesh_admin::AuditReportResponseDto,
            crate::admin::handlers::mesh_admin::SignatureFailureReport,
            crate::admin::handlers::mesh_admin::SignatureFailureResponse,
            crate::admin::handlers::config::MainConfigResponse,
            crate::admin::handlers::config::UpdateMainConfigRequest,
            crate::admin::handlers::probes::BlockProbesRequest,
            crate::admin::handlers::probes::ProbeResponse,
            crate::admin::handlers::probes::ProbeEventResponse,
            crate::admin::handlers::probes::ProbeStatsResponse,
            crate::admin::handlers::probes::ProbeEndpointStatsResponse,
            crate::admin::handlers::probes::SuspiciousWordRecordResponse,
            crate::admin::handlers::probes::SuspiciousWordListResponse,
            crate::admin::handlers::probes::SuspiciousWordStatsResponse,
            crate::admin::handlers::probes::SuspiciousWordCountResponse,
            crate::admin::handlers::probes::UpstreamErrorRecordResponse,
            crate::admin::handlers::probes::UpstreamErrorListResponse,
            crate::admin::handlers::probes::UpstreamErrorStatsResponse,
            crate::admin::handlers::probes::UpstreamErrorEndpointCountResponse,
            crate::admin::handlers::yara_rules::YaraStatusResponse,
            crate::admin::handlers::yara_rules::YaraSubmissionResponse,
            crate::admin::handlers::yara_rules::YaraSubmissionsListResponse,
            crate::admin::handlers::yara_rules::YaraApprovalRequest,
            crate::admin::handlers::yara_rules::YaraRejectionRequest,
            crate::admin::handlers::yara_rules::YaraApproveResponse,
            crate::admin::handlers::yara_rules::YaraRejectResponse,
            crate::admin::handlers::yara_rules::YaraBroadcastResponse,
            crate::admin::handlers::yara_rules::YaraSyncResponse,
            crate::admin::handlers::yara_rules::YaraSubmitRequest,
            crate::admin::handlers::yara_rules::YaraSubmitResponse,
            crate::admin::handlers::yara_rules::YaraApplyRequest,
            crate::admin::handlers::yara_rules::YaraApplyResponse,
            crate::admin::handlers::yara_rules::YaraDeleteResponse,
            crate::admin::handlers::threat_level::ThreatLevelStatusResponse,
            crate::admin::handlers::threat_level::ThreatLevelHistoryResponse,
            crate::admin::handlers::threat_level::HistorySample,
            crate::admin::handlers::threat_level::BaselineStatsResponse,
            crate::admin::handlers::threat_level::BaselineMetric,
            crate::admin::handlers::threat_level::SetLevelRequest,
            crate::admin::handlers::threat_level::BackupResponse,
            crate::admin::handlers::threat_level::BackupsListResponse,
            crate::admin::handlers::threat_level::PruneResponse,
            crate::admin::handlers::tcp_udp::TcpUdpListener,
            crate::admin::handlers::tcp_udp::ListListenersResponse,
            crate::admin::handlers::tcp_udp::CreateListenerRequest,
            crate::admin::handlers::tcp_udp::CreateListenerResponse,
            crate::admin::handlers::tcp_udp::ProtocolInfo,
            crate::admin::handlers::plugins::PluginStatus,
            crate::admin::handlers::plugins::PluginStatusInfo,
            crate::admin::handlers::plugins::WasmModuleInfo,
            crate::admin::handlers::plugins::WasmModulesResponse,
            crate::admin::handlers::rule_feed::RuleFeedStatusResponse,
            crate::admin::handlers::rule_feed::RuleFeedCheckResponse,
            crate::admin::handlers::rule_feed::RuleFeedApplyResponse,
            crate::admin::handlers::icmp::IcmpStatusResponse,
            crate::admin::handlers::icmp::IcmpStats,
            crate::admin::handlers::icmp::IcmpConfigResponse,
            crate::admin::handlers::icmp::UpdateIcmpConfigRequest,
            crate::admin::handlers::icmp::IcmpEnableResponse,
            crate::admin::handlers::icmp::IcmpBackend,
            crate::admin::handlers::icmp::IcmpBackendsResponse,
            crate::admin::handlers::alerting::AlertConfigResponse,
            crate::admin::handlers::alerting::UpdateAlertConfigRequest,
            crate::admin::handlers::alerting::TestAlertResponse,
            crate::admin::handlers::honeypot::HoneypotStatusResponse,
            crate::admin::handlers::honeypot::HoneypotControlRequest,
            crate::admin::handlers::honeypot::HoneypotControlResponse,
        )
    ),
    tags(
        (name = "stats", description = "System statistics endpoints"),
        (name = "sites", description = "Site configuration management"),
        (name = "health", description = "Health check endpoints"),
        (name = "config", description = "Configuration management"),
        (name = "upstreams", description = "Upstream backend management"),
        (name = "logs", description = "Log retrieval"),
        (name = "system", description = "System and process management"),
        (name = "mesh", description = "Mesh network management"),
        (name = "plugins", description = "Plugin management"),
        (name = "serverless", description = "Serverless function management"),
        (name = "honeypot", description = "Honeypot management"),
        (name = "theme", description = "Theme customization"),
        (name = "security", description = "Security settings (TARPIT, threat level)"),
        (name = "icmp", description = "ICMP filtering"),
        (name = "probes", description = "Probe tracking and blocking"),
        (name = "yara", description = "YARA rules management"),
        (name = "threat_level", description = "Threat level management"),
        (name = "tcp_udp", description = "TCP/UDP listener management"),
        (name = "rule_feed", description = "Rule feed management"),
        (name = "alerting", description = "Alerting configuration")
    )
)]
pub struct MaluWafOpenApi;

pub async fn get_openapi_json() -> Json<openapi::OpenApi> {
    Json(MaluWafOpenApi::openapi())
}

impl MaluWafOpenApi {
    pub fn openapi_json() -> Json<openapi::OpenApi> {
        let openapi = Self::openapi();
        Json(openapi)
    }

    pub fn router(state: Arc<AdminState>) -> Router {
        Router::new()
            .route("/openapi.json", get(Self::get_openapi))
            .with_state(state)
    }

    async fn get_openapi() -> Json<openapi::OpenApi> {
        Self::openapi_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_required_fields() {
        let openapi = MaluWafOpenApi::openapi();

        assert_eq!(openapi.info.title, "MaluWAF Admin API");
        assert_eq!(openapi.info.version.as_str(), "1.0.0");
        assert!(openapi.info.description.is_some());
        assert!(openapi.info.contact.is_some());

        assert!(matches!(openapi.openapi, openapi::OpenApiVersion::Version3));
    }

    #[test]
    fn test_openapi_paths_exist() {
        let openapi = MaluWafOpenApi::openapi();

        assert!(!openapi.paths.paths.is_empty());

        let path_names: Vec<_> = openapi.paths.paths.keys().collect();
        assert!(
            path_names.iter().any(|p| p.contains("stats")),
            "Should have stats path. Found: {:?}",
            path_names
        );
        assert!(
            path_names.iter().any(|p| p.contains("site")),
            "Should have site path. Found: {:?}",
            path_names
        );
        assert!(
            path_names.iter().any(|p| p.contains("config")),
            "Should have config path. Found: {:?}",
            path_names
        );
    }

    #[test]
    fn test_openapi_paths_have_operations() {
        let openapi = MaluWafOpenApi::openapi();

        for path_key in openapi.paths.paths.keys() {
            let has_operation = openapi
                .paths
                .get_path_operation(path_key, openapi::path::PathItemType::Get)
                .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::PathItemType::Post)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::PathItemType::Put)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::PathItemType::Delete)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::PathItemType::Patch)
                    .is_some();
            assert!(
                has_operation,
                "Path {} should have at least one operation",
                path_key
            );
        }
    }

    #[test]
    fn test_openapi_components_schemas() {
        let openapi = MaluWafOpenApi::openapi();

        assert!(openapi.components.is_some());
        let components = openapi.components.unwrap();
        assert!(!components.schemas.is_empty());

        let schema_names: Vec<_> = components.schemas.keys().collect();
        assert!(schema_names.iter().any(|s| s.contains("SystemStats")));
        assert!(schema_names.iter().any(|s| s.contains("SiteInfo")));
        assert!(schema_names.iter().any(|s| s.contains("Config")));
    }

    #[test]
    fn test_openapi_tags_defined() {
        let openapi = MaluWafOpenApi::openapi();

        assert!(openapi.tags.is_some());
        let tags = openapi.tags.unwrap();
        assert!(!tags.is_empty());

        let tag_names: Vec<_> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(tag_names.contains(&"stats"));
        assert!(tag_names.contains(&"sites"));
        assert!(tag_names.contains(&"config"));
        assert!(tag_names.contains(&"mesh"));
    }

    #[test]
    fn test_openapi_paths_have_tags() {
        let openapi = MaluWafOpenApi::openapi();

        for path_key in openapi.paths.paths.keys() {
            if let Some(operation) = openapi
                .paths
                .get_path_operation(path_key, openapi::path::PathItemType::Get)
            {
                if let Some(tags) = &operation.tags {
                    assert!(!tags.is_empty(), "GET {} must have tags", path_key);
                }
            }
        }
    }
}
