use axum::{routing::get, Json, Router};
use utoipa::openapi;
use utoipa::OpenApi;
use std::sync::Arc;

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
        crate::admin::handlers::sites::list_sites,
        crate::admin::handlers::sites::get_site,
        crate::admin::handlers::serverless::list_functions,
        crate::admin::handlers::serverless::get_serverless_health,
        crate::admin::handlers::serverless::get_function_stats,
        crate::admin::handlers::upstreams::list_upstreams,
        crate::admin::handlers::upstreams::get_site_upstreams,
        crate::admin::handlers::system::get_master_status,
        crate::admin::handlers::system::get_system_info,
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
    ),
    components(
        schemas(
            crate::admin::handlers::stats::SystemStats,
            crate::admin::handlers::stats::SiteStats,
            crate::admin::handlers::sites::SiteInfo,
            crate::admin::handlers::sites::SiteDetail,
            crate::admin::handlers::serverless::ServerlessStatus,
            crate::admin::handlers::serverless::ServerlessHealth,
            crate::admin::handlers::serverless::FunctionStatsResponse,
            crate::admin::handlers::upstreams::UpstreamStatus,
            crate::admin::handlers::upstreams::SiteUpstreams,
            crate::admin::handlers::system::MasterStatusResponse,
            crate::admin::handlers::system::MasterMetricsResponse,
            crate::admin::handlers::system::SystemInfoResponse,
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
        (name = "icmp", description = "ICMP filtering")
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
    fn test_openapi_generation() {
        let openapi = MaluWafOpenApi::openapi();
        assert_eq!(openapi.info.title, "MaluWAF Admin API");
        assert_eq!(openapi.info.version.as_str(), "1.0.0");
    }
}
