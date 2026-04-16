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
        )
    ),
    tags(
        (name = "stats", description = "System statistics endpoints"),
        (name = "sites", description = "Site configuration management"),
        (name = "health", description = "Health check endpoints"),
        (name = "config", description = "Configuration management"),
        (name = "upstreams", description = "Upstream backend management"),
        (name = "logs", description = "Log retrieval"),
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
