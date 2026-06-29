use axum::Json;
use utoipa::openapi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[cfg(not(feature = "mesh"))]
pub mod mesh_stubs {
    use crate::admin::handlers::common::OptionalAuth;
    use crate::admin::handlers::common::PaginationQuery;
    use crate::admin::handlers::common::StatusResponse;
    use crate::admin::state::AdminState;
    use axum::extract::{Query, State};
    use axum::Json;
    use std::sync::Arc;
    use utoipa::ToSchema;

    #[derive(ToSchema)]
    pub struct MeshNodeListResponse {
        pub nodes: Vec<MeshNodeInfo>,
        pub total: usize,
        pub connected: usize,
    }

    #[derive(ToSchema)]
    pub struct MeshNodeInfo {
        pub node_id: String,
        pub address: String,
        pub role: String,
        pub status: String,
        pub last_seen: i64,
    }

    #[derive(ToSchema)]
    pub struct BanListResponse {
        pub bans: Vec<BanRecord>,
        pub total: usize,
    }

    #[derive(ToSchema)]
    pub struct BanRecord {
        pub ban_type: String,
        pub value: String,
        pub reason: Option<String>,
        pub expires: Option<i64>,
    }

    #[derive(ToSchema)]
    pub struct MeshAdminStatusResponse {
        pub status: String,
        pub connected_nodes: usize,
        pub total_nodes: usize,
    }

    #[derive(ToSchema)]
    pub struct AttestCapabilityRequest {
        pub node_id: String,
        pub capability: String,
    }

    #[derive(ToSchema)]
    pub struct DeriveSigningKeyRequest {
        pub node_id: String,
    }

    #[derive(ToSchema)]
    pub struct DeriveSigningKeyResponse {
        pub public_key: String,
    }

    #[derive(ToSchema)]
    pub struct AuditReportRequest {
        pub mesh_id: String,
    }

    #[derive(ToSchema)]
    pub struct AuditReportResponseDto {
        pub success: bool,
    }

    #[derive(ToSchema)]
    pub struct SignatureFailureReport {
        pub node_id: String,
    }

    #[derive(ToSchema)]
    pub struct SignatureFailureResponse {
        pub acknowledged: bool,
    }

    #[utoipa::path(
        get,
        path = "/mesh/nodes",
        responses(
            (status = 200, description = "List mesh nodes", body = MeshNodeListResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn list_mesh_nodes(
        State(_state): State<Arc<AdminState>>,
        Query(_query): Query<PaginationQuery>,
        _auth: OptionalAuth,
    ) -> Result<Json<MeshNodeListResponse>, axum::http::StatusCode> {
        Ok(Json(MeshNodeListResponse {
            nodes: vec![],
            total: 0,
            connected: 0,
        }))
    }

    #[utoipa::path(
        get,
        path = "/mesh/nodes/{node_id}",
        responses(
            (status = 200, description = "Get mesh node", body = MeshNodeInfo),
            (status = 401, description = "Unauthorized"),
            (status = 404, description = "Node not found"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn get_mesh_node(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<MeshNodeInfo>, axum::http::StatusCode> {
        Ok(Json(MeshNodeInfo {
            node_id: String::new(),
            address: String::new(),
            role: String::new(),
            status: String::new(),
            last_seen: 0,
        }))
    }

    #[utoipa::path(
        post,
        path = "/mesh/ban/ip",
        responses(
            (status = 200, description = "Ban IP", body = StatusResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn ban_ip(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<StatusResponse>, axum::http::StatusCode> {
        Ok(Json(StatusResponse::success("IP banned (mesh disabled)")))
    }

    #[utoipa::path(
        post,
        path = "/mesh/ban/mesh-id",
        responses(
            (status = 200, description = "Ban mesh ID", body = StatusResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn ban_mesh_id(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<StatusResponse>, axum::http::StatusCode> {
        Ok(Json(StatusResponse::success(
            "Mesh ID banned (mesh disabled)",
        )))
    }

    #[utoipa::path(
        delete,
        path = "/mesh/ban",
        responses(
            (status = 200, description = "Unban", body = StatusResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn unban(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<StatusResponse>, axum::http::StatusCode> {
        Ok(Json(StatusResponse::success("Unbanned (mesh disabled)")))
    }

    #[utoipa::path(
        get,
        path = "/mesh/bans",
        responses(
            (status = 200, description = "List bans", body = BanListResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn list_bans(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<BanListResponse>, axum::http::StatusCode> {
        Ok(Json(BanListResponse {
            bans: vec![],
            total: 0,
        }))
    }

    #[utoipa::path(
        get,
        path = "/mesh/status",
        responses(
            (status = 200, description = "Mesh status", body = MeshAdminStatusResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn get_mesh_status(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<MeshAdminStatusResponse>, axum::http::StatusCode> {
        Ok(Json(MeshAdminStatusResponse {
            status: "disabled".to_string(),
            connected_nodes: 0,
            total_nodes: 0,
        }))
    }

    #[utoipa::path(
        post,
        path = "/mesh/attest-capability",
        responses(
            (status = 200, description = "Attest capability"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn attest_capability(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({"status": "stub"})))
    }

    #[utoipa::path(
        post,
        path = "/mesh/derive-signing-key",
        responses(
            (status = 200, description = "Derive signing key", body = DeriveSigningKeyResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn derive_signing_key(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<DeriveSigningKeyResponse>, axum::http::StatusCode> {
        Ok(Json(DeriveSigningKeyResponse {
            public_key: String::new(),
        }))
    }

    #[utoipa::path(
        post,
        path = "/mesh/audit/report",
        responses(
            (status = 200, description = "Submit audit report", body = AuditReportResponseDto),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn submit_audit_report(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<AuditReportResponseDto>, axum::http::StatusCode> {
        Ok(Json(AuditReportResponseDto { success: false }))
    }

    #[utoipa::path(
        post,
        path = "/mesh/report/signature-failure",
        responses(
            (status = 200, description = "Report signature failure", body = SignatureFailureResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn report_signature_failure(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<SignatureFailureResponse>, axum::http::StatusCode> {
        Ok(Json(SignatureFailureResponse {
            acknowledged: false,
        }))
    }

    #[utoipa::path(
        post,
        path = "/mesh/organizations",
        responses(
            (status = 200, description = "Create organization", body = StatusResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn create_organization(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<StatusResponse>, axum::http::StatusCode> {
        Ok(Json(StatusResponse::success(
            "Organization created (mesh disabled)",
        )))
    }

    #[utoipa::path(
        get,
        path = "/mesh/organizations/{org_id}",
        responses(
            (status = 200, description = "Get organization", body = serde_json::Value),
            (status = 401, description = "Unauthorized"),
            (status = 404, description = "Not found"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn get_organization(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::Value::Null))
    }

    #[utoipa::path(
        get,
        path = "/mesh/organizations/{org_id}/public-key",
        responses(
            (status = 200, description = "Get org public key", body = serde_json::Value),
            (status = 401, description = "Unauthorized"),
            (status = 404, description = "Not found"),
            (status = 500, description = "Internal server error")
        ),
        tag = "mesh"
    )]
    pub async fn get_org_public_key(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::Value::Null))
    }

    #[derive(ToSchema)]
    pub struct YaraStatusResponse {
        pub status: String,
        pub rules_loaded: usize,
    }

    #[derive(ToSchema)]
    pub struct YaraSubmissionResponse {
        pub submission_id: String,
        pub status: String,
    }

    #[derive(ToSchema)]
    pub struct YaraSubmissionsListResponse {
        pub submissions: Vec<YaraSubmissionResponse>,
        pub total: usize,
    }

    #[derive(ToSchema)]
    pub struct YaraApprovalRequest {
        pub submission_id: String,
    }

    #[derive(ToSchema)]
    pub struct YaraRejectionRequest {
        pub submission_id: String,
        pub reason: String,
    }

    #[derive(ToSchema)]
    pub struct YaraSubmitRequest {
        pub rules: String,
    }

    #[derive(ToSchema)]
    pub struct YaraApplyRequest {
        pub submission_id: String,
    }

    #[utoipa::path(
        get,
        path = "/yara/status",
        responses(
            (status = 200, description = "YARA status", body = YaraStatusResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn yara_get_status(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<YaraStatusResponse>, axum::http::StatusCode> {
        Ok(Json(YaraStatusResponse {
            status: "disabled".to_string(),
            rules_loaded: 0,
        }))
    }

    #[utoipa::path(
        get,
        path = "/yara/submissions",
        responses(
            (status = 200, description = "List YARA submissions", body = YaraSubmissionsListResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn list_submissions(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<YaraSubmissionsListResponse>, axum::http::StatusCode> {
        Ok(Json(YaraSubmissionsListResponse {
            submissions: vec![],
            total: 0,
        }))
    }

    #[utoipa::path(
        get,
        path = "/yara/submissions/{submission_id}",
        responses(
            (status = 200, description = "Get YARA submission", body = YaraSubmissionResponse),
            (status = 401, description = "Unauthorized"),
            (status = 404, description = "Not found"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn get_submission(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<YaraSubmissionResponse>, axum::http::StatusCode> {
        Ok(Json(YaraSubmissionResponse {
            submission_id: String::new(),
            status: String::new(),
        }))
    }

    #[utoipa::path(
        post,
        path = "/yara/submissions/{submission_id}/approve",
        responses(
            (status = 200, description = "Approve YARA submission"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn approve_submission(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({
            "status": "applied",
            "target": "",
            "local_store_mutated": false,
            "propagation": "not_applicable",
            "message": ""
        })))
    }

    #[utoipa::path(
        post,
        path = "/yara/submissions/{submission_id}/reject",
        responses(
            (status = 200, description = "Reject YARA submission"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn reject_submission(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({
            "status": "applied",
            "target": "",
            "local_store_mutated": false,
            "propagation": "not_applicable",
            "message": ""
        })))
    }

    #[utoipa::path(
        post,
        path = "/yara/broadcast",
        responses(
            (status = 200, description = "Broadcast YARA rules"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn broadcast_rules(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({
            "status": "applied",
            "target": "",
            "local_store_mutated": false,
            "propagation": "queued_best_effort",
            "message": ""
        })))
    }

    #[utoipa::path(
        post,
        path = "/yara/sync",
        responses(
            (status = 200, description = "Sync YARA rules"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn sync_from_global(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({
            "status": "applied",
            "target": "",
            "local_store_mutated": false,
            "propagation": "queued_best_effort",
            "message": ""
        })))
    }

    #[utoipa::path(
        post,
        path = "/yara/submit",
        responses(
            (status = 200, description = "Submit YARA rules"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn submit_rules(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({
            "status": "applied",
            "target": "",
            "local_store_mutated": false,
            "propagation": "not_applicable",
            "message": ""
        })))
    }

    #[utoipa::path(
        post,
        path = "/yara/apply",
        responses(
            (status = 200, description = "Apply YARA rules"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn apply_rules_direct(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({
            "status": "applied",
            "target": "",
            "local_store_mutated": false,
            "propagation": "not_applicable",
            "message": ""
        })))
    }

    #[utoipa::path(
        delete,
        path = "/yara/submissions/{submission_id}",
        responses(
            (status = 200, description = "Delete YARA submission"),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "yara"
    )]
    pub async fn delete_submission(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        Ok(Json(serde_json::json!({
            "status": "applied",
            "target": "",
            "local_store_mutated": false,
            "propagation": "not_applicable",
            "message": ""
        })))
    }
}

pub mod dns_stubs {
    use crate::admin::handlers::common::OptionalAuth;
    use crate::admin::handlers::common::StatusResponse;
    use crate::admin::state::AdminState;
    use axum::extract::State;
    use axum::Json;
    use std::sync::Arc;
    use utoipa::ToSchema;

    #[derive(ToSchema)]
    pub struct DnsConfigResponse {
        pub config: serde_json::Value,
    }

    #[derive(ToSchema)]
    pub struct UpdateDnsConfigRequest {
        pub config: serde_json::Value,
    }

    #[utoipa::path(
        get,
        path = "/config/dns",
        responses(
            (status = 200, description = "DNS configuration", body = DnsConfigResponse),
            (status = 401, description = "Unauthorized"),
            (status = 500, description = "Internal server error")
        ),
        tag = "config"
    )]
    pub async fn get_dns_config(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
    ) -> Result<Json<DnsConfigResponse>, axum::http::StatusCode> {
        Ok(Json(DnsConfigResponse {
            config: serde_json::Value::Null,
        }))
    }

    #[utoipa::path(
        put,
        path = "/config/dns",
        request_body = UpdateDnsConfigRequest,
        responses(
            (status = 200, description = "DNS config updated", body = StatusResponse),
            (status = 401, description = "Unauthorized"),
            (status = 400, description = "Invalid configuration"),
            (status = 500, description = "Internal server error")
        ),
        tag = "config"
    )]
    pub async fn update_dns_config(
        State(_state): State<Arc<AdminState>>,
        _auth: OptionalAuth,
        Json(_body): Json<UpdateDnsConfigRequest>,
    ) -> Result<Json<StatusResponse>, axum::http::StatusCode> {
        Ok(Json(StatusResponse::success(
            "DNS config not available in core profile.",
        )))
    }
}

struct AddBearerAuth;

impl Modify for AddBearerAuth {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("Token")
                        .description(Some("Bearer authentication using API token. Include token in Authorization header: Bearer <token>".to_string()))
                        .build(),
                ),
            );
        }
        openapi.security = Some(vec![openapi::security::SecurityRequirement::new(
            "bearer_auth",
            std::iter::empty::<&str>(),
        )]);
    }
}

#[cfg(not(feature = "mesh"))]
mod core_openapi {
    use super::AddBearerAuth;
    use crate::admin::openapi::dns_stubs;
    use crate::admin::openapi::mesh_stubs;
    use utoipa::OpenApi;

    #[derive(OpenApi)]
    #[openapi(
            info(
                title = "SynVoid Admin API",
                version = "1.0.0",
                description = "REST API for managing SynVoid - Multi-Process Web Application Firewall",
                contact(
                    name = "SynVoid Support",
                    url = "https://github.com/anomalyco/synvoid"
                )
            ),
            servers(
                (url = "http://localhost:8080", description = "Local development server"),
                (url = "https://localhost:8080", description = "Production server")
            ),
            modifiers(&AddBearerAuth),
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
            crate::admin::handlers::system::get_supervisor_status,
            crate::admin::handlers::system::get_system_info,
            crate::admin::handlers::system::get_workers,
            crate::admin::handlers::system::restart_worker,
            crate::admin::handlers::system::get_worker_count,
            crate::admin::handlers::system::scale_workers,
            crate::admin::handlers::system::get_supervisor,
            crate::admin::handlers::php::list_php_pools,
            crate::admin::handlers::php::reload_php_pool,
            crate::admin::handlers::logs::get_logs,
            crate::admin::handlers::logs::list_error_pages,
            crate::admin::handlers::logs::get_error_page,
            crate::admin::handlers::logs::update_error_page,
            crate::admin::handlers::logs::get_audit_logs,
            crate::admin::handlers::theme::get_theme,
            crate::admin::handlers::theme::update_theme,
            crate::admin::handlers::theme::get_theme_css,
            crate::admin::handlers::theme::get_theme_presets,
            mesh_stubs::list_mesh_nodes,
            mesh_stubs::get_mesh_node,
            mesh_stubs::ban_ip,
            mesh_stubs::ban_mesh_id,
            mesh_stubs::unban,
            mesh_stubs::list_bans,
            mesh_stubs::get_mesh_status,
            mesh_stubs::attest_capability,
            mesh_stubs::derive_signing_key,
            mesh_stubs::submit_audit_report,
            mesh_stubs::report_signature_failure,
            mesh_stubs::create_organization,
            mesh_stubs::get_organization,
            mesh_stubs::get_org_public_key,
            crate::admin::handlers::config::get_main_config,
            crate::admin::handlers::config::update_main_config,
            crate::admin::handlers::config::get_config_schema,
            crate::admin::handlers::config::reload_config,
            crate::admin::handlers::config::set_log_level,
            crate::admin::handlers::config::get_log_level,
            crate::admin::handlers::config::export_config,
            crate::admin::handlers::config::import_config,
            crate::admin::handlers::config::check_regex,
            crate::admin::handlers::config::get_supervisor_config,
            crate::admin::handlers::config::update_supervisor_config,
            crate::admin::handlers::config::get_process_manager_config,
            crate::admin::handlers::config::update_process_manager_config,
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
            crate::admin::handlers::config::get_metrics_config,
            crate::admin::handlers::config::update_metrics_config,
            crate::admin::handlers::config::get_tokio_config,
            crate::admin::handlers::config::update_tokio_config,
            crate::admin::handlers::config::get_traffic_shaping_config,
            crate::admin::handlers::config::update_traffic_shaping_config,
            crate::admin::handlers::config::get_threat_level_config,
            crate::admin::handlers::config::update_threat_level_config,
            crate::admin::handlers::config::get_ip_feeds_config,
            crate::admin::handlers::config::update_ip_feeds_config,
            crate::admin::handlers::config::get_mime_types_config,
            crate::admin::handlers::config::update_mime_types_config,
            crate::admin::handlers::config::get_tcp_udp_defaults_config,
            crate::admin::handlers::config::update_tcp_udp_defaults_config,
            crate::admin::handlers::config::get_fallback_config,
            crate::admin::handlers::config::update_fallback_config,
            crate::admin::handlers::config::get_upgrade_config,
            crate::admin::handlers::config::update_upgrade_config,
            #[cfg(not(feature = "dns"))]
            dns_stubs::get_dns_config,
            #[cfg(not(feature = "dns"))]
            dns_stubs::update_dns_config,
            crate::admin::handlers::config::get_rate_limits_config,
            crate::admin::handlers::config::update_rate_limits_config,
            crate::admin::handlers::config::get_bot_detection_config,
            crate::admin::handlers::config::update_bot_detection_config,
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
            mesh_stubs::yara_get_status,
            mesh_stubs::list_submissions,
            mesh_stubs::get_submission,
            mesh_stubs::approve_submission,
            mesh_stubs::reject_submission,
            mesh_stubs::broadcast_rules,
            mesh_stubs::sync_from_global,
            mesh_stubs::submit_rules,
            mesh_stubs::apply_rules_direct,
            mesh_stubs::delete_submission,
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
                crate::admin::handlers::system::SupervisorStatusResponse,
                crate::admin::handlers::system::SupervisorMetricsResponse,
                crate::admin::handlers::system::SystemInfoResponse,
                crate::admin::handlers::system::WorkerStatusResponse,
                crate::admin::handlers::system::ScaleWorkersRequest,
                crate::admin::handlers::system::ScaleWorkersResponse,
                crate::admin::handlers::system::WorkerCountResponse,
                crate::admin::handlers::system::SupervisorProcessStatusResponse,
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
                mesh_stubs::MeshNodeListResponse,
                mesh_stubs::MeshNodeInfo,
                mesh_stubs::BanListResponse,
                mesh_stubs::BanRecord,
                mesh_stubs::MeshAdminStatusResponse,
                mesh_stubs::AttestCapabilityRequest,
                mesh_stubs::DeriveSigningKeyRequest,
                mesh_stubs::DeriveSigningKeyResponse,
                mesh_stubs::AuditReportRequest,
                mesh_stubs::AuditReportResponseDto,
                mesh_stubs::SignatureFailureReport,
                mesh_stubs::SignatureFailureResponse,
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
                mesh_stubs::YaraStatusResponse,
                mesh_stubs::YaraSubmissionResponse,
                mesh_stubs::YaraSubmissionsListResponse,
                mesh_stubs::YaraApprovalRequest,
                mesh_stubs::YaraRejectionRequest,
                mesh_stubs::YaraSubmitRequest,
                mesh_stubs::YaraApplyRequest,
                crate::admin::handlers::threat_level::ThreatLevelStatusResponse,
                crate::admin::handlers::threat_level::ThreatLevelHistoryResponse,
                crate::admin::handlers::threat_level::HistorySample,
                crate::admin::handlers::threat_level::BaselineStatsResponse,
                crate::admin::handlers::threat_level::BaselineMetric,
                crate::admin::handlers::threat_level::SetLevelRequest,
                crate::admin::handlers::threat_level::BackupsListResponse,
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
                crate::admin::handlers::icmp::IcmpBackend,
                crate::admin::handlers::icmp::IcmpBackendsResponse,
                crate::admin::handlers::alerting::AlertConfigResponse,
                crate::admin::handlers::alerting::UpdateAlertConfigRequest,

                crate::admin::handlers::honeypot::HoneypotStatusResponse,
                crate::admin::handlers::honeypot::HoneypotControlRequest,
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
    pub struct CoreOpenApi;
}

#[cfg(feature = "mesh")]
mod mesh_openapi {
    use super::AddBearerAuth;
    use crate::admin::handlers::mesh_admin;
    use crate::admin::handlers::plugins;
    use crate::admin::handlers::yara_rules;
    use utoipa::OpenApi;

    #[derive(OpenApi)]
    #[openapi(
            info(
                title = "SynVoid Admin API",
                version = "1.0.0",
                description = "REST API for managing SynVoid - Multi-Process Web Application Firewall",
                contact(
                    name = "SynVoid Support",
                    url = "https://github.com/anomalyco/synvoid"
                )
            ),
            servers(
                (url = "http://localhost:8080", description = "Local development server"),
                (url = "https://localhost:8080", description = "Production server")
            ),
            modifiers(&AddBearerAuth),
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
            crate::admin::handlers::system::get_supervisor_status,
            crate::admin::handlers::system::get_system_info,
            crate::admin::handlers::system::get_workers,
            crate::admin::handlers::system::restart_worker,
            crate::admin::handlers::system::get_worker_count,
            crate::admin::handlers::system::scale_workers,
            crate::admin::handlers::system::get_supervisor,
            crate::admin::handlers::php::list_php_pools,
            crate::admin::handlers::php::reload_php_pool,
            crate::admin::handlers::logs::get_logs,
            crate::admin::handlers::logs::list_error_pages,
            crate::admin::handlers::logs::get_error_page,
            crate::admin::handlers::logs::update_error_page,
            crate::admin::handlers::logs::get_audit_logs,
            crate::admin::handlers::theme::get_theme,
            crate::admin::handlers::theme::update_theme,
            crate::admin::handlers::theme::get_theme_css,
            crate::admin::handlers::theme::get_theme_presets,
            mesh_admin::list_mesh_nodes,
            mesh_admin::get_mesh_node,
            mesh_admin::ban_ip,
            mesh_admin::ban_mesh_id,
            mesh_admin::unban,
            mesh_admin::list_bans,
            mesh_admin::get_mesh_status,
            mesh_admin::attest_capability,
            mesh_admin::derive_signing_key,
            mesh_admin::submit_audit_report,
            mesh_admin::report_signature_failure,
            mesh_admin::create_organization,
            mesh_admin::get_organization,
            mesh_admin::get_org_public_key,
            crate::admin::handlers::config::get_main_config,
            crate::admin::handlers::config::update_main_config,
            crate::admin::handlers::config::get_config_schema,
            crate::admin::handlers::config::reload_config,
            crate::admin::handlers::config::set_log_level,
            crate::admin::handlers::config::get_log_level,
            crate::admin::handlers::config::export_config,
            crate::admin::handlers::config::import_config,
            crate::admin::handlers::config::check_regex,
            crate::admin::handlers::config::get_supervisor_config,
            crate::admin::handlers::config::update_supervisor_config,
            crate::admin::handlers::config::get_process_manager_config,
            crate::admin::handlers::config::update_process_manager_config,
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
            crate::admin::handlers::config::get_metrics_config,
            crate::admin::handlers::config::update_metrics_config,
            crate::admin::handlers::config::get_tokio_config,
            crate::admin::handlers::config::update_tokio_config,
            crate::admin::handlers::config::get_traffic_shaping_config,
            crate::admin::handlers::config::update_traffic_shaping_config,
            crate::admin::handlers::config::get_threat_level_config,
            crate::admin::handlers::config::update_threat_level_config,
            crate::admin::handlers::config::get_ip_feeds_config,
            crate::admin::handlers::config::update_ip_feeds_config,
            crate::admin::handlers::config::get_mime_types_config,
            crate::admin::handlers::config::update_mime_types_config,
            crate::admin::handlers::config::get_tcp_udp_defaults_config,
            crate::admin::handlers::config::update_tcp_udp_defaults_config,
            crate::admin::handlers::config::get_fallback_config,
            crate::admin::handlers::config::update_fallback_config,
            crate::admin::handlers::config::get_upgrade_config,
            crate::admin::handlers::config::update_upgrade_config,
            #[cfg(feature = "dns")]
            crate::admin::openapi::dns_stubs::get_dns_config,
            crate::admin::openapi::dns_stubs::update_dns_config,
            #[cfg(feature = "dns")]
            crate::admin::handlers::config::get_rate_limits_config,
            crate::admin::handlers::config::update_rate_limits_config,
            crate::admin::handlers::config::get_bot_detection_config,
            crate::admin::handlers::config::update_bot_detection_config,
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
            yara_rules::get_status,
            yara_rules::list_submissions,
            yara_rules::get_submission,
            yara_rules::approve_submission,
            yara_rules::reject_submission,
            yara_rules::broadcast_rules,
            yara_rules::sync_from_global,
            yara_rules::submit_rules,
            yara_rules::apply_rules_direct,
            yara_rules::delete_submission,
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
            plugins::get_mesh_wasm_modules,
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
                crate::admin::handlers::system::SupervisorStatusResponse,
                crate::admin::handlers::system::SupervisorMetricsResponse,
                crate::admin::handlers::system::SystemInfoResponse,
                crate::admin::handlers::system::WorkerStatusResponse,
                crate::admin::handlers::system::ScaleWorkersRequest,
                crate::admin::handlers::system::ScaleWorkersResponse,
                crate::admin::handlers::system::WorkerCountResponse,
                crate::admin::handlers::system::SupervisorProcessStatusResponse,
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
                mesh_admin::MeshNodeListResponse,
                mesh_admin::MeshNodeInfo,
                mesh_admin::BanListResponse,
                mesh_admin::BanRecord,
                mesh_admin::MeshAdminStatusResponse,
                mesh_admin::AttestCapabilityRequest,
                mesh_admin::DeriveSigningKeyRequest,
                mesh_admin::DeriveSigningKeyResponse,
                mesh_admin::AuditReportRequest,
                mesh_admin::AuditReportResponseDto,
                mesh_admin::SignatureFailureReport,
                mesh_admin::SignatureFailureResponse,
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
                yara_rules::YaraStatusResponse,
                yara_rules::YaraSubmissionResponse,
                yara_rules::YaraSubmissionsListResponse,
                yara_rules::YaraApprovalRequest,
                yara_rules::YaraRejectionRequest,
                yara_rules::YaraSubmitRequest,
                yara_rules::YaraApplyRequest,
                crate::admin::handlers::threat_level::ThreatLevelStatusResponse,
                crate::admin::handlers::threat_level::ThreatLevelHistoryResponse,
                crate::admin::handlers::threat_level::HistorySample,
                crate::admin::handlers::threat_level::BaselineStatsResponse,
                crate::admin::handlers::threat_level::BaselineMetric,
                crate::admin::handlers::threat_level::SetLevelRequest,
                crate::admin::handlers::threat_level::BackupsListResponse,
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
                crate::admin::handlers::icmp::IcmpBackend,
                crate::admin::handlers::icmp::IcmpBackendsResponse,
                crate::admin::handlers::alerting::AlertConfigResponse,
                crate::admin::handlers::alerting::UpdateAlertConfigRequest,

                crate::admin::handlers::honeypot::HoneypotStatusResponse,
                crate::admin::handlers::honeypot::HoneypotControlRequest,
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
    pub struct MeshOpenApi;
}

#[cfg(not(feature = "mesh"))]
pub use core_openapi::CoreOpenApi as synvoidOpenApi;

#[cfg(feature = "mesh")]
pub use mesh_openapi::MeshOpenApi as synvoidOpenApi;

impl synvoidOpenApi {
    pub fn openapi_json() -> Json<openapi::OpenApi> {
        Json(Self::openapi())
    }
}

pub async fn get_openapi_json() -> Json<openapi::OpenApi> {
    Json(synvoidOpenApi::openapi())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_required_fields() {
        let openapi = synvoidOpenApi::openapi();

        assert_eq!(openapi.info.title, "SynVoid Admin API");
        assert_eq!(openapi.info.version.as_str(), "1.0.0");
        assert!(openapi.info.description.is_some());
        assert!(openapi.info.contact.is_some());

        assert!(matches!(
            openapi.openapi,
            openapi::OpenApiVersion::Version31
        ));
    }

    #[test]
    fn test_openapi_paths_exist() {
        let openapi = synvoidOpenApi::openapi();

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
        let openapi = synvoidOpenApi::openapi();

        for path_key in openapi.paths.paths.keys() {
            let has_operation = openapi
                .paths
                .get_path_operation(path_key, openapi::path::HttpMethod::Get)
                .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::HttpMethod::Post)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::HttpMethod::Put)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::HttpMethod::Delete)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::HttpMethod::Patch)
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
        let openapi = synvoidOpenApi::openapi();

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
        let openapi = synvoidOpenApi::openapi();

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
        let openapi = synvoidOpenApi::openapi();

        for path_key in openapi.paths.paths.keys() {
            if let Some(operation) = openapi
                .paths
                .get_path_operation(path_key, openapi::path::HttpMethod::Get)
            {
                if let Some(tags) = &operation.tags {
                    assert!(!tags.is_empty(), "GET {} must have tags", path_key);
                }
            }
        }
    }

    #[test]
    fn test_openapi_servers_defined() {
        let openapi = synvoidOpenApi::openapi();

        assert!(
            openapi.servers.is_some(),
            "OpenAPI should have servers defined"
        );
        let servers = openapi.servers.unwrap();
        assert!(!servers.is_empty(), "At least one server should be defined");

        let server_urls: Vec<_> = servers.iter().map(|s| s.url.as_str()).collect();
        assert!(
            server_urls.iter().any(|u| u.contains("localhost")),
            "Should have localhost server"
        );
        assert!(
            server_urls.iter().any(|u| u.contains("https")),
            "Should have HTTPS server"
        );
    }

    #[test]
    fn test_openapi_paths_accessible() {
        let openapi = synvoidOpenApi::openapi();

        for path_key in openapi.paths.paths.keys() {
            let operation_exists = openapi
                .paths
                .get_path_operation(path_key, openapi::path::HttpMethod::Get)
                .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::HttpMethod::Post)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::HttpMethod::Put)
                    .is_some()
                || openapi
                    .paths
                    .get_path_operation(path_key, openapi::path::HttpMethod::Delete)
                    .is_some();

            assert!(
                operation_exists,
                "Path {} should have at least one operation",
                path_key
            );
        }
    }

    #[test]
    fn test_openapi_tags_have_descriptions() {
        let openapi = synvoidOpenApi::openapi();

        assert!(openapi.tags.is_some(), "Tags should be defined");
        let tags = openapi.tags.unwrap();

        for tag in tags {
            assert!(
                tag.description.is_some() && !tag.description.as_ref().unwrap().is_empty(),
                "Tag {} should have a description",
                tag.name
            );
        }
    }

    #[test]
    fn test_openapi_path_count_reasonable() {
        let openapi = synvoidOpenApi::openapi();

        let path_count = openapi.paths.paths.len();
        assert!(
            path_count >= 50,
            "Should have at least 50 API paths defined, found {}",
            path_count
        );
    }

    #[test]
    fn test_cache_stats_schema_exposes_cpu_offload_fields() {
        let openapi_json = serde_json::to_value(synvoidOpenApi::openapi()).expect("openapi json");
        let properties = &openapi_json["components"]["schemas"]["CacheStats"]["properties"];

        assert!(
            properties.get("cpu_offload_pool_in_flight").is_some(),
            "CacheStats schema should include cpu_offload_pool_in_flight"
        );
        assert!(
            properties.get("cpu_offload_pool_connections").is_some(),
            "CacheStats schema should include cpu_offload_pool_connections"
        );
        assert!(
            properties.get("cpu_offload_pool_evictions").is_some(),
            "CacheStats schema should include cpu_offload_pool_evictions"
        );
        assert!(
            properties.get("cpu_offload_pool_submissions").is_some(),
            "CacheStats schema should include cpu_offload_pool_submissions"
        );
        assert!(
            properties.get("cpu_offload_timeouts").is_some(),
            "CacheStats schema should include cpu_offload_timeouts"
        );
        assert!(
            properties.get("cpu_offload_rejections").is_some(),
            "CacheStats schema should include cpu_offload_rejections"
        );
        assert!(
            properties.get("cpu_offload_queued_minify").is_some(),
            "CacheStats schema should include cpu_offload_queued_minify"
        );
        assert!(
            properties
                .get("cpu_offload_queued_get_compressed")
                .is_some(),
            "CacheStats schema should include cpu_offload_queued_get_compressed"
        );
        assert!(
            properties.get("cpu_offload_queued_poison_image").is_some(),
            "CacheStats schema should include cpu_offload_queued_poison_image"
        );
        assert!(
            properties.get("cpu_offload_queued_yara_scan").is_some(),
            "CacheStats schema should include cpu_offload_queued_yara_scan"
        );
        assert!(
            properties.get("cpu_offload_active_minify").is_some(),
            "CacheStats schema should include cpu_offload_active_minify"
        );
        assert!(
            properties
                .get("cpu_offload_active_get_compressed")
                .is_some(),
            "CacheStats schema should include cpu_offload_active_get_compressed"
        );
        assert!(
            properties.get("cpu_offload_active_poison_image").is_some(),
            "CacheStats schema should include cpu_offload_active_poison_image"
        );
        assert!(
            properties.get("cpu_offload_active_yara_scan").is_some(),
            "CacheStats schema should include cpu_offload_active_yara_scan"
        );
        assert!(
            properties.get("cpu_offload_completed_minify").is_some(),
            "CacheStats schema should include cpu_offload_completed_minify"
        );
        assert!(
            properties
                .get("cpu_offload_completed_get_compressed")
                .is_some(),
            "CacheStats schema should include cpu_offload_completed_get_compressed"
        );
        assert!(
            properties
                .get("cpu_offload_completed_poison_image")
                .is_some(),
            "CacheStats schema should include cpu_offload_completed_poison_image"
        );
        assert!(
            properties.get("cpu_offload_completed_yara_scan").is_some(),
            "CacheStats schema should include cpu_offload_completed_yara_scan"
        );
        assert!(
            properties
                .get("cpu_offload_payload_bytes_in_total")
                .is_some(),
            "CacheStats schema should include cpu_offload_payload_bytes_in_total"
        );
        assert!(
            properties
                .get("cpu_offload_payload_bytes_out_total")
                .is_some(),
            "CacheStats schema should include cpu_offload_payload_bytes_out_total"
        );
        assert!(
            properties.get("cpu_offload_task_submitted_total").is_some(),
            "CacheStats schema should include cpu_offload_task_submitted_total"
        );
        assert!(
            properties
                .get("cpu_offload_task_fallback_inline_small_total")
                .is_some(),
            "CacheStats schema should include cpu_offload_task_fallback_inline_small_total"
        );
        assert!(
            properties.get("cpu_offload_task_timeout_total").is_some(),
            "CacheStats schema should include cpu_offload_task_timeout_total"
        );
        assert!(
            properties.get("cpu_offload_task_rejected_total").is_some(),
            "CacheStats schema should include cpu_offload_task_rejected_total"
        );
        assert!(
            properties.get("cpu_offload_task_duration_ms").is_some(),
            "CacheStats schema should include cpu_offload_task_duration_ms"
        );
        assert!(
            properties.get("cpu_offload_failed_total").is_some(),
            "CacheStats schema should include cpu_offload_failed_total"
        );
        assert!(
            properties.get("cpu_offload_worker_rss_bytes").is_some(),
            "CacheStats schema should include cpu_offload_worker_rss_bytes"
        );
    }
}
