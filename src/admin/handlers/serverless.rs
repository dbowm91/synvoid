use super::common::OptionalAuth;
use crate::serverless::registry::get_global_serverless_registry;
use axum::{extract::Path, http::StatusCode, Json};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Clone, Serialize, ToSchema)]
pub struct ServerlessStatus {
    pub functions: Vec<serde_json::Value>,
    pub total_functions: usize,
}

#[derive(Clone, Serialize, ToSchema)]
pub struct FunctionStatsResponse {
    pub name: String,
    pub stats: Option<serde_json::Value>,
}

#[derive(Clone, Serialize, ToSchema)]
pub struct ServerlessHealth {
    pub enabled: bool,
    pub total_functions: usize,
    pub total_invocations: u64,
    pub total_errors: u64,
    pub healthy_functions: usize,
    pub unhealthy_functions: usize,
}

#[utoipa::path(
    get,
    path = "/serverless/health",
    responses(
        (status = 200, description = "Serverless functions health status", body = ServerlessHealth),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "serverless"
)]
pub async fn get_serverless_health(
    _auth: OptionalAuth,
) -> Result<Json<ServerlessHealth>, StatusCode> {
    let registry = get_global_serverless_registry();
    let functions = registry.list();

    let total_invocations: u64 = functions.iter().map(|f| f.invocation_count).sum();
    let total_errors: u64 = functions.iter().map(|f| f.error_count).sum();

    let healthy = functions
        .iter()
        .filter(|f| f.invocation_count > 0 || f.error_count == 0)
        .count();
    let unhealthy = functions.len() - healthy;

    Ok(Json(ServerlessHealth {
        enabled: !functions.is_empty(),
        total_functions: functions.len(),
        total_invocations,
        total_errors,
        healthy_functions: healthy,
        unhealthy_functions: unhealthy,
    }))
}

#[utoipa::path(
    get,
    path = "/serverless/functions",
    responses(
        (status = 200, description = "List of serverless functions", body = ServerlessStatus),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "serverless"
)]
pub async fn list_functions(_auth: OptionalAuth) -> Result<Json<ServerlessStatus>, StatusCode> {
    let registry = get_global_serverless_registry();
    let functions = registry.list();

    let functions_json: Vec<serde_json::Value> = functions
        .iter()
        .map(|f| {
            serde_json::json!({
                "name": f.name,
                "description": f.description,
                "route_count": f.route_count,
                "allowed_methods": f.allowed_methods,
                "memory_mb": f.memory_mb,
                "timeout_seconds": f.timeout_seconds,
                "registered_at": f.registered_at.elapsed().as_secs(),
                "last_invoked": f.last_invoked.as_ref().map(|i| i.elapsed().as_secs()),
                "invocation_count": f.invocation_count,
                "error_count": f.error_count,
            })
        })
        .collect();

    let status = ServerlessStatus {
        total_functions: functions.len(),
        functions: functions_json,
    };

    Ok(Json(status))
}

#[utoipa::path(
    get,
    path = "/serverless/functions/{name}/stats",
    params(
        ("name" = String, Path, description = "Function name")
    ),
    responses(
        (status = 200, description = "Function statistics", body = FunctionStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Function not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "serverless"
)]
pub async fn get_function_stats(
    Path(name): Path<String>,
    _auth: OptionalAuth,
) -> Result<Json<FunctionStatsResponse>, StatusCode> {
    let registry = get_global_serverless_registry();

    let stats = registry.get_stats(&name);

    let stats_json = stats.map(|s| {
        serde_json::json!({
            "invocation_count": s.invocation_count,
            "error_count": s.error_count,
            "avg_errors_per_invocation": s.avg_errors_per_invocation,
        })
    });

    Ok(Json(FunctionStatsResponse {
        name,
        stats: stats_json,
    }))
}
