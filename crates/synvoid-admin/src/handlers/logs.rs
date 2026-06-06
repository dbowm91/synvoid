use super::state::AdminStateProvider;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use super::common::{ErrorPage, OptionalAuth};

#[derive(Debug, Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct LogsQuery {
    pub level: Option<String>,
    pub site_id: Option<String>,
    pub search: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub site_id: Option<String>,
    pub message: String,
    pub client_ip: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
    pub total: usize,
    pub has_more: bool,
}

#[utoipa::path(
    get,
    path = "/logs",
    responses(
        (status = 200, description = "Log entries", body = LogsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "logs"
)]
pub async fn get_logs<S: AdminStateProvider>(
    State(_state): State<Arc<S>>,
    _auth: OptionalAuth,
    Query(_query): Query<LogsQuery>,
) -> Result<Json<LogsResponse>, StatusCode> {
    Ok(Json(LogsResponse {
        entries: vec![],
        total: 0,
        has_more: false,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorPageResponse {
    pub code: u16,
    pub name: String,
    pub description: String,
    pub html_preview: Option<String>,
}

#[utoipa::path(
    get,
    path = "/error-pages",
    responses(
        (status = 200, description = "List of error page templates", body = Vec<ErrorPageResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "logs"
)]
pub async fn list_error_pages<S: AdminStateProvider>(
    State(_state): State<Arc<S>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<ErrorPageResponse>>, StatusCode> {
    let error_pages: Vec<ErrorPageResponse> = ErrorPage::list()
        .into_iter()
        .map(|ep| ErrorPageResponse {
            code: ep.code,
            name: ep.name,
            description: ep.description,
            html_preview: ep.html_preview,
        })
        .collect();

    Ok(Json(error_pages))
}

#[utoipa::path(
    get,
    path = "/error-pages/{code}",
    params(
        ("code" = u16, Path, description = "HTTP status code (e.g., 404, 500)")
    ),
    responses(
        (status = 200, description = "Error page template", body = ErrorPageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Error page not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "logs"
)]
pub async fn get_error_page<S: AdminStateProvider>(
    State(_state): State<Arc<S>>,
    _auth: OptionalAuth,
    Path(code): Path<u16>,
) -> Result<Json<ErrorPageResponse>, StatusCode> {
    let error_page = ErrorPage::from_code(code).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(ErrorPageResponse {
        code: error_page.code,
        name: error_page.name,
        description: error_page.description,
        html_preview: error_page.html_preview,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateErrorPageRequest {
    pub title: Option<String>,
    #[allow(dead_code)]
    pub message: Option<String>,
    pub content: Option<String>,
}

#[utoipa::path(
    put,
    path = "/error-pages/{code}",
    params(
        ("code" = u16, Path, description = "HTTP status code (e.g., 404, 500)")
    ),
    request_body = UpdateErrorPageRequest,
    responses(
        (status = 200, description = "Error page updated", body = ErrorPageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Error page not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "logs"
)]
pub async fn update_error_page<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Path(code): Path<u16>,
    Json(payload): Json<UpdateErrorPageRequest>,
) -> Result<Json<ErrorPageResponse>, StatusCode> {
    let error_page = ErrorPage::from_code(code).ok_or(StatusCode::NOT_FOUND)?;

    let config_arc = state.config();
    let config = config_arc.read().await;
    let error_pages_dir = &config.main.defaults.error_pages.directory;

    let page_path = std::path::Path::new(error_pages_dir.as_str()).join(format!("{}.html", code));

    let html_content = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>{} - {}</title></head>
<body>
<h1>{}</h1>
<p>{}</p>
{}</body>
</html>"#,
        code,
        error_page.name,
        error_page.name,
        error_page.description,
        payload
            .content
            .as_deref()
            .map(|c| format!("\n<div>{}</div>\n", c))
            .unwrap_or_default()
    );

    if let Some(parent) = page_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    tokio::fs::write(&page_path, &html_content)
        .await
        .map_err(|e| {
            tracing::error!("Failed to write error page {}: {}", code, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Updated error page {} at {:?}", code, page_path);

    Ok(Json(ErrorPageResponse {
        code: error_page.code,
        name: payload.title.unwrap_or(error_page.name),
        description: error_page.description,
        html_preview: Some(html_content),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuditLogsQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub username: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditLogsResponse {
    pub logs: Vec<super::state::AuditLog>,
    pub total: usize,
    pub has_more: bool,
}

#[utoipa::path(
    get,
    path = "/audit-logs",
    responses(
        (status = 200, description = "Audit log entries", body = AuditLogsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "logs"
)]
pub async fn get_audit_logs<S: AdminStateProvider>(
    State(state): State<Arc<S>>,
    _auth: OptionalAuth,
    Query(query): Query<AuditLogsQuery>,
) -> Result<Json<AuditLogsResponse>, StatusCode> {
    let limit = query.limit.unwrap_or(50).min(1000);
    let offset = query.offset.unwrap_or(0);

    let logs = if let Some(ref username) = query.username {
        state.get_audit_logs_for_user(username, limit)
    } else if let Some(ref resource) = query.resource {
        state.get_audit_logs_for_resource(resource, limit)
    } else {
        state.get_audit_logs(limit, offset)
    };

    let total = state.audit_log_count();
    let has_more = offset + limit < total;

    Ok(Json(AuditLogsResponse {
        logs,
        total,
        has_more,
    }))
}
