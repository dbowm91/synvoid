use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;

use super::common::{ErrorPage, OptionalAuth};

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[allow(dead_code)] // Fields used for OpenAPI schema/documentation
pub struct LogsQuery {
    pub level: Option<String>,
    pub site_id: Option<String>,
    pub search: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub site_id: Option<String>,
    pub message: String,
    pub client_ip: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
    pub total: usize,
    pub has_more: bool,
}

#[utoipa::path(
    get,
    path = "/logs",
    tag = "Logs",
    params(
        ("level" = Option<String>, Query, description = "Filter by log level"),
        ("site_id" = Option<String>, Query, description = "Filter by site ID"),
        ("search" = Option<String>, Query, description = "Search in log messages"),
        ("limit" = Option<usize>, Query, description = "Maximum number of entries"),
        ("offset" = Option<usize>, Query, description = "Number of entries to skip")
    ),
    responses(
        (status = 200, description = "Log entries", body = [LogsResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_logs(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Query(_query): Query<LogsQuery>,
) -> Result<Json<LogsResponse>, StatusCode> {

    Ok(Json(LogsResponse {
        entries: vec![],
        total: 0,
        has_more: false,
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ErrorPageResponse {
    pub code: u16,
    pub name: String,
    pub description: String,
    pub html_preview: Option<String>,
}

#[utoipa::path(
    get,
    path = "/error-pages",
    tag = "Logs",
    responses(
        (status = 200, description = "List of error pages", body = [ErrorPageResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_error_pages(
    State(state): State<Arc<AdminState>>,
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
    tag = "Logs",
    params(
        ("code" = u16, Path, description = "HTTP status code (e.g., 404, 500)")
    ),
    responses(
        (status = 200, description = "Error page details", body = [ErrorPageResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Error page not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_error_page(
    State(state): State<Arc<AdminState>>,
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateErrorPageRequest {
    pub title: Option<String>,
    pub message: Option<String>,
    pub content: Option<String>,
}

#[utoipa::path(
    put,
    path = "/error-pages/{code}",
    tag = "Logs",
    params(
        ("code" = u16, Path, description = "HTTP status code to update")
    ),
    request_body = UpdateErrorPageRequest,
    responses(
        (status = 200, description = "Error page updated", body = [ErrorPageResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Error page not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_error_page(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(code): Path<u16>,
    Json(payload): Json<UpdateErrorPageRequest>,
) -> Result<Json<ErrorPageResponse>, StatusCode> {

    let _error_page = ErrorPage::from_code(code).ok_or(StatusCode::NOT_FOUND)?;

    tracing::warn!(
        "update_error_page called for {} but is not yet implemented (title={:?})",
        code, payload.title
    );
    
    Err(StatusCode::NOT_IMPLEMENTED)
}
