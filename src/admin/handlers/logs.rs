use super::super::state::AdminState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::common::{ErrorPage, OptionalAuth};

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    #[allow(dead_code)]
    pub level: Option<String>,
    #[allow(dead_code)]
    pub site_id: Option<String>,
    #[allow(dead_code)]
    pub search: Option<String>,
    #[allow(dead_code)]
    pub limit: Option<usize>,
    #[allow(dead_code)]
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub site_id: Option<String>,
    pub message: String,
    pub client_ip: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
    pub total: usize,
    pub has_more: bool,
}

pub async fn get_logs(
    State(_state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Query(_query): Query<LogsQuery>,
) -> Result<Json<LogsResponse>, StatusCode> {
    Ok(Json(LogsResponse {
        entries: vec![],
        total: 0,
        has_more: false,
    }))
}

#[derive(Debug, Serialize)]
pub struct ErrorPageResponse {
    pub code: u16,
    pub name: String,
    pub description: String,
    pub html_preview: Option<String>,
}

pub async fn list_error_pages(
    State(_state): State<Arc<AdminState>>,
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

pub async fn get_error_page(
    State(_state): State<Arc<AdminState>>,
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

#[derive(Debug, Deserialize)]
pub struct UpdateErrorPageRequest {
    pub title: Option<String>,
    #[allow(dead_code)]
    pub message: Option<String>,
    pub content: Option<String>,
}

pub async fn update_error_page(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(code): Path<u16>,
    Json(payload): Json<UpdateErrorPageRequest>,
) -> Result<Json<ErrorPageResponse>, StatusCode> {
    let error_page = ErrorPage::from_code(code).ok_or(StatusCode::NOT_FOUND)?;

    let config = state.process.config.read().await;
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
