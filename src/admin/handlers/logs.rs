use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::super::auth::{require_auth, OptionalAuth};

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub level: Option<String>,
    pub site_id: Option<String>,
    pub search: Option<String>,
    pub limit: Option<usize>,
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
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Query(query): Query<LogsQuery>,
) -> Result<Json<LogsResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let limit = query.limit.unwrap_or(100).min(1000);
    
    Ok(Json(LogsResponse {
        entries: vec![],
        total: 0,
        has_more: false,
    }))
}

#[derive(Debug, Serialize)]
pub struct ErrorPage {
    pub code: u16,
    pub name: String,
    pub description: String,
    pub html_preview: Option<String>,
}

pub async fn list_error_pages(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<ErrorPage>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let error_pages = vec![
        ErrorPage {
            code: 400,
            name: "Bad Request".to_string(),
            description: "The server could not understand the request".to_string(),
            html_preview: None,
        },
        ErrorPage {
            code: 403,
            name: "Forbidden".to_string(),
            description: "Access denied by WAF policy".to_string(),
            html_preview: None,
        },
        ErrorPage {
            code: 404,
            name: "Not Found".to_string(),
            description: "The requested resource was not found".to_string(),
            html_preview: None,
        },
        ErrorPage {
            code: 429,
            name: "Too Many Requests".to_string(),
            description: "Rate limit exceeded".to_string(),
            html_preview: None,
        },
        ErrorPage {
            code: 500,
            name: "Internal Server Error".to_string(),
            description: "An unexpected error occurred".to_string(),
            html_preview: None,
        },
        ErrorPage {
            code: 502,
            name: "Bad Gateway".to_string(),
            description: "Upstream server error".to_string(),
            html_preview: None,
        },
        ErrorPage {
            code: 503,
            name: "Service Unavailable".to_string(),
            description: "Service temporarily unavailable".to_string(),
            html_preview: None,
        },
    ];

    Ok(Json(error_pages))
}

pub async fn get_error_page(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(code): Path<u16>,
) -> Result<Json<ErrorPage>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (name, description) = match code {
        400 => ("Bad Request", "The server could not understand the request"),
        403 => ("Forbidden", "Access denied by WAF policy"),
        404 => ("Not Found", "The requested resource was not found"),
        429 => ("Too Many Requests", "Rate limit exceeded"),
        500 => ("Internal Server Error", "An unexpected error occurred"),
        502 => ("Bad Gateway", "Upstream server error"),
        503 => ("Service Unavailable", "Service temporarily unavailable"),
        _ => return Err(StatusCode::NOT_FOUND),
    };

    Ok(Json(ErrorPage {
        code,
        name: name.to_string(),
        description: description.to_string(),
        html_preview: None,
    }))
}
