#![allow(unused_variables, dead_code)]

use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub type OptionalAuth = Option<TypedHeader<Authorization<Bearer>>>;

pub fn require_auth(auth: &OptionalAuth, admin_token: &str) -> bool {
    match auth {
        Some(TypedHeader(auth_header)) => {
            super::super::auth::constant_time_compare(auth_header.token(), admin_token)
        }
        None => false,
    }
}

pub fn check_rate_limit(
    state: &super::super::state::AdminState,
    ip: &str,
) -> Result<(), axum::http::StatusCode> {
    if let Some(ref limiter) = state.rate_limiter {
        if !limiter.check(ip) {
            tracing::warn!("Admin API rate limit exceeded for IP: {}", ip);
            return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Ok(())
}

pub fn get_client_ip(req: &axum::extract::Request) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|c| c.0.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

pub fn parse_ip(ip: &str) -> Result<IpAddr, StatusCode> {
    ip.parse().map_err(|_| StatusCode::BAD_REQUEST)
}

pub fn config_path(site_id: &str) -> String {
    format!("config/sites/{}.toml", site_id.replace('.', "_"))
}

use axum::http::StatusCode;

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub search: Option<String>,
}

impl PaginationQuery {
    pub fn with_defaults(&self, default_limit: usize, max_limit: usize) -> (usize, usize) {
        let limit = self.limit.unwrap_or(default_limit).min(max_limit);
        let offset = self.offset.unwrap_or(0);
        (limit, offset)
    }
}

impl Default for PaginationQuery {
    fn default() -> Self {
        Self {
            limit: Some(50),
            offset: Some(0),
            search: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub has_more: bool,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: usize, limit: usize, offset: usize) -> Self {
        Self {
            items,
            total,
            has_more: offset + limit < total,
        }
    }

    pub fn empty() -> Self {
        Self {
            items: vec![],
            total: 0,
            has_more: false,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StatusResponse {
    pub status: String,
    pub message: String,
}

impl StatusResponse {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            status: "success".into(),
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "error".into(),
            message: message.into(),
        }
    }

    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            status: "ok".into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaginationLimits {
    pub default: usize,
    pub max: usize,
}

impl PaginationLimits {
    pub const fn new(default: usize, max: usize) -> Self {
        Self { default, max }
    }

    pub fn apply(&self, limit: Option<usize>, offset: Option<usize>) -> (usize, usize) {
        let limit = limit.unwrap_or(self.default).min(self.max);
        let offset = offset.unwrap_or(0);
        (limit, offset)
    }
}

pub const PAGINATION_LIMITS_DEFAULT: PaginationLimits = PaginationLimits::new(50, 500);
pub const PAGINATION_LIMITS_LARGE: PaginationLimits = PaginationLimits::new(100, 1000);
pub const PAGINATION_LIMITS_SMALL: PaginationLimits = PaginationLimits::new(20, 100);

pub const ERROR_PAGES: &[(u16, &str, &str)] = &[
    (
        400,
        "Bad Request",
        "The server could not understand the request",
    ),
    (403, "Forbidden", "Access denied by WAF policy"),
    (404, "Not Found", "The requested resource was not found"),
    (429, "Too Many Requests", "Rate limit exceeded"),
    (500, "Internal Server Error", "An unexpected error occurred"),
    (502, "Bad Gateway", "Upstream server error"),
    (
        503,
        "Service Unavailable",
        "Service temporarily unavailable",
    ),
];

#[derive(Debug, Serialize)]
pub struct ErrorPage {
    pub code: u16,
    pub name: String,
    pub description: String,
    pub html_preview: Option<String>,
}

impl ErrorPage {
    pub fn from_code(code: u16) -> Option<Self> {
        ERROR_PAGES
            .iter()
            .find(|(c, _, _)| *c == code)
            .map(|(code, name, description)| Self {
                code: *code,
                name: name.to_string(),
                description: description.to_string(),
                html_preview: None,
            })
    }

    pub fn list() -> Vec<Self> {
        ERROR_PAGES
            .iter()
            .map(|(code, name, description)| Self {
                code: *code,
                name: name.to_string(),
                description: description.to_string(),
                html_preview: None,
            })
            .collect()
    }
}
