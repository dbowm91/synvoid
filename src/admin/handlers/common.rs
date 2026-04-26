#![allow(dead_code)]
// SAFETY_REASON: Admin API handlers for common functionality - future expansion planned

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use utoipa::ToSchema;

pub type OptionalAuth = Option<TypedHeader<Authorization<Bearer>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredRole {
    Admin,
    User,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
    pub role: RequiredRole,
}

impl RequiredRole {
    pub fn is_admin(&self) -> bool {
        matches!(self, RequiredRole::Admin)
    }
}

pub async fn require_role(
    request: Request,
    required_role: RequiredRole,
    next: axum::middleware::Next,
) -> Response {
    let authenticated_user = request.extensions().get::<AuthenticatedUser>();

    let user = match authenticated_user {
        Some(user) => user,
        None => {
            tracing::warn!("RBAC: No authenticated user found in request");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    if required_role == RequiredRole::Admin && user.role != RequiredRole::Admin {
        tracing::warn!(
            "RBAC: User {} with role {:?} attempted to access Admin-only endpoint",
            user.username,
            user.role
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    next.run(request).await
}

pub fn check_rate_limit(
    state: &super::super::state::AdminState,
    ip: &str,
) -> Result<(), axum::http::StatusCode> {
    if let Some(ref limiter) = state.security.rate_limiter {
        if !limiter.check(ip) {
            tracing::warn!("Admin API rate limit exceeded for IP: {}", ip);
            return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
        }
    }
    Ok(())
}

pub fn get_client_ip(req: &axum::extract::Request) -> String {
    if let Some(client_ip) = req.extensions().get::<super::super::middleware::ClientIp>() {
        return client_ip.0.clone();
    }
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

pub fn config_path(config_dir: &std::path::Path, site_id: &str) -> std::path::PathBuf {
    config_dir.join(format!("{}.toml", site_id.replace('.', "_")))
}

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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_required_role_is_admin() {
        assert!(RequiredRole::Admin.is_admin());
        assert!(!RequiredRole::User.is_admin());
    }

    #[test]
    fn test_parse_ip_valid() {
        let ipv4: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(parse_ip("192.168.1.1").unwrap(), ipv4);

        let ipv6: IpAddr = "::1".parse().unwrap();
        assert_eq!(parse_ip("::1").unwrap(), ipv6);
    }

    #[test]
    fn test_parse_ip_invalid() {
        assert!(parse_ip("not-an-ip").is_err());
        assert!(parse_ip("").is_err());
    }

    #[test]
    fn test_pagination_query_defaults() {
        let query = PaginationQuery::default();
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(0));
        assert!(query.search.is_none());
    }

    #[test]
    fn test_pagination_query_with_defaults() {
        let query = PaginationQuery {
            limit: Some(100),
            offset: Some(20),
            search: Some("test".to_string()),
        };

        let (limit, offset) = query.with_defaults(50, 500);
        assert_eq!(limit, 100);
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_pagination_query_with_defaults_respects_max() {
        let query = PaginationQuery {
            limit: Some(1000),
            offset: Some(0),
            search: None,
        };

        let (limit, _) = query.with_defaults(50, 500);
        assert_eq!(limit, 500);
    }

    #[test]
    fn test_pagination_query_uses_default_when_none() {
        let query = PaginationQuery {
            limit: None,
            offset: None,
            search: None,
        };

        let (limit, offset) = query.with_defaults(50, 500);
        assert_eq!(limit, 50);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_paginated_response_new_with_items() {
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let response = PaginatedResponse::new(items, 10, 3, 0);

        assert_eq!(response.items.len(), 3);
        assert_eq!(response.total, 10);
        assert!(response.has_more);
    }

    #[test]
    fn test_paginated_response_has_more_false_at_end() {
        let items = vec!["a".to_string()];
        let response = PaginatedResponse::new(items, 5, 5, 0);

        assert!(!response.has_more);
    }

    #[test]
    fn test_paginated_response_empty() {
        let response: PaginatedResponse<String> = PaginatedResponse::empty();

        assert!(response.items.is_empty());
        assert_eq!(response.total, 0);
        assert!(!response.has_more);
    }

    #[test]
    fn test_pagination_limits_constants() {
        assert_eq!(PAGINATION_LIMITS_DEFAULT.default, 50);
        assert_eq!(PAGINATION_LIMITS_DEFAULT.max, 500);

        assert_eq!(PAGINATION_LIMITS_LARGE.default, 100);
        assert_eq!(PAGINATION_LIMITS_LARGE.max, 1000);

        assert_eq!(PAGINATION_LIMITS_SMALL.default, 20);
        assert_eq!(PAGINATION_LIMITS_SMALL.max, 100);
    }

    #[test]
    fn test_pagination_limits_apply_within_bounds() {
        let limits = PAGINATION_LIMITS_DEFAULT;

        let (limit, offset) = limits.apply(Some(25), Some(10));
        assert_eq!(limit, 25);
        assert_eq!(offset, 10);
    }

    #[test]
    fn test_pagination_limits_apply_above_max() {
        let limits = PAGINATION_LIMITS_DEFAULT;

        let (limit, offset) = limits.apply(Some(1000), Some(5));
        assert_eq!(limit, 500);
        assert_eq!(offset, 5);
    }

    #[test]
    fn test_pagination_limits_apply_uses_default() {
        let limits = PAGINATION_LIMITS_DEFAULT;

        let (limit, offset) = limits.apply(None, None);
        assert_eq!(limit, 50);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_status_response_factory_methods() {
        let success = StatusResponse::success("done");
        assert_eq!(success.status, "success");

        let error = StatusResponse::error("failed");
        assert_eq!(error.status, "error");

        let ok = StatusResponse::ok("ok");
        assert_eq!(ok.status, "ok");
    }

    #[test]
    fn test_error_page_list_all() {
        let pages = ErrorPage::list();
        assert_eq!(pages.len(), ERROR_PAGES.len());

        for page in &pages {
            let found = ERROR_PAGES.iter().any(|(code, _, _)| *code == page.code);
            assert!(found);
        }
    }

    #[test]
    fn test_error_page_from_code_valid() {
        let page = ErrorPage::from_code(400).unwrap();
        assert_eq!(page.code, 400);
        assert_eq!(page.name, "Bad Request");

        let page = ErrorPage::from_code(500).unwrap();
        assert_eq!(page.code, 500);
        assert_eq!(page.name, "Internal Server Error");
    }

    #[test]
    fn test_error_page_from_code_invalid() {
        assert!(ErrorPage::from_code(600).is_none());
        assert!(ErrorPage::from_code(199).is_none());
    }

    #[test]
    fn test_config_path_sanitization() {
        let config_dir = std::path::PathBuf::from("/etc/config");
        let site_id = "example.com";

        let path = config_path(&config_dir, site_id);
        assert_eq!(
            path,
            std::path::PathBuf::from("/etc/config/example_com.toml")
        );
    }

    #[test]
    fn test_config_path_preserves_underscores() {
        let config_dir = std::path::PathBuf::from("/etc/config");
        let site_id = "my_site.test";

        let path = config_path(&config_dir, site_id);
        assert_eq!(
            path,
            std::path::PathBuf::from("/etc/config/my_site_test.toml")
        );
    }
}
