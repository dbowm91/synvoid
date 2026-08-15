use gloo::net::http::{Request, Response};
use serde::{de::DeserializeOwned, Serialize};
use serde_json;
use std::cell::RefCell;

use crate::types::{MasterStatus, SystemInfo, WorkerStatus};

const MAX_ERROR_BODY: usize = 512;

/// Truncate a string to at most `max_bytes` bytes without splitting a UTF-8 code point.
/// Returns the original string unchanged if it fits.
fn truncate_utf8_safe(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}: {}", self.status, self.message)
    }
}

impl ApiError {
    fn from_response(status: u16, body: &str) -> Self {
        let message = if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            json.get("error")
                .or_else(|| json.get("message"))
                .or_else(|| json.get("detail"))
                .and_then(|v| v.as_str())
                .unwrap_or("Request failed")
                .to_string()
        } else {
            let trimmed = body.trim();
            truncate_utf8_safe(trimmed, MAX_ERROR_BODY)
        };
        Self { status, message }
    }
}

impl From<ApiError> for String {
    fn from(e: ApiError) -> String {
        format!("HTTP {}: {}", e.status, e.message)
    }
}

thread_local! {
    static CSRF_TOKEN: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn set_csrf_token(token: Option<String>) {
    CSRF_TOKEN.with(|cell| *cell.borrow_mut() = token);
}

pub fn get_csrf_token() -> Option<String> {
    CSRF_TOKEN.with(|cell| cell.borrow().clone())
}

pub fn clear_auth_state() {
    set_csrf_token(None);
}

pub struct ApiService {
    base_url: String,
}

impl Default for ApiService {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiService {
    pub fn new() -> Self {
        Self {
            base_url: "/api".to_string(),
        }
    }

    pub fn with_base_url(base_url: String) -> Self {
        Self { base_url }
    }

    /// Bootstrap a browser session using the bearer token.
    /// Sends the token only to /api/auth/session, then discards it.
    /// Returns the CSRF token on success.
    pub async fn login(bearer_token: &str) -> Result<String, String> {
        let url = "/api/auth/session";
        let request = Request::post(url)
            .header("Authorization", &format!("Bearer {}", bearer_token))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| format!("Login request failed: {}", e))?;

        if !request.ok() {
            let body = match request.text().await {
                Ok(text) if !text.is_empty() => truncate_utf8_safe(&text, MAX_ERROR_BODY),
                _ => String::new(),
            };
            let err = ApiError::from_response(request.status(), &body);
            return Err(err.message);
        }

        let csrf_token = request.headers().get("X-CSRF-Token").unwrap_or_default();

        set_csrf_token(Some(csrf_token.clone()));

        Ok(csrf_token)
    }

    /// Attempt to restore an existing session via the CSRF endpoint.
    /// Used on page reload when the HttpOnly session cookie is still valid.
    pub async fn restore_session() -> Result<String, String> {
        let url = "/api/auth/csrf";
        let request = Request::get(url)
            .send()
            .await
            .map_err(|e| format!("Session restore request failed: {}", e))?;

        if !request.ok() {
            clear_auth_state();
            return Err("Session expired".to_string());
        }

        let body: serde_json::Value = request
            .json()
            .await
            .map_err(|e| format!("Failed to parse CSRF response: {}", e))?;

        let csrf_token = body
            .get("csrf_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if csrf_token.is_empty() {
            clear_auth_state();
            return Err("Empty CSRF token".to_string());
        }

        set_csrf_token(Some(csrf_token.clone()));

        Ok(csrf_token)
    }

    /// Logout: invalidate the server session and clear client state.
    pub async fn logout() -> Result<(), String> {
        let url = "/api/auth/session";
        let mut builder = Request::delete(url);

        if let Some(csrf) = get_csrf_token() {
            builder = builder.header("X-CSRF-Token", &csrf);
        }

        let request = builder
            .credentials(web_sys::RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| format!("Logout request failed: {}", e))?;

        clear_auth_state();

        if request.ok() {
            Ok(())
        } else {
            Err(format!("Logout failed (HTTP {})", request.status()))
        }
    }

    async fn request(&self, method: &str, path: &str) -> Result<Response, ApiError> {
        let url = format!("{}{}", self.base_url, path);

        let mut builder = match method {
            "GET" => Request::get(&url),
            "POST" => Request::post(&url),
            "PUT" => Request::put(&url),
            "DELETE" => Request::delete(&url),
            _ => {
                return Err(ApiError {
                    status: 0,
                    message: "Unsupported HTTP method".to_string(),
                })
            }
        };

        if let Some(csrf) = get_csrf_token() {
            builder = builder.header("X-CSRF-Token", &csrf);
        }

        builder
            .credentials(web_sys::RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError {
                status: 0,
                message: format!("Request failed: {}", e),
            })
    }

    async fn request_with_body<B: Serialize>(
        &self,
        method: &str,
        path: &str,
        body: &B,
    ) -> Result<Response, ApiError> {
        let url = format!("{}{}", self.base_url, path);

        let body_str = serde_json::to_string(body).map_err(|e| ApiError {
            status: 0,
            message: format!("Serialization error: {}", e),
        })?;

        let mut builder = match method {
            "POST" => Request::post(&url),
            "PUT" => Request::put(&url),
            _ => {
                return Err(ApiError {
                    status: 0,
                    message: "Unsupported HTTP method".to_string(),
                })
            }
        };

        if let Some(csrf) = get_csrf_token() {
            builder = builder.header("X-CSRF-Token", &csrf);
        }

        builder = builder
            .header("Content-Type", "application/json")
            .credentials(web_sys::RequestCredentials::Include);

        builder
            .body(body_str)
            .map_err(|e| ApiError {
                status: 0,
                message: format!("Request failed: {}", e),
            })?
            .send()
            .await
            .map_err(|e| ApiError {
                status: 0,
                message: format!("Request failed: {}", e),
            })
    }

    fn handle_auth_error(status: u16) -> Result<(), ApiError> {
        if status == 401 || status == 403 {
            clear_auth_state();
            return Err(ApiError {
                status,
                message: "Session expired".to_string(),
            });
        }
        Ok(())
    }

    async fn read_error_body(response: &Response) -> String {
        match response.text().await {
            Ok(text) if !text.is_empty() => truncate_utf8_safe(&text, MAX_ERROR_BODY),
            _ => String::new(),
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let response = self.request("GET", path).await?;

        Self::handle_auth_error(response.status())?;

        if !response.ok() {
            let body = Self::read_error_body(&response).await;
            return Err(ApiError::from_response(response.status(), &body));
        }

        response.json().await.map_err(|e| ApiError {
            status: response.status(),
            message: format!("JSON parse error: {}", e),
        })
    }

    pub async fn get_text(&self, path: &str) -> Result<String, ApiError> {
        let response = self.request("GET", path).await?;

        Self::handle_auth_error(response.status())?;

        if !response.ok() {
            let body = Self::read_error_body(&response).await;
            return Err(ApiError::from_response(response.status(), &body));
        }

        response.text().await.map_err(|e| ApiError {
            status: response.status(),
            message: format!("Text parse error: {}", e),
        })
    }

    #[allow(dead_code)]
    pub async fn health_check(&self) -> Result<bool, ApiError> {
        match self.get_text("/health").await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn get_stats_summary(&self) -> Result<crate::types::SystemStats, ApiError> {
        self.get("/stats/summary").await
    }

    pub async fn get_stats_sites(&self) -> Result<Vec<crate::types::SiteStats>, ApiError> {
        self.get("/stats/sites").await
    }

    pub async fn get_stats_history(
        &self,
        seconds: Option<u64>,
    ) -> Result<Vec<crate::types::RealtimeMetrics>, ApiError> {
        let path = match seconds {
            Some(s) => format!("/stats/history?seconds={}", s),
            None => "/stats/history".to_string(),
        };
        self.get(&path).await
    }

    pub async fn get_attack_stats(&self) -> Result<crate::types::AttackStats, ApiError> {
        self.get("/stats/attacks").await
    }

    pub async fn get_cache_stats(&self) -> Result<crate::types::CacheStats, ApiError> {
        self.get("/stats/cache").await
    }

    pub async fn get_bandwidth(&self) -> Result<crate::types::BandwidthPayload, ApiError> {
        self.get("/stats/bandwidth").await
    }

    pub async fn get_request_logs(
        &self,
        site_id: Option<&str>,
        method: Option<&str>,
        status: Option<&str>,
        search: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<crate::types::RequestLogsResponse, ApiError> {
        let mut params = Vec::new();

        if let Some(site_id) = site_id {
            params.push(format!("site_id={}", site_id));
        }
        if let Some(method) = method {
            params.push(format!("method={}", method));
        }
        if let Some(status) = status {
            params.push(format!("status={}", status));
        }
        if let Some(search) = search {
            params.push(format!("search={}", search));
        }
        if let Some(limit) = limit {
            params.push(format!("limit={}", limit));
        }
        if let Some(offset) = offset {
            params.push(format!("offset={}", offset));
        }

        let path = if params.is_empty() {
            "/stats/requests".to_string()
        } else {
            format!("/stats/requests?{}", params.join("&"))
        };

        self.get(&path).await
    }

    pub async fn get_system_info(&self) -> Result<SystemInfo, ApiError> {
        self.get("/system/info").await
    }

    pub async fn get_master_status(&self) -> Result<MasterStatus, ApiError> {
        self.get("/system/master").await
    }

    pub async fn get_workers(&self) -> Result<Vec<WorkerStatus>, ApiError> {
        self.get("/system/workers").await
    }

    pub async fn get_supervisor(&self) -> Result<MasterStatus, ApiError> {
        self.get("/system/supervisor").await
    }

    pub async fn get_workers_status(&self) -> Result<Vec<WorkerStatus>, ApiError> {
        self.get_workers().await
    }

    pub async fn get_supervisor_status(&self) -> Result<MasterStatus, ApiError> {
        self.get_supervisor().await
    }

    pub async fn restart_worker(&self, worker_id: &str) -> Result<serde_json::Value, ApiError> {
        self.post(
            &format!("/system/workers/{}/restart", worker_id),
            &serde_json::json!({}),
        )
        .await
    }

    pub async fn get_worker_count(&self) -> Result<crate::types::WorkerCountResponse, ApiError> {
        self.get("/system/workers/count").await
    }

    pub async fn scale_workers(
        &self,
        target_count: usize,
    ) -> Result<crate::types::ScaleWorkersResponse, ApiError> {
        self.post(
            "/system/workers/scale",
            &serde_json::json!({ "target_count": target_count }),
        )
        .await
    }

    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let response = self.request_with_body("POST", path, body).await?;

        Self::handle_auth_error(response.status())?;

        if !response.ok() {
            let body = Self::read_error_body(&response).await;
            return Err(ApiError::from_response(response.status(), &body));
        }

        response.json().await.map_err(|e| ApiError {
            status: response.status(),
            message: format!("JSON parse error: {}", e),
        })
    }

    pub async fn get_theme(&self) -> Result<crate::types::ThemeResponse, ApiError> {
        self.get("/theme").await
    }

    pub async fn update_theme(
        &self,
        request: &crate::types::UpdateThemeRequest,
    ) -> Result<crate::types::ThemeResponse, ApiError> {
        self.put("/theme", request).await
    }

    pub async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let response = self.request_with_body("PUT", path, body).await?;

        Self::handle_auth_error(response.status())?;

        if !response.ok() {
            let body = Self::read_error_body(&response).await;
            return Err(ApiError::from_response(response.status(), &body));
        }

        response.json().await.map_err(|e| ApiError {
            status: response.status(),
            message: format!("JSON parse error: {}", e),
        })
    }

    pub async fn get_theme_css(&self) -> Result<String, ApiError> {
        self.get_text("/theme/css").await
    }

    pub async fn get_site_theme(
        &self,
        site_id: &str,
    ) -> Result<Option<crate::types::SiteThemeResponse>, ApiError> {
        self.get(&format!("/sites/{}/theme", site_id)).await
    }

    pub async fn update_site_theme(
        &self,
        site_id: &str,
        request: &crate::types::UpdateThemeRequest,
    ) -> Result<crate::types::SiteThemeResponse, ApiError> {
        self.put(&format!("/sites/{}/theme", site_id), request)
            .await
    }

    pub async fn get_site_error_pages(
        &self,
        site_id: &str,
    ) -> Result<crate::types::SiteErrorPagesResponse, ApiError> {
        self.get(&format!("/sites/{}/error-pages", site_id)).await
    }

    pub async fn update_site_error_pages(
        &self,
        site_id: &str,
        request: &crate::types::UpdateSiteErrorPagesRequest,
    ) -> Result<crate::types::SiteErrorPagesResponse, ApiError> {
        self.put(&format!("/sites/{}/error-pages", site_id), request)
            .await
    }

    pub async fn get_threat_level_status(
        &self,
    ) -> Result<crate::types::ThreatLevelStatus, ApiError> {
        self.get("/threat-level").await
    }

    pub async fn get_threat_level_history(
        &self,
    ) -> Result<crate::types::ThreatLevelHistory, ApiError> {
        self.get("/threat-level/history").await
    }

    pub async fn get_threat_level_baseline(
        &self,
    ) -> Result<crate::types::ThreatLevelBaseline, ApiError> {
        self.get("/threat-level/baseline").await
    }

    pub async fn reset_threat_level_baseline(&self) -> Result<serde_json::Value, ApiError> {
        self.post("/threat-level/reset", &serde_json::json!({}))
            .await
    }

    pub async fn set_threat_level(&self, level: u8) -> Result<serde_json::Value, ApiError> {
        self.post(
            &format!("/threat-level/set/{}", level),
            &serde_json::json!({}),
        )
        .await
    }

    pub async fn set_threat_level_auto(
        &self,
        _enabled: bool,
    ) -> Result<serde_json::Value, ApiError> {
        self.post("/threat-level/auto", &serde_json::json!({}))
            .await
    }

    pub async fn list_threat_level_backups(
        &self,
    ) -> Result<crate::types::BackupsListResponse, ApiError> {
        self.get("/threat-level/history/backups").await
    }

    pub async fn create_threat_level_backup(
        &self,
        _name: Option<&str>,
    ) -> Result<crate::types::BackupInfo, ApiError> {
        self.post("/threat-level/history/backup", &serde_json::json!({}))
            .await
    }

    pub async fn delete_threat_level_backup(&self, backup_id: &str) -> Result<bool, ApiError> {
        let url = format!("/threat-level/history/backups?path={}", backup_id);
        let response = self.request("DELETE", &url).await?;
        if response.ok() {
            Ok(true)
        } else {
            let body = Self::read_error_body(&response).await;
            Err(ApiError::from_response(response.status(), &body))
        }
    }

    pub async fn list_sites(&self) -> Result<Vec<crate::types::SiteInfo>, ApiError> {
        self.get("/sites").await
    }

    pub async fn get_site(&self, site_id: &str) -> Result<serde_json::Value, ApiError> {
        self.get(&format!("/sites/{}", site_id)).await
    }

    pub async fn create_site(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.post("/sites", request).await
    }

    pub async fn update_site(
        &self,
        site_id: &str,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put(&format!("/sites/{}", site_id), request).await
    }

    pub async fn delete_site(&self, site_id: &str) -> Result<serde_json::Value, ApiError> {
        let url = format!("/sites/{}", site_id);
        let response = self.request("DELETE", &url).await?;
        if response.ok() {
            Ok(serde_json::json!({ "status": "ok" }))
        } else {
            let body = Self::read_error_body(&response).await;
            Err(ApiError::from_response(response.status(), &body))
        }
    }

    pub async fn list_upstreams(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/upstreams").await
    }

    pub async fn get_site_upstreams(&self, site_id: &str) -> Result<serde_json::Value, ApiError> {
        self.get(&format!("/upstreams/{}", site_id)).await
    }

    pub async fn trigger_health_check(&self, site_id: &str) -> Result<serde_json::Value, ApiError> {
        self.post(
            &format!("/upstreams/{}/check", site_id),
            &serde_json::json!({}),
        )
        .await
    }

    pub async fn get_logs(&self, limit: Option<u32>) -> Result<serde_json::Value, ApiError> {
        let path = match limit {
            Some(l) => format!("/logs?limit={}", l),
            None => "/logs".to_string(),
        };
        self.get(&path).await
    }

    pub async fn get_config_main(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/main").await
    }

    pub async fn update_config_main(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/main", config).await
    }

    pub async fn reload_config(&self) -> Result<serde_json::Value, ApiError> {
        self.post("/config/reload", &serde_json::json!({})).await
    }

    pub async fn get_alert_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/alerts/config").await
    }

    pub async fn update_alert_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/alerts/config", config).await
    }

    pub async fn test_alert_webhook(&self) -> Result<serde_json::Value, ApiError> {
        self.post("/alerts/test-webhook", &serde_json::json!({}))
            .await
    }

    pub async fn get_process_manager_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/process-manager").await
    }

    pub async fn update_process_manager_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/process-manager", config).await
    }

    pub async fn get_supervisor_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/supervisor").await
    }

    pub async fn update_supervisor_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/supervisor", config).await
    }

    pub async fn get_main_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/main").await
    }

    pub async fn update_main_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/main", config).await
    }

    pub async fn get_http_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/http").await
    }

    pub async fn update_http_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/http", config).await
    }

    pub async fn get_logging_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/logging").await
    }

    pub async fn update_logging_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/logging", config).await
    }

    pub async fn get_security_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/security").await
    }

    pub async fn update_security_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/security", config).await
    }

    pub async fn get_tls_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/tls").await
    }

    pub async fn update_tls_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/tls", config).await
    }

    pub async fn get_acme_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/acme").await
    }

    pub async fn update_acme_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/acme", config).await
    }

    pub async fn get_http3_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/http3").await
    }

    pub async fn update_http3_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/http3", config).await
    }

    pub async fn get_tunnel_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/tunnel").await
    }

    pub async fn update_tunnel_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/tunnel", config).await
    }

    pub async fn get_plugins_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/plugins").await
    }

    pub async fn update_plugins_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/plugins", config).await
    }

    pub async fn get_traffic_shaping_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/traffic-shaping").await
    }

    pub async fn update_traffic_shaping_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/traffic-shaping", config).await
    }

    pub async fn get_ip_feeds_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/ip-feeds").await
    }

    pub async fn update_ip_feeds_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/ip-feeds", config).await
    }

    pub async fn get_rate_limits_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/rate-limits").await
    }

    pub async fn update_rate_limits_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/rate-limits", config).await
    }

    pub async fn get_mime_types_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/mime-types").await
    }

    pub async fn update_mime_types_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/mime-types", config).await
    }

    pub async fn get_tcp_udp_defaults_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/tcp-udp-defaults").await
    }

    pub async fn update_tcp_udp_defaults_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/tcp-udp-defaults", config).await
    }

    pub async fn get_fallback_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/fallback").await
    }

    pub async fn update_fallback_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/fallback", config).await
    }

    pub async fn get_upgrade_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/upgrade").await
    }

    pub async fn update_upgrade_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/upgrade", config).await
    }

    pub async fn get_bot_detection_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/bot-detection").await
    }

    pub async fn update_bot_detection_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/bot-detection", config).await
    }

    pub async fn get_mesh_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/mesh").await
    }

    pub async fn get_mesh_status(&self) -> Result<crate::types::MeshAdminStatus, ApiError> {
        self.get("/mesh/status").await
    }

    pub async fn derive_signing_key(
        &self,
        genesis_key_base64: &str,
    ) -> Result<crate::types::DeriveSigningKeyResponse, ApiError> {
        self.post(
            "/mesh/derive-signing-key",
            &crate::types::DeriveSigningKeyRequest {
                genesis_key_base64: genesis_key_base64.to_string(),
            },
        )
        .await
    }

    pub async fn update_mesh_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/mesh", config).await
    }

    pub async fn get_dns_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/dns").await
    }

    pub async fn update_dns_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/config/dns", config).await
    }

    pub async fn validate_config(&self) -> Result<serde_json::Value, ApiError> {
        self.post("/config/validate", &serde_json::json!({})).await
    }

    pub async fn export_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/config/export").await
    }

    pub async fn import_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.post("/config/import", config).await
    }

    pub async fn get_honeypot_status(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/honeypot/status").await
    }

    pub async fn control_honeypot(&self, action: &str) -> Result<serde_json::Value, ApiError> {
        self.post(
            "/honeypot/control",
            &serde_json::json!({ "action": action }),
        )
        .await
    }

    pub async fn get_icmp_status(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/icmp/status").await
    }

    pub async fn get_icmp_config(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/icmp/config").await
    }

    pub async fn enable_icmp(&self) -> Result<serde_json::Value, ApiError> {
        self.post("/icmp/enable", &serde_json::json!({})).await
    }

    pub async fn disable_icmp(&self) -> Result<serde_json::Value, ApiError> {
        self.post("/icmp/disable", &serde_json::json!({})).await
    }

    pub async fn get_icmp_backends(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/icmp/backends").await
    }

    pub async fn update_icmp_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        self.put("/icmp/config", config).await
    }

    pub async fn get_yara_status(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/yara/status").await
    }

    pub async fn get_yara_submissions(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/yara/submissions").await
    }

    pub async fn get_serverless_health(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/serverless/health").await
    }

    pub async fn get_serverless_functions(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/serverless/functions").await
    }

    pub async fn list_tier_keys(&self) -> Result<serde_json::Value, ApiError> {
        self.get("/tier-keys").await
    }

    pub async fn issue_tier_key(
        &self,
        org_id: &str,
        tier: u32,
    ) -> Result<serde_json::Value, ApiError> {
        self.post(
            "/tier-keys/issue",
            &serde_json::json!({ "org_id": org_id, "tier": tier }),
        )
        .await
    }

    pub async fn revoke_tier_key(
        &self,
        org_id: &str,
        key_id: &str,
    ) -> Result<serde_json::Value, ApiError> {
        self.post(
            "/tier-keys/revoke",
            &serde_json::json!({ "org_id": org_id, "key_id": key_id }),
        )
        .await
    }

    pub async fn unbind_tier_key(
        &self,
        org_id: &str,
        key_id: &str,
    ) -> Result<serde_json::Value, ApiError> {
        self.post(
            "/tier-keys/unbind",
            &serde_json::json!({ "org_id": org_id, "key_id": key_id }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_short_ascii() {
        assert_eq!(truncate_utf8_safe("hello", 10), "hello");
    }

    #[test]
    fn truncate_utf8_exact_limit() {
        assert_eq!(truncate_utf8_safe("12345", 5), "12345");
    }

    #[test]
    fn truncate_utf8_long_ascii() {
        assert_eq!(
            truncate_utf8_safe("hello world this is long", 10),
            "hello worl..."
        );
    }

    #[test]
    fn truncate_utf8_multibyte_within_limit() {
        assert_eq!(truncate_utf8_safe("日本語テスト", 20), "日本語テスト");
    }

    #[test]
    fn truncate_utf8_multibyte_crossing_boundary() {
        let text = "abc日本語def";
        // "abc" = 3 bytes, "日" = 3 bytes, "本" = 3 bytes, "語" = 3 bytes, "def" = 3 bytes
        // Total = 18 bytes. Limit 7 means: "abc" (3) + "日" starts at 3, full "日" ends at 6, "本" starts at 6, would cross 7.
        // So we back up to char boundary at 6: "abc日" (but "日" ends at 6, so "abc日" = 6 bytes)
        let result = truncate_utf8_safe(text, 7);
        assert_eq!(result, "abc日...");
    }

    #[test]
    fn truncate_utf8_empty() {
        assert_eq!(truncate_utf8_safe("", 10), "");
    }

    #[test]
    fn truncate_utf8_multibyte_at_boundary() {
        let text = "abc日本語";
        // "abc" = 3, "日" = 3 (ends at 6), "本" = 3 (ends at 9)
        let result = truncate_utf8_safe(text, 6);
        assert_eq!(result, "abc日...");
    }
}
