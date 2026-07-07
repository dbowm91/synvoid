use gloo::net::http::{Request, Response};
use serde::{de::DeserializeOwned, Serialize};
use serde_json;

use crate::types::{MasterStatus, OverseerStatus, SystemInfo, WorkerStatus};

pub use crate::types::{MasterStatus as MasterStatusResponse, SystemInfo as SystemInfoResponse};

fn load_admin_token() -> Option<String> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|storage| storage.get_item("admin_token").ok())
        .flatten()
}

pub struct ApiService {
    base_url: String,
    token: Option<String>,
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
            token: load_admin_token(),
        }
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    async fn request(&self, method: &str, path: &str) -> Result<Response, String> {
        let url = format!("{}{}", self.base_url, path);

        let mut builder = match method {
            "GET" => Request::get(&url),
            "POST" => Request::post(&url),
            "PUT" => Request::put(&url),
            "DELETE" => Request::delete(&url),
            _ => return Err(format!("Unsupported HTTP method: {}", method)),
        };

        if let Some(token) = &self.token {
            builder = builder.header("Authorization", &format!("Bearer {}", token));
        }

        builder
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let response = self.request("GET", path).await?;

        if !response.ok() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        response
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))
    }

    pub async fn get_text(&self, path: &str) -> Result<String, String> {
        let response = self.request("GET", path).await?;

        if !response.ok() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        response
            .text()
            .await
            .map_err(|e| format!("Text parse error: {}", e))
    }

    pub async fn health_check(&self) -> Result<bool, String> {
        match self.get_text("/health").await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn get_stats_summary(&self) -> Result<crate::types::SystemStats, String> {
        self.get("/stats/summary").await
    }

    pub async fn get_stats_sites(&self) -> Result<Vec<crate::types::SiteStats>, String> {
        self.get("/stats/sites").await
    }

    pub async fn get_stats_history(
        &self,
        seconds: Option<u64>,
    ) -> Result<Vec<crate::types::RealtimeMetrics>, String> {
        let path = match seconds {
            Some(s) => format!("/stats/history?seconds={}", s),
            None => "/stats/history".to_string(),
        };
        self.get(&path).await
    }

    pub async fn get_attack_stats(&self) -> Result<crate::types::AttackStats, String> {
        self.get("/stats/attacks").await
    }

    pub async fn get_cache_stats(&self) -> Result<crate::types::CacheStats, String> {
        self.get("/stats/cache").await
    }

    pub async fn get_bandwidth(&self) -> Result<crate::types::BandwidthPayload, String> {
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
    ) -> Result<crate::types::RequestLogsResponse, String> {
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

    pub async fn get_system_info(&self) -> Result<SystemInfo, String> {
        self.get("/system/info").await
    }

    pub async fn get_master_status(&self) -> Result<MasterStatus, String> {
        self.get("/system/master").await
    }

    pub async fn get_workers(&self) -> Result<Vec<WorkerStatus>, String> {
        self.get("/system/workers").await
    }

    pub async fn get_overseer(&self) -> Result<OverseerStatus, String> {
        self.get("/system/overseer").await
    }

    pub async fn get_workers_status(&self) -> Result<Vec<WorkerStatus>, String> {
        self.get_workers().await
    }

    pub async fn get_overseer_status(&self) -> Result<OverseerStatus, String> {
        self.get_overseer().await
    }

    pub async fn restart_worker(&self, worker_id: &str) -> Result<serde_json::Value, String> {
        self.post(
            &format!("/system/worker/{}/restart", worker_id),
            &serde_json::json!({}),
        )
        .await
    }

    pub async fn get_worker_count(&self) -> Result<crate::types::WorkerCountResponse, String> {
        self.get("/system/workers/count").await
    }

    pub async fn scale_workers(
        &self,
        target_count: usize,
    ) -> Result<crate::types::ScaleWorkersResponse, String> {
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
    ) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, path);

        let body_str =
            serde_json::to_string(body).map_err(|e| format!("Serialization error: {}", e))?;

        let mut builder = Request::post(&url);

        if let Some(token) = &self.token {
            builder = builder.header("Authorization", &format!("Bearer {}", token));
        }

        builder = builder.header("Content-Type", "application/json");

        let response = builder
            .body(body_str)
            .map_err(|e| format!("Request failed: {}", e))?
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.ok() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        response
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))
    }

    pub async fn get_theme(&self) -> Result<crate::types::ThemeResponse, String> {
        self.get("/theme").await
    }

    pub async fn update_theme(
        &self,
        request: &crate::types::UpdateThemeRequest,
    ) -> Result<crate::types::ThemeResponse, String> {
        self.put("/theme", request).await
    }

    pub async fn put<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, path);

        let body_str =
            serde_json::to_string(body).map_err(|e| format!("Serialization error: {}", e))?;

        let mut builder = Request::put(&url);

        if let Some(token) = &self.token {
            builder = builder.header("Authorization", &format!("Bearer {}", token));
        }

        builder = builder.header("Content-Type", "application/json");

        let response = builder
            .body(body_str)
            .map_err(|e| format!("Request failed: {}", e))?
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.ok() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        response
            .json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))
    }

    pub async fn get_theme_css(&self) -> Result<String, String> {
        self.get_text("/theme/css").await
    }

    pub async fn get_site_theme(
        &self,
        site_id: &str,
    ) -> Result<Option<crate::types::SiteThemeResponse>, String> {
        self.get(&format!("/sites/{}/theme", site_id)).await
    }

    pub async fn update_site_theme(
        &self,
        site_id: &str,
        request: &crate::types::UpdateThemeRequest,
    ) -> Result<crate::types::SiteThemeResponse, String> {
        self.put(&format!("/sites/{}/theme", site_id), request)
            .await
    }

    pub async fn get_site_error_pages(
        &self,
        site_id: &str,
    ) -> Result<crate::types::SiteErrorPagesResponse, String> {
        self.get(&format!("/sites/{}/error-pages", site_id)).await
    }

    pub async fn update_site_error_pages(
        &self,
        site_id: &str,
        request: &crate::types::UpdateSiteErrorPagesRequest,
    ) -> Result<crate::types::SiteErrorPagesResponse, String> {
        self.put(&format!("/sites/{}/error-pages", site_id), request)
            .await
    }

    pub async fn get_threat_level_status(&self) -> Result<crate::types::ThreatLevelStatus, String> {
        self.get("/threat-level").await
    }

    pub async fn get_threat_level_history(
        &self,
    ) -> Result<crate::types::ThreatLevelHistory, String> {
        self.get("/threat-level/history").await
    }

    pub async fn get_threat_level_baseline(
        &self,
    ) -> Result<crate::types::ThreatLevelBaseline, String> {
        self.get("/threat-level/baseline").await
    }

    pub async fn reset_threat_level_baseline(&self) -> Result<serde_json::Value, String> {
        self.post("/threat-level/reset", &serde_json::json!({}))
            .await
    }

    pub async fn set_threat_level(&self, level: u8) -> Result<serde_json::Value, String> {
        self.post(
            &format!("/threat-level/set/{}", level),
            &serde_json::json!({}),
        )
        .await
    }

    pub async fn set_threat_level_auto(&self, _enabled: bool) -> Result<serde_json::Value, String> {
        self.post("/threat-level/auto", &serde_json::json!({}))
            .await
    }

    pub async fn list_threat_level_backups(
        &self,
    ) -> Result<crate::types::BackupsListResponse, String> {
        self.get("/threat-level/history/backups").await
    }

    pub async fn create_threat_level_backup(
        &self,
        _name: Option<&str>,
    ) -> Result<crate::types::BackupInfo, String> {
        self.post("/threat-level/history/backup", &serde_json::json!({}))
            .await
    }

    pub async fn delete_threat_level_backup(&self, backup_id: &str) -> Result<bool, String> {
        let url = format!("/threat-level/history/backups?path={}", backup_id);
        let response = self.request("DELETE", &url).await?;
        if response.ok() {
            Ok(true)
        } else {
            Err(format!("HTTP error: {}", response.status()))
        }
    }

    pub async fn list_sites(&self) -> Result<Vec<crate::types::SiteInfo>, String> {
        self.get("/sites").await
    }

    pub async fn get_site(&self, site_id: &str) -> Result<serde_json::Value, String> {
        self.get(&format!("/sites/{}", site_id)).await
    }

    pub async fn create_site(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.post("/sites", request).await
    }

    pub async fn update_site(
        &self,
        site_id: &str,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put(&format!("/sites/{}", site_id), request).await
    }

    pub async fn delete_site(&self, site_id: &str) -> Result<serde_json::Value, String> {
        let url = format!("/sites/{}", site_id);
        let response = self.request("DELETE", &url).await?;
        if response.ok() {
            Ok(serde_json::json!({ "status": "ok" }))
        } else {
            Err(format!("HTTP error: {}", response.status()))
        }
    }

    pub async fn list_upstreams(&self) -> Result<serde_json::Value, String> {
        self.get("/upstreams").await
    }

    pub async fn get_site_upstreams(&self, site_id: &str) -> Result<serde_json::Value, String> {
        self.get(&format!("/upstreams/{}", site_id)).await
    }

    pub async fn trigger_health_check(&self, site_id: &str) -> Result<serde_json::Value, String> {
        self.post(
            &format!("/upstreams/{}/check", site_id),
            &serde_json::json!({}),
        )
        .await
    }

    pub async fn get_logs(&self, limit: Option<u32>) -> Result<serde_json::Value, String> {
        let path = match limit {
            Some(l) => format!("/logs?limit={}", l),
            None => "/logs".to_string(),
        };
        self.get(&path).await
    }

    pub async fn get_config_main(&self) -> Result<serde_json::Value, String> {
        self.get("/config/main").await
    }

    pub async fn update_config_main(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/main", config).await
    }

    pub async fn reload_config(&self) -> Result<serde_json::Value, String> {
        self.post("/config/reload", &serde_json::json!({})).await
    }

    pub async fn get_alert_config(&self) -> Result<serde_json::Value, String> {
        self.get("/alerts/config").await
    }

    pub async fn update_alert_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/alerts/config", config).await
    }

    pub async fn test_alert_webhook(&self) -> Result<serde_json::Value, String> {
        self.post("/alerts/test-webhook", &serde_json::json!({}))
            .await
    }

    pub async fn get_overseer_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/overseer").await
    }

    pub async fn update_overseer_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/overseer", config).await
    }

    pub async fn get_process_manager_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/process-manager").await
    }

    pub async fn update_process_manager_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/process-manager", config).await
    }

    pub async fn get_supervisor_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/supervisor").await
    }

    pub async fn update_supervisor_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/supervisor", config).await
    }

    pub async fn get_main_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/main").await
    }

    pub async fn update_main_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/main", config).await
    }

    pub async fn get_http_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/http").await
    }

    pub async fn update_http_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/http", config).await
    }

    pub async fn get_logging_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/logging").await
    }

    pub async fn update_logging_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/logging", config).await
    }

    pub async fn get_security_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/security").await
    }

    pub async fn update_security_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/security", config).await
    }

    pub async fn get_tls_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/tls").await
    }

    pub async fn update_tls_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/tls", config).await
    }

    pub async fn get_acme_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/acme").await
    }

    pub async fn update_acme_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/acme", config).await
    }

    pub async fn get_http3_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/http3").await
    }

    pub async fn update_http3_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/http3", config).await
    }

    pub async fn get_tunnel_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/tunnel").await
    }

    pub async fn update_tunnel_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/tunnel", config).await
    }

    pub async fn get_plugins_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/plugins").await
    }

    pub async fn update_plugins_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/plugins", config).await
    }

    pub async fn get_traffic_shaping_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/traffic-shaping").await
    }

    pub async fn update_traffic_shaping_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/traffic-shaping", config).await
    }

    pub async fn get_ip_feeds_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/ip-feeds").await
    }

    pub async fn update_ip_feeds_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/ip-feeds", config).await
    }

    pub async fn get_rate_limits_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/rate-limits").await
    }

    pub async fn update_rate_limits_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/rate-limits", config).await
    }

    pub async fn get_mime_types_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/mime-types").await
    }

    pub async fn update_mime_types_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/mime-types", config).await
    }

    pub async fn get_tcp_udp_defaults_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/tcp-udp-defaults").await
    }

    pub async fn update_tcp_udp_defaults_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/tcp-udp-defaults", config).await
    }

    pub async fn get_fallback_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/fallback").await
    }

    pub async fn update_fallback_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/fallback", config).await
    }

    pub async fn get_upgrade_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/upgrade").await
    }

    pub async fn update_upgrade_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/upgrade", config).await
    }

    pub async fn get_bot_detection_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/bot-detection").await
    }

    pub async fn update_bot_detection_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/bot-detection", config).await
    }

    pub async fn get_mesh_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/mesh").await
    }

    pub async fn get_mesh_status(&self) -> Result<crate::types::MeshAdminStatus, String> {
        self.get("/mesh/status").await
    }

    pub async fn derive_signing_key(
        &self,
        genesis_key_base64: &str,
    ) -> Result<crate::types::DeriveSigningKeyResponse, String> {
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
    ) -> Result<serde_json::Value, String> {
        self.put("/config/mesh", config).await
    }

    pub async fn get_dns_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/dns").await
    }

    pub async fn update_dns_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.put("/config/dns", config).await
    }

    pub async fn validate_config(&self) -> Result<serde_json::Value, String> {
        self.post("/config/validate", &serde_json::json!({})).await
    }

    pub async fn export_config(&self) -> Result<serde_json::Value, String> {
        self.get("/config/export").await
    }

    pub async fn import_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.post("/config/import", config).await
    }

    pub async fn get_honeypot_status(&self) -> Result<serde_json::Value, String> {
        self.get("/honeypot/status").await
    }

    pub async fn control_honeypot(&self, action: &str) -> Result<serde_json::Value, String> {
        self.post(
            "/honeypot/control",
            &serde_json::json!({ "action": action }),
        )
        .await
    }

    pub async fn get_icmp_status(&self) -> Result<serde_json::Value, String> {
        self.get("/icmp/status").await
    }

    pub async fn get_icmp_config(&self) -> Result<serde_json::Value, String> {
        self.get("/icmp/config").await
    }

    pub async fn enable_icmp(&self) -> Result<serde_json::Value, String> {
        self.post("/icmp/enable", &serde_json::json!({})).await
    }

    pub async fn disable_icmp(&self) -> Result<serde_json::Value, String> {
        self.post("/icmp/disable", &serde_json::json!({})).await
    }

    pub async fn get_icmp_backends(&self) -> Result<serde_json::Value, String> {
        self.get("/icmp/backends").await
    }

    pub async fn update_icmp_config(
        &self,
        config: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.post("/icmp/config", config).await
    }

    pub async fn get_yara_status(&self) -> Result<serde_json::Value, String> {
        self.get("/yara/status").await
    }

    pub async fn get_yara_submissions(&self) -> Result<serde_json::Value, String> {
        self.get("/yara/submissions").await
    }

    pub async fn get_serverless_health(&self) -> Result<serde_json::Value, String> {
        self.get("/serverless/health").await
    }

    pub async fn get_serverless_functions(&self) -> Result<serde_json::Value, String> {
        self.get("/serverless/functions").await
    }
}
