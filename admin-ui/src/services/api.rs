use gloo::net::http::{Request, Response};
use serde::{de::DeserializeOwned, Serialize};
use serde_json;

use crate::types::{MasterStatus, OverseerStatus, SystemInfo, WorkerStatus};

pub use crate::types::{MasterStatus as MasterStatusResponse, SystemInfo as SystemInfoResponse};

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
            token: None,
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

    pub async fn get_stats_history(&self, seconds: Option<u64>) -> Result<Vec<crate::types::RealtimeMetrics>, String> {
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
        self.post(&format!("/system/worker/{}/restart", worker_id), &serde_json::json!({})).await
    }

    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, path);
        
        let body_str = serde_json::to_string(body).map_err(|e| format!("Serialization error: {}", e))?;
        
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

    pub async fn update_theme(&self, request: &crate::types::UpdateThemeRequest) -> Result<crate::types::ThemeResponse, String> {
        self.put("/theme", request).await
    }

    pub async fn put<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T, String> {
        let url = format!("{}{}", self.base_url, path);
        
        let body_str = serde_json::to_string(body).map_err(|e| format!("Serialization error: {}", e))?;
        
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

    pub async fn get_site_theme(&self, site_id: &str) -> Result<Option<crate::types::SiteThemeResponse>, String> {
        self.get(&format!("/sites/{}/theme", site_id)).await
    }

    pub async fn update_site_theme(&self, site_id: &str, request: &crate::types::UpdateThemeRequest) -> Result<crate::types::SiteThemeResponse, String> {
        self.put(&format!("/sites/{}/theme", site_id), request).await
    }

    pub async fn get_threat_level_status(&self) -> Result<crate::types::ThreatLevelStatus, String> {
        self.get("/threat-level/status").await
    }

    pub async fn get_threat_level_history(&self) -> Result<crate::types::ThreatLevelHistory, String> {
        self.get("/threat-level/history").await
    }

    pub async fn get_threat_level_baseline(&self) -> Result<crate::types::ThreatLevelBaseline, String> {
        self.get("/threat-level/baseline").await
    }

    pub async fn reset_threat_level_baseline(&self) -> Result<serde_json::Value, String> {
        self.post("/threat-level/baseline/reset", &serde_json::json!({})).await
    }

    pub async fn set_threat_level(&self, level: u8) -> Result<serde_json::Value, String> {
        self.post(&format!("/threat-level/level/{}", level), &serde_json::json!({})).await
    }

    pub async fn set_threat_level_auto(&self, _enabled: bool) -> Result<serde_json::Value, String> {
        self.post("/threat-level/auto", &serde_json::json!({})).await
    }

    pub async fn list_threat_level_backups(&self) -> Result<crate::types::BackupsListResponse, String> {
        self.get("/threat-level/backups").await
    }

    pub async fn create_threat_level_backup(&self, _name: Option<&str>) -> Result<crate::types::BackupInfo, String> {
        self.post("/threat-level/backup", &serde_json::json!({})).await
    }

    pub async fn delete_threat_level_backup(&self, backup_id: &str) -> Result<bool, String> {
        #[derive(serde::Serialize)]
        struct DeleteQuery {
            path: String,
        }
        let _: serde_json::Value = self.post("/threat-level/backup", &DeleteQuery { path: backup_id.to_string() }).await?;
        Ok(true)
    }

    pub async fn list_sites(&self) -> Result<Vec<crate::types::SiteInfo>, String> {
        self.get("/sites").await
    }

    pub async fn get_site(&self, site_id: &str) -> Result<crate::types::SiteInfo, String> {
        self.get(&format!("/sites/{}", site_id)).await
    }

    pub async fn create_site(&self, request: &serde_json::Value) -> Result<crate::types::SiteInfo, String> {
        self.post("/sites", request).await
    }

    pub async fn update_site(&self, site_id: &str, request: &serde_json::Value) -> Result<crate::types::SiteInfo, String> {
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
        self.post(&format!("/upstreams/{}/check", site_id), &serde_json::json!({})).await
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

    pub async fn update_config_main(&self, config: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.put("/config/main", config).await
    }

    pub async fn reload_config(&self) -> Result<serde_json::Value, String> {
        self.post("/config/reload", &serde_json::json!({})).await
    }

    pub async fn get_alert_config(&self) -> Result<serde_json::Value, String> {
        self.get("/alerts/config").await
    }

    pub async fn update_alert_config(&self, config: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.put("/alerts/config", config).await
    }

    pub async fn test_alert_webhook(&self) -> Result<serde_json::Value, String> {
        self.post("/alerts/test-webhook", &serde_json::json!({})).await
    }
}
