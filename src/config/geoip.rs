use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub database_path: Option<String>,

    #[serde(default)]
    pub block_countries: Vec<String>,

    #[serde(default)]
    pub allow_countries: Vec<String>,

    #[serde(default = "default_log_blocked")]
    pub log_blocked: bool,

    #[serde(default)]
    pub update_enabled: bool,

    #[serde(default)]
    pub update_url: Option<String>,

    #[serde(default)]
    pub account_id: Option<String>,

    #[serde(default)]
    pub license_key: Option<String>,

    #[serde(default = "default_update_interval")]
    pub update_interval_hours: u32,

    #[serde(default = "default_edition_ids")]
    pub edition_ids: Vec<String>,

    #[serde(default = "default_download_timeout")]
    pub download_timeout_secs: u64,

    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    #[serde(default = "default_stale_threshold_days")]
    pub stale_threshold_days: u32,

    #[serde(default = "default_backoff_base_secs")]
    pub backoff_base_secs: u64,
}

fn default_log_blocked() -> bool {
    true
}

fn default_update_interval() -> u32 {
    168
}

fn default_edition_ids() -> Vec<String> {
    vec!["GeoLite2-City".to_string(), "GeoLite2-ASN".to_string()]
}

fn default_download_timeout() -> u64 {
    300
}

fn default_max_retries() -> u32 {
    3
}

fn default_stale_threshold_days() -> u32 {
    7
}

fn default_backoff_base_secs() -> u64 {
    60
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: None,
            block_countries: Vec::new(),
            allow_countries: Vec::new(),
            log_blocked: true,
            update_enabled: false,
            update_url: None,
            account_id: None,
            license_key: None,
            update_interval_hours: 168,
            edition_ids: default_edition_ids(),
            download_timeout_secs: default_download_timeout(),
            max_retries: default_max_retries(),
            stale_threshold_days: default_stale_threshold_days(),
            backoff_base_secs: default_backoff_base_secs(),
        }
    }
}
