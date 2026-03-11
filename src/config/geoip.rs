use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
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
}

fn default_log_blocked() -> bool {
    true
}

fn default_update_interval() -> u32 {
    168
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
        }
    }
}
