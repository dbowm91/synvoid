use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteBotConfig {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub block_ai_crawlers: Option<bool>,
    #[serde(default)]
    pub enable_css_honeypot: Option<bool>,
    #[serde(default)]
    pub enable_js_challenge: Option<bool>,
    #[serde(default)]
    pub challenge_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteProbeConfig {
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub suspicious_words_enabled: Option<bool>,
    #[serde(default)]
    pub upstream_errors_enabled: Option<bool>,
    #[serde(default)]
    pub upstream_errors_auto_ban: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteTarpitConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub links_per_page: Option<u32>,
    #[serde(default)]
    pub response_delay_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteCssChallengeConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub invalid_count_min: Option<u32>,
    #[serde(default)]
    pub invalid_count_max: Option<u32>,
    #[serde(default)]
    pub valid_count: Option<u32>,
    #[serde(default)]
    pub asset_path: Option<String>,
    #[serde(default)]
    pub verification_window_secs: Option<u32>,
    #[serde(default)]
    pub block: Option<SiteCssBlockConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteCssBlockConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ban_duration: Option<String>,
}
