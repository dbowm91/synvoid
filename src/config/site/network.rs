use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteTcpConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ports: std::collections::HashMap<String, SitePortConfig>,
    #[serde(default)]
    pub filter: Option<SiteProtocolFilterConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteUdpConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub ports: std::collections::HashMap<String, SiteUdpPortConfig>,
    #[serde(default)]
    pub filter: Option<SiteProtocolFilterConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteUdpPortConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub expected_protocol: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SitePortConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteProtocolFilterConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub http_on_smtp: Option<String>,
    #[serde(default)]
    pub http_on_imap: Option<String>,
    #[serde(default)]
    pub http_on_mysql: Option<String>,
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
    #[serde(default)]
    pub blocked: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteTunnelConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, u16>,
}
