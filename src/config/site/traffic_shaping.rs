use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SiteTrafficShapingConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub ingress_max_mb_s: Option<u64>,
    #[serde(default)]
    pub egress_max_mb_s: Option<u64>,
    #[serde(default)]
    pub burst_allowance_mb: Option<u64>,
    #[serde(default)]
    pub connection: SiteTrafficConnectionConfig,
}

impl Default for SiteTrafficShapingConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            inherit: Some(true),
            ingress_max_mb_s: None,
            egress_max_mb_s: None,
            burst_allowance_mb: None,
            connection: SiteTrafficConnectionConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteTrafficConnectionConfig {
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub max_connections_per_ip: Option<u32>,
    #[serde(default)]
    pub connection_queue_size: Option<u32>,
    #[serde(default)]
    pub connection_burst: Option<u32>,
}
