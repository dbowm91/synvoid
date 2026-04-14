use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(default)]
pub struct DnsRpzConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub primary_zone: String,

    #[serde(default)]
    pub allow_transfer: Vec<String>,

    #[serde(default)]
    pub refresh_interval_secs: u64,

    #[serde(default)]
    pub retry_interval_secs: u64,

    #[serde(default)]
    pub expire_interval_secs: u64,

    #[serde(default)]
    pub min_ttl: u32,

    #[serde(default)]
    pub max_ttl: u32,

    #[serde(default)]
    pub default_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Dns64Config {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_dns64_prefix")]
    pub prefix: String,

    #[serde(default)]
    pub exclude_aaaa_synthesis: bool,
}

fn default_dns64_prefix() -> String {
    "64:ff9b::".to_string()
}

impl Default for Dns64Config {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: default_dns64_prefix(),
            exclude_aaaa_synthesis: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct DnsPrefetchConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_prefetch_min_queries")]
    pub min_query_count: u32,

    #[serde(default = "default_prefetch_ttl_threshold")]
    pub prefetch_ttl_threshold: u32,

    #[serde(default = "default_max_prefetch_names")]
    pub max_prefetched_names: usize,
}

fn default_prefetch_min_queries() -> u32 {
    10
}

fn default_prefetch_ttl_threshold() -> u32 {
    300
}

fn default_max_prefetch_names() -> usize {
    1000
}

impl Default for DnsPrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_query_count: default_prefetch_min_queries(),
            prefetch_ttl_threshold: default_prefetch_ttl_threshold(),
            max_prefetched_names: default_max_prefetch_names(),
        }
    }
}
