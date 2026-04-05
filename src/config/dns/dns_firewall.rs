use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(default)]
pub struct DnsLimitsConfig {
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,

    #[serde(default = "default_max_concurrent_queries")]
    pub max_concurrent_queries: usize,

    #[serde(default = "default_max_query_size")]
    pub max_query_size: usize,

    #[serde(default = "default_max_response_size")]
    pub max_response_size: usize,

    #[serde(default = "default_max_records_per_response")]
    pub max_records_per_response: usize,

    #[serde(default = "default_max_tcp_idle_time")]
    pub max_tcp_idle_time_secs: u64,

    #[serde(default = "default_max_tcp_query_time")]
    pub max_tcp_query_time_secs: u64,

    #[serde(default = "default_udp_buffer_size")]
    pub udp_buffer_size: usize,

    #[serde(default)]
    pub enable_graceful_degradation: bool,
}

fn default_max_tcp_connections() -> usize {
    500
}

fn default_max_concurrent_queries() -> usize {
    2500
}

fn default_max_query_size() -> usize {
    65535
}

fn default_max_response_size() -> usize {
    65535
}

fn default_max_records_per_response() -> usize {
    1000
}

fn default_max_tcp_idle_time() -> u64 {
    300
}

fn default_max_tcp_query_time() -> u64 {
    30
}

fn default_udp_buffer_size() -> usize {
    65535
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(default)]
pub struct DnsFirewallConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub default_action: FirewallAction,

    #[serde(default = "default_true")]
    pub block_internal_ips: bool,

    #[serde(default = "default_true")]
    pub block_zone_transfers: bool,

    #[serde(default = "default_firewall_max_rules")]
    pub max_rules: usize,

    #[serde(default)]
    pub rebinding_protection: RebindingProtectionConfig,
}

use super::defaults::default_true;

fn default_firewall_max_rules() -> usize {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(default)]
pub struct RebindingProtectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_min_rebinding_ttl")]
    pub min_ttl_for_internal: u32,

    #[serde(default)]
    pub allowed_internal_domains: Vec<String>,

    #[serde(default)]
    pub block_short_ttl_internal: bool,
}

fn default_min_rebinding_ttl() -> u32 {
    1800
}
