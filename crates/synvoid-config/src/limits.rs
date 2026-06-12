use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct RateLimitMemoryConfig {
    #[serde(default = "default_max_ip_entries")]
    pub max_ip_entries: usize,
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
    #[serde(default = "default_num_shards")]
    pub num_shards: usize,
}

impl Default for RateLimitMemoryConfig {
    fn default() -> Self {
        Self {
            max_ip_entries: 100_000,
            cleanup_interval_secs: 60,
            num_shards: 256,
        }
    }
}

fn default_max_ip_entries() -> usize {
    100_000
}
fn default_cleanup_interval() -> u64 {
    60
}
fn default_num_shards() -> usize {
    256
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct ProxyLimitsConfig {
    #[serde(default = "default_max_response_size")]
    pub max_response_size: usize,
    #[serde(default = "default_connection_pool_size")]
    pub connection_pool_size: usize,
}

impl Default for ProxyLimitsConfig {
    fn default() -> Self {
        Self {
            max_response_size: 10_000_000,
            connection_pool_size: 100,
        }
    }
}

fn default_max_response_size() -> usize {
    10_000_000
}
fn default_connection_pool_size() -> usize {
    100
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct BlocklistLimitsConfig {
    #[serde(default = "default_max_block_entries")]
    pub max_entries: usize,
    #[serde(default = "default_blocklist_persist_interval")]
    pub persist_interval_secs: u64,
    #[serde(default = "default_true")]
    pub target_state_persist: bool,
    #[serde(default = "default_target_state_max_records")]
    pub target_state_max_records: usize,
    #[serde(default = "default_target_state_ttl_secs")]
    pub target_state_ttl_secs: u64,
}

impl Default for BlocklistLimitsConfig {
    fn default() -> Self {
        Self {
            max_entries: 500_000,
            persist_interval_secs: 60,
            target_state_persist: true,
            target_state_max_records: 100_000,
            target_state_ttl_secs: 604_800, // 7 days
        }
    }
}

fn default_max_block_entries() -> usize {
    500_000
}
fn default_blocklist_persist_interval() -> u64 {
    60
}
fn default_true() -> bool {
    true
}
fn default_target_state_max_records() -> usize {
    100_000
}
fn default_target_state_ttl_secs() -> u64 {
    604_800 // 7 days
}
