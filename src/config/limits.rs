use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlocklistLimitsConfig {
    #[serde(default = "default_max_block_entries")]
    pub max_entries: usize,
    #[serde(default = "default_blocklist_persist_interval")]
    pub persist_interval_secs: u64,
}

impl Default for BlocklistLimitsConfig {
    fn default() -> Self {
        Self {
            max_entries: 500_000,
            persist_interval_secs: 60,
        }
    }
}

fn default_max_block_entries() -> usize {
    500_000
}
fn default_blocklist_persist_interval() -> u64 {
    60
}
