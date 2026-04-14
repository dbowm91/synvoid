use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::DnsConfigError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RecursiveUpstreamProvider {
    #[default]
    System,
    Google,
    Cloudflare,
    Custom,
    Recursive,
    GlobalNodes,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RecursiveUpstreamServer {
    #[serde(default)]
    pub address: String,

    #[serde(default)]
    pub port: u16,

    #[serde(default)]
    pub ip: Option<std::net::IpAddr>,
}

impl Default for RecursiveUpstreamServer {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: 53,
            ip: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RecursiveCacheConfig {
    #[serde(default = "default_recursive_cache_size")]
    pub capacity: usize,

    #[serde(default = "default_recursive_negative_cache_ttl")]
    pub negative_ttl_secs: u64,

    #[serde(default = "default_recursive_stale_ttl")]
    pub stale_ttl_secs: u64,

    #[serde(default = "default_recursive_max_ttl")]
    pub max_ttl_secs: u64,

    #[serde(default = "default_recursive_min_ttl")]
    pub min_ttl_secs: u64,
}

fn default_recursive_cache_size() -> usize {
    1000000
}

fn default_recursive_negative_cache_ttl() -> u64 {
    300
}

fn default_recursive_stale_ttl() -> u64 {
    86400
}

fn default_recursive_max_ttl() -> u64 {
    86400
}

fn default_recursive_min_ttl() -> u64 {
    0
}

impl Default for RecursiveCacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_recursive_cache_size(),
            negative_ttl_secs: default_recursive_negative_cache_ttl(),
            stale_ttl_secs: default_recursive_stale_ttl(),
            max_ttl_secs: default_recursive_max_ttl(),
            min_ttl_secs: default_recursive_min_ttl(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RecursiveDnsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_recursive_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_recursive_port")]
    pub port: u16,

    #[serde(default)]
    pub upstream_provider: RecursiveUpstreamProvider,

    #[serde(default)]
    pub upstream_servers: Vec<RecursiveUpstreamServer>,

    #[serde(default)]
    pub cache: RecursiveCacheConfig,

    #[serde(default = "default_recursive_true")]
    pub dnssec_validation: bool,

    #[serde(default = "default_recursive_true")]
    pub qname_minimization: bool,

    #[serde(default = "default_recursive_query_timeout")]
    pub query_timeout_secs: u64,

    #[serde(default = "default_recursive_max_concurrent_queries")]
    pub max_concurrent_queries: usize,

    #[serde(default)]
    pub ratelimit: super::DnsRateLimitConfig,

    #[serde(default)]
    pub firewall: super::DnsFirewallConfig,

    #[serde(default = "default_root_hints_path")]
    pub root_hints_path: String,

    #[serde(default = "default_recursive_trust_anchor_path")]
    pub trust_anchor_path: String,
}

fn default_recursive_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_recursive_port() -> u16 {
    1053
}

fn default_recursive_true() -> bool {
    true
}

fn default_recursive_query_timeout() -> u64 {
    5
}

fn default_recursive_max_concurrent_queries() -> usize {
    10000
}

fn default_root_hints_path() -> String {
    "root.hints".to_string()
}

fn default_recursive_trust_anchor_path() -> String {
    "trusted-key.key".to_string()
}

impl Default for RecursiveDnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_recursive_bind_address(),
            port: default_recursive_port(),
            upstream_provider: RecursiveUpstreamProvider::System,
            upstream_servers: Vec::new(),
            cache: RecursiveCacheConfig::default(),
            dnssec_validation: true,
            qname_minimization: true,
            query_timeout_secs: default_recursive_query_timeout(),
            max_concurrent_queries: default_recursive_max_concurrent_queries(),
            ratelimit: super::DnsRateLimitConfig::default(),
            firewall: super::DnsFirewallConfig::default(),
            root_hints_path: default_root_hints_path(),
            trust_anchor_path: default_recursive_trust_anchor_path(),
        }
    }
}

impl RecursiveDnsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.upstream_provider == RecursiveUpstreamProvider::Custom
            && self.upstream_servers.is_empty()
        {
            return Err(DnsConfigError::InvalidRecursive(
                "Custom upstream provider requires at least one upstream server".to_string(),
            ));
        }

        for server in &self.upstream_servers {
            if server.ip.is_none() && server.address.is_empty() {
                return Err(DnsConfigError::InvalidRecursive(
                    "Upstream server must have either an IP address or hostname".to_string(),
                ));
            }
        }

        if self.query_timeout_secs == 0 {
            return Err(DnsConfigError::InvalidRecursive(
                "query_timeout_secs must be greater than zero".to_string(),
            ));
        }

        if self.max_concurrent_queries == 0 {
            return Err(DnsConfigError::InvalidRecursive(
                "max_concurrent_queries must be greater than zero".to_string(),
            ));
        }

        self.ratelimit.validate()?;

        if self.cache.negative_ttl_secs > self.cache.max_ttl_secs {
            return Err(DnsConfigError::InvalidRecursive(
                "negative_ttl_secs cannot exceed max_ttl_secs".to_string(),
            ));
        }

        if self.cache.stale_ttl_secs < self.cache.negative_ttl_secs {
            return Err(DnsConfigError::InvalidRecursive(
                "stale_ttl_secs should be >= negative_ttl_secs for effective negative caching"
                    .to_string(),
            ));
        }

        Ok(())
    }

    pub fn upstream_ips(&self) -> Vec<std::net::IpAddr> {
        let mut ips: Vec<std::net::IpAddr> =
            self.upstream_servers.iter().filter_map(|s| s.ip).collect();

        if ips.is_empty() {
            match self.upstream_provider {
                RecursiveUpstreamProvider::Google => {
                    ips.push(std::net::IpAddr::from([8, 8, 8, 8]));
                    ips.push(std::net::IpAddr::from([8, 8, 4, 4]));
                }
                RecursiveUpstreamProvider::Cloudflare => {
                    ips.push(std::net::IpAddr::from([1, 1, 1, 1]));
                    ips.push(std::net::IpAddr::from([1, 0, 0, 1]));
                }
                _ => {}
            }
        }

        ips
    }
}
