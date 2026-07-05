use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EcsForwardingPolicy {
    #[default]
    Never,
    Always,
    CdnOnly,
    IfPresent,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct RecursiveEcsConfig {
    #[serde(default)]
    pub forwarding_policy: EcsForwardingPolicy,

    #[serde(default = "default_ecs_prefix_v4")]
    pub prefix_v4: u8,

    #[serde(default = "default_ecs_prefix_v6")]
    pub prefix_v6: u8,

    #[serde(default = "default_ecs_include_in_response")]
    pub include_scope_in_response: bool,
}

fn default_ecs_prefix_v4() -> u8 {
    24
}

fn default_ecs_prefix_v6() -> u8 {
    56
}

fn default_ecs_include_in_response() -> bool {
    false
}

impl Default for RecursiveEcsConfig {
    fn default() -> Self {
        Self {
            forwarding_policy: EcsForwardingPolicy::default(),
            prefix_v4: default_ecs_prefix_v4(),
            prefix_v6: default_ecs_prefix_v6(),
            include_scope_in_response: default_ecs_include_in_response(),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(default)]
pub struct RecursiveClientAcl {
    #[serde(default)]
    pub allowed_clients: Vec<String>,

    #[serde(default = "default_acl_action")]
    pub action: String,
}

fn default_acl_action() -> String {
    "reject".to_string()
}

impl Default for RecursiveClientAcl {
    fn default() -> Self {
        Self {
            allowed_clients: Vec::new(),
            action: default_acl_action(),
        }
    }
}

impl RecursiveClientAcl {
    pub fn is_client_allowed(&self, client_ip: IpAddr) -> bool {
        if self.allowed_clients.is_empty() {
            return true;
        }

        for cidr in &self.allowed_clients {
            if let Ok(network) = cidr.parse::<ipnetwork::IpNetwork>() {
                if network.contains(client_ip) {
                    return true;
                }
            }
        }

        self.action == "allow"
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

    #[serde(default)]
    pub client_acl: Option<RecursiveClientAcl>,

    #[serde(default = "default_max_cname_depth")]
    pub max_cname_depth: u8,

    #[serde(default = "default_max_recursion_depth")]
    pub max_recursion_depth: u8,

    #[serde(default = "default_max_per_client_queries")]
    pub max_per_client_queries: u32,

    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    #[serde(default)]
    pub ecs: RecursiveEcsConfig,
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

fn default_max_cname_depth() -> u8 {
    10
}

fn default_max_recursion_depth() -> u8 {
    16
}

fn default_max_per_client_queries() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    #[serde(default = "default_recovery_timeout_secs")]
    pub recovery_timeout_secs: u64,

    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_recovery_timeout_secs() -> u64 {
    30
}

fn default_success_threshold() -> u32 {
    2
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            recovery_timeout_secs: default_recovery_timeout_secs(),
            success_threshold: default_success_threshold(),
        }
    }
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
            client_acl: None,
            max_cname_depth: default_max_cname_depth(),
            max_recursion_depth: default_max_recursion_depth(),
            max_per_client_queries: default_max_per_client_queries(),
            circuit_breaker: CircuitBreakerConfig::default(),
            ecs: RecursiveEcsConfig::default(),
        }
    }
}

impl RecursiveDnsConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.bind_address == "0.0.0.0" || self.bind_address == "::" {
            return Err(DnsConfigError::InvalidRecursive(
                "Recursive DNS bind address must not be 0.0.0.0 or :: (open resolver). Bind to 127.0.0.1 or a specific interface.".to_string(),
            ));
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

        if let Some(ref acl) = self.client_acl {
            for cidr in &acl.allowed_clients {
                if cidr.parse::<ipnetwork::IpNetwork>().is_err() {
                    return Err(DnsConfigError::InvalidRecursive(format!(
                        "Invalid CIDR notation in client_acl.allowed_clients: {}",
                        cidr
                    )));
                }
            }
            if acl.action != "reject" && acl.action != "allow" {
                return Err(DnsConfigError::InvalidRecursive(format!(
                    "Invalid client_acl.action: {} (must be 'reject' or 'allow')",
                    acl.action
                )));
            }
        }

        if self.circuit_breaker.failure_threshold == 0 {
            return Err(DnsConfigError::InvalidRecursive(
                "circuit_breaker.failure_threshold must be greater than zero".to_string(),
            ));
        }

        if self.circuit_breaker.success_threshold == 0 {
            return Err(DnsConfigError::InvalidRecursive(
                "circuit_breaker.success_threshold must be greater than zero".to_string(),
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
