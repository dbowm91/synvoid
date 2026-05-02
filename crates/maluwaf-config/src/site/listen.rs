use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteListenConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ssl: Option<bool>,
    #[serde(default)]
    pub http2: Option<bool>,
    #[serde(default)]
    pub http3: Option<bool>,
    #[serde(default)]
    pub default_server: Option<bool>,
    #[serde(default)]
    pub proxy_protocol: Option<bool>,
}

impl SiteListenConfig {
    pub fn to_socket_addr(&self, default_port: u16) -> Option<SocketAddr> {
        let port = self.port.unwrap_or(default_port);
        let addr = self.address.as_deref().unwrap_or("0.0.0.0");

        let addr_clean = addr.trim_start_matches('[').trim_end_matches(']');

        if let Ok(ip) = addr_clean.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, port));
        }

        if let Ok(mut addrs) = (addr_clean, port).to_socket_addrs() {
            return addrs.next();
        }

        None
    }

    pub fn is_ssl(&self) -> bool {
        self.ssl.unwrap_or(false)
    }

    pub fn is_default_server(&self) -> bool {
        self.default_server.unwrap_or(false)
    }

    pub fn is_http2_enabled(&self) -> bool {
        self.http2.unwrap_or(true)
    }

    pub fn is_http3_enabled(&self) -> bool {
        self.http3.unwrap_or(false)
    }

    pub fn is_proxy_protocol(&self) -> bool {
        self.proxy_protocol.unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteInfo {
    pub domains: Vec<String>,
    #[serde(default)]
    pub listen: Vec<SiteListenConfig>,
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct UpstreamConfig {
    #[serde(default = "default_upstream")]
    pub default: String,
    #[serde(default)]
    pub routes: HashMap<String, String>,
    #[serde(default)]
    pub tunnel_mappings: HashMap<String, u16>,
}

fn default_upstream() -> String {
    "http://127.0.0.1:8000".to_string()
}

impl UpstreamConfig {
    pub fn get_upstream(&self, path: &str) -> String {
        for (route_prefix, upstream) in &self.routes {
            if path.starts_with(route_prefix) {
                return self.resolve_tunnel_upstream(upstream);
            }
        }
        self.resolve_tunnel_upstream(&self.default)
    }

    fn resolve_tunnel_upstream(&self, upstream: &str) -> String {
        if upstream.starts_with("tunnel:") {
            let identifier = upstream
                .trim_start_matches("tunnel:")
                .trim_start_matches("tunnel://");
            if let Some(&port) = self.tunnel_mappings.get(identifier) {
                return format!("http://127.0.0.1:{}", 6000 + (port % 1000));
            }
            tracing::warn!("No tunnel mapping found for identifier: {}", identifier);
        }
        upstream.to_string()
    }

    pub fn is_tunnel_upstream(&self, upstream: &str) -> bool {
        upstream.starts_with("tunnel:") || upstream.starts_with("tunnel://")
    }
}

impl SiteInfo {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.domains.is_empty() {
            return Err(ConfigValidationError {
                field: "site.domains".to_string(),
                message: "At least one domain is required".to_string(),
            });
        }
        for domain in &self.domains {
            if domain.is_empty() {
                return Err(ConfigValidationError {
                    field: "site.domains".to_string(),
                    message: "Domain cannot be empty".to_string(),
                });
            }
            if domain.len() > 253 {
                return Err(ConfigValidationError {
                    field: "site.domains".to_string(),
                    message: format!("Domain too long: {}", domain),
                });
            }
        }
        self.upstream.validate()
    }
}

impl UpstreamConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.default.is_empty() {
            return Err(ConfigValidationError {
                field: "site.upstream.default".to_string(),
                message: "Default upstream is required".to_string(),
            });
        }
        if !self.default.starts_with("http://")
            && !self.default.starts_with("https://")
            && !self.default.starts_with("tunnel:")
            && !self.default.starts_with("unix:")
        {
            return Err(ConfigValidationError {
                field: "site.upstream.default".to_string(),
                message: "Upstream must start with http://, https://, tunnel:, or unix:"
                    .to_string(),
            });
        }
        for (route, upstream) in &self.routes {
            if route.is_empty() {
                return Err(ConfigValidationError {
                    field: "site.upstream.routes".to_string(),
                    message: "Route pattern cannot be empty".to_string(),
                });
            }
            if upstream.is_empty() {
                return Err(ConfigValidationError {
                    field: "site.upstream.routes".to_string(),
                    message: format!("Upstream for route {} cannot be empty", route),
                });
            }
        }
        Ok(())
    }
}
