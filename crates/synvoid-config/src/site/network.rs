use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::validation::ConfigValidationError;

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

impl SiteTcpConfig {
    /// Reject the retired per-site listener schema.
    ///
    /// Raw TCP has no `Host` header, so a site cannot select a listener the way
    /// an HTTP vhost selects a domain. Listener definitions live in the global
    /// `[tcp.protocols.*]` map; accepting this table would silently do nothing.
    pub fn validate_retired(&self) -> Result<(), ConfigValidationError> {
        if self.enabled.is_some() || !self.ports.is_empty() || self.filter.is_some() {
            return Err(ConfigValidationError {
                field: "site.tcp".to_string(),
                message: "site-level TCP listeners are retired: declare listener ports,                           upstreams and filters in the global [tcp.protocols.*] map"
                    .to_string(),
            });
        }
        Ok(())
    }
}

impl SiteUdpConfig {
    pub fn validate_retired(&self) -> Result<(), ConfigValidationError> {
        if self.enabled.is_some() || !self.ports.is_empty() || self.filter.is_some() {
            return Err(ConfigValidationError {
                field: "site.udp".to_string(),
                message: "site-level UDP listeners are retired: declare listener ports,                           upstreams and filters in the global [udp.protocols.*] map"
                    .to_string(),
            });
        }
        Ok(())
    }
}
