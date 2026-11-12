use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteInfo {
    pub domains: Vec<String>,
    /// Canonical listener membership allowlist.
    ///
    /// Omitted means "candidate on every `[[http.listeners]]` entry". A
    /// present list restricts the site to the named listeners. The legacy
    /// per-site `[[site.listen]]` socket declaration remains rejected; sites
    /// reference process-wide listeners instead.
    #[serde(
        default,
        rename = "listen",
        deserialize_with = "reject_site_listen",
        skip_serializing
    )]
    #[schemars(skip)]
    pub listen: (),
    #[serde(
        default,
        deserialize_with = "deserialize_listeners",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub listeners: Vec<String>,
    pub upstream: UpstreamConfig,
}

fn deserialize_listeners<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let listeners = Vec::<String>::deserialize(deserializer)?;
    if listeners.is_empty() {
        return Err(D::Error::custom(
            "site.listeners cannot be empty; omit it to allow every listener",
        ));
    }
    Ok(listeners)
}

fn reject_site_listen<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    serde::de::IgnoredAny::deserialize(deserializer)?;
    Err(D::Error::custom(
        "site.listen is retired: declare process-wide sockets with [[http.listeners]] \
         and select them with [site].listeners; [site] domains remain the virtual-host names",
    ))
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
        for listener in &self.listeners {
            if listener.trim().is_empty() {
                return Err(ConfigValidationError {
                    field: "site.listeners".to_string(),
                    message: "Listener name cannot be empty".to_string(),
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
