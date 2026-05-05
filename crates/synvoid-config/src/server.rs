use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub host_v6: Option<String>,
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
}

fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1".to_string(), "::1".to_string()]
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.host.parse::<std::net::IpAddr>().is_err() && self.host != "0.0.0.0" {
            return Err(ConfigValidationError {
                field: "server.host".to_string(),
                message: format!("Invalid IP address: {}", self.host),
            });
        }
        if self.port == 0 {
            return Err(ConfigValidationError {
                field: "server.port".to_string(),
                message: "Port cannot be 0".to_string(),
            });
        }
        for proxy in &self.trusted_proxies {
            if proxy.parse::<std::net::IpAddr>().is_err() {
                if let Some(cidr) = proxy.strip_suffix("/32") {
                    if cidr.parse::<std::net::IpAddr>().is_err() {
                        return Err(ConfigValidationError {
                            field: "server.trusted_proxies".to_string(),
                            message: format!("Invalid trusted proxy: {}", proxy),
                        });
                    }
                } else if let Some(cidr) = proxy.strip_suffix("/128") {
                    if cidr.parse::<std::net::IpAddr>().is_err() {
                        return Err(ConfigValidationError {
                            field: "server.trusted_proxies".to_string(),
                            message: format!("Invalid trusted proxy: {}", proxy),
                        });
                    }
                } else {
                    return Err(ConfigValidationError {
                        field: "server.trusted_proxies".to_string(),
                        message: format!("Invalid trusted proxy: {}", proxy),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct FallbackConfig {
    #[serde(default = "default_fallback_mode", alias = "strategy")]
    pub mode: String,
    #[serde(default)]
    pub upstream: Option<String>,
}

fn default_fallback_mode() -> String {
    "return_404".to_string()
}

impl FallbackConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self.mode.as_str() {
            "return_404" | "proxy" => {}
            _ => {
                return Err(ConfigValidationError {
                    field: "fallback.mode".to_string(),
                    message: "Mode must be 'return_404' or 'proxy'".to_string(),
                });
            }
        }
        if self.mode == "proxy" && self.upstream.is_none() {
            return Err(ConfigValidationError {
                field: "fallback.upstream".to_string(),
                message: "Proxy mode requires an upstream URL".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_config_alias() {
        let toml_old = r#"
            mode = "return_404"
        "#;
        let config_old: FallbackConfig = toml::from_str(toml_old).unwrap();
        assert_eq!(config_old.mode, "return_404");

        let toml_new = r#"
            strategy = "proxy"
            upstream = "http://localhost:8080"
        "#;
        let config_new: FallbackConfig = toml::from_str(toml_new).unwrap();
        assert_eq!(config_new.mode, "proxy");
        assert_eq!(config_new.upstream.unwrap(), "http://localhost:8080");
    }
}
