use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::validation::ConfigValidationError;

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SiteRateLimitConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub ip: Option<IpRateLimitOverride>,
    #[serde(default)]
    pub global: Option<GlobalRateLimitOverride>,
    #[serde(default)]
    pub endpoints: Vec<EndpointRateLimitConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct IpRateLimitOverride {
    pub per_second: Option<u32>,
    pub per_minute: Option<u32>,
    pub per_5min: Option<u32>,
    pub per_hour: Option<u32>,
    pub per_day: Option<u32>,
    pub burst: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct GlobalRateLimitOverride {
    pub per_second: Option<u32>,
    pub per_minute: Option<u32>,
    pub per_5min: Option<u32>,
    pub max_connections: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct EndpointRateLimitConfig {
    pub path_pattern: String,
    pub per_minute: Option<u32>,
    pub per_hour: Option<u32>,
    pub burst: Option<u32>,
}

impl SiteRateLimitConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(ref mode) = self.mode {
            match mode.as_str() {
                "shared" | "isolated" => {}
                _ => {
                    return Err(ConfigValidationError {
                        field: "ratelimit.mode".to_string(),
                        message: "Mode must be 'shared' or 'isolated'".to_string(),
                    });
                }
            }
        }
        for endpoint in &self.endpoints {
            if endpoint.path_pattern.is_empty() {
                return Err(ConfigValidationError {
                    field: "ratelimit.endpoints".to_string(),
                    message: "Path pattern cannot be empty".to_string(),
                });
            }
        }
        Ok(())
    }
}
