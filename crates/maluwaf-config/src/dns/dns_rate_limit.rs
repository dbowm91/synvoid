use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsRateLimitConfig {
    #[serde(default)]
    pub mode: super::DnsRateLimitMode,

    #[serde(default = "default_dns_per_second")]
    pub per_second: u64,

    #[serde(default = "default_dns_per_minute")]
    pub per_minute: u64,
}

fn default_dns_per_second() -> u64 {
    500
}

fn default_dns_per_minute() -> u64 {
    5000
}

impl Default for DnsRateLimitConfig {
    fn default() -> Self {
        Self {
            mode: super::DnsRateLimitMode::Shared,
            per_second: default_dns_per_second(),
            per_minute: default_dns_per_minute(),
        }
    }
}

impl DnsRateLimitConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.per_second == 0 && self.per_minute == 0 {
            return Err(DnsConfigError::InvalidRateLimit(
                "At least one of per_second or per_minute must be greater than zero".to_string(),
            ));
        }

        if self.per_second > 1000000 {
            return Err(DnsConfigError::InvalidRateLimit(
                "per_second cannot exceed 1000000".to_string(),
            ));
        }

        if self.per_minute > 60000000 {
            return Err(DnsConfigError::InvalidRateLimit(
                "per_minute cannot exceed 60000000".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsRrlConfig {
    #[serde(default = "default_rrl_enabled")]
    pub enabled: bool,

    #[serde(default = "default_rrl_responses_per_second")]
    pub responses_per_second: u64,

    #[serde(default = "default_rrl_window_secs")]
    pub window_secs: u64,

    #[serde(default = "default_rrl_max_responses")]
    pub max_responses: u64,

    #[serde(default = "default_rrl_ttl")]
    pub ttl: u32,
}

fn default_rrl_enabled() -> bool {
    true
}

fn default_rrl_responses_per_second() -> u64 {
    100
}

fn default_rrl_window_secs() -> u64 {
    5
}

fn default_rrl_max_responses() -> u64 {
    1000
}

fn default_rrl_ttl() -> u32 {
    300
}

impl DnsRrlConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.enabled {
            if self.responses_per_second == 0 {
                return Err(DnsConfigError::InvalidRrl(
                    "responses_per_second must be greater than zero when enabled".to_string(),
                ));
            }

            if self.window_secs == 0 {
                return Err(DnsConfigError::InvalidRrl(
                    "window_secs must be greater than zero".to_string(),
                ));
            }

            if self.ttl > 86400 {
                return Err(DnsConfigError::InvalidRrl(
                    "ttl cannot exceed 86400 seconds (24 hours)".to_string(),
                ));
            }
        }

        Ok(())
    }
}
