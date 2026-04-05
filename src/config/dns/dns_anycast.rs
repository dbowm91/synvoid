use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct DnsAnycastConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub bind_addresses: Vec<String>,

    #[serde(default)]
    pub port: u16,

    #[serde(default)]
    pub use_pktinfo: bool,

    #[serde(default = "default_health_check_domain")]
    pub health_check_domain: String,

    #[serde(default)]
    pub health_check_interval_secs: u64,

    #[serde(default = "default_capacity")]
    pub capacity: u32,

    #[serde(default)]
    pub mesh_based_sync: bool,

    #[serde(default = "default_anycast_sync_interval")]
    pub sync_interval_secs: u64,

    #[serde(default)]
    pub geo: Option<String>,

    #[serde(default = "default_sync_trigger_on_update")]
    pub sync_trigger_on_update: bool,
}

fn default_capacity() -> u32 {
    10000
}

fn default_health_check_domain() -> String {
    "_healthcheck.local".to_string()
}

fn default_anycast_sync_interval() -> u64 {
    300
}

fn default_sync_trigger_on_update() -> bool {
    true
}

impl Default for DnsAnycastConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addresses: Vec::new(),
            port: 53,
            use_pktinfo: true,
            health_check_domain: default_health_check_domain(),
            health_check_interval_secs: 5,
            capacity: 10000,
            mesh_based_sync: true,
            sync_interval_secs: default_anycast_sync_interval(),
            geo: None,
            sync_trigger_on_update: default_sync_trigger_on_update(),
        }
    }
}

impl DnsAnycastConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.bind_addresses.is_empty() {
            return Err(DnsConfigError::InvalidAnycast(
                "bind_addresses cannot be empty when anycast is enabled".to_string(),
            ));
        }

        if self.health_check_interval_secs == 0 {
            return Err(DnsConfigError::InvalidAnycast(
                "health_check_interval_secs must be greater than zero".to_string(),
            ));
        }

        if self.capacity == 0 {
            return Err(DnsConfigError::InvalidAnycast(
                "capacity must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}
