use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{unsupported, DnsConfigError};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
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

        // Phase 45 fail-closed contract: anycast requires mesh integration
        // that is not wired (DnsServer::start errors without the mesh
        // feature). Reject activation at validation time so the failure
        // surfaces with a typed config path instead of at listener startup.
        // When mesh-based anycast sync lands, re-introduce the structural
        // checks (non-empty bind_addresses, health_check_interval_secs > 0,
        // capacity > 0) ahead of this rejection.
        Err(unsupported(
            "dns.anycast.enabled",
            "anycast requires mesh integration that is not wired. Keep disabled \
             until mesh-based anycast sync lands (Workstream F).",
        ))
    }
}
