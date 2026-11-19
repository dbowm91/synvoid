use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsMeshConfig {
    #[serde(default = "default_true")]
    pub register_to_global: bool,

    #[serde(default = "default_registration_interval")]
    pub registration_interval_secs: u64,

    #[serde(default = "default_true")]
    pub accept_registrations: bool,

    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,

    #[serde(default = "default_upstream_dns_servers")]
    pub upstream_dns_servers: Vec<String>,

    #[serde(default = "default_verification_retry_interval")]
    pub verification_retry_interval_secs: u64,

    #[serde(default = "default_verification_timeout")]
    pub verification_timeout_secs: u64,

    #[serde(default)]
    pub qname_minimization: bool,

    #[serde(default)]
    pub require_cert_chain_verification: bool,

    /// Domains a DHT-sourced origin registration may answer for.
    ///
    /// Authenticity (a valid signature bound to the claimed publisher) does
    /// not prove authorization to serve a name. A signed registration for a
    /// domain that is neither listed here, nor already declared by the origin
    /// through a live mTLS registration, nor authorized by an org-key claim is
    /// retained for telemetry but never served. Default deny: empty.
    #[serde(default)]
    pub authorized_domains: Vec<String>,
}

use super::defaults::default_true;

fn default_registration_interval() -> u64 {
    60
}

fn default_sync_interval() -> u64 {
    30
}

fn default_verification_retry_interval() -> u64 {
    30
}

fn default_verification_timeout() -> u64 {
    600
}

fn default_upstream_dns_servers() -> Vec<String> {
    vec![]
}

impl Default for DnsMeshConfig {
    fn default() -> Self {
        Self {
            register_to_global: true,
            registration_interval_secs: default_registration_interval(),
            accept_registrations: true,
            sync_interval_secs: default_sync_interval(),
            upstream_dns_servers: default_upstream_dns_servers(),
            verification_retry_interval_secs: default_verification_retry_interval(),
            verification_timeout_secs: default_verification_timeout(),
            qname_minimization: true,
            require_cert_chain_verification: false,
            authorized_domains: Vec::new(),
        }
    }
}

impl DnsMeshConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if self.registration_interval_secs == 0 {
            return Err(DnsConfigError::InvalidMesh(
                "registration_interval_secs must be greater than zero".to_string(),
            ));
        }

        if self.sync_interval_secs == 0 {
            return Err(DnsConfigError::InvalidMesh(
                "sync_interval_secs must be greater than zero".to_string(),
            ));
        }

        for domain in &self.authorized_domains {
            let normalized = domain.trim().trim_end_matches('.');
            if normalized.is_empty() {
                return Err(DnsConfigError::InvalidMesh(
                    "authorized_domains entries must be non-empty domain names".to_string(),
                ));
            }
        }

        Ok(())
    }
}
