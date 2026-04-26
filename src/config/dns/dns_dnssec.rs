use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::defaults::default_true;
use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct DnsSecConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub domain: String,

    #[serde(default = "default_dnssec_key_path")]
    pub key_path: String,

    #[serde(default = "default_rollover_interval")]
    pub rollover_interval_days: u32,

    #[serde(default)]
    pub algorithm: super::DnsSecAlgorithm,

    #[serde(default = "default_rsa_key_size")]
    pub rsa_key_size: u32,

    #[serde(default = "default_ksk_key_size")]
    pub ksk_key_size: u32,

    #[serde(default = "default_true")]
    pub nsec3_enabled: bool,

    #[serde(default)]
    pub nsec_enabled: bool,

    #[serde(default = "default_nsec3_iterations")]
    pub nsec3_iterations: u16,

    #[serde(default = "default_nsec3_algorithm")]
    pub nsec3_algorithm: u8,

    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,

    #[serde(default)]
    pub hsm: HsmConfig,
}

fn default_dnssec_key_path() -> String {
    "/var/lib/maluwaf/dns/keys".to_string()
}

fn default_rollover_interval() -> u32 {
    30
}

fn default_rsa_key_size() -> u32 {
    2048
}

fn default_ksk_key_size() -> u32 {
    4096
}

fn default_nsec3_iterations() -> u16 {
    50
}

fn default_nsec3_algorithm() -> u8 {
    1
}

impl Default for DnsSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: String::new(),
            key_path: default_dnssec_key_path(),
            rollover_interval_days: default_rollover_interval(),
            algorithm: super::DnsSecAlgorithm::Ed25519,
            rsa_key_size: default_rsa_key_size(),
            ksk_key_size: default_ksk_key_size(),
            nsec3_enabled: default_true(),
            nsec_enabled: false,
            nsec3_iterations: default_nsec3_iterations(),
            nsec3_algorithm: default_nsec3_algorithm(),
            tsig_keys: Vec::new(),
            hsm: HsmConfig::default(),
        }
    }
}

impl DnsSecConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.domain.is_empty() {
            return Err(DnsConfigError::InvalidDnsSec(
                "domain must be specified when DNSSEC is enabled".to_string(),
            ));
        }

        if self.key_path.is_empty() {
            return Err(DnsConfigError::InvalidDnsSec(
                "key_path must be specified when DNSSEC is enabled".to_string(),
            ));
        }

        match self.algorithm {
            super::DnsSecAlgorithm::RsaSha256 => {
                if self.rsa_key_size < 1024 || self.rsa_key_size > 4096 {
                    return Err(DnsConfigError::InvalidDnsSec(
                        "rsa_key_size must be between 1024 and 4096".to_string(),
                    ));
                }
            }
            super::DnsSecAlgorithm::Ed25519 => {}
        }

        if self.rollover_interval_days == 0 {
            return Err(DnsConfigError::InvalidDnsSec(
                "rollover_interval_days must be greater than zero".to_string(),
            ));
        }

        if self.nsec3_algorithm != 1 && self.nsec3_algorithm != 2 {
            return Err(DnsConfigError::InvalidDnsSec(
                "nsec3_algorithm must be 1 (SHA-1) or 2 (SHA-256)".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
#[serde(default)]
pub struct HsmConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub provider: HsmProvider,

    #[serde(default)]
    pub module_path: String,

    #[serde(default)]
    pub slot_id: Option<usize>,

    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum HsmProvider {
    #[default]
    Pkcs11,
    Soft,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum TsigAlgorithm {
    #[default]
    HmacSha256,
    HmacSha1,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    pub fn to_u16(&self) -> u16 {
        match self {
            TsigAlgorithm::HmacSha256 => 161,
            TsigAlgorithm::HmacSha1 => 249,
            TsigAlgorithm::HmacSha384 => 170,
            TsigAlgorithm::HmacSha512 => 172,
        }
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            161 => Some(TsigAlgorithm::HmacSha256),
            249 => Some(TsigAlgorithm::HmacSha1),
            170 => Some(TsigAlgorithm::HmacSha384),
            172 => Some(TsigAlgorithm::HmacSha512),
            _ => None,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            TsigAlgorithm::HmacSha256 => 32,
            TsigAlgorithm::HmacSha1 => 20,
            TsigAlgorithm::HmacSha384 => 48,
            TsigAlgorithm::HmacSha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, ToSchema)]
#[serde(default)]
pub struct TsigKeyConfig {
    pub name: String,
    pub secret_base64: String,
    #[serde(default)]
    pub algorithm: TsigAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(default)]
pub struct TrustAnchorConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_db_path")]
    pub db_path: String,

    #[serde(default = "default_trust_anchor_path")]
    pub anchor_file_path: String,

    #[serde(default = "default_trust_anchor_refresh")]
    pub refresh_interval_secs: u64,

    #[serde(default = "default_pending_observation")]
    pub pending_observation_days: u64,

    #[serde(default = "default_revocation_grace")]
    pub revocation_grace_days: u64,

    #[serde(default = "default_extended_removal")]
    pub extended_removal_days: u64,

    #[serde(default = "default_trust_anchor_retention")]
    pub trust_anchor_retention_days: u64,

    #[serde(default)]
    pub allow_key_rotation: bool,
}

fn default_db_path() -> String {
    "/var/lib/maluwaf/dns/trust_anchors.db".to_string()
}

fn default_trust_anchor_path() -> String {
    "/var/lib/maluwaf/dns/trusted-key.key".to_string()
}

fn default_trust_anchor_refresh() -> u64 {
    3600
}

fn default_pending_observation() -> u64 {
    30
}

fn default_revocation_grace() -> u64 {
    30
}

fn default_extended_removal() -> u64 {
    60
}

fn default_trust_anchor_retention() -> u64 {
    7
}

impl Default for TrustAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            db_path: default_db_path(),
            anchor_file_path: default_trust_anchor_path(),
            refresh_interval_secs: default_trust_anchor_refresh(),
            pending_observation_days: default_pending_observation(),
            revocation_grace_days: default_revocation_grace(),
            extended_removal_days: default_extended_removal(),
            trust_anchor_retention_days: default_trust_anchor_retention(),
            allow_key_rotation: true,
        }
    }
}
