use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::DnsConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema, ToSchema)]
pub struct DnsZonesConfig {
    #[serde(default)]
    pub items: Vec<DnsZoneEntry>,
}

impl DnsZonesConfig {
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        for zone in &self.items {
            if zone.zone.is_empty() {
                return Err(DnsConfigError::InvalidZones(
                    "Zone name cannot be empty".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct DnsZoneEntry {
    pub zone: String,

    #[serde(default)]
    pub records: Vec<DnsRecordEntry>,

    #[serde(default)]
    pub dnssec: Option<DnsZoneDnssecConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct DnsZoneDnssecConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub algorithm: Option<super::DnsSecAlgorithm>,

    #[serde(default)]
    pub nsec_enabled: bool,

    #[serde(default)]
    pub nsec3_enabled: bool,

    #[serde(default)]
    pub nsec3_iterations: Option<u16>,

    #[serde(default)]
    pub nsec3_algorithm: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DnsRecordType {
    A,
    Aaaa,
    CName,
    Mx,
    Txt,
    Ns,
    Soa,
    Srv,
    Ptr,
    Caa,
    Tlsa,
    Svcb,
    Https,
    Naptr,
    Sshfp,
    Uri,
    Rp,
    Afsdb,
    Ds,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct DnsRecordEntry {
    pub name: String,

    #[serde(default = "default_record_type_a")]
    pub record_type: DnsRecordType,

    pub value: String,

    #[serde(default = "default_record_ttl")]
    pub ttl: Option<u32>,

    #[serde(default)]
    pub priority: Option<u32>,
}

fn default_record_type_a() -> DnsRecordType {
    DnsRecordType::A
}

fn default_record_ttl() -> Option<u32> {
    None
}
