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
    /// Phase 132: a declared zone must be activatable.
    ///
    /// Config-declared zones are activated at server startup, and
    /// `DnsServer::load_zones` rejects a zone carrying no SOA record
    /// (RFC 1035 §3.3.13 requires at least one SOA per authoritative zone).
    /// A record-less entry is therefore a configuration error rather than an
    /// inert value: it can never do what it appears to declare.
    ///
    /// An **empty** `items` list stays valid — a server with no configured
    /// zones is a legitimate recursive-only or empty-authoritative
    /// deployment, and that is what the default config uses.
    pub fn validate(&self) -> Result<(), DnsConfigError> {
        for zone in &self.items {
            if zone.zone.trim().is_empty() {
                return Err(DnsConfigError::InvalidZone(
                    "zone origin cannot be empty".to_string(),
                ));
            }

            if zone.records.is_empty() {
                return Err(DnsConfigError::InvalidZone(format!(
                    "zone '{}' declares no records; an authoritative zone must \
                     contain at least one SOA record (RFC 1035 section 3.3.13)",
                    zone.zone
                )));
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
