//! Stable wire enums and contract errors.
//!
//! Definitions are copied verbatim from `synvoid-mesh/src/mesh/protocol.rs`
//! (same variant order, same derives) minus non-wire `schemars::JsonSchema`
//! derives, which do not affect serde byte representation. Any change here is
//! a wire-compatibility event and requires golden-vector updates plus an
//! explicit protocol-version decision.

/// Message categories (transport-level routing hint, not serialized on the wire
/// as a standalone enum; preserved here so classifiers agree).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageCategory {
    Handshake,
    Sync,
    Routing,
    Upstream,
    KeyExchange,
    Dht,
    Lookup,
    Health,
    Peer,
    Organization,
    ThreatIntel,
    Yara,
    Dns,
    Anycast,
    ZoneSync,
    Wasm,
    Config,
    System,
    Serverless,
}

impl MessageCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Handshake => "Handshake",
            Self::Sync => "Sync",
            Self::Routing => "Routing",
            Self::Upstream => "Upstream",
            Self::KeyExchange => "KeyExchange",
            Self::Dht => "DHT",
            Self::Lookup => "Lookup",
            Self::Health => "Health",
            Self::Peer => "Peer",
            Self::Organization => "Organization",
            Self::ThreatIntel => "ThreatIntel",
            Self::Yara => "YARA",
            Self::Dns => "DNS",
            Self::Anycast => "Anycast",
            Self::ZoneSync => "ZoneSync",
            Self::Wasm => "WASM",
            Self::Config => "Config",
            Self::System => "System",
            Self::Serverless => "Serverless",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AckStatus {
    Success,
    Processing,
    InvalidMessage,
    Unauthorized,
    NotFound,
    RateLimited,
    InternalError,
}

impl AckStatus {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AckStatus::Success,
            1 => AckStatus::Processing,
            2 => AckStatus::InvalidMessage,
            3 => AckStatus::Unauthorized,
            4 => AckStatus::NotFound,
            5 => AckStatus::RateLimited,
            6 => AckStatus::InternalError,
            _ => AckStatus::InternalError,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            AckStatus::Success => 0,
            AckStatus::Processing => 1,
            AckStatus::InvalidMessage => 2,
            AckStatus::Unauthorized => 3,
            AckStatus::NotFound => 4,
            AckStatus::RateLimited => 5,
            AckStatus::InternalError => 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AnnounceAction {
    Add,
    Update,
    Remove,
}

impl AnnounceAction {
    pub fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(AnnounceAction::Add),
            1 => Ok(AnnounceAction::Update),
            2 => Ok(AnnounceAction::Remove),
            _ => Err(format!("Unknown AnnounceAction value: {}", v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GlobalNodeAction {
    Add,
    Remove,
    UpdateKeyExchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LookupType {
    KeyValue,
    Route,
    Peer,
    Certificate,
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WasmModuleType {
    Plugin = 0,
    Serverless = 1,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum ThreatType {
    Unspecified,
    IpBlock,
    IpThrottle,
    RateLimitViolation,
    SuspiciousActivity,
    AsnBlock,
    DomainBlock,
    UrlBlock,
    CertBlock,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum ThreatSeverity {
    Unspecified,
    Low,
    Medium,
    High,
    Critical,
}

/// Contract decode errors for the protocol crate's own framing helpers and for
/// re-export compatibility with `synvoid-mesh::protocol::ProtocolError`.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Missing payload")]
    MissingPayload,
    #[error("Missing field: {0}")]
    MissingField(&'static str),
    #[error("Conversion error: {0}")]
    ConversionFailed(&'static str),
    #[error("Invalid value: {0}")]
    InvalidValue(&'static str),
    #[error("Invalid field: {0}")]
    InvalidField(&'static str),
    #[error("Decode error: {0}")]
    DecodeError(String),
}

impl From<ThreatSeverity> for i32 {
    fn from(s: ThreatSeverity) -> Self {
        match s {
            ThreatSeverity::Unspecified => 0,
            ThreatSeverity::Low => 1,
            ThreatSeverity::Medium => 2,
            ThreatSeverity::High => 3,
            ThreatSeverity::Critical => 4,
        }
    }
}

impl From<ThreatType> for i32 {
    fn from(t: ThreatType) -> Self {
        match t {
            ThreatType::Unspecified => 0,
            ThreatType::IpBlock => 1,
            ThreatType::IpThrottle => 2,
            ThreatType::RateLimitViolation => 3,
            ThreatType::SuspiciousActivity => 4,
            ThreatType::AsnBlock => 5,
            ThreatType::DomainBlock => 6,
            ThreatType::UrlBlock => 7,
            ThreatType::CertBlock => 8,
        }
    }
}
