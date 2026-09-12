//! `ThreatIndicator` value struct (no policy, no storage).
//!
//! Copied verbatim from `synvoid-mesh/src/mesh/protocol.rs` (same field order,
//! same derives). Enforcement stays in `synvoid-mesh` threat-intel policy and
//! `synvoid-block-store`; this type is diagnostic carriage only.

use crate::wire::{ThreatSeverity, ThreatType};

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct ThreatIndicator {
    pub threat_type: ThreatType,
    pub indicator_value: String,
    pub severity: ThreatSeverity,
    pub reason: String,
    pub ttl_seconds: u64,
    pub source_node_id: String,
    pub timestamp: u64,
    pub site_scope: String,
    pub rate_limit_requests: Option<u64>,
    pub rate_limit_window_secs: Option<u64>,
    pub suspicious_pattern: Option<String>,
    pub signature: Vec<u8>,
    pub signer_public_key: Option<String>,
}

impl ThreatIndicator {
    /// Stable numeric codes matching the protobuf `ThreatIndicator` mapping in
    /// `synvoid-mesh` (`protocol_types.rs`).
    pub fn threat_type_code(&self) -> i32 {
        match self.threat_type {
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

    pub fn severity_code(&self) -> i32 {
        match self.severity {
            ThreatSeverity::Unspecified => 0,
            ThreatSeverity::Low => 1,
            ThreatSeverity::Medium => 2,
            ThreatSeverity::High => 3,
            ThreatSeverity::Critical => 4,
        }
    }
}
