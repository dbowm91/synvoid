//! Narrow capability traits for request-path code.
//!
//! These traits decouple request-path modules from concrete control-plane,
//! mesh, and supervisor infrastructure. Request-path code should consume
//! `Arc<dyn Trait>` instead of concrete types.

use std::net::IpAddr;
use std::sync::Arc;

/// Request-time threat intelligence lookup capability.
///
/// Provides read-only access to threat indicators for request-path
/// evaluation. This trait decouples WAF/request code from the concrete
/// `ThreatIntelligenceManager`.
///
/// # Scope
///
/// This trait is intentionally narrow: it exposes only diagnostic and
/// read-only lookup behavior needed by request-path code. Mutation
/// operations (adding indicators, policy updates) remain on the concrete
/// manager and are owned by the composition root.
pub trait ThreatIntelLookup: Send + Sync + 'static {
    /// Check if an IP address is a known threat indicator.
    fn is_known_threat_ip(&self, ip: IpAddr) -> bool;

    /// Get the threat level for an IP address, if available.
    fn threat_level_for_ip(&self, ip: IpAddr) -> Option<u8>;
}

/// Request-time behavioral intelligence lookup capability.
///
/// Provides read-only access to behavioral fingerprints for request-path
/// bot detection. This trait decouples WAF code from the concrete
/// `BehavioralIntelligenceManager`.
pub trait BehavioralIntelLookup: Send + Sync + 'static {
    /// Check if a behavioral fingerprint matches known attack patterns.
    fn matches_known_pattern(&self, fingerprint: &[u8]) -> bool;

    /// Get the confidence score for a behavioral pattern, if available.
    fn pattern_confidence(&self, fingerprint: &[u8]) -> Option<f64>;
}

/// Adapter that wraps a concrete `ThreatIntelligenceManager` behind the
/// narrow `ThreatIntelLookup` trait.
pub struct ThreatIntelLookupAdapter<T> {
    inner: Arc<T>,
}

impl<T> ThreatIntelLookupAdapter<T> {
    pub fn new(inner: Arc<T>) -> Self {
        Self { inner }
    }
}

/// Adapter that wraps a concrete `BehavioralIntelligenceManager` behind the
/// narrow `BehavioralIntelLookup` trait.
pub struct BehavioralIntelLookupAdapter<T> {
    inner: Arc<T>,
}

impl<T> BehavioralIntelLookupAdapter<T> {
    pub fn new(inner: Arc<T>) -> Self {
        Self { inner }
    }
}
