use std::sync::Arc;

use crate::plugin::GlobalPluginManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::mesh::behavioral::BehavioralFingerprint;
#[cfg(feature = "mesh")]
use synvoid_mesh::mesh::behavioral_intel::RequestFeatures;
#[cfg(feature = "mesh")]
use synvoid_mesh::yara_rules::YaraRulesManager;
use synvoid_serverless::registry::ServerlessRegistry;
use synvoid_upload::UploadValidator;

/// Narrow trait for request-time threat intelligence lookups.
///
/// Request-path code consumes `Arc<dyn ThreatIntelLookup>` instead of the
/// concrete `ThreatIntelligenceManager`. This decouples request dispatch
/// from control-plane infrastructure.
#[cfg(feature = "mesh")]
pub trait ThreatIntelLookup: Send + Sync + 'static {
    /// Check if an IP address is a known threat indicator.
    fn is_known_threat_ip(&self, ip: std::net::IpAddr) -> bool;

    /// Get the threat level for an IP address, if available.
    fn threat_level_for_ip(&self, ip: std::net::IpAddr) -> Option<u8>;
}

/// Narrow trait for request-time behavioral intelligence analysis.
///
/// Request-path code consumes `Arc<dyn BehavioralIntelLookup>` instead of the
/// concrete `BehavioralIntelligenceManager`. This decouples WAF attack detection
/// from mesh behavioral intelligence infrastructure.
#[cfg(feature = "mesh")]
pub trait BehavioralIntelLookup: Send + Sync + 'static {
    /// Analyze request features and return a behavioral fingerprint if a
    /// known pattern matches.
    fn analyze_request(&self, features: &RequestFeatures) -> Option<BehavioralFingerprint>;

    /// Adjust the paranoia level based on behavioral analysis.
    fn adjust_paranoia_level(&self, features: &RequestFeatures, base_paranoia: u8) -> u8;
}

/// Narrow service handle for request execution.
///
/// This type is intentionally smaller than `DataPlaneServices` and must not
/// grow lifecycle/supervision/shutdown dependencies. Add only services that
/// are required while handling a request.
///
/// # Ownership contract
///
/// - Consumed by WAF/request dispatch modules (installed via `set_request_services`)
/// - Built by `DataPlaneServicesBuilder::build()` — do not construct directly
/// - Must not import worker startup, supervision, or shutdown modules
/// - Must not carry mesh transport, IPC, or task registry handles
pub struct RequestServices {
    /// Threat intelligence lookup for request-time indicator evaluation.
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<dyn ThreatIntelLookup>>,
    /// Behavioral intelligence analysis for request-time bot detection.
    #[cfg(feature = "mesh")]
    pub behavioral_intel: Option<Arc<dyn BehavioralIntelLookup>>,
    /// Upload validator for request body size/type checks.
    pub upload_validator: Option<Arc<UploadValidator>>,
    /// YARA rules manager for content scanning.
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    /// Global plugin manager (currently unused by builder — legacy field).
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
    /// Serverless function registry (currently unused by builder — legacy field).
    pub serverless_registry: Option<Arc<ServerlessRegistry>>,
}

impl RequestServices {
    #[cfg(feature = "mesh")]
    pub fn new(
        threat_intel: Option<Arc<dyn ThreatIntelLookup>>,
        behavioral_intel: Option<Arc<dyn BehavioralIntelLookup>>,
        upload_validator: Option<Arc<UploadValidator>>,
        yara_rules: Option<Arc<YaraRulesManager>>,
        plugin_manager: Option<Arc<GlobalPluginManager>>,
        serverless_registry: Option<Arc<ServerlessRegistry>>,
    ) -> Self {
        Self {
            threat_intel,
            behavioral_intel,
            upload_validator,
            yara_rules,
            plugin_manager,
            serverless_registry,
        }
    }

    #[cfg(not(feature = "mesh"))]
    pub fn new(
        upload_validator: Option<Arc<UploadValidator>>,
        plugin_manager: Option<Arc<GlobalPluginManager>>,
        serverless_registry: Option<Arc<ServerlessRegistry>>,
    ) -> Self {
        Self {
            upload_validator,
            plugin_manager,
            serverless_registry,
        }
    }
}
