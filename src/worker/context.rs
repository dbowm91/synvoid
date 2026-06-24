use std::sync::Arc;

use crate::plugin::GlobalPluginManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::threat_intel::ThreatIntelligenceManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::yara_rules::YaraRulesManager;
use synvoid_serverless::registry::ServerlessRegistry;
use synvoid_upload::UploadValidator;

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
    /// Threat intelligence manager for request-time indicator evaluation.
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
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
        threat_intel: Option<Arc<ThreatIntelligenceManager>>,
        upload_validator: Option<Arc<UploadValidator>>,
        yara_rules: Option<Arc<YaraRulesManager>>,
        plugin_manager: Option<Arc<GlobalPluginManager>>,
        serverless_registry: Option<Arc<ServerlessRegistry>>,
    ) -> Self {
        Self {
            threat_intel,
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
