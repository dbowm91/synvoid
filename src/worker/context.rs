use std::sync::Arc;

#[cfg(feature = "mesh")]
use crate::mesh::threat_intel::ThreatIntelligenceManager;
#[cfg(feature = "mesh")]
use crate::mesh::yara_rules::YaraRulesManager;
use crate::plugin::GlobalPluginManager;
use crate::serverless::registry::ServerlessRegistry;
use crate::upload::UploadValidator;

pub struct RequestServices {
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    pub upload_validator: Option<Arc<UploadValidator>>,
    #[cfg(feature = "mesh")]
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
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
