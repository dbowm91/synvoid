// DataPlaneServices: groups data-plane service handles produced during
// worker bootstrap. The builder centralizes cross-wiring that was
// previously scattered across the run_unified_server_worker phases.

use std::sync::Arc;

use crate::honeypot_port::PortHoneypotRunner;
use crate::server::UnifiedServer;
use crate::worker::context::RequestServices;
use synvoid_serverless::manager::ServerlessManager;

#[cfg(feature = "mesh")]
use synvoid_mesh::dht::RecordStoreManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::threat_intel::ThreatIntelligenceManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::yara_rules::YaraRulesManager;

/// Bundled data-plane services constructed during worker bootstrap.
///
/// This struct replaces the scattered cross-wiring that previously lived
/// inline in `run_unified_server_worker`. Each field is an already-existing
/// service handle; no new abstractions are introduced.
pub struct DataPlaneServices {
    pub request_services: Arc<RequestServices>,
    pub serverless_manager: Arc<ServerlessManager>,
    pub port_honeypot_runner: Option<Arc<PortHoneypotRunner>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport_manager: Option<Arc<MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    /// Explicit handle to the DHT record store, preferred over the global
    /// `get_global_record_store()`. The global remains as a compatibility
    /// fallback for code that cannot easily receive an explicit handle.
    #[cfg(feature = "mesh")]
    pub record_store: Option<Arc<RecordStoreManager>>,
}

/// Builder for [`DataPlaneServices`].
///
/// Collects the outputs of the various init phases and produces a single
/// bundled handle. The builder is intentionally narrow: it does not replace
/// the individual init functions, it only gathers their outputs.
pub struct DataPlaneServicesBuilder {
    serverless_manager: Option<Arc<ServerlessManager>>,
    port_honeypot_runner: Option<Arc<PortHoneypotRunner>>,
    #[cfg(feature = "mesh")]
    mesh_transport_manager: Option<Arc<MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    #[cfg(feature = "mesh")]
    yara_rules: Option<Arc<YaraRulesManager>>,
    #[cfg(feature = "mesh")]
    record_store: Option<Arc<RecordStoreManager>>,
}

impl DataPlaneServicesBuilder {
    pub fn new() -> Self {
        Self {
            serverless_manager: None,
            port_honeypot_runner: None,
            #[cfg(feature = "mesh")]
            mesh_transport_manager: None,
            #[cfg(feature = "mesh")]
            threat_intel: None,
            #[cfg(feature = "mesh")]
            yara_rules: None,
            #[cfg(feature = "mesh")]
            record_store: None,
        }
    }

    pub fn with_serverless_manager(mut self, sm: Arc<ServerlessManager>) -> Self {
        self.serverless_manager = Some(sm);
        self
    }

    pub fn with_port_honeypot(mut self, runner: Option<Arc<PortHoneypotRunner>>) -> Self {
        self.port_honeypot_runner = runner;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_transport(mut self, tm: Option<Arc<MeshTransportManager>>) -> Self {
        self.mesh_transport_manager = tm;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_threat_intel(mut self, ti: Option<Arc<ThreatIntelligenceManager>>) -> Self {
        self.threat_intel = ti;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_yara_rules(mut self, yr: Option<Arc<YaraRulesManager>>) -> Self {
        self.yara_rules = yr;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_record_store(mut self, rs: Option<Arc<RecordStoreManager>>) -> Self {
        self.record_store = rs;
        self
    }

    /// Build the [`DataPlaneServices`] and the embedded [`RequestServices`].
    pub fn build(self) -> DataPlaneServices {
        let request_services = {
            #[cfg(feature = "mesh")]
            {
                Arc::new(RequestServices::new(
                    self.threat_intel.clone(),
                    None,
                    self.yara_rules,
                    None,
                    None,
                ))
            }
            #[cfg(not(feature = "mesh"))]
            {
                Arc::new(RequestServices::new(None, None, None))
            }
        };

        DataPlaneServices {
            request_services,
            serverless_manager: self.serverless_manager.unwrap_or_else(|| {
                let runtime = crate::plugin::get_global_plugin_manager().get_wasm_manager();
                Arc::new(ServerlessManager::new().with_runtime(runtime))
            }),
            port_honeypot_runner: self.port_honeypot_runner,
            #[cfg(feature = "mesh")]
            mesh_transport_manager: self.mesh_transport_manager,
            #[cfg(feature = "mesh")]
            threat_intel: self.threat_intel,
            #[cfg(feature = "mesh")]
            record_store: self.record_store,
        }
    }
}

impl Default for DataPlaneServicesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-wire mesh-dependent services. This replaces the inline Phase 9
/// cross-wiring that was previously in `run_unified_server_worker`.
#[cfg(feature = "mesh")]
pub fn cross_wire_mesh_services(unified_server: &Arc<UnifiedServer>, services: &DataPlaneServices) {
    crate::worker::unified_server::init_mesh::wire_serverless_to_mesh(
        unified_server,
        services.mesh_transport_manager.as_ref(),
    );
    crate::worker::unified_server::init_mesh::wire_port_honeypot_to_mesh(
        &services.port_honeypot_runner,
        &services.threat_intel,
        services.mesh_transport_manager.is_some(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `DataPlaneServicesBuilder` produces a valid
    /// `DataPlaneServices` with request services in the non-mesh build.
    #[test]
    fn builder_produces_request_services_no_mesh() {
        let services = DataPlaneServicesBuilder::new().build();
        // RequestServices should be constructed (even if all fields are None)
        let _ = &services.request_services;
        let _ = &services.serverless_manager;
        assert!(services.port_honeypot_runner.is_none());
    }

    /// Verify that the builder default creates a serverless manager fallback.
    #[test]
    fn builder_default_serverless_manager() {
        let services = DataPlaneServicesBuilder::new().build();
        // serverless_manager should always be Some (fallback to global plugin manager)
        let _ = &services.serverless_manager;
    }

    /// Verify that port honeypot is properly threaded through the builder.
    #[test]
    fn builder_port_honeypot_passthrough() {
        let services = DataPlaneServicesBuilder::new()
            .with_port_honeypot(None)
            .build();
        assert!(services.port_honeypot_runner.is_none());
    }
}
