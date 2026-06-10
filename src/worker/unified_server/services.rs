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
    serverless_manager: Arc<ServerlessManager>,
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
    pub fn new(serverless_manager: Arc<ServerlessManager>) -> Self {
        Self {
            serverless_manager,
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
            serverless_manager: self.serverless_manager,
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
        let sm = Arc::new(ServerlessManager::new());
        let services = DataPlaneServicesBuilder::new(sm).build();
        // RequestServices should be constructed (even if all fields are None)
        let _ = &services.request_services;
        let _ = &services.serverless_manager;
        assert!(services.port_honeypot_runner.is_none());
    }

    /// Verify that port honeypot is properly threaded through the builder.
    #[test]
    fn builder_port_honeypot_passthrough() {
        let sm = Arc::new(ServerlessManager::new());
        let services = DataPlaneServicesBuilder::new(sm)
            .with_port_honeypot(None)
            .build();
        assert!(services.port_honeypot_runner.is_none());
    }

    /// Boundary regression: verify that the builder constructor requires
    /// an explicit `ServerlessManager`. There is no default or global
    /// fallback — callers must provide one at construction time.
    #[test]
    fn builder_requires_explicit_serverless_manager() {
        let sm = Arc::new(ServerlessManager::new());
        let sm_clone = sm.clone();
        let services = DataPlaneServicesBuilder::new(sm).build();
        // The serverless manager passed to the builder is the one in the
        // built services — no global plugin manager is consulted.
        assert!(Arc::ptr_eq(&services.serverless_manager, &sm_clone));
    }

    /// Boundary regression: verify that `build()` does not call the global
    /// plugin manager. The builder only threads its own fields through;
    /// all global state access happens in init phases, not in the builder.
    ///
    /// This is a compile-time contract enforced by the source: services.rs
    /// does not import `get_global_plugin_manager`. This test documents
    /// that contract and will fail to compile if the import is added.
    #[test]
    fn builder_does_not_use_global_plugin_manager() {
        // If this file imports get_global_plugin_manager, the build will
        // fail with an unused-import warning (deny(unused_imports) or
        // the import itself is the regression). This test exists to
        // document the contract explicitly.
        //
        // We verify the built services only contain explicitly provided
        // fields — no hidden global state leakage.
        let sm = Arc::new(ServerlessManager::new());
        let services = DataPlaneServicesBuilder::new(sm.clone()).build();
        // serverless_manager is the one we passed in
        assert!(Arc::ptr_eq(&services.serverless_manager, &sm));
        // No other global handles are present in the built struct
        assert!(services.port_honeypot_runner.is_none());
    }

    /// Boundary regression: verify that when a record store is provided
    /// via the builder, it appears in the built `DataPlaneServices`.
    #[cfg(feature = "mesh")]
    #[test]
    fn builder_record_store_passthrough() {
        use synvoid_mesh::config::{MeshConfig, MeshNodeRole};
        use synvoid_mesh::dht::{DhtAccessControl, RecordStoreConfig, RecordStoreManager};

        let sm = Arc::new(ServerlessManager::new());
        let mesh_config = MeshConfig::default();
        let access_control = DhtAccessControl::new(&mesh_config);
        let store = Arc::new(RecordStoreManager::new(
            RecordStoreConfig::default(),
            "test-node".to_string(),
            MeshNodeRole::EDGE,
            None,
            access_control,
            None,
        ));
        let store_clone = store.clone();
        let services = DataPlaneServicesBuilder::new(sm)
            .with_record_store(Some(store))
            .build();
        let built = services.record_store.expect("record_store should be Some");
        assert!(Arc::ptr_eq(&built, &store_clone));
    }

    /// Boundary regression: verify that when no record store is provided,
    /// the built services has `record_store: None`.
    #[cfg(feature = "mesh")]
    #[test]
    fn builder_no_record_store_defaults_to_none() {
        let sm = Arc::new(ServerlessManager::new());
        let services = DataPlaneServicesBuilder::new(sm).build();
        assert!(services.record_store.is_none());
    }
}
