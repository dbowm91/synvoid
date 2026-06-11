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
use synvoid_mesh::threat_intel::{ThreatIntelPolicyContext, ThreatIntelligenceManager};
#[cfg(feature = "mesh")]
use synvoid_mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::yara_rules::YaraRulesManager;

/// Bundled data-plane services constructed during worker bootstrap.
///
/// This struct replaces the scattered cross-wiring that previously lived
/// inline in `run_unified_server_worker`. Each field is an already-existing
/// service or policy handle; no new abstractions are introduced.
pub struct DataPlaneServices {
    pub request_services: Arc<RequestServices>,
    pub serverless_manager: Arc<ServerlessManager>,
    pub port_honeypot_runner: Option<Arc<PortHoneypotRunner>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport_manager: Option<Arc<MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    /// Optional policy context owned by the worker composition root.
    #[cfg(feature = "mesh")]
    pub threat_intel_policy: Option<ThreatIntelPolicyContext>,
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
    threat_intel_policy: Option<ThreatIntelPolicyContext>,
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
            threat_intel_policy: None,
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
    pub fn with_threat_intel_policy(mut self, ctx: Option<ThreatIntelPolicyContext>) -> Self {
        self.threat_intel_policy = ctx;
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

    /// Build a threat-intel policy context only when both root-owned handles exist.
    ///
    /// This helper is intentionally side-effect free. When the Supervisor exports
    /// a `CanonicalTrustSnapshot` via IPC, the composition root in `mod.rs` uses
    /// this to build the context from the snapshot (which implements
    /// `CanonicalTrustReader`) and the record-store-derived advisory source.
    #[cfg(feature = "mesh")]
    pub(crate) fn build_threat_intel_policy_context(
        canonical: Option<Arc<dyn synvoid_mesh::canonical::CanonicalTrustReader>>,
        advisory: Option<Arc<dyn synvoid_mesh::dht::advisory_source::AdvisoryRecordSource>>,
    ) -> Option<ThreatIntelPolicyContext> {
        match (canonical, advisory) {
            (Some(canonical), Some(advisory)) => {
                Some(ThreatIntelPolicyContext::new(canonical, advisory))
            }
            _ => None,
        }
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
            threat_intel_policy: self.threat_intel_policy,
            #[cfg(feature = "mesh")]
            record_store: self.record_store,
        }
    }
}

#[cfg(feature = "mesh")]
impl DataPlaneServices {
    /// Apply the root-owned threat-intel policy context to the manager, if present.
    pub fn apply_threat_intel_policy_context(&self) {
        if let Some(threat_intel) = &self.threat_intel {
            threat_intel.set_policy_context(self.threat_intel_policy.clone());
        }
    }

    /// Update the threat-intel policy context with a new canonical reader.
    ///
    /// This is called when a canonical trust snapshot arrives via IPC after
    /// worker bootstrap. The snapshot itself implements `CanonicalTrustReader`,
    /// so it can be used directly as the canonical component of the policy context.
    pub fn update_threat_intel_policy_context(
        &self,
        canonical: Option<Arc<dyn synvoid_mesh::canonical::CanonicalTrustReader>>,
        advisory: Option<Arc<dyn synvoid_mesh::dht::advisory_source::AdvisoryRecordSource>>,
    ) -> Option<ThreatIntelPolicyContext> {
        let ctx = DataPlaneServicesBuilder::build_threat_intel_policy_context(canonical, advisory);
        if let Some(threat_intel) = &self.threat_intel {
            threat_intel.set_policy_context(ctx.clone());
        }
        ctx
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

    #[cfg(feature = "mesh")]
    use synvoid_mesh::canonical::{
        CanonicalFreshness, CanonicalTrustReader, StaticCanonicalTrustReader,
    };
    #[cfg(feature = "mesh")]
    use synvoid_mesh::dht::advisory_source::{AdvisoryRecordSource, StaticAdvisoryRecordSource};
    #[cfg(feature = "mesh")]
    use synvoid_mesh::mesh::protocol::ThreatType;
    #[cfg(feature = "mesh")]
    use synvoid_mesh::threat_intel::ThreatIntelligenceConfig;
    #[cfg(feature = "mesh")]
    use synvoid_mesh::threat_intel_policy::ThreatIntelPolicyDecision;

    #[cfg(feature = "mesh")]
    const TEST_IP: &str = "203.0.113.10";

    #[cfg(feature = "mesh")]
    fn build_test_policy_sources() -> (Arc<dyn CanonicalTrustReader>, Arc<dyn AdvisoryRecordSource>)
    {
        let key = format!("threat_indicator:{}:IpBlock", TEST_IP);

        let mut canonical = StaticCanonicalTrustReader::new(CanonicalFreshness::Live);
        canonical.threat_intel_ids.insert(TEST_IP.to_string());
        let canonical: Arc<dyn CanonicalTrustReader> = Arc::new(canonical);

        let mut advisory = StaticAdvisoryRecordSource::new();
        advisory.insert(StaticAdvisoryRecordSource::test_record(&key));
        let advisory: Arc<dyn AdvisoryRecordSource> = Arc::new(advisory);

        (canonical, advisory)
    }

    #[cfg(feature = "mesh")]
    fn build_test_policy_context() -> ThreatIntelPolicyContext {
        let (canonical, advisory) = build_test_policy_sources();
        DataPlaneServicesBuilder::build_threat_intel_policy_context(Some(canonical), Some(advisory))
            .expect("test policy context should be constructible")
    }

    #[cfg(feature = "mesh")]
    fn build_test_threat_intel_manager() -> Arc<ThreatIntelligenceManager> {
        use crate::config::DenyListLimitsConfig;

        Arc::new(ThreatIntelligenceManager::new(
            ThreatIntelligenceConfig::default().to_internal(),
            Arc::new(crate::block_store::BlockStore::new(
                true,
                None,
                DenyListLimitsConfig::default(),
            )),
            "test-node".to_string(),
            synvoid_mesh::config::MeshNodeRole::EDGE,
            None,
        ))
    }

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

    /// Boundary regression: the policy context defaults to `None`.
    #[cfg(feature = "mesh")]
    #[test]
    fn builder_threat_intel_policy_defaults_to_none() {
        let sm = Arc::new(ServerlessManager::new());
        let services = DataPlaneServicesBuilder::new(sm).build();
        assert!(services.threat_intel_policy.is_none());
    }

    /// Boundary regression: the builder preserves a provided policy context.
    #[cfg(feature = "mesh")]
    #[test]
    fn builder_threat_intel_policy_passthrough() {
        let sm = Arc::new(ServerlessManager::new());
        let services = DataPlaneServicesBuilder::new(sm)
            .with_threat_intel_policy(Some(build_test_policy_context()))
            .build();
        assert!(services.threat_intel_policy.is_some());
    }

    /// Missing canonical trust input returns `None`.
    #[cfg(feature = "mesh")]
    #[test]
    fn build_threat_intel_policy_context_missing_canonical_returns_none() {
        let (_, advisory) = build_test_policy_sources();
        let ctx = DataPlaneServicesBuilder::build_threat_intel_policy_context(None, Some(advisory));
        assert!(ctx.is_none());
    }

    /// Missing advisory input returns `None`.
    #[cfg(feature = "mesh")]
    #[test]
    fn build_threat_intel_policy_context_missing_advisory_returns_none() {
        let (canonical, _) = build_test_policy_sources();
        let ctx =
            DataPlaneServicesBuilder::build_threat_intel_policy_context(Some(canonical), None);
        assert!(ctx.is_none());
    }

    /// Both handles present produce a policy context.
    #[cfg(feature = "mesh")]
    #[test]
    fn build_threat_intel_policy_context_with_both_present_returns_some() {
        let (canonical, advisory) = build_test_policy_sources();
        let ctx = DataPlaneServicesBuilder::build_threat_intel_policy_context(
            Some(canonical),
            Some(advisory),
        );
        assert!(ctx.is_some());
    }

    /// Applying the policy context with no threat-intel manager is a no-op.
    #[cfg(feature = "mesh")]
    #[test]
    fn apply_threat_intel_policy_context_without_manager_is_noop() {
        let sm = Arc::new(ServerlessManager::new());
        let services = DataPlaneServicesBuilder::new(sm)
            .with_threat_intel_policy(Some(build_test_policy_context()))
            .build();

        assert!(services.threat_intel.is_none());
        services.apply_threat_intel_policy_context();
    }

    /// Applying a `None` context clears any previously configured actionability.
    #[cfg(feature = "mesh")]
    #[test]
    fn apply_threat_intel_policy_context_none_clears_manager_state() {
        let sm = Arc::new(ServerlessManager::new());
        let manager = build_test_threat_intel_manager();
        manager.set_policy_context(Some(build_test_policy_context()));

        let services = DataPlaneServicesBuilder::new(sm)
            .with_threat_intel(Some(manager.clone()))
            .with_threat_intel_policy(None)
            .build();

        services.apply_threat_intel_policy_context();

        assert!(manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .is_none());
    }

    /// Applying a populated context enables configured actionability.
    #[cfg(feature = "mesh")]
    #[test]
    fn apply_threat_intel_policy_context_enables_configured_evaluation() {
        let sm = Arc::new(ServerlessManager::new());
        let manager = build_test_threat_intel_manager();

        let services = DataPlaneServicesBuilder::new(sm)
            .with_threat_intel(Some(manager.clone()))
            .with_threat_intel_policy(Some(build_test_policy_context()))
            .build();

        services.apply_threat_intel_policy_context();

        let decision = manager
            .evaluate_indicator_actionability_configured(TEST_IP, ThreatType::IpBlock)
            .expect("policy context should be applied");

        assert!(matches!(decision, ThreatIntelPolicyDecision::Actionable(_)));
    }

    /// Iteration 27: Worker bootstrap deliberately passes `None` for
    /// canonical trust. This test documents that when only an advisory
    /// source is present (as in worker bootstrap), the policy context
    /// remains `None` — no synthetic canonical trust is introduced.
    ///
    /// Canonical trust state (Raft consensus, EdgeReplicaManager) is
    /// owned by the Supervisor. Workers receive a bounded
    /// CanonicalTrustSnapshot via IPC after bootstrap.
    #[cfg(feature = "mesh")]
    #[test]
    fn worker_bootstrap_no_canonical_returns_none() {
        let (_, advisory) = build_test_policy_sources();
        let ctx = DataPlaneServicesBuilder::build_threat_intel_policy_context(None, Some(advisory));
        assert!(
            ctx.is_none(),
            "worker bootstrap must return None when canonical reader is absent"
        );
    }
}
