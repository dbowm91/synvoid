// Submodule: Mesh + Threat Intelligence + YARA rules initialization.
//
// This is a behavior-preserving extraction of the original
// `run_unified_server_worker` mesh block. The function returns a
// `MeshInit` of optional resources so the orchestrator can wire them
// into the rest of the worker.
//
// ## Canonical Reader Ownership (Iteration 28)
//
// Canonical trust state (Raft consensus, EdgeReplicaManager) is
// owned by the Supervisor process. Workers receive a bounded
// `CanonicalTrustSnapshot` via IPC. The snapshot itself implements
// `CanonicalTrustReader` and is carried in `MeshInit` so the
// composition root can use it to build the policy context.
//
// Task Ownership Inventory (Iteration 84 Part F):
//
// Task                                     | Correct Owner              | Start Phase       | Stop Signal              | Join Path                      | Restart Generation
// -----------------------------------------|----------------------------|-------------------|--------------------------|--------------------------------|--------------------
// topology.start_background_tasks()        | Mesh topology              | transport init    | mesh shutdown            | mesh task group                | per-generation
// routing_manager.init()                   | WorkerTaskRegistry         | Phase 13.5        | registry shutdown        | registry join                  | N/A (one-shot)
// DnsRegistry verification loops           | WorkerTaskRegistry         | Phase 13.5        | registry shutdown        | registry join                  | per-generation
// threat_intel.start_background_tasks()    | Threat intel               | transport init    | mesh shutdown            | mesh task group                | per-generation
// YARA broadcast loop                      | WorkerTaskRegistry         | Phase 13.5        | mpsc sender drop         | registry join                  | per-generation
//
// All bare spawns have been eliminated from this file.
// Components are returned in MeshInit for the composition root
// (mod.rs Phase 13.5) to spawn and register in WorkerTaskRegistry.

use std::sync::Arc;

use tokio::sync::RwLock;

#[cfg(feature = "mesh")]
use synvoid_mesh::threat_intel::ThreatIntelligenceManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::transports::MeshTransportManager;

use crate::server::UnifiedServer;
use synvoid_config::ConfigManager;

/// Bundled resources produced by the mesh initialization phase.
///
/// # Canonical Reader Ownership (Iteration 28)
///
/// Workers receive a `CanonicalTrustSnapshot` from the Supervisor via IPC.
/// The snapshot itself implements `CanonicalTrustReader` and can be used
/// directly to build the threat-intel policy context. The ownership
/// boundary is documented in `mod.rs`.
///
/// # Task Ownership (Iteration 84 Part F)
///
/// Background tasks (DNS verification loops, YARA broadcast, DHT routing
/// init) are NOT spawned in this function. Instead, the components needed
/// to spawn them are returned here so the composition root in `mod.rs`
/// can register them in the `WorkerTaskRegistry`.
pub struct MeshInit {
    #[cfg(feature = "mesh")]
    pub transport_manager: Option<Arc<MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    /// Canonical trust snapshot from Supervisor, if available.
    #[cfg(feature = "mesh")]
    pub canonical_snapshot: Option<synvoid_mesh::canonical::CanonicalTrustSnapshot>,
    /// DNS verification registries that need verification loops spawned.
    /// Each entry is a (registry, is_global) pair.
    #[cfg(all(feature = "mesh", feature = "dns"))]
    pub dns_verification_registries: Vec<(Arc<crate::dns::mesh_sync::MeshDnsRegistry>, bool)>,
    /// Components for the YARA broadcast loop: (mpsc_receiver, mesh_transport, semaphore).
    #[cfg(all(feature = "mesh", feature = "dns"))]
    pub yara_broadcast: Option<(
        tokio::sync::mpsc::Receiver<crate::mesh::protocol::MeshMessage>,
        Arc<crate::mesh::transport::MeshTransport>,
        Arc<tokio::sync::Semaphore>,
    )>,
    /// DHT routing manager for one-shot init task (if routing is enabled).
    #[cfg(feature = "mesh")]
    pub dht_routing_init: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
}

/// Initialize the mesh + threat-intel subsystem. Returns
/// `(Option<Arc<MeshTransportManager>>, Option<Arc<ThreatIntelligenceManager>>,
/// Option<Arc<MeshMessageSigner>>)`. When the `mesh` feature is disabled, all
/// three are `None`.
///
/// This is a direct extraction of the mesh init block from
/// `run_unified_server_worker`; the only behavioral change is that the
/// original code path was inside a giant async fn, while this is a
/// standalone function.
pub async fn init_mesh_and_threat_intel(
    shared_config: &Arc<RwLock<ConfigManager>>,
    config_path: &std::path::Path,
    unified_server: &Arc<UnifiedServer>,
) -> MeshInit {
    #[cfg(feature = "mesh")]
    {
        let mesh_config_external = {
            let config = shared_config.read().await;
            config.main.tunnel.mesh.clone()
        };

        let mesh_config: Option<crate::mesh::config::MeshConfig> = mesh_config_external
            .map(|c| serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap());

        if let Some(ref mesh_config) = mesh_config {
            // Phase 3: Mesh Control Plane is relegated to the Supervisor process.
            // Workers act as dumb data-planes and receive intelligence via IPC.
            //
            // Iteration 28-30: Canonical trust state (Raft consensus,
            // EdgeReplicaManager) is owned by the Supervisor. During init,
            // workers have no access to a SnapshotCanonicalTrustReader or
            // EdgeReplicaManager — the snapshot arrives later via IPC
            // (CanonicalTrustSnapshotUpdate) and is handled in lifecycle.rs.
            let node_id = mesh_config.node_id();
            let mesh_config_arc = Arc::new(mesh_config.clone());

            let topology = Arc::new(crate::mesh::topology::MeshTopology::new(
                mesh_config_arc.clone(),
            ));
            topology.start_background_tasks();

            let routing_manager = if mesh_config
                .dht
                .as_ref()
                .map(|d| d.routing_enabled)
                .unwrap_or(false)
            {
                let manager = Arc::new(crate::mesh::dht::routing::DhtRoutingManager::new(
                    mesh_config_arc.clone(),
                ));
                manager.start_background_tasks();
                Some(manager)
            } else {
                None
            };

            let verification_pool =
                Arc::new(crate::mesh::crypto_verification::CryptoVerificationPool::default());

            // Clone routing_manager before it's moved into create_record_store.
            #[cfg(feature = "mesh")]
            let dht_routing_init_for_spawn = routing_manager.clone();

            let record_store = crate::mesh::backend::create_record_store(
                mesh_config,
                routing_manager,
                Some(verification_pool.clone()),
            );

            let transport_manager = Arc::new(MeshTransportManager::new(
                mesh_config_arc.clone(),
                topology.clone(),
                record_store.clone(),
            ));

            let proxy = Arc::new(crate::mesh::proxy::MeshProxy::new(
                mesh_config_arc.clone(),
                topology.clone(),
                None,
            ));
            let _ = &proxy;

            // Use global_node_key if available, otherwise HKDF-derive from node_id.
            let signer_key = if let Some(ref key) = mesh_config.global_node_key {
                let mut key_bytes = [0u8; 32];
                let key_str = key.as_bytes();
                let len = key_str.len().min(32);
                key_bytes[..len].copy_from_slice(&key_str[..len]);
                key_bytes
            } else {
                use hkdf::Hkdf;
                use sha2::Sha256;
                let ikm = node_id.as_bytes();
                let hk = Hkdf::<Sha256>::new(None, ikm);
                let mut okm = [0u8; 32];
                hk.expand(b"synvoid-mesh-signer", &mut okm)
                    .expect("HKDF expand failed");
                okm
            };

            let Some(block_store) = unified_server.get_block_store() else {
                tracing::warn!("BlockStore not initialized, skipping threat intelligence setup");
                return MeshInit {
                    transport_manager: None,
                    threat_intel: None,
                    mesh_signer: None,
                    canonical_snapshot: None,
                    #[cfg(all(feature = "mesh", feature = "dns"))]
                    dns_verification_registries: Vec::new(),
                    #[cfg(all(feature = "mesh", feature = "dns"))]
                    yara_broadcast: None,
                    #[cfg(feature = "mesh")]
                    dht_routing_init: None,
                };
            };

            let mesh_threat_intel = mesh_config.threat_intel.clone();

            let threat_config = crate::mesh::config::ThreatIntelligenceConfig {
                enabled: mesh_threat_intel.enabled,
                push_enabled: mesh_threat_intel.push_enabled,
                sync_enabled: mesh_threat_intel.sync_enabled,
                sync_interval_secs: mesh_threat_intel.sync_interval_secs,
                threat_sync_interval_secs: mesh_threat_intel.threat_sync_interval_secs,
                push_severity_threshold: mesh_threat_intel.push_severity_threshold,
                min_ttl_seconds: mesh_threat_intel.min_ttl_seconds,
                max_indicators_per_message: mesh_threat_intel.max_indicators_per_message,
                hub_only_mode: mesh_threat_intel.hub_only_mode,
                reputation_config: mesh_threat_intel.reputation_config.clone(),
                fanout_factor: mesh_threat_intel.fanout_factor,
                re_announce_interval_secs: mesh_threat_intel.re_announce_interval_secs,
                trusted_signers: mesh_threat_intel.trusted_signers.clone(),
                behavioral_enabled: mesh_threat_intel.behavioral_enabled,
                min_samples_for_fingerprint: mesh_threat_intel.min_samples_for_fingerprint,
                fingerprint_ttl_secs: mesh_threat_intel.fingerprint_ttl_secs,
                high_severity_threshold: mesh_threat_intel.high_severity_threshold,
            };

            let signer_for_threat = crate::mesh::protocol::MeshMessageSigner::new(signer_key)
                .with_verification_pool(verification_pool.clone());
            let signer_key_clone = signer_key;

            let threat_intel = Arc::new(ThreatIntelligenceManager::from_external_config(
                threat_config.clone(),
                block_store.clone(),
                node_id.clone(),
                mesh_config.role,
                Some(Arc::new(signer_for_threat)),
            ));

            // Iteration 84 Part F: Background task components are returned for
            // the composition root to spawn and register in WorkerTaskRegistry.
            // No bare tokio::spawn() calls remain in this function.
            #[cfg(all(feature = "mesh", feature = "dns"))]
            let mut dns_verification_registries: Vec<(
                Arc<crate::dns::mesh_sync::MeshDnsRegistry>,
                bool,
            )> = Vec::new();
            // Default values for components populated inside #[cfg(feature = "dns")].
            #[cfg(all(feature = "mesh", feature = "dns"))]
            let mut yara_broadcast: Option<(
                tokio::sync::mpsc::Receiver<crate::mesh::protocol::MeshMessage>,
                Arc<crate::mesh::transport::MeshTransport>,
                Arc<tokio::sync::Semaphore>,
            )> = None;
            #[cfg(feature = "mesh")]
            let mut dht_routing_init: Option<
                Arc<crate::mesh::dht::routing::DhtRoutingManager>,
            > = None;

            #[cfg(feature = "dns")]
            {
                let backend_pool = Arc::new(crate::mesh::backend::MeshBackendPool::new(
                    proxy.clone(),
                    topology.clone(),
                ));
                let signer_for_mesh =
                    crate::mesh::protocol::MeshMessageSigner::new(signer_key_clone)
                        .with_verification_pool(verification_pool.clone());

                {
                    let config = shared_config.read().await;
                    let dns_cfg = config.main.dns.clone();

                    if !dns_cfg.enabled {
                        if mesh_config.role.is_global() {
                            tracing::warn!(
                                "Global node has dns.enabled = false — global nodes are required \
                                 to serve DNS. DNS-dependent mesh features (verification, \
                                 zone signing) will be unavailable."
                            );
                        }
                    } else if !mesh_config.role.is_global() {
                        tracing::debug!(
                            "Edge node - DNS resolver not created (verification only on global nodes)"
                        );

                        let registry_config = crate::dns::mesh_sync::MeshDnsRegistryConfig {
                            verification_timeout_secs: dns_cfg.mesh.verification_timeout_secs,
                            verification_retry_interval_secs: dns_cfg
                                .mesh
                                .verification_retry_interval_secs,
                            require_cert_chain_verification: dns_cfg
                                .mesh
                                .require_cert_chain_verification,
                            ..Default::default()
                        };

                        let registry = crate::dns::mesh_sync::MeshDnsRegistry::with_config(
                            mesh_config.node_id(),
                            false,
                            registry_config,
                        );
                        // Iteration 84 Part F: Return registry for composition
                        // root to spawn and register in WorkerTaskRegistry.
                        dns_verification_registries.push((Arc::new(registry), false));
                    } else {
                        let upstream_servers: Vec<std::net::IpAddr> = dns_cfg
                            .mesh
                            .upstream_dns_servers
                            .iter()
                            .filter_map(|s| s.parse().ok())
                            .collect();

                        if upstream_servers.is_empty() {
                            tracing::warn!(
                                "No valid upstream DNS servers configured, DNS verification will not work"
                            );
                        } else {
                            match crate::dns::HickoryResolver::with_upstream_servers(
                                &upstream_servers,
                            ) {
                                Ok(resolver) => {
                                    tracing::info!(
                                        "Global node DNS resolver initialized with upstream servers: {:?}",
                                        upstream_servers
                                    );

                                    let registry_config =
                                        crate::dns::mesh_sync::MeshDnsRegistryConfig {
                                            verification_timeout_secs: dns_cfg
                                                .mesh
                                                .verification_timeout_secs,
                                            verification_retry_interval_secs: dns_cfg
                                                .mesh
                                                .verification_retry_interval_secs,
                                            require_cert_chain_verification: dns_cfg
                                                .mesh
                                                .require_cert_chain_verification,
                                            ..Default::default()
                                        };

                                    let registry =
                                        crate::dns::mesh_sync::MeshDnsRegistry::with_config(
                                            mesh_config.node_id(),
                                            true,
                                            registry_config,
                                        )
                                        .with_dns_resolver(resolver);

                                    // Iteration 84 Part F: Return registry for composition
                                    // root to spawn and register in WorkerTaskRegistry.
                                    dns_verification_registries.push((Arc::new(registry), true));
                                }
                                Err(e) => {
                                    tracing::error!("Failed to create DNS resolver: {}", e);
                                }
                            }
                        }
                    }
                }

                if let Err(e) = crate::mesh::backend::initialize_mesh_transports(
                    mesh_config,
                    transport_manager.clone(),
                    backend_pool,
                    Some(threat_intel.clone()),
                    Some(Arc::new(signer_for_mesh)),
                )
                .await
                {
                    tracing::warn!("Mesh transport initialization failed: {}", e);
                }
            }

            #[cfg(not(feature = "dns"))]
            {
                if mesh_config.role.is_global() {
                    tracing::warn!(
                        "Global node compiled without dns feature — DNS serving is unavailable. \
                         Global nodes are required to serve DNS."
                    );
                }
                let backend_pool = Arc::new(crate::mesh::backend::MeshBackendPool::new(
                    proxy.clone(),
                    topology.clone(),
                ));
                let signer_for_mesh =
                    crate::mesh::protocol::MeshMessageSigner::new(signer_key_clone)
                        .with_verification_pool(verification_pool.clone());
                if let Err(e) = crate::mesh::backend::initialize_mesh_transports(
                    &mesh_config,
                    transport_manager.clone(),
                    backend_pool,
                    Some(threat_intel.clone()),
                    Some(Arc::new(signer_for_mesh)),
                )
                .await
                {
                    tracing::warn!("Mesh transport initialization failed: {}", e);
                }
            }

            #[cfg(feature = "dns")]
            {
                yara_broadcast = {
                    let (mesh_broadcast_tx, mesh_broadcast_rx) =
                        tokio::sync::mpsc::channel::<crate::mesh::protocol::MeshMessage>(128);

                    threat_intel.set_mesh_sender(mesh_broadcast_tx.clone());

                    if let Some(quic_transport) = transport_manager.get_quic_transport() {
                        let mesh_transport = quic_transport.get_inner();
                        let broadcast_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
                        // Iteration 84 Part F: Return broadcast components for composition
                        // root to spawn and register in WorkerTaskRegistry.
                        Some((mesh_broadcast_rx, mesh_transport, broadcast_semaphore))
                    } else {
                        None
                    }
                };

                if mesh_config.role.is_global()
                    && mesh_config.global_node.key_exchange_enabled
                    && mesh_config.origin_signing_key.is_some()
                {
                    transport_manager.update_key_exchange_endpoint().await;
                }

                if mesh_config.role == crate::mesh::config::MeshNodeRole::EDGE
                    && mesh_config.global_node.key_exchange_enabled
                    && mesh_config.global_node.key_exchange_require_edge_auth
                {
                    if let Some(ref global_node_key) = mesh_config.global_node_key {
                        transport_manager
                            .announce_edge_key(&mesh_config.node_id(), global_node_key);
                    }
                }

                {
                    let capabilities = crate::mesh::protocol::MeshCapabilities::from_config(
                        mesh_config,
                        mesh_config.role,
                    );
                    if !capabilities.supported_services.is_empty() {
                        transport_manager.announce_capabilities(
                            &mesh_config.node_id(),
                            &capabilities.supported_services,
                        );
                    }
                }

                threat_intel.start_background_tasks();
                crate::waf::set_threat_intel(threat_intel.clone());

                // Register mesh DHT provider for WASM plugin runtime
                if let Some(record_store) = transport_manager.get_record_store() {
                    struct MeshDhtAdapter(Arc<crate::mesh::dht::RecordStoreManager>);

                    impl synvoid_plugin_runtime::mesh_callbacks::MeshDhtProvider for MeshDhtAdapter {
                        fn get_record(&self, key: &str) -> Option<Vec<u8>> {
                            self.0.get_record(key).map(|r| r.value)
                        }
                        fn check_threat(&self, ip: &str) -> bool {
                            let key = format!("threat_indicator:{}:IpBlock", ip);
                            self.0.get_record(&key).is_some()
                        }
                        fn store_event(&self, topic: &str, data: &[u8]) {
                            let key = format!("event:{}", topic);
                            let value = data.to_vec();
                            self.0.store_and_announce(key, value, 300);
                        }
                    }

                    synvoid_plugin_runtime::mesh_callbacks::set_mesh_provider(std::sync::Arc::new(
                        MeshDhtAdapter(record_store),
                    ));
                    tracing::debug!("Mesh DHT provider registered for WASM plugin runtime");
                } else {
                    tracing::warn!("Mesh DHT provider not registered — no record store available");
                }

                // Store dht_routing_init for composition root to spawn.
                #[cfg(feature = "mesh")]
                {
                    dht_routing_init = dht_routing_init_for_spawn;
                }
            }

            tracing::info!("Mesh and threat intelligence initialized in UnifiedServer Worker");

            let is_global = mesh_config_arc.role.is_global();
            if is_global
                && mesh_config_arc.global_node.key_exchange_enabled
                && mesh_config_arc.origin_signing_key.is_some()
            {
                tracing::info!(
                    "Key exchange endpoints enabled on global node at /key-request-origin, /key-confirm, /health"
                );
            } else if is_global && !mesh_config_arc.global_node.key_exchange_enabled {
                tracing::info!(
                    "Key exchange server disabled on global node (key_exchange_enabled=false)"
                );
            }

            return MeshInit {
                transport_manager: Some(transport_manager),
                threat_intel: Some(threat_intel),
                mesh_signer: Some(Arc::new(crate::mesh::protocol::MeshMessageSigner::new(
                    signer_key_clone,
                ))),
                canonical_snapshot: None,
                #[cfg(all(feature = "mesh", feature = "dns"))]
                dns_verification_registries,
                #[cfg(all(feature = "mesh", feature = "dns"))]
                yara_broadcast,
                #[cfg(feature = "mesh")]
                dht_routing_init,
            };
        }

        // mesh_config is None - still produce a dummy threat intel so
        // downstream code (and the WAF) sees a non-None manager.
        let dummy_threat = build_dummy_threat_intel(config_path).await;
        dummy_threat.start_background_tasks();
        crate::waf::set_threat_intel(dummy_threat.clone());
        MeshInit {
            transport_manager: None,
            threat_intel: Some(dummy_threat),
            mesh_signer: None,
            canonical_snapshot: None,
            #[cfg(all(feature = "mesh", feature = "dns"))]
            dns_verification_registries: Vec::new(),
            #[cfg(all(feature = "mesh", feature = "dns"))]
            yara_broadcast: None,
            #[cfg(feature = "mesh")]
            dht_routing_init: None,
        }
    }

    #[cfg(not(feature = "mesh"))]
    {
        let _ = (shared_config, config_path, unified_server);
        MeshInit {}
    }
}

/// Build a "dummy" threat-intel manager used when mesh is not configured.
/// This is a direct extraction of the original code path.
#[cfg(feature = "mesh")]
pub async fn build_dummy_threat_intel(
    config_path: &std::path::Path,
) -> Arc<ThreatIntelligenceManager> {
    let threat_persistence_path = config_path.parent().map(|p| p.join("threat_intel.json"));
    if let Some(ref path) = threat_persistence_path {
        Arc::new(ThreatIntelligenceManager::new_for_standalone(
            crate::mesh::threat_intel::ThreatIntelligenceConfig::default().to_internal(),
            Arc::new(crate::block_store::BlockStore::new(
                true,
                None,
                crate::config::DenyListLimitsConfig::default(),
            )),
            "dummy".to_string(),
            crate::mesh::config::MeshNodeRole::EDGE,
            None,
            path.clone(),
        ))
    } else {
        Arc::new(ThreatIntelligenceManager::new(
            crate::mesh::threat_intel::ThreatIntelligenceConfig::default().to_internal(),
            Arc::new(crate::block_store::BlockStore::new(
                true,
                None,
                crate::config::DenyListLimitsConfig::default(),
            )),
            "dummy".to_string(),
            crate::mesh::config::MeshNodeRole::EDGE,
            None,
        ))
    }
}

#[cfg(feature = "mesh")]
pub fn wire_serverless_to_mesh(
    unified_server: &crate::server::UnifiedServer,
    transport_manager: Option<&Arc<MeshTransportManager>>,
) {
    if let Some(sm) = unified_server.get_serverless_manager() {
        if let Some(tm) = transport_manager {
            if let Some(rs) = tm.get_record_store() {
                struct RecordStoreAdapter(Arc<crate::mesh::dht::RecordStoreManager>);
                impl synvoid_serverless::mesh_integration::MeshDhtProvider for RecordStoreAdapter {
                    fn store_function(&self, name: &str, data: Vec<u8>, ttl: u64) {
                        self.0
                            .store_and_announce(format!("function:{}", name), data, ttl);
                    }
                    fn get_record(&self, key: &str) -> Option<Vec<u8>> {
                        self.0.get_record(key).map(|r| r.value)
                    }
                }
                synvoid_serverless::mesh_integration::set_mesh_dht(Arc::new(RecordStoreAdapter(
                    rs,
                )));
                tracing::info!("Serverless manager wired to DHT record store");
            }
            if let Some(quic) = tm.get_quic_transport() {
                struct TransportAdapter(Arc<crate::mesh::transport::MeshTransport>);
                impl synvoid_serverless::mesh_integration::MeshTransportProvider for TransportAdapter {
                    fn announce_serverless(&self) {
                        self.0.announce_serverless();
                    }
                    fn node_id(&self) -> String {
                        self.0.get_node_id()
                    }
                }
                synvoid_serverless::mesh_integration::set_mesh_transport(Arc::new(
                    TransportAdapter(quic.get_inner()),
                ));
                tracing::info!("Serverless manager wired to mesh transport");
            }
            if let Some(quic) = tm.get_quic_transport() {
                let inner = quic.get_inner();
                inner.set_serverless_manager(sm.clone());
                tracing::info!("Mesh transport wired to serverless manager for origin mode");
            }
        }
    }
}

#[cfg(feature = "mesh")]
pub fn wire_port_honeypot_to_mesh(
    port_honeypot_runner: &Option<Arc<crate::honeypot_port::PortHoneypotRunner>>,
    threat_intel_manager: &Option<Arc<ThreatIntelligenceManager>>,
    has_mesh_transport: bool,
) {
    if let Some(runner) = port_honeypot_runner {
        if let Some(threat_intel) = threat_intel_manager {
            Arc::clone(runner).start_mesh_threat_publishing(threat_intel.clone(), 30);
            if has_mesh_transport {
                tracing::info!("Port honeypot threat publishing wired to mesh network");
            } else {
                tracing::info!("Port honeypot threat publishing in standalone mode");
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) fn _phantom_config_manager(_: &ConfigManager) {}
