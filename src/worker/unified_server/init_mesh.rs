// Submodule: Mesh + Threat Intelligence + YARA rules initialization.
//
// This is a behavior-preserving extraction of the original
// `run_unified_server_worker` mesh block. The function returns a
// 3-tuple of optional resources so the orchestrator can wire them
// into the rest of the worker.

use std::sync::Arc;

use tokio::sync::RwLock;

#[cfg(feature = "mesh")]
use crate::mesh::threat_intel::ThreatIntelligenceManager;
#[cfg(feature = "mesh")]
use crate::mesh::transports::MeshTransportManager;

use crate::config::ConfigManager;
use crate::server::UnifiedServer;

/// Bundled resources produced by the mesh initialization phase.
pub struct MeshInit {
    #[cfg(feature = "mesh")]
    pub transport_manager: Option<Arc<MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
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
            if true {
                tracing::info!("Mesh control plane is disabled in worker process");
                let dummy_threat = build_dummy_threat_intel(config_path).await;
                dummy_threat.start_background_tasks();
                crate::waf::set_threat_intel(dummy_threat.clone());
                return MeshInit {
                    transport_manager: None,
                    threat_intel: Some(dummy_threat),
                    mesh_signer: None,
                };
            }

            // The else branch constructs the full mesh transport. It is
            // intentionally preserved verbatim from the original code path so
            // that behavior is unchanged when the Phase 3 control plane is
            // re-enabled.
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
                let manager_clone = manager.clone();
                manager.start_background_tasks();
                tokio::spawn(async move {
                    manager_clone.init().await;
                });
                Some(manager)
            } else {
                None
            };

            let verification_pool =
                Arc::new(crate::mesh::crypto_verification::CryptoVerificationPool::default());

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
            let backend_pool = Arc::new(crate::mesh::backend::MeshBackendPool::new(
                proxy.clone(),
                topology.clone(),
            ));

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

            let signer_for_mesh = crate::mesh::protocol::MeshMessageSigner::new(signer_key_clone)
                .with_verification_pool(verification_pool.clone());

            #[cfg(feature = "dns")]
            {
                let dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>> = {
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
                        None
                    } else if !mesh_config.role.is_global() {
                        tracing::debug!(
                            "Edge node - DNS resolver not created (verification only on global nodes)"
                        );

                        let registry_config = crate::dns::MeshDnsRegistryConfig {
                            verification_timeout_secs: dns_cfg.mesh.verification_timeout_secs,
                            verification_retry_interval_secs: dns_cfg
                                .mesh
                                .verification_retry_interval_secs,
                            require_cert_chain_verification: dns_cfg
                                .mesh
                                .require_cert_chain_verification,
                            ..Default::default()
                        };

                        let registry = crate::dns::MeshDnsRegistry::with_config(
                            mesh_config.node_id(),
                            false,
                            registry_config,
                        );
                        Some(Arc::new(registry))
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
                            None
                        } else {
                            match crate::dns::HickoryResolver::with_upstream_servers(
                                &upstream_servers,
                            ) {
                                Ok(resolver) => {
                                    tracing::info!(
                                        "Global node DNS resolver initialized with upstream servers: {:?}",
                                        upstream_servers
                                    );

                                    let registry_config = crate::dns::MeshDnsRegistryConfig {
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

                                    let registry = crate::dns::MeshDnsRegistry::with_config(
                                        mesh_config.node_id(),
                                        true,
                                        registry_config,
                                    )
                                    .with_dns_resolver(resolver);

                                    let registry_clone = registry.clone();
                                    tokio::spawn(async move {
                                        registry_clone.start_verification_loop().await;
                                    });

                                    Some(Arc::new(registry))
                                }
                                Err(e) => {
                                    tracing::error!("Failed to create DNS resolver: {}", e);
                                    None
                                }
                            }
                        }
                    }
                };

                if let Err(e) = crate::mesh::backend::initialize_mesh_transports(
                    mesh_config,
                    transport_manager.clone(),
                    backend_pool.clone(),
                    Some(threat_intel.clone()),
                    Some(Arc::new(signer_for_mesh)),
                    None::<Arc<dyn crate::dns::resolver::DnsResolver>>,
                    dns_registry,
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

            let mesh_broadcast_tx_for_yara = {
                let (mesh_broadcast_tx, mut mesh_broadcast_rx) =
                    tokio::sync::mpsc::channel::<crate::mesh::protocol::MeshMessage>(128);

                threat_intel.set_mesh_sender(mesh_broadcast_tx.clone());

                if let Some(quic_transport) = transport_manager.get_quic_transport() {
                    let mesh_transport = quic_transport.get_inner();
                    let broadcast_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
                    tokio::spawn(async move {
                        while let Some(msg) = mesh_broadcast_rx.recv().await {
                            let transport = mesh_transport.clone();
                            let permit = broadcast_semaphore.clone().acquire_owned().await.ok();
                            tokio::spawn(async move {
                                transport
                                    .broadcast_to_all_peers(
                                        msg,
                                        Some(crate::mesh::config::MeshNodeRole::GLOBAL),
                                    )
                                    .await;
                                drop(permit);
                            });
                        }
                    });
                }

                mesh_broadcast_tx
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
                    transport_manager.announce_edge_key(&mesh_config.node_id(), global_node_key);
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
            {
                struct MeshDhtAdapter;

                impl synvoid_plugin_runtime::mesh_callbacks::MeshDhtProvider for MeshDhtAdapter {
                    fn get_record(&self, key: &str) -> Option<Vec<u8>> {
                        crate::mesh::get_global_record_store()
                            .and_then(|rs| rs.get_record(key))
                            .map(|r| r.value)
                    }
                    fn check_threat(&self, ip: &str) -> bool {
                        crate::mesh::get_global_record_store().map_or(false, |rs| {
                            let key = format!("threat_indicator:{}:IpBlock", ip);
                            rs.get_record(&key).is_some()
                        })
                    }
                    fn store_event(&self, topic: &str, data: &[u8]) {
                        if let Some(rs) = crate::mesh::get_global_record_store() {
                            let key = format!("event:{}", topic);
                            let value = data.to_vec();
                            rs.store_and_announce(key, value, 300);
                        }
                    }
                }

                synvoid_plugin_runtime::mesh_callbacks::set_mesh_provider(std::sync::Arc::new(
                    MeshDhtAdapter,
                ));
                tracing::debug!("Mesh DHT provider registered for WASM plugin runtime");
            }

            // YARA rules manager
            {
                let main_config = {
                    let config = shared_config.read().await;
                    config.main.clone()
                };

                if mesh_config.yara_rules.enabled || main_config.yara_feed.enabled {
                    let feed_mgr: Option<Arc<crate::upload::yara_rule_feed::YaraRuleFeedManager>> =
                        if main_config.yara_feed.enabled {
                            Some(crate::upload::YaraRuleFeedManager::new(
                                main_config.yara_feed.clone(),
                            ))
                        } else {
                            None
                        };

                    let yara_data_dir = config_path.parent().map(|p| p.to_path_buf());

                    let signer_for_yara: Option<Arc<crate::mesh::protocol::MeshMessageSigner>> =
                        Some(Arc::new(crate::mesh::protocol::MeshMessageSigner::new(
                            signer_key,
                        )));

                    let yara_rules = Arc::new(crate::mesh::yara_rules::YaraRulesManager::new(
                        mesh_config.yara_rules.clone().into(),
                        node_id.clone(),
                        mesh_config.role,
                        signer_for_yara,
                        feed_mgr,
                        yara_data_dir,
                    ));

                    yara_rules.set_mesh_sender(mesh_broadcast_tx_for_yara.clone());

                    if let Some(record_store) = transport_manager.get_record_store() {
                        yara_rules.set_record_store(record_store.clone());
                        crate::mesh::set_global_record_store(record_store);
                    }

                    let is_elevated: Arc<parking_lot::RwLock<bool>> =
                        Arc::new(parking_lot::RwLock::new(false));

                    if yara_rules.has_feed_manager() {
                        let fm = yara_rules
                            .get_feed_manager()
                            .expect("guarded by has_feed_manager check");
                        let elevated_clone = is_elevated.clone();
                        fm.start_background_fetching(elevated_clone);

                        if let Err(e) = yara_rules.apply_rules_from_feed() {
                            tracing::debug!("No feed rules to apply on startup: {}", e);
                        }
                    }

                    crate::waf::set_yara_rules(yara_rules.clone());

                    if mesh_config.yara_rules.sync_interval_secs > 0 {
                        let sync_manager = yara_rules.clone();
                        let sync_interval = std::time::Duration::from_secs(
                            mesh_config.yara_rules.sync_interval_secs,
                        );
                        tokio::spawn(async move {
                            let mut ticker = tokio::time::interval(sync_interval);
                            loop {
                                ticker.tick().await;
                                let _ = sync_manager.sync_from_dht();
                                sync_manager.record_sync();
                            }
                        });
                        tracing::info!(
                            "YARA DHT sync task started (interval: {}s)",
                            mesh_config.yara_rules.sync_interval_secs
                        );
                    }

                    if mesh_config.yara_rules.re_announce_interval_secs > 0
                        && mesh_config.role.is_global()
                    {
                        let rules_manager = yara_rules.clone();
                        let re_announce_interval = std::time::Duration::from_secs(
                            mesh_config.yara_rules.re_announce_interval_secs,
                        );
                        tokio::spawn(async move {
                            let mut ticker = tokio::time::interval(re_announce_interval);
                            loop {
                                ticker.tick().await;
                                rules_manager.publish_rules_to_dht();
                            }
                        });
                        tracing::info!(
                            "YARA re-announce task started (interval: {}s)",
                            mesh_config.yara_rules.re_announce_interval_secs
                        );
                    }

                    tracing::info!("YARA rules manager initialized");
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
                sm.set_record_store(rs);
                tracing::info!("Serverless manager wired to DHT record store");
            }
            if let Some(quic) = tm.get_quic_transport() {
                sm.set_transport(quic.get_inner());
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
            runner.start_mesh_threat_publishing(threat_intel.clone(), 30);
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
