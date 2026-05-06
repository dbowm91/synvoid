use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use parking_lot::RwLock;

use crate::mesh::cert::MeshCertManager;
use crate::mesh::config::MeshConfig;
use crate::mesh::dht::{DhtAccessControl, RecordStoreConfig, RecordStoreManager};
use crate::mesh::proxy::{MeshProxy, MeshProxyError};
use crate::mesh::topology::MeshTopology;
use crate::mesh::transport::MeshTransport;
use crate::mesh::transports::{MeshTransportManager, QuicMeshTransport};

pub fn create_record_store(
    config: &MeshConfig,
    routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
    verification_pool: Option<Arc<crate::mesh::crypto_verification::CryptoVerificationPool>>,
) -> Option<Arc<RecordStoreManager>> {
    if !config.dht.as_ref().map(|d| d.enabled).unwrap_or(false) {
        tracing::info!("DHT RecordStore disabled");
        return None;
    }

    let node_id = config.node_id().to_string();
    let role = config.role;

    let dht_config = config.dht.as_ref().unwrap();

    let store_config = RecordStoreConfig {
        enabled: dht_config.enabled,
        sync_interval_secs: 300,
        replication_factor: 20,
        query_timeout_secs: dht_config.query_timeout_secs,
        write_quorum: dht_config.write_quorum as u32,
        read_quorum: dht_config.read_quorum as u32,
        record_ttl: Duration::from_secs(3600),
        edge_cache_enabled: dht_config.edge_cache_enabled,
        edge_cache_max_entries: dht_config.edge_cache_max_entries,
        edge_cache_ttl_secs: dht_config.edge_cache_ttl_secs,
        edge_write_enabled: dht_config.edge_write_enabled,
        health_ttl_secs: dht_config.health_ttl_secs,
        load_ttl_secs: dht_config.load_ttl_secs,
        initial_sync_interval_secs: dht_config.initial_sync_interval_secs,
        max_sync_interval_secs: dht_config.max_sync_interval_secs,
        fanout_factor: dht_config.fanout_factor,
        convergence_threshold: dht_config.convergence_threshold,
        manual_quorum_override: 0,
        enable_degraded_quorum: true,
        neighborhood_persistence_enabled: false,
        neighborhood_cache_size: 1000,
        persist_max_age_secs: 604800,
        disk_storage_path: None,
        regional_quorum_enabled: false,
        regional_quorum_max_nodes: 20,
        regional_quorum_min_nodes: 3,
    };

    let access_control = DhtAccessControl::new(config);

    let mut signer = None;
    if let Some(key) = config.global_node_key.as_ref() {
        let mut key_bytes = [0u8; 32];
        let bytes = key.as_bytes();
        let len = bytes.len().min(32);
        key_bytes[..len].copy_from_slice(&bytes[..len]);
        let mut s = crate::mesh::protocol::MeshMessageSigner::new(key_bytes);
        if let Some(ref pool) = verification_pool {
            s = s.with_verification_pool(pool.clone());
        }
        signer = Some(s);
    }

    let verifier = crate::mesh::dht::capability_access::CapabilityAccessVerifier::new(
        |node_id, capability| {
            let key = format!("capability_attestation:{}:{}", node_id, capability);
            crate::mesh::get_global_record_store().and_then(|rs| {
                rs.get_record(&key).and_then(|r| {
                    crate::serialization::deserialize::<
                        crate::mesh::dht::capability_attestation::CapabilityAttestation,
                    >(&r.value)
                    .ok()
                })
            })
        },
    );

    let rs = Arc::new(RecordStoreManager::new(
        store_config,
        node_id,
        role,
        signer,
        access_control,
        Some(Arc::new(verifier)),
    ));

    rs.enable_rate_limiting(
        dht_config.announce_rate_limit_max_requests,
        dht_config.announce_rate_limit_window_secs,
    );

    if let Some(rm) = routing_manager {
        rs.set_routing_manager(rm);
    }

    if role.is_global() {
        let quorum_manager = Arc::new(crate::mesh::dht::quorum::QuorumManager::new());
        rs.set_quorum_manager(quorum_manager);
    }

    rs.start_background_tasks();

    if config.role.is_global() {
        if let Some(pubkey) = config.signing_public_key() {
            rs.publish_global_node_public_key(&pubkey);
        }
    }

    tracing::info!(
        "DHT RecordStore initialized: enabled=true, role={:?}, edge_cache={}",
        config.role,
        dht_config.edge_cache_enabled
    );

    Some(rs)
}

pub struct MeshBackend {
    upstream_id: String,
    proxy: Arc<MeshProxy>,
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    topology: Arc<MeshTopology>,
    current_peer: Arc<RwLock<Option<String>>>,
    health_status: Arc<std::sync::atomic::AtomicBool>,
    consecutive_failures: Arc<std::sync::atomic::AtomicU32>,
    consecutive_successes: Arc<std::sync::atomic::AtomicU32>,
}

impl MeshBackend {
    pub fn new(upstream_id: String, proxy: Arc<MeshProxy>, topology: Arc<MeshTopology>) -> Self {
        Self {
            upstream_id,
            proxy,
            topology,
            current_peer: Arc::new(RwLock::new(None)),
            health_status: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            consecutive_failures: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            consecutive_successes: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }

    pub fn is_healthy(&self) -> bool {
        self.health_status
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn record_success(&self) {
        self.consecutive_failures
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let successes = self
            .consecutive_successes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if successes >= 3
            && !self
                .health_status
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            self.health_status
                .store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("MeshBackend {} marked as healthy", self.upstream_id);
        }
    }

    pub fn record_failure(&self) {
        self.consecutive_successes
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let failures = self
            .consecutive_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if failures >= 3
            && self
                .health_status
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            self.health_status
                .store(false, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                "MeshBackend {} marked as unhealthy after {} failures",
                self.upstream_id,
                failures
            );
        }
    }

    pub async fn proxy_request<B>(
        &self,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<BoxBody<bytes::Bytes, Infallible>>, MeshProxyError>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: std::fmt::Debug + Send,
    {
        self.proxy.route_request(&self.upstream_id, req).await
    }

    pub fn select_peer(&self) -> Option<String> {
        let current = self.current_peer.read();
        current.clone()
    }

    pub fn set_peer(&self, peer_id: Option<String>) {
        let mut current = self.current_peer.write();
        *current = peer_id;
    }
}

pub struct MeshBackendPool {
    backends: Arc<RwLock<Vec<Arc<MeshBackend>>>>,
    proxy: Arc<MeshProxy>,
    topology: Arc<MeshTopology>,
    last_selected: Arc<AtomicUsize>,
}

impl MeshBackendPool {
    pub fn new(proxy: Arc<MeshProxy>, topology: Arc<MeshTopology>) -> Self {
        Self {
            backends: Arc::new(RwLock::new(Vec::new())),
            proxy,
            topology,
            last_selected: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn add_backend(&self, upstream_id: String) {
        let mut backends = self.backends.write();
        if !backends.iter().any(|b| b.upstream_id() == upstream_id) {
            let backend = Arc::new(MeshBackend::new(
                upstream_id.clone(),
                self.proxy.clone(),
                self.topology.clone(),
            ));
            backends.push(backend);
            tracing::info!("Added mesh backend for upstream: {}", upstream_id);
        }
    }

    pub fn remove_backend(&self, upstream_id: &str) {
        let mut backends = self.backends.write();
        backends.retain(|b| b.upstream_id() != upstream_id);
        tracing::info!("Removed mesh backend for upstream: {}", upstream_id);
    }

    // Topology read lock held briefly across peer score lookup; low contention.
    #[allow(clippy::await_holding_lock)]
    pub async fn select_backend(&self, upstream_id: &str) -> Option<Arc<MeshBackend>> {
        if self.topology.is_upstream_blocked(upstream_id).await {
            tracing::debug!("Upstream {} is currently blocked", upstream_id);
            return None;
        }

        let available: Vec<Arc<MeshBackend>> = {
            let backends = self.backends.read();
            backends
                .iter()
                .filter(|b| b.is_healthy())
                .cloned()
                .collect()
        };

        if available.is_empty() {
            return None;
        }

        let idx = self.last_selected.fetch_add(1, Ordering::SeqCst) % available.len();
        Some(available[idx].clone())
    }

    pub async fn get_blocked_until(&self, upstream_id: &str) -> Option<std::time::Instant> {
        self.topology.get_blocked_until(upstream_id).await
    }

    pub fn get_backend(&self, upstream_id: &str) -> Option<Arc<MeshBackend>> {
        let backends = self.backends.read();
        backends
            .iter()
            .find(|b| b.upstream_id() == upstream_id)
            .cloned()
    }

    pub fn get_all_backends(&self) -> Vec<Arc<MeshBackend>> {
        let backends = self.backends.read();
        backends.iter().cloned().collect()
    }
}

pub fn create_mesh_backend_from_config(
    config: &MeshConfig,
) -> (
    Arc<MeshTopology>,
    Arc<MeshProxy>,
    Arc<MeshBackendPool>,
    Arc<MeshTransportManager>,
) {
    // Validate system time on startup for mesh operations
    crate::mesh::transport::validate_system_time();

    let config = Arc::new(config.clone());
    let topology = Arc::new(MeshTopology::new(config.clone()));
    topology.start_background_tasks();
    let _cert_manager = Arc::new(RwLock::new(MeshCertManager::new(&config)));

    let cache_settings = config.proxy_cache.as_ref().map(|cc| {
        crate::proxy_cache::ProxyCacheSettings::from_config(
            cc.enable,
            cc.path.clone(),
            cc.max_size.clone(),
            cc.inactive,
            cc.use_temp_file,
            cc.valid_status.clone(),
            cc.methods.clone(),
            cc.use_stale.clone(),
            cc.min_uses,
            cc.key.clone(),
            cc.vary_by.clone(),
            cc.memory_max.clone(),
            cc.disk_max.clone(),
            cc.stale_while_revalidate,
            cc.stale_if_error,
            None,
        )
    });

    let proxy = Arc::new(MeshProxy::new(
        config.clone(),
        topology.clone(),
        cache_settings,
    ));
    let backend_pool = Arc::new(MeshBackendPool::new(proxy.clone(), topology.clone()));

    let transport_manager = Arc::new(MeshTransportManager::new(
        config.clone(),
        topology.clone(),
        None,
    ));

    proxy.set_transport_manager(transport_manager.clone());

    (topology, proxy, backend_pool, transport_manager)
}

pub async fn initialize_mesh_transports(
    config: &MeshConfig,
    transport_manager: Arc<MeshTransportManager>,
    threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
    mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    #[cfg(feature = "dns")] dns_resolver: Option<Arc<dyn crate::dns::resolver::DnsResolver>>,
    #[cfg(feature = "dns")] dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(config.clone());
    let topology = transport_manager.get_topology();

    let routing_manager = if config
        .dht
        .as_ref()
        .map(|d| d.routing_enabled)
        .unwrap_or(false)
    {
        let manager = Arc::new(crate::mesh::dht::routing::DhtRoutingManager::new(
            config.clone(),
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

    let record_store = create_record_store(
        &config,
        routing_manager.clone(),
        Some(verification_pool.clone()),
    );

    let stake_manager = config.stake.as_ref().map(|stake_config| {
        let is_global = config.role.is_global();
        let stake_mgr = crate::mesh::dht::StakeManager::new(
            stake_config.clone(),
            config.node_id(),
            is_global,
        );
        tracing::info!("StakeManager initialized: min_stake_write={}, min_stake_routing={}, slashing_enabled={}",
            stake_config.min_stake_for_dht_write,
            stake_config.min_stake_for_routing,
            stake_config.slashing_enabled);
        Arc::new(stake_mgr)
    });

    if let Some(ref rs) = record_store {
        if let Some(ref sm) = stake_manager {
            rs.set_stake_manager(sm.clone());
        }
    }

    if let Some(ref _rm) = routing_manager {
        tracing::info!(
            "DHT Routing initialized: enabled=true, is_global={}",
            config.role.is_global()
        );
    }

    tracing::info!(
        "DHT RecordStore initialized: enabled={}, role={:?}, edge_cache={}",
        record_store
            .as_ref()
            .map(|r| r.is_enabled())
            .unwrap_or(false),
        config.role,
        config
            .dht
            .as_ref()
            .map(|d| d.edge_cache_enabled)
            .unwrap_or(false)
    );

    if let Some(rm) = routing_manager.clone() {
        transport_manager.set_routing_manager(rm);
    }

    if let Some(ref rs) = record_store {
        transport_manager.set_verification_record_store(rs.clone());
        topology.set_record_store(rs.clone());
    }

    let quic_transport = QuicMeshTransport::new(
        config.clone(),
        topology.clone(),
        record_store,
        routing_manager,
        threat_intel,
        mesh_signer,
        stake_manager,
        #[cfg(feature = "dns")]
        dns_resolver,
        #[cfg(feature = "dns")]
        dns_registry,
    );

    let quic_transport_inner = quic_transport.get_inner();
    MeshTransport::initialize_component_transports(quic_transport_inner.clone());

    quic_transport_inner.set_verification_manager(transport_manager.get_verification_manager());

    let db_path = std::path::PathBuf::from("/var/lib/synvoid");
    if let Some(erm) = crate::mesh::raft::edge_replica::create_edge_replica_manager(Some(db_path)) {
        quic_transport_inner.set_edge_replica_manager(Arc::new(erm));
        tracing::info!("Edge replica manager initialized");
    }

    quic_transport_inner
        .org_key_manager
        .start_background_tasks();

    transport_manager.set_quic_transport(quic_transport);

    tracing::info!(
        "Mesh transports initialized: preferred={:?}, wireguard_available={}, quic_available={}",
        config.transport_preference,
        transport_manager.is_quic_available(),
        transport_manager.is_quic_available()
    );

    Ok(())
}
