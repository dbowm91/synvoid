#![allow(clippy::type_complexity, clippy::manual_let_else)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru_time_cache::LruCache;
use metrics::{counter, histogram};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

use crate::mesh::config::MeshConfig;
use crate::mesh::protocol::MeshMessage;
use crate::mesh::topology::MeshTopology;
use crate::mesh::transports::{
    MeshTransportError, MeshTransportTrait, MeshTransportType, QuicMeshTransport, TransportHint,
};
use crate::mesh::verification::{VerificationConfig, VerificationTaskManager};
use crate::utils::current_timestamp;

pub const DEFAULT_MAX_RETRIES: u32 = 5;
pub const RETRY_BACKOFF_BASE_MS: u64 = 500;
pub const RETRY_BACKOFF_MAX_MS: u64 = 5000;

pub const DHT_TTL_KEY_EXCHANGE_ENDPOINT: u64 = 3600;
pub const DHT_TTL_EDGE_KEY: u64 = 86400;
pub const DHT_TTL_GLOBAL_NODE_KEY: u64 = 86400;

pub const DHT_KEY_PREFIX_KEY_EXCHANGE_ENDPOINT: &str = "key_exchange_endpoint:";
pub const DHT_KEY_PREFIX_EDGE_KEY: &str = "edge_key:";
pub const DHT_KEY_PREFIX_GLOBAL_NODE_KEY: &str = "global_node_key:";

#[derive(Debug, Clone)]
pub struct PeerTransportState {
    pub preferred_transport: MeshTransportType,
    pub fallback_count: u32,
    pub last_fallback_at: Option<Instant>,
    pub max_retries: u32,
    pub peer_preferred_transport: Option<MeshTransportType>,
}

impl PeerTransportState {
    pub fn new(preferred: MeshTransportType) -> Self {
        Self {
            preferred_transport: preferred,
            fallback_count: 0,
            last_fallback_at: None,
            max_retries: DEFAULT_MAX_RETRIES,
            peer_preferred_transport: None,
        }
    }

    pub fn can_retry(&self) -> bool {
        self.fallback_count < self.max_retries
    }

    pub fn record_fallback(&mut self) {
        self.fallback_count += 1;
        self.last_fallback_at = Some(Instant::now());
    }

    pub fn reset_fallback(&mut self) {
        self.fallback_count = 0;
        self.last_fallback_at = None;
    }

    pub fn backoff_duration(&self) -> Duration {
        let backoff = RETRY_BACKOFF_BASE_MS * (2_u64.pow(self.fallback_count.min(5)));
        Duration::from_millis(backoff.min(RETRY_BACKOFF_MAX_MS))
    }
}

pub struct MeshTransportManager {
    config: Arc<MeshConfig>,
    topology: Arc<MeshTopology>,
    quic_transport: Arc<RwLock<Option<Arc<QuicMeshTransport>>>>,
    preferred_transport: Arc<RwLock<MeshTransportType>>,
    peer_states: Arc<RwLock<HashMap<String, PeerTransportState>>>,
    record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
    routing_manager: Arc<RwLock<Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>>>,
    verification_manager: Arc<VerificationTaskManager>,
    // Config caches with metrics
    image_protection_cache:
        Arc<RwLock<LruCache<String, (crate::mesh::config::MeshImageProtectionConfig, Instant)>>>,
    compression_cache:
        Arc<RwLock<LruCache<String, (crate::mesh::config::MeshCompressionConfig, Instant)>>>,
    minification_cache:
        Arc<RwLock<LruCache<String, (crate::mesh::config::MeshMinificationConfig, Instant)>>>,
    image_poison_cache:
        Arc<RwLock<LruCache<String, (crate::config::site::SiteImagePoisonConfig, Instant)>>>,
    proxy_cache_preferences_cache:
        Arc<RwLock<LruCache<String, (crate::mesh::protocol::ProxyCachePreferences, Instant)>>>,
    // Inflight tracking for stampede prevention
    image_protection_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    compression_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    minification_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    image_poison_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    proxy_cache_preferences_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    // Metrics counters
    image_protection_cache_hits: AtomicU64,
    image_protection_cache_misses: AtomicU64,
    compression_cache_hits: AtomicU64,
    compression_cache_misses: AtomicU64,
    minification_cache_hits: AtomicU64,
    minification_cache_misses: AtomicU64,
    image_poison_cache_hits: AtomicU64,
    image_poison_cache_misses: AtomicU64,
    proxy_cache_preferences_cache_hits: AtomicU64,
    proxy_cache_preferences_cache_misses: AtomicU64,
}

impl MeshTransportManager {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
    ) -> Self {
        let image_protection_cache =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 1000);
        let compression_cache =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 1000);
        let minification_cache =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 1000);
        let image_poison_cache =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 1000);
        let proxy_cache_preferences_cache =
            LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 1000);

        let node_id = config
            .node_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let verification_config = VerificationConfig::default();
        let verification_manager =
            Arc::new(VerificationTaskManager::new(node_id, verification_config));

        Self {
            config,
            topology,
            quic_transport: Arc::new(RwLock::new(None)),
            preferred_transport: Arc::new(RwLock::new(MeshTransportType::Quic)),
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            record_store,
            routing_manager: Arc::new(RwLock::new(None)),
            verification_manager,
            image_protection_cache: Arc::new(RwLock::new(image_protection_cache)),
            compression_cache: Arc::new(RwLock::new(compression_cache)),
            minification_cache: Arc::new(RwLock::new(minification_cache)),
            image_poison_cache: Arc::new(RwLock::new(image_poison_cache)),
            proxy_cache_preferences_cache: Arc::new(RwLock::new(proxy_cache_preferences_cache)),
            image_protection_inflight: Arc::new(Mutex::new(HashMap::new())),
            compression_inflight: Arc::new(Mutex::new(HashMap::new())),
            minification_inflight: Arc::new(Mutex::new(HashMap::new())),
            image_poison_inflight: Arc::new(Mutex::new(HashMap::new())),
            proxy_cache_preferences_inflight: Arc::new(Mutex::new(HashMap::new())),
            image_protection_cache_hits: AtomicU64::new(0),
            image_protection_cache_misses: AtomicU64::new(0),
            compression_cache_hits: AtomicU64::new(0),
            compression_cache_misses: AtomicU64::new(0),
            minification_cache_hits: AtomicU64::new(0),
            minification_cache_misses: AtomicU64::new(0),
            image_poison_cache_hits: AtomicU64::new(0),
            image_poison_cache_misses: AtomicU64::new(0),
            proxy_cache_preferences_cache_hits: AtomicU64::new(0),
            proxy_cache_preferences_cache_misses: AtomicU64::new(0),
        }
    }

    pub fn set_routing_manager(&self, manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>) {
        *self.routing_manager.write() = Some(manager);
    }

    pub fn get_verification_manager(&self) -> Arc<VerificationTaskManager> {
        self.verification_manager.clone()
    }

    pub fn set_verification_record_store(
        &self,
        record_store: Arc<crate::mesh::dht::RecordStoreManager>,
    ) {
        self.verification_manager.set_record_store(record_store);
    }

    pub fn report_reachability(
        &self,
        upstream_id: &str,
        provider_node_id: &str,
        status: crate::mesh::dht::ReachabilityStatus,
        latency_ms: u32,
        error_rate: f32,
        consecutive_failures: u32,
    ) {
        self.verification_manager.report_reachability(
            upstream_id,
            provider_node_id,
            status,
            latency_ms,
            error_rate,
            consecutive_failures,
        );
    }

    pub fn get_topology(&self) -> Arc<MeshTopology> {
        self.topology.clone()
    }

    pub fn is_global_node(&self) -> bool {
        self.config.role.is_global()
    }

    pub async fn find_origin_by_mesh_id(&self, mesh_id: &str) -> Option<String> {
        self.topology.find_origin_by_mesh_id(mesh_id).await
    }

    pub fn start_verification_processing(self: &Arc<Self>) {
        if !self.config.role.is_global() {
            tracing::debug!("Verification processing only runs on global nodes");
            return;
        }

        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;

                manager.verification_manager.process_pending_tasks();

                let tasks_to_dispatch = manager.verification_manager.get_pending_dispatch_tasks();
                for (task_key, _task_id, task) in tasks_to_dispatch {
                    let peer_ids = manager.topology.get_peer_ids().await;
                    let node_id = manager.config.node_id().to_string();

                    if peer_ids.is_empty() {
                        tracing::warn!("No peers available for verification dispatch");
                        continue;
                    }

                    let nodes_to_query = std::cmp::min(
                        manager.verification_manager.get_verification_nodes_count(),
                        peer_ids.len(),
                    );

                    use rand::rngs::StdRng;
                    use rand::seq::IteratorRandom;
                    use rand::SeedableRng;
                    let mut rng = StdRng::from_os_rng();
                    let selected_peers: Vec<String> = peer_ids
                        .iter()
                        .filter(|p| *p != &node_id)
                        .choose_multiple(&mut rng, nodes_to_query)
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect();

                    if selected_peers.is_empty() {
                        tracing::warn!("No suitable peers for verification dispatch");
                        continue;
                    }

                    tracing::info!(
                        "Dispatching verification query for {} to {} nodes: {:?}",
                        task.upstream_id,
                        selected_peers.len(),
                        selected_peers
                    );

                    let request_id = uuid::Uuid::new_v4().to_string();
                    let query = crate::mesh::protocol::MeshMessage::UpstreamVerificationQuery {
                        request_id: request_id.clone().into(),
                        upstream_id: task.upstream_id.clone().into(),
                        querying_node_id: node_id.clone().into(),
                        timestamp: crate::utils::safe_unix_timestamp(),
                        provider_node_id: task.provider_node_id.clone().into(),
                    };

                    for peer_id in &selected_peers {
                        match manager
                            .send_message(peer_id, &query, TransportHint::Default)
                            .await
                        {
                            Ok(_) => {
                                tracing::debug!("Sent verification query to {}", peer_id);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to send verification query to {}: {}",
                                    peer_id,
                                    e
                                );
                            }
                        }
                    }

                    manager
                        .verification_manager
                        .mark_task_in_progress(&task_key, selected_peers);
                }
            }
        });
        tracing::info!("Verification task processing started");
    }

    pub fn set_quic_transport(&self, transport: QuicMeshTransport) {
        let mut t = self.quic_transport.write();
        *t = Some(Arc::new(transport));
        self.update_preferred_transport();
    }

    fn update_preferred_transport(&self) {
        let mut preferred = self.preferred_transport.write();
        *preferred = MeshTransportType::Quic;
        tracing::info!("Mesh transport preference updated: QUIC");
    }

    pub fn preferred_transport(&self) -> MeshTransportType {
        *self.preferred_transport.read()
    }

    pub fn is_quic_available(&self) -> bool {
        self.quic_transport
            .read()
            .as_ref()
            .map(|t| t.is_available())
            .unwrap_or(false)
    }

    pub fn update_peer_preferred_transport(
        &self,
        peer_id: &str,
        peer_preferred: Option<MeshTransportType>,
    ) {
        let mut states = self.peer_states.write();
        let state = states
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerTransportState::new(self.preferred_transport()));
        state.peer_preferred_transport = peer_preferred;
    }

    pub fn get_peer_preferred_transport(&self, peer_id: &str) -> Option<MeshTransportType> {
        let states = self.peer_states.read();
        states.get(peer_id).and_then(|s| s.peer_preferred_transport)
    }

    pub fn get_or_create_peer_state(&self, peer_id: &str) -> PeerTransportState {
        let mut states = self.peer_states.write();
        states
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerTransportState::new(self.preferred_transport()))
            .clone()
    }

    pub fn get_effective_transport(&self, peer_id: &str, hint: TransportHint) -> MeshTransportType {
        if let Some(peer_pref) = self.get_peer_preferred_transport(peer_id) {
            return peer_pref;
        }

        match hint {
            TransportHint::Reliable | TransportHint::LowLatency | TransportHint::HighThroughput => {
                if self.is_quic_available() {
                    return MeshTransportType::Quic;
                }
            }
            TransportHint::Default => {}
        }

        self.preferred_transport()
    }

    pub async fn send_message(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        _hint: TransportHint,
    ) -> Result<(), MeshTransportError> {
        let transport = self.quic_transport.read().clone();
        if let Some(ref t) = transport {
            if t.is_connected(peer_id) {
                return t.send_stream(peer_id, message).await;
            }
        }
        Err(MeshTransportError::PeerNotConnected(peer_id.to_string()))
    }

    pub async fn send_datagram(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        _hint: TransportHint,
    ) -> Result<(), MeshTransportError> {
        let transport = self.quic_transport.read().clone();
        if let Some(ref t) = transport {
            if t.is_connected(peer_id) {
                return t.send_datagram(peer_id, message).await;
            }
        }
        Err(MeshTransportError::PeerNotConnected(peer_id.to_string()))
    }

    pub async fn broadcast_datagram(
        &self,
        message: &MeshMessage,
        hint: TransportHint,
    ) -> Result<(), MeshTransportError> {
        let preferred = match hint {
            TransportHint::Reliable => {
                if self.is_quic_available() {
                    MeshTransportType::Quic
                } else {
                    return Err(MeshTransportError::NotAvailable);
                }
            }
            _ => self.preferred_transport(),
        };

        let quic_transport = {
            let guard = self.quic_transport.read();
            guard.clone()
        };

        match preferred {
            MeshTransportType::Quic => {
                if let Some(transport) = quic_transport {
                    if transport.is_available() {
                        return transport.broadcast_datagram(message).await;
                    }
                }
            }
        }

        Err(MeshTransportError::NotAvailable)
    }

    pub async fn broadcast_datagram_fanout(
        &self,
        message: &MeshMessage,
        fanout_factor: f64,
    ) -> Result<usize, MeshTransportError> {
        let peer_count = self.topology.get_healthy_peer_count().await;

        if peer_count == 0 {
            return Ok(0);
        }

        let fanout_count = ((peer_count as f64) * fanout_factor).ceil() as usize;
        let target_count = fanout_count.max(1).min(peer_count);

        let peers = self.topology.get_random_peers(target_count, None).await;

        if peers.is_empty() {
            return Ok(0);
        }

        let mut sent_count = 0;

        for peer in &peers {
            let result = self
                .send_datagram(&peer.node_id, message, TransportHint::Default)
                .await;
            match result {
                Ok(_) => sent_count += 1,
                Err(e) => {
                    tracing::debug!("Fanout broadcast to {} failed: {}", peer.node_id, e);
                }
            }
        }

        tracing::debug!(
            "Fanout broadcast: {} peers selected, {} sent successfully (mesh size: {})",
            target_count,
            sent_count,
            peer_count
        );

        Ok(sent_count)
    }

    pub fn get_connected_peers(&self) -> Vec<String> {
        if self.is_quic_available() {
            if let Some(ref transport) = *self.quic_transport.read() {
                return transport.get_connected_peers();
            }
        }

        Vec::new()
    }

    pub fn local_addresses(&self) -> Vec<String> {
        if self.is_quic_available() {
            if let Some(ref transport) = *self.quic_transport.read() {
                return transport.local_addresses();
            }
        }

        Vec::new()
    }

    pub fn get_quic_transport(&self) -> Option<Arc<QuicMeshTransport>> {
        self.quic_transport.read().clone()
    }

    pub fn get_routing_manager(&self) -> Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>> {
        self.routing_manager.read().clone()
    }

    pub fn get_record_store(&self) -> Option<Arc<crate::mesh::dht::RecordStoreManager>> {
        self.record_store.clone()
    }

    pub async fn proxy_serverless_request<B>(
        &self,
        function_name: &str,
        peer_node_id: &str,
        request: http::Request<B>,
    ) -> Result<http::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>>, String>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: std::fmt::Debug + Send,
    {
        let quic = self.quic_transport.read().clone().ok_or_else(|| {
            "No QUIC transport available for serverless proxy".to_string()
        })?;
        let transport = quic.get_inner();
        transport
            .proxy_http_request(peer_node_id, &format!("serverless:{}", function_name), request)
            .await
            .map_err(|e| e.to_string())
    }

    #[cfg(feature = "dns")]
    pub fn get_http01_challenge(&self, token: &str) -> Option<String> {
        self.quic_transport
            .read()
            .as_ref()
            .and_then(|qt| qt.get_inner().get_http01_challenge(token))
    }

    #[cfg(feature = "dns")]
    pub fn get_dns01_challenge(
        &self,
        txt_record_name: &str,
    ) -> Option<crate::mesh::transport::Dns01Challenge> {
        self.quic_transport
            .read()
            .as_ref()
            .and_then(|qt| qt.get_inner().get_dns01_challenge(txt_record_name))
    }

    pub fn announce_capabilities(&self, node_id: &str, capabilities: &[String]) {
        if let Some(ref record_store) = self.record_store {
            let ttl = 3600; // 1 hour TTL for capabilities
            for capability in capabilities {
                let key = crate::mesh::dht::keys::DhtKey::node_capability(node_id, capability);
                let key_str = key.as_str();
                let value = serde_json::json!({
                    "node_id": node_id,
                    "capability": capability,
                    "announced_at": crate::mesh::safe_unix_timestamp(),
                });
                if let Ok(bytes) = serde_json::to_vec(&value) {
                    record_store.store_and_announce(key_str.to_string(), bytes, ttl);
                }
            }
            tracing::debug!(
                "Announced {} capabilities for {} to DHT",
                capabilities.len(),
                node_id
            );
        }
    }

    pub fn get_peer_fallback_count(&self, peer_id: &str) -> u32 {
        let states = self.peer_states.read();
        states.get(peer_id).map(|s| s.fallback_count).unwrap_or(0)
    }

    pub fn should_retry_preferred(&self, peer_id: &str) -> bool {
        let states = self.peer_states.read();
        if let Some(state) = states.get(peer_id) {
            if !state.can_retry() {
                return false;
            }
            if let Some(last_fallback) = state.last_fallback_at {
                return last_fallback.elapsed() > state.backoff_duration();
            }
        }
        true
    }

    pub fn get_key_exchange_endpoint(&self) -> Option<String> {
        if !self.config.global_node.key_exchange_enabled {
            return None;
        }

        let port = self.config.global_node.key_exchange_port;

        match crate::utils::get_first_non_loopback_ip() {
            Ok(ip) => Some(format!("https://{}:{}", ip, port)),
            Err(_) => {
                let bind_address = self.config.bind_address.as_deref().unwrap_or("0.0.0.0");
                Some(format!("https://{}:{}", bind_address, port))
            }
        }
    }

    pub async fn update_key_exchange_endpoint(&self) {
        if !self.config.role.is_global() {
            return;
        }

        let genesis_key = match self.config.genesis_key() {
            Some(g) => g,
            None => {
                tracing::warn!("No genesis key configured - cannot update key exchange endpoint");
                return;
            }
        };

        let timestamp = current_timestamp();

        let key_exchange_endpoint = self.get_key_exchange_endpoint();
        let node_id = self.config.node_id();
        let public_key = self.config.global_node_key.clone().unwrap_or_default();

        // Store key exchange endpoint in DHT for edge node discovery
        if let Some(ref record_store) = self.record_store {
            let dht_key = format!("{}{}", DHT_KEY_PREFIX_KEY_EXCHANGE_ENDPOINT, node_id);
            let endpoint_for_dht = key_exchange_endpoint.clone().unwrap_or_default();
            let value = serde_json::json!({
                "node_id": node_id,
                "public_key": public_key,
                "endpoint": endpoint_for_dht,
                "timestamp": timestamp,
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                if record_store.store_and_announce(dht_key, bytes, DHT_TTL_KEY_EXCHANGE_ENDPOINT) {
                    tracing::debug!("Stored key exchange endpoint for {} in DHT", node_id);
                } else {
                    tracing::warn!("Failed to store key exchange endpoint in DHT");
                }
            }
        }

        let endpoint_for_signing = key_exchange_endpoint.clone().unwrap_or_default();
        let signable = format!(
            "{}:{}:{}:{}:{}",
            node_id,
            public_key,
            crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange as u8,
            timestamp,
            endpoint_for_signing
        );

        let signature = match genesis_key.sign(&signable) {
            Some(sig) => sig,
            None => {
                tracing::warn!("Failed to sign key exchange endpoint update");
                return;
            }
        };

        // Broadcast update via preferred transport
        let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: node_id.into(),
            public_key: public_key.into(),
            action: crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange,
            timestamp,
            signature,
            key_exchange_endpoint: key_exchange_endpoint.map(|s| s.into()),
        };

        // Use the manager's broadcast method
        use crate::mesh::transports::TransportHint;
        let _ = self.broadcast_datagram(&msg, TransportHint::Default).await;

        tracing::info!("Broadcasted key exchange endpoint update for global node");
    }

    pub fn get_key_exchange_endpoint_for_node(&self, node_id: &str) -> Option<String> {
        if let Some(ref record_store) = self.record_store {
            let key = format!("{}{}", DHT_KEY_PREFIX_KEY_EXCHANGE_ENDPOINT, node_id);
            if let Some(record) = record_store.get_record(&key) {
                match serde_json::from_slice::<serde_json::Value>(&record.value) {
                    Ok(value) => {
                        let timestamp =
                            value.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);

                        let max_age_secs = DHT_TTL_KEY_EXCHANGE_ENDPOINT * 2;
                        let current_time = current_timestamp();

                        if current_time > timestamp + max_age_secs {
                            tracing::warn!(
                                "Stale key exchange endpoint record for {} (age: {}s)",
                                node_id,
                                current_time - timestamp
                            );
                        } else {
                            return value
                                .get("endpoint")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to deserialize key exchange endpoint for {}: {}",
                            node_id,
                            e
                        );
                    }
                }
            }
        } else {
            tracing::warn!(
                "Cannot lookup key exchange endpoint from DHT: record store not available"
            );
        }

        if let Some(endpoint) = self.config.global_node.known_origin_keys.get(node_id) {
            tracing::debug!("Fallback: using known_origin_keys for node {}", node_id);
            return Some(endpoint.clone());
        }

        None
    }

    pub fn announce_edge_key(&self, edge_id: &str, public_key: &str) {
        if let Some(ref record_store) = self.record_store {
            let key = format!("{}{}", DHT_KEY_PREFIX_EDGE_KEY, edge_id);
            let timestamp = current_timestamp();
            let value = serde_json::json!({
                "edge_id": edge_id,
                "public_key": public_key,
                "timestamp": timestamp,
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                if record_store.store_and_announce(key, bytes, DHT_TTL_EDGE_KEY) {
                    tracing::debug!("Announced edge key for {} to DHT", edge_id);
                } else {
                    tracing::warn!("Failed to announce edge key for {} to DHT", edge_id);
                }
            } else {
                tracing::warn!("Failed to serialize edge key data for {}", edge_id);
            }
        } else {
            tracing::warn!("Cannot announce edge key: record store not available");
        }
    }

    pub fn get_edge_key(&self, edge_id: &str) -> Option<String> {
        if let Some(ref record_store) = self.record_store {
            let key = format!("{}{}", DHT_KEY_PREFIX_EDGE_KEY, edge_id);
            if let Some(record) = record_store.get_record(&key) {
                match serde_json::from_slice::<serde_json::Value>(&record.value) {
                    Ok(value) => {
                        let timestamp =
                            value.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);

                        let max_age_secs = DHT_TTL_EDGE_KEY * 2;
                        let current_time = current_timestamp();

                        if current_time > timestamp + max_age_secs {
                            tracing::warn!(
                                "Stale edge key record for {} (age: {}s)",
                                edge_id,
                                current_time - timestamp
                            );
                        } else {
                            return value
                                .get("public_key")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize edge key for {}: {}", edge_id, e);
                    }
                }
            }
        } else {
            tracing::warn!("Cannot lookup edge key from DHT: record store not available");
        }

        if let Some(key) = self.config.global_node.known_edge_keys.get(edge_id) {
            tracing::debug!("Fallback: using known_edge_keys for edge {}", edge_id);
            return Some(key.clone());
        }

        None
    }

    pub fn get_global_node_public_key(&self, node_id: &str) -> Option<String> {
        if let Some(ref record_store) = self.record_store {
            let key = format!("{}{}", DHT_KEY_PREFIX_GLOBAL_NODE_KEY, node_id);
            if let Some(record) = record_store.get_record(&key) {
                match serde_json::from_slice::<serde_json::Value>(&record.value) {
                    Ok(value) => {
                        let timestamp =
                            value.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);

                        let max_age_secs = DHT_TTL_GLOBAL_NODE_KEY * 2;
                        let current_time = current_timestamp();

                        if current_time > timestamp + max_age_secs {
                            tracing::warn!(
                                "Stale global node key record for {} (age: {}s)",
                                node_id,
                                current_time - timestamp
                            );
                        } else {
                            return value
                                .get("public_key")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to deserialize global node key for {}: {}",
                            node_id,
                            e
                        );
                        return Some(String::from_utf8_lossy(&record.value).to_string());
                    }
                }
            }
        } else {
            tracing::warn!(
                "Cannot lookup global node public key from DHT: record store not available"
            );
        }

        if let Some(key) = self.config.global_node.known_origin_keys.get(node_id) {
            tracing::debug!(
                "Fallback: using known_origin_keys for global node {}",
                node_id
            );
            return Some(key.clone());
        }

        None
    }

    async fn fetch_cached_config<T: Clone>(
        &self,
        upstream_id: &str,
        dht_key_prefix: &str,
        parse_json: impl FnOnce(serde_json::Value) -> Option<T>,
        cache: &Arc<RwLock<LruCache<String, (T, Instant)>>>,
        inflight: &Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
        cache_hits: &AtomicU64,
        cache_misses: &AtomicU64,
        metric_prefix: &str,
    ) -> Option<T> {
        // Quick cache check
        {
            let mut c = cache.write();
            if let Some((config, cached_at)) = c.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    cache_hits.fetch_add(1, Ordering::Relaxed);
                    counter!(
                        "maluwaf.mesh.{metric_prefix}_cache_hits",
                        "upstream" => upstream_id.to_string()
                    )
                    .increment(1);
                    tracing::debug!("{} cache hit for upstream: {}", metric_prefix, upstream_id);
                    return Some(config);
                }
            }
            cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        // Get or create per-key mutex for stampede protection
        let key_lock = {
            let mut i = inflight.lock().await;
            i.entry(upstream_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };

        let _guard = key_lock.lock().await;

        // Double-check cache
        {
            let mut c = cache.write();
            if let Some((config, cached_at)) = c.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(config);
                }
            }
        }

        // Fetch from DHT
        let fetch_start = Instant::now();
        let Some(ref record_store) = self.record_store else {
            counter!(
                "maluwaf.mesh.{metric_prefix}_dht_errors",
                "type" => "no_record_store",
                "upstream" => upstream_id.to_string()
            )
            .increment(1);
            return None;
        };

        let key = format!("{}{}", dht_key_prefix, upstream_id);

        let record = match record_store.get_record(&key) {
            Some(r) => r,
            None => {
                counter!(
                    "maluwaf.mesh.{metric_prefix}_dht_errors",
                    "type" => "record_not_found",
                    "upstream" => upstream_id.to_string()
                )
                .increment(1);
                return None;
            }
        };

        let value = match String::from_utf8(record.value.clone()) {
            Ok(v) => v,
            Err(e) => {
                counter!(
                    "maluwaf.mesh.{metric_prefix}_dht_errors",
                    "type" => "utf8_error",
                    "upstream" => upstream_id.to_string()
                )
                .increment(1);
                tracing::warn!("Failed to parse {} config: {}", metric_prefix, e);
                return None;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(e) => {
                counter!(
                    "maluwaf.mesh.{metric_prefix}_dht_errors",
                    "type" => "parse_error",
                    "upstream" => upstream_id.to_string()
                )
                .increment(1);
                tracing::warn!("Failed to parse {} JSON: {}", metric_prefix, e);
                return None;
            }
        };

        let Some(config) = parse_json(parsed) else {
            return None;
        };

        // Cache the result
        {
            let mut c = cache.write();
            c.insert(upstream_id.to_string(), (config.clone(), Instant::now()));
        }

        counter!(
            "maluwaf.mesh.{metric_prefix}_dht_fetches",
            "status" => "success",
            "upstream" => upstream_id.to_string()
        )
        .increment(1);
        histogram!("maluwaf.mesh.{metric_prefix}_dht_fetch_latency")
            .record(fetch_start.elapsed().as_secs_f64());
        tracing::debug!(
            "Fetched {} from DHT for upstream: {}",
            metric_prefix,
            upstream_id
        );

        Some(config)
    }

    pub async fn get_image_protection_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::mesh::config::MeshImageProtectionConfig> {
        self.fetch_cached_config(
            upstream_id,
            "upstream_image_protection:",
            |parsed| {
                Some(crate::mesh::config::MeshImageProtectionConfig {
                    enabled: parsed.get("enabled").and_then(|v| v.as_bool()),
                    min_size_bytes: parsed
                        .get("min_size_bytes")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as usize),
                    whitelist_patterns: parsed
                        .get("whitelist_patterns")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        }),
                })
            },
            &self.image_protection_cache,
            &self.image_protection_inflight,
            &self.image_protection_cache_hits,
            &self.image_protection_cache_misses,
            "image_protection",
        )
        .await
    }

    pub async fn get_image_poison_config_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::config::site::SiteImagePoisonConfig> {
        self.fetch_cached_config(
            upstream_id,
            "site_image_poison_config:",
            |parsed| {
                Some(crate::config::site::SiteImagePoisonConfig {
                    enabled: parsed.get("enabled").and_then(|v| v.as_bool()),
                    level: parsed
                        .get("level")
                        .and_then(|v| v.as_str().map(String::from)),
                    intensity: parsed
                        .get("intensity")
                        .and_then(|v| v.as_f64())
                        .map(|v| v as f32),
                    seed: parsed.get("seed").and_then(|v| v.as_u64()),
                    max_dimension: parsed
                        .get("max_dimension")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    jpeg_quality: parsed
                        .get("jpeg_quality")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u8),
                    whitelist_patterns: parsed
                        .get("whitelist_patterns")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        }),
                })
            },
            &self.image_poison_cache,
            &self.image_poison_inflight,
            &self.image_poison_cache_hits,
            &self.image_poison_cache_misses,
            "image_poison",
        )
        .await
    }

    pub async fn get_compression_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::mesh::config::MeshCompressionConfig> {
        self.fetch_cached_config(
            upstream_id,
            "upstream_compression:",
            |parsed| {
                Some(crate::mesh::config::MeshCompressionConfig {
                    enabled: parsed.get("enabled").and_then(|v| v.as_bool()),
                    gzip_on_the_fly: parsed.get("gzip_on_the_fly").and_then(|v| v.as_bool()),
                    gzip_level: parsed
                        .get("gzip_level")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    gzip_min_size: parsed
                        .get("gzip_min_size")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as usize),
                    gzip_types: parsed
                        .get("gzip_types")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        }),
                    enable_brotli: parsed.get("enable_brotli").and_then(|v| v.as_bool()),
                    brotli_level: parsed
                        .get("brotli_level")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                })
            },
            &self.compression_cache,
            &self.compression_inflight,
            &self.compression_cache_hits,
            &self.compression_cache_misses,
            "compression",
        )
        .await
    }

    pub async fn get_minification_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::mesh::config::MeshMinificationConfig> {
        self.fetch_cached_config(
            upstream_id,
            "upstream_minification:",
            |parsed| {
                Some(crate::mesh::config::MeshMinificationConfig {
                    enabled: parsed.get("enabled").and_then(|v| v.as_bool()),
                    enable_html: parsed.get("enable_html").and_then(|v| v.as_bool()),
                    enable_css: parsed.get("enable_css").and_then(|v| v.as_bool()),
                    enable_js: parsed.get("enable_js").and_then(|v| v.as_bool()),
                })
            },
            &self.minification_cache,
            &self.minification_inflight,
            &self.minification_cache_hits,
            &self.minification_cache_misses,
            "minification",
        )
        .await
    }

    pub async fn get_proxy_cache_preferences_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::mesh::protocol::ProxyCachePreferences> {
        self.fetch_cached_config(
            upstream_id,
            "upstream_proxy_cache_preferences:",
            |parsed| {
                Some(crate::mesh::protocol::ProxyCachePreferences {
                    enable: parsed
                        .get("enable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    inactive: parsed.get("inactive").and_then(|v| v.as_u64()).unwrap_or(0),
                    valid_status: parsed
                        .get("valid_status")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64())
                                .map(|v| v as u32)
                                .collect()
                        })
                        .unwrap_or_default(),
                    methods: parsed
                        .get("methods")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    use_stale: parsed
                        .get("use_stale")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    min_uses: parsed.get("min_uses").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    stale_while_revalidate: parsed
                        .get("stale_while_revalidate")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    stale_if_error: parsed
                        .get("stale_if_error")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                })
            },
            &self.proxy_cache_preferences_cache,
            &self.proxy_cache_preferences_inflight,
            &self.proxy_cache_preferences_cache_hits,
            &self.proxy_cache_preferences_cache_misses,
            "proxy_cache_preferences",
        )
        .await
    }

    pub fn get_cache_metrics(&self) -> serde_json::Value {
        serde_json::json!({
            "image_protection": {
                "hits": self.image_protection_cache_hits.load(Ordering::Relaxed),
                "misses": self.image_protection_cache_misses.load(Ordering::Relaxed),
            },
            "compression": {
                "hits": self.compression_cache_hits.load(Ordering::Relaxed),
                "misses": self.compression_cache_misses.load(Ordering::Relaxed),
            },
            "minification": {
                "hits": self.minification_cache_hits.load(Ordering::Relaxed),
                "misses": self.minification_cache_misses.load(Ordering::Relaxed),
            },
            "proxy_cache_preferences": {
                "hits": self.proxy_cache_preferences_cache_hits.load(Ordering::Relaxed),
                "misses": self.proxy_cache_preferences_cache_misses.load(Ordering::Relaxed),
            },
        })
    }

    pub fn publish_upstream_transform_configs(
        &self,
        sites: &std::collections::HashMap<String, crate::config::site::SiteConfig>,
    ) {
        let Some(ref record_store) = self.record_store else {
            tracing::warn!("Cannot publish transform configs: no record store");
            return;
        };

        for (site_id, site_config) in sites.iter() {
            let image_poison_config = &site_config.image_poison;
            let static_config = &site_config.r#static;

            let image_protection_json = serde_json::json!({
                "enabled": image_poison_config.enabled,
                "min_size_bytes": image_poison_config.max_dimension.map(|v| v as u64),
                "whitelist_patterns": image_poison_config.whitelist_patterns,
            });
            let image_protection_key = format!("upstream_image_protection:{}", site_id);
            if let Ok(bytes) = serde_json::to_vec(&image_protection_json) {
                record_store.store_and_announce(image_protection_key, bytes, 3600);
            }

            let site_image_poison_json = serde_json::json!({
                "enabled": image_poison_config.enabled,
                "level": image_poison_config.level,
                "intensity": image_poison_config.intensity,
                "seed": image_poison_config.seed,
                "max_dimension": image_poison_config.max_dimension,
                "jpeg_quality": image_poison_config.jpeg_quality,
            });
            let site_image_poison_key = format!("site_image_poison_config:{}", site_id);
            if let Ok(bytes) = serde_json::to_vec(&site_image_poison_json) {
                record_store.store_and_announce(site_image_poison_key, bytes, 3600);
            }

            let minification_json = serde_json::json!({
                "enabled": static_config.enable_minification,
                "enable_html": static_config.enable_html_minification,
                "enable_css": static_config.enable_css_minification,
                "enable_js": static_config.enable_js_minification,
            });
            let minification_key = format!("upstream_minification:{}", site_id);
            if let Ok(bytes) = serde_json::to_vec(&minification_json) {
                record_store.store_and_announce(minification_key, bytes, 3600);
            }

            let compression_json = serde_json::json!({
                "enabled": static_config.enable_compression,
                "gzip_on_the_fly": static_config.gzip_on_the_fly,
                "gzip_level": static_config.gzip_level,
                "gzip_min_size": static_config.gzip_min_size,
                "gzip_types": static_config.gzip_types,
                "enable_brotli": static_config.enable_brotli,
                "brotli_level": static_config.brotli_level,
            });
            let compression_key = format!("upstream_compression:{}", site_id);
            if let Ok(bytes) = serde_json::to_vec(&compression_json) {
                record_store.store_and_announce(compression_key, bytes, 3600);
            }

            tracing::debug!("Published transform configs for site {} to DHT", site_id);
        }
    }

    pub fn publish_single_site_transform_config(
        &self,
        site_id: &str,
        site_config: &crate::config::site::SiteConfig,
    ) {
        let Some(ref record_store) = self.record_store else {
            tracing::warn!("Cannot publish transform config: no record store");
            return;
        };

        let image_poison_config = &site_config.image_poison;
        let static_config = &site_config.r#static;

        let image_protection_json = serde_json::json!({
            "enabled": image_poison_config.enabled,
            "min_size_bytes": image_poison_config.max_dimension.map(|v| v as u64),
            "whitelist_patterns": image_poison_config.whitelist_patterns,
        });
        let image_protection_key = format!("upstream_image_protection:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&image_protection_json) {
            record_store.store_and_announce(image_protection_key, bytes, 3600);
        }

        let site_image_poison_json = serde_json::json!({
            "enabled": image_poison_config.enabled,
            "level": image_poison_config.level,
            "intensity": image_poison_config.intensity,
            "seed": image_poison_config.seed,
            "max_dimension": image_poison_config.max_dimension,
            "jpeg_quality": image_poison_config.jpeg_quality,
        });
        let site_image_poison_key = format!("site_image_poison_config:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&site_image_poison_json) {
            record_store.store_and_announce(site_image_poison_key, bytes, 3600);
        }

        let minification_json = serde_json::json!({
            "enabled": static_config.enable_minification,
            "enable_html": static_config.enable_html_minification,
            "enable_css": static_config.enable_css_minification,
            "enable_js": static_config.enable_js_minification,
        });
        let minification_key = format!("upstream_minification:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&minification_json) {
            record_store.store_and_announce(minification_key, bytes, 3600);
        }

        let compression_json = serde_json::json!({
            "enabled": static_config.enable_compression,
            "gzip_on_the_fly": static_config.gzip_on_the_fly,
            "gzip_level": static_config.gzip_level,
            "gzip_min_size": static_config.gzip_min_size,
            "gzip_types": static_config.gzip_types,
            "enable_brotli": static_config.enable_brotli,
            "brotli_level": static_config.brotli_level,
        });
        let compression_key = format!("upstream_compression:{}", site_id);
        if let Ok(bytes) = serde_json::to_vec(&compression_json) {
            record_store.store_and_announce(compression_key, bytes, 3600);
        }

        if let Some(ref cache_config) = site_config.proxy.cache {
            let proxy_cache_prefs =
                crate::mesh::protocol::ProxyCachePreferences::from(cache_config);
            if let Ok(bytes) = serde_json::to_vec(&proxy_cache_prefs) {
                let key = format!("upstream_proxy_cache_preferences:{}", site_id);
                record_store.store_and_announce(key, bytes, 3600);
            }
        }

        tracing::debug!("Published transform config for site {} to DHT", site_id);
    }
}
