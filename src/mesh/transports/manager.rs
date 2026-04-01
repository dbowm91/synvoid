use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru_time_cache::LruCache;
use metrics::{counter, histogram};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::mesh::config::MeshConfig;
use crate::mesh::protocol::MeshMessage;
use crate::mesh::topology::MeshTopology;
use crate::mesh::transports::{
    MeshTransportError, MeshTransportTrait, MeshTransportType, QuicMeshTransport, TransportHint,
    WireGuardMeshTransport,
};
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
    wireguard_transport: Arc<RwLock<Option<Arc<WireGuardMeshTransport>>>>,
    preferred_transport: Arc<RwLock<MeshTransportType>>,
    peer_states: Arc<RwLock<HashMap<String, PeerTransportState>>>,
    record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
    routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
    // Config caches with metrics
    image_protection_cache:
        Arc<RwLock<LruCache<String, (crate::mesh::config::MeshImageProtectionConfig, Instant)>>>,
    compression_cache:
        Arc<RwLock<LruCache<String, (crate::mesh::config::MeshCompressionConfig, Instant)>>>,
    minification_cache:
        Arc<RwLock<LruCache<String, (crate::mesh::config::MeshMinificationConfig, Instant)>>>,
    // Inflight tracking for stampede prevention
    image_protection_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    compression_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    minification_inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    // Metrics counters
    image_protection_cache_hits: AtomicU64,
    image_protection_cache_misses: AtomicU64,
    compression_cache_hits: AtomicU64,
    compression_cache_misses: AtomicU64,
    minification_cache_hits: AtomicU64,
    minification_cache_misses: AtomicU64,
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

        Self {
            config,
            topology,
            quic_transport: Arc::new(RwLock::new(None)),
            wireguard_transport: Arc::new(RwLock::new(None)),
            preferred_transport: Arc::new(RwLock::new(MeshTransportType::Quic)),
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            record_store,
            routing_manager: None,
            image_protection_cache: Arc::new(RwLock::new(image_protection_cache)),
            compression_cache: Arc::new(RwLock::new(compression_cache)),
            minification_cache: Arc::new(RwLock::new(minification_cache)),
            image_protection_inflight: Arc::new(Mutex::new(HashMap::new())),
            compression_inflight: Arc::new(Mutex::new(HashMap::new())),
            minification_inflight: Arc::new(Mutex::new(HashMap::new())),
            image_protection_cache_hits: AtomicU64::new(0),
            image_protection_cache_misses: AtomicU64::new(0),
            compression_cache_hits: AtomicU64::new(0),
            compression_cache_misses: AtomicU64::new(0),
            minification_cache_hits: AtomicU64::new(0),
            minification_cache_misses: AtomicU64::new(0),
        }
    }

    pub fn set_routing_manager(
        &mut self,
        manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>,
    ) {
        self.routing_manager = Some(manager);
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

    pub fn set_quic_transport(&self, transport: QuicMeshTransport) {
        let mut t = self.quic_transport.write();
        *t = Some(Arc::new(transport));
        self.update_preferred_transport();
    }

    pub fn set_wireguard_transport(&self, transport: WireGuardMeshTransport) {
        let mut t = self.wireguard_transport.write();
        *t = Some(Arc::new(transport));
        self.update_preferred_transport();
    }

    fn update_preferred_transport(&self) {
        let mut preferred = self.preferred_transport.write();
        let wg_available = self
            .wireguard_transport
            .read()
            .as_ref()
            .map(|t| t.is_available())
            .unwrap_or(false);

        if wg_available {
            *preferred = MeshTransportType::WireGuard;
            tracing::info!("Mesh transport preference updated: WireGuard (available)");
        } else {
            *preferred = MeshTransportType::Quic;
            tracing::info!("Mesh transport preference updated: QUIC (fallback)");
        }
    }

    pub fn preferred_transport(&self) -> MeshTransportType {
        *self.preferred_transport.read()
    }

    pub fn is_wireguard_available(&self) -> bool {
        self.wireguard_transport
            .read()
            .as_ref()
            .map(|t| t.is_available())
            .unwrap_or(false)
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
            TransportHint::HighThroughput => {
                if self.is_wireguard_available() {
                    return MeshTransportType::WireGuard;
                }
            }
            TransportHint::LowLatency => {
                if self.is_wireguard_available() {
                    return MeshTransportType::WireGuard;
                }
            }
            TransportHint::Reliable => {
                if self.is_quic_available() {
                    return MeshTransportType::Quic;
                }
            }
            TransportHint::Default => {}
        }

        self.preferred_transport()
    }

    // Transport selection holds read lock across send await; low contention.
    #[allow(clippy::await_holding_lock)]
    pub async fn send_message(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        hint: TransportHint,
    ) -> Result<(), MeshTransportError> {
        let effective = self.get_effective_transport(peer_id, hint);
        let fallback = match effective {
            MeshTransportType::WireGuard => MeshTransportType::Quic,
            MeshTransportType::Quic => MeshTransportType::WireGuard,
        };

        let result = self.try_send_primary(peer_id, message, effective).await;

        if result.is_ok() {
            self.reset_peer_fallback(peer_id);
            return result;
        }

        tracing::warn!(
            "Primary transport {:?} failed for peer {}, trying fallback {:?}",
            effective,
            peer_id,
            fallback
        );

        let fallback_result = self.try_send_with_retry(peer_id, message, fallback).await;

        if fallback_result.is_ok() {
            self.record_fallback(peer_id);
        }

        fallback_result
    }

    // Transport read lock held across send await; low contention.
    #[allow(clippy::await_holding_lock)]
    async fn try_send_primary(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        transport_type: MeshTransportType,
    ) -> Result<(), MeshTransportError> {
        match transport_type {
            MeshTransportType::WireGuard => {
                let transport = self.wireguard_transport.read();
                if let Some(ref t) = *transport {
                    if !t.is_connected(peer_id) {
                        return Err(MeshTransportError::PeerNotConnected(peer_id.to_string()));
                    }
                    return t.send_stream(peer_id, message).await;
                }
            }
            MeshTransportType::Quic => {
                let transport = self.quic_transport.read();
                if let Some(ref t) = *transport {
                    if !t.is_connected(peer_id) {
                        return Err(MeshTransportError::PeerNotConnected(peer_id.to_string()));
                    }
                    return t.send_stream(peer_id, message).await;
                }
            }
        }
        Err(MeshTransportError::NotAvailable)
    }

    async fn try_send_with_retry(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        fallback: MeshTransportType,
    ) -> Result<(), MeshTransportError> {
        let mut retry_count = {
            let states = self.peer_states.read();
            states.get(peer_id).map(|s| s.fallback_count).unwrap_or(0)
        };

        let max_retries = DEFAULT_MAX_RETRIES;

        loop {
            let result = self.try_send_primary(peer_id, message, fallback).await;

            if result.is_ok() {
                return Ok(());
            }

            if retry_count >= max_retries {
                tracing::warn!(
                    "Max retries ({}) exceeded for peer {} fallback transport",
                    max_retries,
                    peer_id
                );
                break;
            }

            let backoff = RETRY_BACKOFF_BASE_MS * (2_u64.pow(retry_count.min(5)));
            let backoff_duration = Duration::from_millis(backoff.min(RETRY_BACKOFF_MAX_MS));

            tracing::debug!(
                "Retry attempt {}/{} for peer {} after {:?}",
                retry_count + 1,
                max_retries,
                peer_id,
                backoff_duration
            );

            retry_count += 1;
            {
                let mut states = self.peer_states.write();
                if let Some(state) = states.get_mut(peer_id) {
                    state.record_fallback();
                }
            }

            sleep(backoff_duration).await;
        }

        Err(MeshTransportError::PeerNotConnected(peer_id.to_string()))
    }

    fn record_fallback(&self, peer_id: &str) {
        let mut states = self.peer_states.write();
        if let Some(state) = states.get_mut(peer_id) {
            state.record_fallback();
        }
    }

    fn reset_peer_fallback(&self, peer_id: &str) {
        let mut states = self.peer_states.write();
        if let Some(state) = states.get_mut(peer_id) {
            state.reset_fallback();
        }
    }

    // Transport selection holds read lock across send await; low contention.
    #[allow(clippy::await_holding_lock)]
    pub async fn send_datagram(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        hint: TransportHint,
    ) -> Result<(), MeshTransportError> {
        let effective = self.get_effective_transport(peer_id, hint);
        let fallback = match effective {
            MeshTransportType::WireGuard => MeshTransportType::Quic,
            MeshTransportType::Quic => MeshTransportType::WireGuard,
        };

        let result = self
            .try_send_datagram_primary(peer_id, message, effective)
            .await;

        if result.is_ok() {
            self.reset_peer_fallback(peer_id);
            return result;
        }

        tracing::warn!(
            "Primary datagram transport {:?} failed for peer {}, trying fallback {:?}",
            effective,
            peer_id,
            fallback
        );

        let fallback_result = self
            .try_send_datagram_with_retry(peer_id, message, fallback)
            .await;

        if fallback_result.is_ok() {
            self.record_fallback(peer_id);
        }

        fallback_result
    }

    // Transport read lock held across datagram send await; low contention.
    #[allow(clippy::await_holding_lock)]
    async fn try_send_datagram_primary(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        transport_type: MeshTransportType,
    ) -> Result<(), MeshTransportError> {
        match transport_type {
            MeshTransportType::WireGuard => {
                let transport = self.wireguard_transport.read();
                if let Some(ref t) = *transport {
                    if !t.is_connected(peer_id) {
                        return Err(MeshTransportError::PeerNotConnected(peer_id.to_string()));
                    }
                    return t.send_datagram(peer_id, message).await;
                }
            }
            MeshTransportType::Quic => {
                let transport = self.quic_transport.read();
                if let Some(ref t) = *transport {
                    if !t.is_connected(peer_id) {
                        return Err(MeshTransportError::PeerNotConnected(peer_id.to_string()));
                    }
                    return t.send_datagram(peer_id, message).await;
                }
            }
        }
        Err(MeshTransportError::NotAvailable)
    }

    async fn try_send_datagram_with_retry(
        &self,
        peer_id: &str,
        message: &MeshMessage,
        fallback: MeshTransportType,
    ) -> Result<(), MeshTransportError> {
        let mut retry_count = {
            let states = self.peer_states.read();
            states.get(peer_id).map(|s| s.fallback_count).unwrap_or(0)
        };

        let max_retries = DEFAULT_MAX_RETRIES;

        loop {
            let result = self
                .try_send_datagram_primary(peer_id, message, fallback)
                .await;

            if result.is_ok() {
                return Ok(());
            }

            if retry_count >= max_retries {
                tracing::warn!(
                    "Max retries ({}) exceeded for peer {} datagram fallback",
                    max_retries,
                    peer_id
                );
                break;
            }

            let backoff = RETRY_BACKOFF_BASE_MS * (2_u64.pow(retry_count.min(5)));
            let backoff_duration = Duration::from_millis(backoff.min(RETRY_BACKOFF_MAX_MS));

            tracing::debug!(
                "Datagram retry attempt {}/{} for peer {} after {:?}",
                retry_count + 1,
                max_retries,
                peer_id,
                backoff_duration
            );

            retry_count += 1;
            {
                let mut states = self.peer_states.write();
                if let Some(state) = states.get_mut(peer_id) {
                    state.record_fallback();
                }
            }

            sleep(backoff_duration).await;
        }

        Err(MeshTransportError::PeerNotConnected(peer_id.to_string()))
    }

    // Transport selection holds read lock across broadcast await; low contention.
    #[allow(clippy::await_holding_lock)]
    pub async fn broadcast_datagram(
        &self,
        message: &MeshMessage,
        hint: TransportHint,
    ) -> Result<(), MeshTransportError> {
        let preferred = match hint {
            TransportHint::HighThroughput | TransportHint::LowLatency => {
                if self.is_wireguard_available() {
                    MeshTransportType::WireGuard
                } else {
                    MeshTransportType::Quic
                }
            }
            TransportHint::Reliable => {
                if self.is_quic_available() {
                    MeshTransportType::Quic
                } else {
                    MeshTransportType::WireGuard
                }
            }
            TransportHint::Default => self.preferred_transport(),
        };

        match preferred {
            MeshTransportType::WireGuard => {
                if let Some(ref transport) = *self.wireguard_transport.read() {
                    if transport.is_available() {
                        return transport.broadcast_datagram(message).await;
                    }
                }
            }
            MeshTransportType::Quic => {
                if let Some(ref transport) = *self.quic_transport.read() {
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
        if self.is_wireguard_available() {
            if let Some(ref transport) = *self.wireguard_transport.read() {
                return transport.get_connected_peers();
            }
        }

        if self.is_quic_available() {
            if let Some(ref transport) = *self.quic_transport.read() {
                return transport.get_connected_peers();
            }
        }

        Vec::new()
    }

    pub fn local_addresses(&self) -> Vec<String> {
        if self.is_wireguard_available() {
            if let Some(ref transport) = *self.wireguard_transport.read() {
                return transport.local_addresses();
            }
        }

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
        self.routing_manager.clone()
    }

    pub fn get_wireguard_transport(&self) -> Option<Arc<WireGuardMeshTransport>> {
        self.wireguard_transport.read().clone()
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
        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
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

    pub async fn get_image_protection_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::mesh::config::MeshImageProtectionConfig> {
        // Quick cache check
        {
            let mut cache = self.image_protection_cache.write();
            if let Some((config, cached_at)) = cache.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    self.image_protection_cache_hits
                        .fetch_add(1, Ordering::Relaxed);
                    counter!("maluwaf.mesh.image_protection_cache_hits", "upstream" => upstream_id.to_string()).increment(1);
                    tracing::debug!("Image protection cache hit for upstream: {}", upstream_id);
                    return Some(config);
                }
            }
            self.image_protection_cache_misses
                .fetch_add(1, Ordering::Relaxed);
        }

        // Get or create per-key mutex for stampede protection
        let key_lock = {
            let mut inflight = self.image_protection_inflight.lock().await;
            inflight
                .entry(upstream_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };

        let _guard = key_lock.lock().await;

        // Double-check cache
        {
            let mut cache = self.image_protection_cache.write();
            if let Some((config, cached_at)) = cache.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    self.image_protection_cache_hits
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(config);
                }
            }
        }

        // Fetch from DHT
        let fetch_start = Instant::now();
        let Some(ref record_store) = self.record_store else {
            counter!("maluwaf.mesh.image_protection_dht_errors", "type" => "no_record_store", "upstream" => upstream_id.to_string()).increment(1);
            return None;
        };

        let key = format!("upstream_image_protection:{}", upstream_id);

        let record = match record_store.get_record(&key) {
            Some(r) => r,
            None => {
                counter!("maluwaf.mesh.image_protection_dht_errors", "type" => "record_not_found", "upstream" => upstream_id.to_string()).increment(1);
                return None;
            }
        };

        let value = match String::from_utf8(record.value.clone()) {
            Ok(v) => v,
            Err(e) => {
                counter!("maluwaf.mesh.image_protection_dht_errors", "type" => "utf8_error", "upstream" => upstream_id.to_string()).increment(1);
                tracing::warn!("Failed to parse image protection config: {}", e);
                return None;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(e) => {
                counter!("maluwaf.mesh.image_protection_dht_errors", "type" => "parse_error", "upstream" => upstream_id.to_string()).increment(1);
                tracing::warn!("Failed to parse image protection JSON: {}", e);
                return None;
            }
        };

        let config = crate::mesh::config::MeshImageProtectionConfig {
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
        };

        // Cache the result
        {
            let mut cache = self.image_protection_cache.write();
            cache.insert(upstream_id.to_string(), (config.clone(), Instant::now()));
        }

        counter!("maluwaf.mesh.image_protection_dht_fetches", "status" => "success", "upstream" => upstream_id.to_string()).increment(1);
        histogram!("maluwaf.mesh.image_protection_dht_fetch_latency")
            .record(fetch_start.elapsed().as_secs_f64());
        tracing::debug!(
            "Fetched image protection from DHT for upstream: {}",
            upstream_id
        );

        Some(config)
    }

    pub async fn get_compression_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::mesh::config::MeshCompressionConfig> {
        // Quick cache check
        {
            let mut cache = self.compression_cache.write();
            if let Some((config, cached_at)) = cache.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    self.compression_cache_hits.fetch_add(1, Ordering::Relaxed);
                    counter!("maluwaf.mesh.compression_cache_hits", "upstream" => upstream_id.to_string()).increment(1);
                    tracing::debug!("Compression cache hit for upstream: {}", upstream_id);
                    return Some(config);
                }
            }
            self.compression_cache_misses
                .fetch_add(1, Ordering::Relaxed);
        }

        // Get or create per-key mutex
        let key_lock = {
            let mut inflight = self.compression_inflight.lock().await;
            inflight
                .entry(upstream_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };

        let _guard = key_lock.lock().await;

        // Double-check cache
        {
            let mut cache = self.compression_cache.write();
            if let Some((config, cached_at)) = cache.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    self.compression_cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(config);
                }
            }
        }

        // Fetch from DHT
        let fetch_start = Instant::now();
        let Some(ref record_store) = self.record_store else {
            counter!("maluwaf.mesh.compression_dht_errors", "type" => "no_record_store", "upstream" => upstream_id.to_string()).increment(1);
            return None;
        };

        let key = format!("upstream_compression:{}", upstream_id);

        let record = match record_store.get_record(&key) {
            Some(r) => r,
            None => {
                counter!("maluwaf.mesh.compression_dht_errors", "type" => "record_not_found", "upstream" => upstream_id.to_string()).increment(1);
                return None;
            }
        };

        let value = match String::from_utf8(record.value.clone()) {
            Ok(v) => v,
            Err(e) => {
                counter!("maluwaf.mesh.compression_dht_errors", "type" => "utf8_error", "upstream" => upstream_id.to_string()).increment(1);
                tracing::warn!("Failed to parse compression config: {}", e);
                return None;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(e) => {
                counter!("maluwaf.mesh.compression_dht_errors", "type" => "parse_error", "upstream" => upstream_id.to_string()).increment(1);
                tracing::warn!("Failed to parse compression JSON: {}", e);
                return None;
            }
        };

        let config = crate::mesh::config::MeshCompressionConfig {
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
        };

        // Cache the result
        {
            let mut cache = self.compression_cache.write();
            cache.insert(upstream_id.to_string(), (config.clone(), Instant::now()));
        }

        counter!("maluwaf.mesh.compression_dht_fetches", "status" => "success", "upstream" => upstream_id.to_string()).increment(1);
        histogram!("maluwaf.mesh.compression_dht_fetch_latency")
            .record(fetch_start.elapsed().as_secs_f64());
        tracing::debug!("Fetched compression from DHT for upstream: {}", upstream_id);

        Some(config)
    }

    pub async fn get_minification_for_site(
        &self,
        upstream_id: &str,
    ) -> Option<crate::mesh::config::MeshMinificationConfig> {
        // Quick cache check
        {
            let mut cache = self.minification_cache.write();
            if let Some((config, cached_at)) = cache.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    self.minification_cache_hits.fetch_add(1, Ordering::Relaxed);
                    counter!("maluwaf.mesh.minification_cache_hits", "upstream" => upstream_id.to_string()).increment(1);
                    tracing::debug!("Minification cache hit for upstream: {}", upstream_id);
                    return Some(config);
                }
            }
            self.minification_cache_misses
                .fetch_add(1, Ordering::Relaxed);
        }

        // Get or create per-key mutex
        let key_lock = {
            let mut inflight = self.minification_inflight.lock().await;
            inflight
                .entry(upstream_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };

        let _guard = key_lock.lock().await;

        // Double-check cache
        {
            let mut cache = self.minification_cache.write();
            if let Some((config, cached_at)) = cache.get(upstream_id).cloned() {
                if cached_at.elapsed() < Duration::from_secs(300) {
                    self.minification_cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(config);
                }
            }
        }

        // Fetch from DHT
        let fetch_start = Instant::now();
        let Some(ref record_store) = self.record_store else {
            counter!("maluwaf.mesh.minification_dht_errors", "type" => "no_record_store", "upstream" => upstream_id.to_string()).increment(1);
            return None;
        };

        let key = format!("upstream_minification:{}", upstream_id);

        let record = match record_store.get_record(&key) {
            Some(r) => r,
            None => {
                counter!("maluwaf.mesh.minification_dht_errors", "type" => "record_not_found", "upstream" => upstream_id.to_string()).increment(1);
                return None;
            }
        };

        let value = match String::from_utf8(record.value.clone()) {
            Ok(v) => v,
            Err(e) => {
                counter!("maluwaf.mesh.minification_dht_errors", "type" => "utf8_error", "upstream" => upstream_id.to_string()).increment(1);
                tracing::warn!("Failed to parse minification config: {}", e);
                return None;
            }
        };

        let parsed: serde_json::Value = match serde_json::from_str(&value) {
            Ok(v) => v,
            Err(e) => {
                counter!("maluwaf.mesh.minification_dht_errors", "type" => "parse_error", "upstream" => upstream_id.to_string()).increment(1);
                tracing::warn!("Failed to parse minification JSON: {}", e);
                return None;
            }
        };

        let config = crate::mesh::config::MeshMinificationConfig {
            enabled: parsed.get("enabled").and_then(|v| v.as_bool()),
            enable_html: parsed.get("enable_html").and_then(|v| v.as_bool()),
            enable_css: parsed.get("enable_css").and_then(|v| v.as_bool()),
            enable_js: parsed.get("enable_js").and_then(|v| v.as_bool()),
        };

        // Cache the result
        {
            let mut cache = self.minification_cache.write();
            cache.insert(upstream_id.to_string(), (config.clone(), Instant::now()));
        }

        counter!("maluwaf.mesh.minification_dht_fetches", "status" => "success", "upstream" => upstream_id.to_string()).increment(1);
        histogram!("maluwaf.mesh.minification_dht_fetch_latency")
            .record(fetch_start.elapsed().as_secs_f64());
        tracing::debug!(
            "Fetched minification from DHT for upstream: {}",
            upstream_id
        );

        Some(config)
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
        })
    }
}
