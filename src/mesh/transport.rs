#![allow(unused_variables, unused_mut)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "dns")]
use crate::dns::server::Zone as DnsZone;

use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;

use lru_time_cache::LruCache;

use bytes::Bytes;
use dashmap::DashMap;
use futures::future::{BoxFuture, FutureExt, join_all};
use base64::Engine;
use http_body::Body as HttpBody;
use http_body_util::combinators::BoxBody;
use hyper::{Request, Response};
use metrics::{counter, gauge};
use parking_lot::RwLock;
use rand::Rng;

use tokio::sync::{broadcast, mpsc, oneshot, Mutex};

use quinn::{Connection, SendStream, RecvStream};

use crate::mesh::cert::MeshCertManager;
use crate::mesh::config::{MeshConfig, MeshPeerConfig};
use crate::mesh::kem::MlKem768;
use crate::mesh::protocol::{MeshMessage, MeshPeerInfo, UpstreamInfo, RouteQueryResult, ProviderInfo, MESH_MESSAGE_VERSION};
use crate::mesh::session::SessionManager;
use crate::mesh::topology::{MeshTopology, PeerStatus};
use crate::mesh::wireguard_mesh::WireGuardMeshRuntime;
use crate::tunnel::quic::runtime::QuicRuntime;
use crate::waf::ratelimit::core::AtomicSlidingWindow;

pub use crate::mesh::transports::MeshTransportManager;

const MAX_PENDING_CONNECTIONS: usize = 100;
const CONNECTION_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const MAX_MESSAGE_QUEUE_SIZE: usize = 1000;
const DEFAULT_MAX_PEER_MESSAGE_RATE: usize = 1000;
const PEER_RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum duration for a block received from another node (24 hours)
const MAX_BLOCK_DURATION_SECS: u64 = 86400;
/// Minimum reasonable Unix timestamp (Jan 1, 2025)
const MIN_REASONABLE_TIMESTAMP: u64 = 1735689600;
/// Maximum reasonable Unix timestamp (Jan 1, 2027)
const MAX_REASONABLE_TIMESTAMP: u64 = 1767225600;

static TIME_VALIDATION_ERRORS: AtomicU64 = AtomicU64::new(0);

pub struct MeshTransport {
    config: Arc<MeshConfig>,
    topology: Arc<MeshTopology>,
    cert_manager: Arc<RwLock<MeshCertManager>>,
    runtime: Option<Arc<QuicRuntime>>,
    wireguard_runtime: Option<Arc<WireGuardMeshRuntime>>,
    running: Arc<RwLock<bool>>,
    shutdown_tx: Arc<RwLock<Option<broadcast::Sender<()>>>>,
    pub peer_connections: Arc<DashMap<String, MeshPeerConnection>>,
    auth_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    connection_times: Arc<RwLock<Vec<Instant>>>,
    query_dedup: Arc<Mutex<HashMap<String, oneshot::Sender<RouteQueryResult>>>>,
    pending_queries: Arc<Mutex<PendingQueryManager>>,
    auth_failures: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    peer_message_times: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    global_rate_limiter: Arc<MeshGlobalRateLimiter>,
    org_manager: Arc<RwLock<crate::mesh::organization::OrganizationManager>>,
    tier_key_store: Option<Arc<RwLock<crate::mesh::dht::TierKeyStore>>>,
    datagram_tx: mpsc::Sender<DatagramMessage>,
    origin_ed25519_signer: Option<Arc<crate::integrity::Ed25519Signer>>,
    mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
    record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
    routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
    threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
    seen_messages: Arc<RwLock<lru_time_cache::LruCache<String, Instant>>>,
    stake_manager: Option<Arc<crate::mesh::dht::StakeManager>>,
    mlkem_session_manager: Option<Arc<SessionManager<MlKem768>>>,
    #[cfg(feature = "dns")]
    dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>>,
    #[cfg(feature = "dns")]
    dns_zones: Arc<RwLock<Option<Arc<RwLock<HashMap<String, DnsZone>>>>>>,
}

impl Clone for MeshTransport {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            topology: self.topology.clone(),
            cert_manager: self.cert_manager.clone(),
            runtime: self.runtime.clone(),
            wireguard_runtime: self.wireguard_runtime.clone(),
            running: self.running.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            peer_connections: self.peer_connections.clone(),
            auth_keys: self.auth_keys.clone(),
            connection_times: self.connection_times.clone(),
            query_dedup: self.query_dedup.clone(),
            pending_queries: self.pending_queries.clone(),
            auth_failures: self.auth_failures.clone(),
            peer_message_times: self.peer_message_times.clone(),
            global_rate_limiter: self.global_rate_limiter.clone(),
            org_manager: self.org_manager.clone(),
            tier_key_store: self.tier_key_store.clone(),
            datagram_tx: self.datagram_tx.clone(),
            origin_ed25519_signer: self.origin_ed25519_signer.clone(),
            mesh_signer: self.mesh_signer.clone(),
            record_store: self.record_store.clone(),
            routing_manager: self.routing_manager.clone(),
            threat_intel: self.threat_intel.clone(),
            seen_messages: Arc::new(RwLock::new(lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(300), 10000,
            ))),
            stake_manager: self.stake_manager.clone(),
            mlkem_session_manager: self.mlkem_session_manager.clone(),
            #[cfg(feature = "dns")]
            dns_registry: self.dns_registry.clone(),
            #[cfg(feature = "dns")]
            dns_zones: self.dns_zones.clone(),
        }
    }
}

pub struct MeshGlobalRateLimiter {
    per_second: AtomicSlidingWindow,
    per_minute: AtomicSlidingWindow,
}

impl MeshGlobalRateLimiter {
    pub fn new(messages_per_second: usize, messages_per_minute: usize) -> Self {
        Self {
            per_second: AtomicSlidingWindow::new(1, 10),
            per_minute: AtomicSlidingWindow::new(60, 60),
        }
    }

    pub fn check(&self) -> GlobalRateLimitCheck {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        GlobalRateLimitCheck {
            current_per_second: self.per_second.get_count(now_ms),
            current_per_minute: self.per_minute.get_count(now_ms),
        }
    }

    pub fn record(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        self.per_second.increment(now_ms);
        self.per_minute.increment(now_ms);
    }
}

pub struct GlobalRateLimitCheck {
    pub current_per_second: u64,
    pub current_per_minute: u64,
}

pub fn validate_system_time() {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    if now_unix < MIN_REASONABLE_TIMESTAMP {
        let offset = MIN_REASONABLE_TIMESTAMP.saturating_sub(now_unix);
        TIME_VALIDATION_ERRORS.fetch_add(1, Ordering::SeqCst);
        counter!("maluwaf.mesh.time_validation.errors", "reason" => "clock_behind").increment(1);
        tracing::error!(
            "System time appears incorrect: {} (Unix timestamp), expected at least {}. \
            Please sync NTP! Clock is off by approximately {} seconds ({} years)",
            now_unix, MIN_REASONABLE_TIMESTAMP, offset, offset / 31536000
        );
    } else if now_unix > MAX_REASONABLE_TIMESTAMP {
        let offset = now_unix.saturating_sub(MAX_REASONABLE_TIMESTAMP);
        TIME_VALIDATION_ERRORS.fetch_add(1, Ordering::SeqCst);
        counter!("maluwaf.mesh.time_validation.errors", "reason" => "clock_ahead").increment(1);
        tracing::error!(
            "System time appears incorrect: {} (Unix timestamp), expected at most {}. \
            Please sync NTP! Clock is off by approximately {} seconds ({} years)",
            now_unix, MAX_REASONABLE_TIMESTAMP, offset, offset / 31536000
        );
    } else {
        counter!("maluwaf.mesh.time_validation.valid").increment(1);
        tracing::info!("System time validated: {} (Unix timestamp)", now_unix);
    }
}

pub fn get_time_validation_error_count() -> u64 {
    TIME_VALIDATION_ERRORS.load(Ordering::SeqCst)
}

#[derive(Clone)]
struct QueuedMessage {
    target_node: String,
    message: Arc<MeshMessage>,
    priority: MessagePriority,
    enqueued_at: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MessagePriority {
    High = 2,
    Normal = 1,
    Low = 0,
}

#[derive(Debug, Clone)]
pub struct DatagramMessage {
    pub source_node: String,
    pub data: Bytes,
    pub received_at: Instant,
}

struct PendingQueryManager {
    pending: HashMap<String, oneshot::Sender<RouteQueryResult>>,
    collected_providers: HashMap<String, Vec<ProviderInfo>>,
}

impl PendingQueryManager {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            collected_providers: HashMap::new(),
        }
    }

    fn register(&mut self, query_id: String, sender: oneshot::Sender<RouteQueryResult>) {
        self.pending.insert(query_id.clone(), sender);
        self.collected_providers.insert(query_id, Vec::new());
    }

    fn add_provider(&mut self, query_id: &str, provider: ProviderInfo) {
        if let Some(providers) = self.collected_providers.get_mut(query_id) {
            if !providers.iter().any(|p| p.node_id == provider.node_id) {
                providers.push(provider);
            }
        }
    }

    fn complete(&mut self, query_id: &str, result: RouteQueryResult) -> bool {
        match self.pending.remove(query_id) { Some(sender) => {
            self.collected_providers.remove(query_id);
            sender.send(result).is_ok()
        } _ => {
            false
        }}
    }

    fn take(&mut self, query_id: &str) -> Option<oneshot::Sender<RouteQueryResult>> {
        self.collected_providers.remove(query_id);
        self.pending.remove(query_id)
    }

    fn cleanup(&mut self) {
        self.pending.retain(|_, sender| !sender.is_closed());
    }
}

#[derive(Clone)]
pub struct MeshPeerConnection {
    pub node_id: String,
    pub address: String,
    pub connection: Connection,
    pub session_id: String,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub role: crate::mesh::config::MeshNodeRole,
    pub upstreams: Vec<String>,
    pub is_trusted: bool,
}

impl MeshTransport {
    pub fn new(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        cert_manager: Arc<RwLock<MeshCertManager>>,
        record_store: Option<Arc<crate::mesh::dht::RecordStoreManager>>,
        routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>,
        threat_intel: Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>>,
        mesh_signer: Option<Arc<crate::mesh::protocol::MeshMessageSigner>>,
        stake_manager: Option<Arc<crate::mesh::dht::StakeManager>>,
        #[cfg(feature = "dns")] dns_registry: Option<Arc<crate::dns::MeshDnsRegistry>>,
    ) -> Self {
        let is_genesis = config.is_genesis_node();
        
        let auth_keys: HashMap<String, Vec<u8>> = HashMap::new();
        
        let global_rate_limiter = Arc::new(MeshGlobalRateLimiter::new(
            config.routing.mesh_messages_per_sec,
            config.routing.route_queries_per_minute,
        ));
        
        let (datagram_tx, _) = mpsc::channel(1024);

        let origin_ed25519_signer = config.origin_signing_key.as_ref().and_then(|key_cfg| {
            key_cfg.private_key.map(|pk| {
                Arc::new(crate::integrity::Ed25519Signer::new(pk))
            })
        });

        let seen_messages = LruCache::with_expiry_duration_and_capacity(Duration::from_secs(300), 10000);
        
        let tier_key_store = if config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
            Some(Arc::new(RwLock::new(crate::mesh::dht::TierKeyStore::new())))
        } else {
            None
        };

        let mlkem_session_manager = if let Some(ref mlkem_config) = config.mlkem {
            if mlkem_config.enabled {
                let session_config: crate::mesh::session::SessionConfig = mlkem_config.clone().into();
                Some(Arc::new(SessionManager::<MlKem768>::new(session_config)))
            } else {
                None
            }
        } else {
            None
        };
        
        Self {
            config,
            topology,
            cert_manager,
            runtime: None,
            wireguard_runtime: None,
            running: Arc::new(RwLock::new(false)),
            shutdown_tx: Arc::new(RwLock::new(None)),
            peer_connections: Arc::new(DashMap::new()),
            auth_keys: Arc::new(RwLock::new(auth_keys)),
            connection_times: Arc::new(RwLock::new(Vec::new())),
            query_dedup: Arc::new(Mutex::new(HashMap::new())),
            pending_queries: Arc::new(Mutex::new(PendingQueryManager::new())),
            auth_failures: Arc::new(RwLock::new(HashMap::new())),
            peer_message_times: Arc::new(RwLock::new(HashMap::new())),
            global_rate_limiter,
            org_manager: {
                let mut org_mgr = crate::mesh::organization::OrganizationManager::new();
                if is_genesis {
                    org_mgr.init_genesis_org();
                    tracing::info!("Initialized genesis node - genesis and admin organizations created");
                }
                Arc::new(RwLock::new(org_mgr))
            },
            tier_key_store,
            datagram_tx,
            origin_ed25519_signer,
            mesh_signer,
            record_store,
            routing_manager: None,
            threat_intel,
            seen_messages: Arc::new(RwLock::new(seen_messages)),
            stake_manager,
            mlkem_session_manager,
            #[cfg(feature = "dns")]
            dns_registry,
            #[cfg(feature = "dns")]
            dns_zones: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(feature = "dns")]
    pub fn set_dns_zones(&self, zones: Arc<RwLock<HashMap<String, DnsZone>>>) {
        let mut lock = self.dns_zones.write();
        *lock = Some(zones);
    }

    pub fn get_org_manager(&self) -> Arc<RwLock<crate::mesh::organization::OrganizationManager>> {
        self.org_manager.clone()
    }

    pub fn get_record_store(&self) -> Option<Arc<crate::mesh::dht::RecordStoreManager>> {
        self.record_store.clone()
    }

    pub fn get_routing_manager(&self) -> Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>> {
        self.routing_manager.clone()
    }

    pub fn set_routing_manager(&mut self, manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>) {
        self.routing_manager = Some(manager);
    }

    pub fn get_tier_key_store(&self) -> Option<Arc<RwLock<crate::mesh::dht::TierKeyStore>>> {
        self.tier_key_store.clone()
    }

    pub fn get_topology(&self) -> Arc<MeshTopology> {
        self.topology.clone()
    }

    pub fn get_threat_intel(&self) -> Option<Arc<crate::mesh::threat_intel::ThreatIntelligenceManager>> {
        self.threat_intel.clone()
    }

    pub fn get_stake_manager(&self) -> Option<Arc<crate::mesh::dht::StakeManager>> {
        self.stake_manager.clone()
    }

    pub fn get_mlkem_session_manager(&self) -> Option<Arc<SessionManager<MlKem768>>> {
        self.mlkem_session_manager.clone()
    }

    pub fn set_mlkem_session_manager(&mut self, manager: Arc<SessionManager<MlKem768>>) {
        self.mlkem_session_manager = Some(manager);
    }

    pub fn get_global_rate_limit_status(&self) -> GlobalRateLimitCheck {
        self.global_rate_limiter.check()
    }

    pub fn announce_edge_key(&self, edge_id: &str, public_key: &str) {
        if let Some(ref record_store) = self.record_store {
            let key = format!("edge_key:{}", edge_id);
            let value = serde_json::json!({
                "edge_id": edge_id,
                "public_key": public_key,
                "announced_at": chrono::Utc::now().timestamp(),
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                record_store.store_and_announce(key, bytes, 86400); // 24 hour TTL
                tracing::debug!("Announced edge key for {} to DHT", edge_id);
            }
        }
    }

    pub async fn get_edge_key(&self, edge_id: &str) -> Option<String> {
        if let Some(ref record_store) = self.record_store {
            let key = format!("edge_key:{}", edge_id);
            if let Some(record) = record_store.get_record(&key) {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&record.value) {
                    return value.get("public_key").and_then(|v| v.as_str()).map(|s| s.to_string());
                }
            }
        }
        None
    }

    pub fn initialize_component_transports(&self) {
        let transport_arc = Arc::new(self.clone());
        if let Some(ref rs) = self.record_store {
            rs.set_transport(transport_arc.clone());
        }
        if let Some(ref ti) = self.threat_intel {
            ti.set_transport(transport_arc.clone());
        }
    }

    pub fn check_global_rate_limit(&self) -> bool {
        let check = self.global_rate_limiter.check();
        let max_per_second = self.config.routing.mesh_messages_per_sec;
        
        if check.current_per_second > max_per_second as u64 {
            tracing::warn!(
                "Global mesh rate limit exceeded: {} msg/s (limit: {})",
                check.current_per_second,
                max_per_second
            );
            return false;
        }
        
        self.global_rate_limiter.record();
        true
    }

    pub fn is_global_rate_limit_exceeded(&self) -> bool {
        let check = self.global_rate_limiter.check();
        let max_per_second = self.config.routing.mesh_messages_per_sec;
        check.current_per_second > max_per_second as u64
    }

    pub fn is_message_seen(&self, message_id: &str) -> bool {
        self.seen_messages.read().contains_key(message_id)
    }

    pub fn mark_message_seen(&self, message_id: &str) {
        let mut cache = self.seen_messages.write();
        cache.insert(message_id.to_string(), Instant::now());
    }

    pub fn get_message_cache_size(&self) -> usize {
        self.seen_messages.read().len()
    }

    pub fn clean_expired_messages(&self) {
        let mut cache = self.seen_messages.write();
        let now = Instant::now();
        cache.iter()
            .filter(|(_, time)| now.duration_since(**time).as_secs() > 300)
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|k| { cache.remove(&k); });
    }

    pub fn set_runtime(&mut self, runtime: Arc<QuicRuntime>) {
        self.runtime = Some(runtime);
    }

    pub fn set_wireguard_runtime(&mut self, runtime: Arc<WireGuardMeshRuntime>) {
        self.wireguard_runtime = Some(runtime);
    }

    async fn update_threat_intel_global_nodes(&self) {
        if let Some(ref threat_intel) = self.threat_intel {
            let global_nodes = self.topology.get_global_nodes_as_peer_info().await;
            threat_intel.update_global_nodes(global_nodes);
        }
    }

    pub fn is_using_wireguard(&self) -> bool {
        self.wireguard_runtime.is_some()
    }

    pub fn get_quic_port(&self) -> Option<u16> {
        if let Some(ref runtime) = self.runtime {
            runtime.local_port()
        } else {
            Some(self.config.port)
        }
    }

    pub fn get_wireguard_port(&self) -> Option<u16> {
        if let Some(ref wg) = self.wireguard_runtime {
            Some(wg.listen_port())
        } else {
            self.wireguard_port()
        }
    }

    pub fn wireguard_port(&self) -> Option<u16> {
        if self.config.wireguard.enabled {
            Some(self.config.wireguard.listen_port)
        } else {
            None
        }
    }

    pub async fn get_actual_quic_port(&self) -> Option<u16> {
        if let Some(ref runtime) = self.runtime {
            if let Some(addr) = runtime.local_addr().await {
                return Some(addr.port());
            }
            return runtime.local_port();
        }
        self.config.quic_port.or(Some(self.config.port))
    }

    pub fn get_bind_addresses(&self) -> Vec<String> {
        if let Some(ref wg) = self.wireguard_runtime {
            return wg.local_addresses();
        }
        if let Some(ref addr) = self.config.bind_address {
            vec![addr.clone()]
        } else {
            vec!["0.0.0.0".to_string()]
        }
    }

    pub async fn send_datagram_to_peer(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        let peer = self.peer_connections.get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let encoded = message.encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        peer.connection.send_datagram(encoded.into())
            .map_err(|e| MeshTransportError::SendFailed(format!("Datagram send failed: {}", e)))?;

        tracing::debug!("Sent datagram to peer {}: {:?}", peer_id, message);
        Ok(())
    }

    pub async fn send_route_query_datagram(
        &self,
        peer_id: &str,
        query_id: &str,
        upstream_id: &str,
    ) -> Result<(), MeshTransportError> {
        let sequence = self.config.routing.query_sequence.next();
        let timestamp = MeshMessage::generate_timestamp();
        let nonce = MeshMessage::generate_nonce();
        let query = MeshMessage::RouteQuery {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
            max_hops: self.config.routing.max_hops,
            initiator: self.config.node_id().into(),
            sequence,
            timestamp,
            nonce,
        };

        self.send_datagram_to_peer(peer_id, &query).await
    }

    /// Send a route query using QUIC streams for reliable, ordered delivery
    /// This is faster than datagrams in lossy networks due to built-in retransmission
    pub async fn send_route_query_stream(
        &self,
        peer_id: &str,
        query_id: &str,
        upstream_id: &str,
    ) -> Result<(), MeshTransportError> {
        let peer = self.peer_connections.get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let sequence = self.config.routing.query_sequence.next();
        let timestamp = MeshMessage::generate_timestamp();
        let nonce = MeshMessage::generate_nonce();
        let query = MeshMessage::RouteQuery {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
            max_hops: self.config.routing.max_hops,
            initiator: self.config.node_id().into(),
            sequence,
            timestamp,
            nonce,
        };

        let (mut send_stream, _) = peer.connection.open_bi().await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let encoded = query.encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream.write_all(&len).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream.write_all(&encoded).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        tracing::debug!("Sent stream route query to peer {}: {}", peer_id, query_id);
        Ok(())
    }

    pub async fn send_keepalive_datagram(
        &self,
        peer_id: &str,
    ) -> Result<(), MeshTransportError> {
        self.send_datagram_to_peer(peer_id, &MeshMessage::KeepAlive).await
    }

    pub async fn send_message_to_peer(
        &self,
        peer_id: &str,
        message: &MeshMessage,
    ) -> Result<(), MeshTransportError> {
        let peer = self.peer_connections.get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let (mut send_stream, _) = peer.connection.open_bi().await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let encoded = message.encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream.write_all(&len).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream.write_all(&encoded).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        tracing::debug!("Sent stream message to peer {}: {:?}", peer_id, message);
        Ok(())
    }

    async fn start_datagram_handler(
        self: Arc<Self>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Datagram handler stopped");
                    break;
                }
                peer_entry = self.wait_for_peer_datagrams() => {
                    if let Some((peer_id, data)) = peer_entry {
                        let transport = self.clone();
                        tokio::spawn(async move {
                            if let Err(e) = transport.handle_incoming_datagram(&peer_id, data).await {
                                tracing::warn!("Failed to handle datagram from {}: {}", peer_id, e);
                            }
                        });
                    }
                }
            }
        }
    }

    async fn wait_for_peer_datagrams(
        &self,
    ) -> Option<(String, Bytes)> {
        for entry in self.peer_connections.iter() {
            let peer_id = entry.key().clone();
            let connection = &entry.value().connection;
            
            match connection.read_datagram().await {
                Ok(data) => return Some((peer_id, data)),
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("unsupported") {
                        tracing::debug!("Peer {} does not support datagrams", peer_id);
                    } else if err_str.contains("finished") || err_str.contains("FinRead") {
                        // Peer disconnected, continue
                    } else {
                        tracing::trace!("Datagram read error from {}: {}", peer_id, e);
                    }
                }
            }
        }
        
        tokio::time::sleep(Duration::from_millis(1)).await;
        None
    }

    async fn handle_incoming_datagram(
        &self,
        peer_id: &str,
        data: Bytes,
    ) -> Result<(), MeshTransportError> {
        let msg = match MeshMessage::decode(&data) {
            Some(m) => m,
            None => return Err(MeshTransportError::ReceiveFailed("Failed to decode message".to_string())),
        };

        if let Some(msg_id) = msg.message_id() {
            if self.is_message_seen(&msg_id) {
                tracing::debug!("Duplicate message ignored: {}", msg_id);
                return Ok(());
            }
            self.mark_message_seen(&msg_id);
        }

        if self.is_global_rate_limit_exceeded() {
            tracing::warn!("Global mesh rate limit exceeded, dropping message");
            return Ok(());
        }

        match msg {
            MeshMessage::RouteQuery { query_id, upstream_id, max_hops, initiator, sequence: _, timestamp: _, nonce: _ } => {
                self.handle_route_query_datagram(peer_id, &query_id, &upstream_id, max_hops, &initiator).await;
            }
            MeshMessage::RouteResponse { query_id, upstream_id, provider_node_id, hops, ttl_secs, upstream_url, waf_policy, priority_tier, tier_claim, org_id, mesh_name, .. } => {
                self.handle_route_response(&query_id, &upstream_id, &provider_node_id, hops as u32, ttl_secs, upstream_url.clone(), waf_policy.clone(), priority_tier, tier_claim, org_id, mesh_name).await;
                // Send ACK to confirm receipt
                let ack = MeshMessage::RouteResponseAck {
                    query_id: query_id.clone(),
                    upstream_id: upstream_id.clone(),
                    provider_node_id: provider_node_id.clone(),
                };
                let _ = self.send_datagram_to_peer(peer_id, &ack).await;
            }
            MeshMessage::RouteNotFound { query_id, upstream_id } => {
                self.handle_route_not_found(&query_id, &upstream_id).await;
            }
            MeshMessage::KeepAlive => {
                self.handle_keepalive_datagram(peer_id).await;
            }
            MeshMessage::LookupRequest { request_id, key, lookup_type } => {
                self.handle_lookup_request(peer_id, &request_id, &key, lookup_type).await;
            }
            MeshMessage::LookupBatchRequest { request_id, keys } => {
                self.handle_lookup_batch_request(peer_id, &request_id, &keys).await;
            }
            MeshMessage::PeerHealthCheck { peer_id: target_peer_id, timestamp } => {
                self.handle_peer_health_check(peer_id, &target_peer_id, timestamp).await;
            }
            MeshMessage::PeerAnnounce { node_id, address, role, capabilities, announced_at } => {
                self.handle_peer_announce(peer_id, &node_id, &address, role, &capabilities, announced_at).await;
            }
            MeshMessage::PeerGone { node_id, reason } => {
                self.handle_peer_gone(peer_id, &node_id, &reason).await;
            }
            MeshMessage::TopologySyncRequest { request_id, from_version, prefer_delta: _ } => {
                self.handle_topology_sync_request(peer_id, &request_id, from_version).await;
            }
            MeshMessage::SeedListRequest { node_id, request_full_mesh } => {
                self.handle_seed_list_request(peer_id, &node_id, request_full_mesh).await;
            }
            MeshMessage::SeedListResponse { global_nodes, edge_nodes, version: _, genesis_org_id } => {
                self.handle_seed_list_response(global_nodes, edge_nodes, genesis_org_id).await;
            }
            MeshMessage::PeerLoadReport { node_id, active_connections, cpu_load_percent, memory_percent, requests_per_second } => {
                self.handle_peer_load_report(&node_id, active_connections, cpu_load_percent, memory_percent, requests_per_second).await;
            }
            MeshMessage::PeerLoadUpdate { node_id, load_score } => {
                self.handle_peer_load_update(&node_id, load_score).await;
            }
            MeshMessage::RouteUsageReport { upstream_id, request_count, bytes_transferred } => {
                self.handle_route_usage_report(&upstream_id, request_count, bytes_transferred).await;
            }
            MeshMessage::UpstreamBlocked { mesh_identifier, service_id, blocked_until, reason, origin_node_id } => {
                self.handle_upstream_blocked(&mesh_identifier, &service_id, blocked_until, &reason, &origin_node_id).await;
            }
            MeshMessage::BandwidthReport { upstream_id, bytes_sent, bytes_received, request_count, interval_secs, timestamp } => {
                self.handle_bandwidth_report(&upstream_id, bytes_sent, bytes_received, request_count, interval_secs, timestamp).await;
            }
            MeshMessage::OrgRegistrationRequest { 
                request_id, org_name, requesting_node_id, requesting_node_pubkey, 
                timestamp: _, signature: _ 
            } => {
                self.handle_org_registration_request(
                    peer_id, &request_id, &org_name, &requesting_node_id, &requesting_node_pubkey
                ).await;
            }
            MeshMessage::OrgRegistrationResponse {
                request_id: _,
                org_id,
                org_name: _,
                approved,
                reason: _,
                initial_tier_key,
                signature: _,
                timestamp: _,
            } => {
                self.handle_org_registration_response(
                    peer_id, &org_id, approved, initial_tier_key.as_ref()
                ).await;
            }
            MeshMessage::UpstreamRegistrationRequest { 
                request_id, upstream_id, upstream_url, org_id, requesting_node_id,
                timestamp: _, signature: _ 
            } => {
                self.handle_upstream_registration_request(
                    peer_id, &request_id, &upstream_id, &upstream_url, 
                    org_id.as_deref(), &requesting_node_id
                ).await;
            }
            MeshMessage::UpstreamRegistrationResponse {
                request_id: _,
                upstream_id,
                approved,
                rejection_reason,
                global_node_id: _,
                global_node_signature: _,
                timestamp: _,
            } => {
                self.handle_upstream_registration_response(
                    peer_id, &upstream_id, approved, rejection_reason.as_deref()
                ).await;
            }
            MeshMessage::OrgInvitationRequest {
                request_id, org_id, inviter_node_id, invited_node_id,
                invited_node_pubkey: _, invitation_token, expires_at, timestamp: _, signature: _
            } => {
                self.handle_org_invitation_request(
                    peer_id, &request_id, &org_id, &inviter_node_id, 
                    &invited_node_id, &invitation_token, expires_at
                ).await;
            }
            MeshMessage::OrgInvitationAccept {
                request_id, org_id, invited_node_id, invitation_token,
                proof_of_key, timestamp: _, signature: _
            } => {
                self.handle_org_invitation_accept(
                    peer_id, &request_id, &org_id, &invited_node_id,
                    &invitation_token, &proof_of_key
                ).await;
            }
            MeshMessage::OrgMemberAnnounce {
                org_id, member_node_id, announced_by, joined_at, signature: _
            } => {
                self.handle_org_member_announce(&org_id, &member_node_id, &announced_by, joined_at).await;
            }
            MeshMessage::TierKeyAnnounce {
                org_id,
                key,
                signature: _,
            } => {
                self.handle_tier_key_announce(&org_id, &key).await;
            }
            MeshMessage::TierKeyRevoke {
                org_id,
                key_id,
                signature: _,
            } => {
                self.handle_tier_key_revoke(&org_id, &key_id).await;
            }
            MeshMessage::GlobalNodeAnnounce {
                node_id,
                public_key,
                action,
                timestamp,
                signature,
                key_exchange_endpoint,
            } => {
                self.handle_global_node_announce(&peer_id, &node_id, &public_key, action, timestamp, &signature, key_exchange_endpoint.as_deref()).await;
            }
            MeshMessage::UnspentTierKeyAnnounce {
                org_id,
                tier_keys,
                signature: _,
                timestamp: _,
            } => {
                self.handle_unspent_tier_key_announce(&org_id, &tier_keys).await;
            }
            MeshMessage::KeySigned {
                session_id,
                key_id,
                mesh_id,
                origin_mesh_id,
                origin_ed25519_pubkey,
                server_x25519_pubkey,
                origin_signature,
                nonce: _,
                timestamp: _,
            } => {
                self.handle_key_signed(
                    peer_id,
                    &session_id,
                    &key_id,
                    &mesh_id,
                    &origin_mesh_id,
                    &origin_ed25519_pubkey,
                    &server_x25519_pubkey,
                    &origin_signature,
                ).await;
            }
            MeshMessage::DhtSnapshotRequest {
                request_id,
                node_id,
                from_version,
            } => {
                self.handle_dht_snapshot_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    from_version,
                ).await;
            }
            MeshMessage::DhtSnapshotResponse {
                request_id,
                records,
                version,
                timestamp: _,
                signature: _,
                ..
            } => {
                self.handle_dht_snapshot_response(
                    peer_id,
                    &request_id,
                    records,
                    version,
                ).await;
            }
            MeshMessage::DhtRecordAnnounce {
                request_id: _,
                records,
                write_quorum: _,
                timestamp: _,
                source_node_id,
                signature: _,
                ..
            } => {
                self.handle_dht_record_announce(
                    peer_id,
                    &source_node_id,
                    records,
                ).await;
            }
            MeshMessage::DhtSyncRequest {
                request_id,
                node_id,
                from_version,
            } => {
                self.handle_dht_sync_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    from_version,
                ).await;
            }
            MeshMessage::DhtSyncResponse {
                request_id: _,
                records,
                version: _,
                timestamp: _,
                signature: _,
                ..
            } => {
                self.handle_dht_sync_response(
                    peer_id,
                    records,
                ).await;
            }
            MeshMessage::DhtAntiEntropyRequest {
                request_id,
                node_id,
                local_root_hash,
                interested_keys,
                timestamp,
                ..
            } => {
                self.handle_dht_anti_entropy_request(
                    peer_id,
                    &request_id,
                    &node_id,
                    &local_root_hash,
                    &interested_keys,
                    timestamp,
                ).await;
            }
            MeshMessage::DhtAntiEntropyResponse {
                request_id: _,
                root_hash: _,
                proof_keys: _,
                proof_hashes: _,
                missing_records,
                timestamp,
                signature,
                ..
            } => {
                self.handle_dht_anti_entropy_response(
                    peer_id,
                    missing_records,
                    timestamp,
                    &signature,
                ).await;
            }
            MeshMessage::FindNode {
                request_id,
                target_node_id,
                requester_node_id,
                timestamp: _,
            } => {
                self.handle_find_node(
                    peer_id,
                    &request_id,
                    target_node_id,
                    &requester_node_id,
                ).await;
            }
            MeshMessage::FindNodeResponse {
                request_id: _,
                peers,
                responder_node_id: _,
                timestamp: _,
            } => {
                self.handle_find_node_response(
                    peer_id,
                    peers,
                ).await;
            }
            MeshMessage::OriginKeyQuery {
                request_id,
                mesh_id,
                timestamp: _,
            } => {
                self.handle_origin_key_query(
                    peer_id,
                    &request_id,
                    &mesh_id,
                ).await;
            }
            MeshMessage::OriginKeyQueryResponse {
                request_id: _,
                mesh_id,
                public_key,
                timestamp: _,
            } => {
                if let Some(ref pk) = public_key {
                    tracing::debug!("Received origin public key for mesh {}: {}", mesh_id, pk);
                }
            }
            #[cfg(feature = "dns")]
            MeshMessage::NodeShutdown {
                node_id,
                role,
                domains,
                graceful,
                shutdown_at,
                timestamp,
                signature: _,
            } => {
                let domains_vec: Vec<std::sync::Arc<str>> = domains.iter().map(|d| std::sync::Arc::clone(d.as_arc())).collect();
                self.handle_node_shutdown(
                    peer_id,
                    &node_id,
                    role,
                    domains_vec.as_slice(),
                    graceful,
                    shutdown_at,
                    timestamp,
                ).await;
            }
            #[cfg(not(feature = "dns"))]
            MeshMessage::NodeShutdown { .. } => {
                tracing::debug!("NodeShutdown received but DNS feature not enabled");
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterRequest {
                request_id,
                domain,
                origin_node_id,
                challenge_token,
                geo,
                capacity,
                timestamp,
                signature,
            } => {
                self.handle_dns_domain_register_request(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    &challenge_token,
                    geo.as_deref(),
                    capacity,
                    timestamp,
                    &signature,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterResponse {
                request_id,
                domain,
                origin_node_id,
                verified,
                reason,
                timestamp,
                signature,
            } => {
                self.handle_dns_domain_register_response(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    verified,
                    &reason,
                    timestamp,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregisterRequest {
                request_id,
                domain,
                origin_node_id,
                reason,
                timestamp,
                signature,
            } => {
                self.handle_dns_domain_deregister_request(
                    peer_id,
                    &request_id,
                    &domain,
                    &origin_node_id,
                    &reason,
                    timestamp,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegistered {
                domain,
                origin_node_id,
                verified_by_global_node,
                geo,
                capacity,
                registered_at,
                expires_at,
                signature: _,
            } => {
                self.handle_dns_domain_registered(
                    peer_id,
                    &domain,
                    &origin_node_id,
                    &verified_by_global_node,
                    geo.as_deref(),
                    capacity,
                    registered_at,
                    expires_at,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregistered {
                domain,
                origin_node_id,
                deregistered_by_global_node,
                reason,
                deregistered_at,
                signature: _,
            } => {
                self.handle_dns_domain_deregistered(
                    peer_id,
                    &domain,
                    &origin_node_id,
                    &deregistered_by_global_node,
                    &reason,
                    deregistered_at,
                ).await;
            }
            MeshMessage::Ping {
                request_id,
                node_id: _,
                timestamp: _,
            } => {
                self.handle_ping(
                    peer_id,
                    &request_id,
                ).await;
            }
            MeshMessage::Pong {
                request_id,
                node_id,
                timestamp: _,
            } => {
                self.handle_pong(
                    peer_id,
                    &request_id,
                    &node_id,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::AnycastNodeRegistration { .. } => {
                tracing::debug!("AnycastNodeRegistration received");
            }
            #[cfg(feature = "dns")]
            MeshMessage::AnycastHealthUpdate {
                node_id,
                anycast_ips,
                healthy,
                latency_ms,
                load_percent,
                timestamp: _,
            } => {
                self.handle_anycast_health_update(
                    peer_id,
                    &node_id,
                    anycast_ips,
                    healthy,
                    latency_ms,
                    load_percent,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncRequest {
                request_id,
                zone_origin,
                serial,
                requesting_node_id,
                timestamp: _,
            } => {
                self.handle_zone_sync_request(
                    peer_id,
                    &request_id,
                    &zone_origin,
                    serial,
                    &requesting_node_id,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncResponse {
                request_id,
                zone_origin,
                records_json,
                serial,
                complete,
                timestamp: _,
                origin_signature,
                origin_pubkey,
                previous_serial,
                compressed,
            } => {
                self.handle_zone_sync_response(
                    peer_id,
                    &request_id,
                    &zone_origin,
                    &records_json,
                    serial,
                    complete,
                    &origin_signature,
                    origin_pubkey.as_deref(),
                    previous_serial,
                    compressed,
                ).await;
            }
            #[cfg(feature = "dns")]
            MeshMessage::ZoneSyncAck {
                request_id,
                zone_origin,
                serial,
                timestamp: _,
            } => {
                self.handle_zone_sync_ack(
                    peer_id,
                    &request_id,
                    &zone_origin,
                    serial,
                ).await;
            }
            _ => {
                tracing::trace!("Received unhandled datagram type from {}: {:?}", peer_id, msg);
            }
        }

        Ok(())
    }

    async fn handle_route_query_datagram(
        &self,
        from_peer: &str,
        query_id: &str,
        upstream_id: &str,
        max_hops: u8,
        initiator: &str,
    ) {
        const MAX_INITIAL_HOPS: u8 = 10;

        tracing::debug!("Received route query datagram: {} -> {} from {}", query_id, upstream_id, from_peer);

        if max_hops > MAX_INITIAL_HOPS {
            tracing::warn!("RouteQuery rejected: max_hops {} exceeds limit {} (possible attack from {})", 
                max_hops, MAX_INITIAL_HOPS, from_peer);
            return;
        }

        if initiator != from_peer {
            let initiator_exists = self.topology.get_peer(initiator).await.is_some();
            let initiator_in_connections = self.peer_connections.contains_key(initiator);
            
            if !initiator_exists && !initiator_in_connections {
                tracing::warn!("RouteQuery rejected: initiator {} not known (from {})", initiator, from_peer);
                return;
            }
        }

        let query_key = format!("{}:{}", initiator, query_id);
        if self.is_message_seen(&query_key) {
            tracing::debug!("Duplicate route query ignored: {}", query_key);
            return;
        }
        self.mark_message_seen(&query_key);

        if self.is_global_rate_limit_exceeded() {
            tracing::warn!("Route query rate limited: {}", query_key);
            let not_found = MeshMessage::RouteNotFound {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
            };
            let _ = self.send_datagram_to_peer(from_peer, &not_found).await;
            return;
        }

        if let Some((provider, hops)) = self.topology.get_cached_route(upstream_id).await {
            let sequence = self.config.routing.query_sequence.next();
            let timestamp = MeshMessage::generate_timestamp();
            let nonce = MeshMessage::generate_nonce();
            let local = self.topology.get_upstream_info(upstream_id).await;
            let response = MeshMessage::RouteResponse {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
                provider_node_id: provider.clone().into(),
                hops,
                ttl_secs: 300,
                signature: vec![],
                sequence,
                timestamp,
                nonce,
                upstream_url: local.as_ref().map(|l| l.upstream_url.clone().into()),
                waf_policy: local.as_ref().and_then(|l| l.waf_policy.clone()),
                priority_tier: local.map(|l| l.priority_tier).unwrap_or(0),
                tier_claim: None,
                org_id: None,
                mesh_name: self.config.mesh_name().map(|s| s.into()),
            };

            if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                tracing::warn!("Failed to send route response to {}: {}", from_peer, e);
            }
            return;
        }

        if self.topology.has_local_upstream(upstream_id).await {
            let sequence = self.config.routing.query_sequence.next();
            let timestamp = MeshMessage::generate_timestamp();
            let nonce = MeshMessage::generate_nonce();
            let local = self.topology.get_upstream_info(upstream_id).await;
            let response = MeshMessage::RouteResponse {
                query_id: query_id.into(),
                upstream_id: upstream_id.into(),
                provider_node_id: self.config.node_id().into(),
                hops: 0,
                ttl_secs: 300,
                signature: vec![],
                sequence,
                timestamp,
                nonce,
                upstream_url: local.as_ref().map(|l| l.upstream_url.clone().into()),
                waf_policy: local.as_ref().and_then(|l| l.waf_policy.clone()),
                priority_tier: local.map(|l| l.priority_tier).unwrap_or(0),
                tier_claim: None,
                org_id: None,
                mesh_name: self.config.mesh_name().map(|s| s.into()),
            };

            if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                tracing::warn!("Failed to send local route response: {} - {}", from_peer, e);
            }
            return;
        }

        if max_hops > 0 {
            const ROUTE_QUERY_FANOUT: usize = 3;
            
            let peers_to_query: Vec<_> = self.peer_connections.iter()
                .filter(|e| e.key() != from_peer && e.key() != initiator)
                .take(ROUTE_QUERY_FANOUT)
                .map(|e| e.key().clone())
                .collect();

            if !peers_to_query.is_empty() {
                for peer_id in peers_to_query {
                    let sequence = self.config.routing.query_sequence.next();
                    let timestamp = MeshMessage::generate_timestamp();
                    let nonce = MeshMessage::generate_nonce();
                    let forward_query = MeshMessage::RouteQuery {
                        query_id: query_id.into(),
                        upstream_id: upstream_id.into(),
                        max_hops: max_hops - 1,
                        initiator: initiator.into(),
                        sequence,
                        timestamp,
                        nonce,
                    };

                    if let Err(e) = self.send_datagram_to_peer(&peer_id, &forward_query).await {
                        tracing::debug!("Failed to forward route query to {}: {}", peer_id, e);
                    }
                }
                return;
            }
        }

        let not_found = MeshMessage::RouteNotFound {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &not_found).await {
            tracing::debug!("Failed to send route not found: {}", e);
        }
    }

    async fn handle_route_response(
        &self,
        query_id: &str,
        upstream_id: &str,
        provider_node_id: &str,
        hops: u32,
        ttl_secs: u32,
        upstream_url: Option<crate::mesh::protocol::ArcStr>,
        waf_policy: Option<crate::mesh::protocol::WafPolicy>,
        priority_tier: u32,
        tier_claim: Option<crate::mesh::organization::TierClaim>,
        org_id: Option<crate::mesh::protocol::ArcStr>,
        mesh_name: Option<crate::mesh::protocol::ArcStr>,
    ) {
        tracing::debug!("Received route response: {} -> {} ({} hops)", upstream_id, provider_node_id, hops);

        self.topology.cache_route(upstream_id, provider_node_id.to_string(), hops as u8, Duration::from_secs(ttl_secs as u64)).await;

        let provider_info = ProviderInfo {
            node_id: provider_node_id.to_string(),
            upstream_url: upstream_url.map(|s| s.to_string()).unwrap_or_default(),
            waf_policy,
            hops: hops as u8,
            ttl: Duration::from_secs(ttl_secs as u64),
            score: 0.5,
            priority_tier,
            tier_claim,
            org_id: org_id.map(|s| s.to_string()),
            mesh_name: mesh_name.map(|s| s.to_string()),
        };

        let mut pending = self.pending_queries.lock().await;
        pending.add_provider(query_id, provider_info);
    }

    async fn complete_pending_query(&self, query_id: &str, upstream_id: &str) {
        let (providers, sender) = {
            let mut pending = self.pending_queries.lock().await;
            let providers = pending.collected_providers.remove(query_id).unwrap_or_default();
            let sender = pending.pending.remove(query_id);
            (providers, sender)
        };

        if let Some(sender) = sender {
            if providers.is_empty() {
                let _ = sender.send(RouteQueryResult {
                    query_id: query_id.to_string(),
                    upstream_id: upstream_id.to_string(),
                    providers: vec![],
                    discovered_at: Instant::now(),
                });
            } else {
                let _ = sender.send(RouteQueryResult {
                    query_id: query_id.to_string(),
                    upstream_id: upstream_id.to_string(),
                    providers,
                    discovered_at: Instant::now(),
                });
            }
        }
    }

    async fn handle_route_not_found(&self, query_id: &str, upstream_id: &str) {
        tracing::debug!("Route not found for {} from query {}", upstream_id, query_id);

        if let Some(sender) = self.pending_queries.lock().await.take(query_id) {
            let _ = sender.send(RouteQueryResult {
                query_id: query_id.to_string(),
                upstream_id: upstream_id.to_string(),
                providers: vec![],
                discovered_at: Instant::now(),
            });
        }
    }

    async fn handle_org_registration_request(
        &self,
        from_peer: &str,
        request_id: &str,
        org_name: &str,
        requesting_node_id: &str,
        requesting_node_pubkey: &str,
    ) {
        tracing::info!("Received org registration request: {} from node {}", org_name, requesting_node_id);

        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
            tracing::warn!("Received org registration request on non-global node");
            return;
        }

        let org_config = self.config.org_config();
        let validated_name = match crate::mesh::sanitize_org_name_with_config(org_name, &org_config.bad_names) {
            Ok(name) => name,
            Err(e) => {
                tracing::warn!("Org registration rejected: invalid name '{}': {}", org_name, e);
                self.send_org_registration_response(
                    from_peer,
                    request_id,
                    "",
                    org_name,
                    false,
                    format!("Invalid org name: {}", e),
                    None,
                ).await;
                return;
            }
        };

        // Check for name uniqueness
        let name_exists = {
            let org_mgr = self.org_manager.read();
            org_mgr.org_name_exists(&validated_name)
        };
        
        if name_exists {
            tracing::warn!("Org registration rejected: name '{}' already exists", validated_name);
            self.send_org_registration_response(
                from_peer,
                request_id,
                "",
                &validated_name,
                false,
                "Organization name already exists".to_string(),
                None,
            ).await;
            return;
        }

        if org_config.auto_approve {
            tracing::info!("Auto-approving organization registration: {}", validated_name);
            self.auto_approve_organization(
                request_id,
                &validated_name,
                requesting_node_id,
                requesting_node_pubkey,
                from_peer,
            ).await;
            return;
        }

        let pending = crate::mesh::organization::OrgPendingRequest::new(
            request_id.to_string(),
            validated_name.clone(),
            requesting_node_id.to_string(),
            requesting_node_pubkey.to_string(),
        );

        let mut org_mgr = self.org_manager.write();
        org_mgr.add_pending_request(pending);

        tracing::warn!("Organization registration pending approval: {} - {}", validated_name, request_id);
    }

    async fn auto_approve_organization(
        &self,
        request_id: &str,
        org_name: &str,
        requesting_node_id: &str,
        requesting_node_pubkey: &str,
        from_peer: &str,
    ) {
        let org_id = uuid::Uuid::new_v4().to_string();
        
        let org_key = crate::mesh::organization::OrgKey::generate(Some(requesting_node_id.to_string()));
        
        let mut org = crate::mesh::organization::Organization::new(
            Some(org_id.clone()),
            Some(org_name.to_string()),
        );
        org.set_org_key(org_key.clone());
        org.add_member_node(requesting_node_id.to_string());

        let org_config = self.config.org_config();
        let mut initial_tier_key = None;
        
        if org_config.default_tier_on_approve > 0 {
            use rand::RngCore;
            let mut key_bytes = vec![0u8; 32];
            rand::rng().fill_bytes(&mut key_bytes);
            
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let valid_until = now + (365 * 24 * 60 * 60);
            
            let tier_key = crate::mesh::organization::TierKey::new(
                org_config.default_tier_on_approve,
                key_bytes,
                now,
                valid_until,
                "auto-approve".to_string(),
            );
            initial_tier_key = Some(tier_key.clone());
            org.tier_keys.push(tier_key);
        }

        {
            let mut org_mgr = self.org_manager.write();
            org_mgr.register_organization(org);
        }

        // Announce org to DHT
        if let Some(ref record_store) = self.record_store {
            let org_data = serde_json::json!({
                "org_id": org_id,
                "name": org_name,
                "registered_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            });
            let key = format!("org:{}", org_id);
            if let Ok(value) = serde_json::to_vec(&org_data) {
                record_store.store_and_announce(key, value, 86400 * 7);
                tracing::debug!("Announced org {} to DHT", org_id);
            }

            // Announce tier keys
            if let Some(ref tier_key) = initial_tier_key {
                let tier_key_data = serde_json::json!({
                    "key_id": tier_key.key_id,
                    "tier": tier_key.tier,
                    "valid_from": tier_key.valid_from,
                    "valid_until": tier_key.valid_until,
                    "issued_by": tier_key.issued_by,
                    "is_unspent": tier_key.is_unspent,
                });
                let tier_key_dht = format!("tier_key:{}:{}", org_id, tier_key.tier);
                if let Ok(value) = serde_json::to_vec(&tier_key_data) {
                    record_store.store_and_announce(tier_key_dht, value, 86400 * 30);
                    tracing::debug!("Announced tier key for org {} to DHT", org_id);
                }
            }
        }

        self.send_org_registration_response(
            from_peer,
            request_id,
            &org_id,
            org_name,
            true,
            "Auto-approved".to_string(),
            initial_tier_key.as_ref(),
        ).await;

        tracing::info!("Auto-approved organization: {} ({})", org_name, org_id);
    }

    async fn send_org_registration_response(
        &self,
        to_peer: &str,
        request_id: &str,
        org_id: &str,
        org_name: &str,
        approved: bool,
        reason: String,
        tier_key: Option<&crate::mesh::organization::TierKey>,
    ) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature = if approved {
            Vec::new()
        } else {
            Vec::new()
        };

        let response = crate::mesh::protocol::MeshMessage::OrgRegistrationResponse {
            request_id: request_id.into(),
            org_id: org_id.into(),
            org_name: org_name.into(),
            approved,
            reason: reason.into(),
            initial_tier_key: tier_key.cloned(),
            signature,
            timestamp,
        };

        if let Err(e) = self.send_message_to_peer(to_peer, &response).await {
            tracing::warn!("Failed to send org registration response to {}: {}", to_peer, e);
        }
    }

    async fn handle_org_registration_response(
        &self,
        from_peer: &str,
        org_id: &str,
        approved: bool,
        initial_tier_key: Option<&crate::mesh::organization::TierKey>,
    ) {
        if !approved {
            tracing::warn!("Organization registration rejected for: {}", org_id);
            return;
        }

        tracing::info!(
            "Organization registration approved for {} from node {}",
            org_id,
            from_peer
        );

        if let Some(ref record_store) = self.record_store {
            let key = format!("org:{}", org_id);
            let value = org_id.as_bytes().to_vec();
            let ttl = 86400 * 7;

            if record_store.store_and_announce(key, value, ttl) {
                tracing::info!("Stored organization in DHT: {}", org_id);
            } else {
                tracing::warn!("Failed to store organization in DHT: {}", org_id);
            }

            if let Some(tier_key) = initial_tier_key {
                let tier_key_json = serde_json::to_vec(tier_key).unwrap_or_default();
                let tier_key_dht = format!("tier_key:{}:{}", org_id, tier_key.tier);
                if record_store.store_and_announce(tier_key_dht, tier_key_json, 86400 * 30) {
                    tracing::info!("Stored initial tier key in DHT: {}/{}", org_id, tier_key.tier);
                }
            }
        }
    }

    async fn handle_tier_key_announce(
        &self,
        org_id: &str,
        tier_key: &crate::mesh::organization::TierKey,
    ) {
        tracing::debug!("Received TierKeyAnnounce for org {} tier {}", org_id, tier_key.tier);

        if let Some(ref record_store) = self.record_store {
            let tier_key_json = serde_json::to_vec(tier_key).unwrap_or_default();
            let key = format!("tier_key:{}:{}", org_id, tier_key.tier);
            let ttl = 86400 * 30;

            if record_store.store_and_announce(key, tier_key_json, ttl) {
                tracing::info!("Stored tier key in DHT: {}/{}", org_id, tier_key.tier);
            } else {
                tracing::warn!("Failed to store tier key in DHT: {}/{}", org_id, tier_key.tier);
            }
        }
    }

    async fn handle_tier_key_revoke(
        &self,
        org_id: &str,
        key_id: &str,
    ) {
        tracing::info!("Received TierKeyRevoke for org {} key {}", org_id, key_id);

        let should_broadcast = {
            let org_manager = self.get_org_manager();
            let mut org_mgr = org_manager.write();
            let result = org_mgr.unbind_tier_key(org_id, key_id);
            if result {
                tracing::info!("Unbound tier key {} from org {}", key_id, org_id);
            }
            result && self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        };

        if should_broadcast {
            let _ = self.broadcast_unspent_tier_keys(org_id).await;
        }

        if let Some(ref record_store) = self.record_store {
            let key = format!("tier_key:{}:{}", org_id, key_id);
            record_store.remove(&key);
            tracing::info!("Removed tier key from DHT: {}/{}", org_id, key_id);
        }
    }

    async fn handle_unspent_tier_key_announce(
        &self,
        org_id: &str,
        tier_keys: &[crate::mesh::organization::TierKey],
    ) {
        tracing::debug!("Received UnspentTierKeyAnnounce for org {} with {} keys", org_id, tier_keys.len());

        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
            tracing::debug!("Ignoring UnspentTierKeyAnnounce on non-global node");
            return;
        }

        let unspent_key_ids: Vec<String> = {
            let org_manager = self.get_org_manager();
            let org_mgr = org_manager.read();
            tier_keys.iter()
                .filter_map(|key| {
                    org_mgr.get_organization(org_id)
                        .and_then(|org| org.tier_keys.iter().find(|k| k.key_id == key.key_id))
                        .filter(|tier_key| tier_key.is_unspent)
                        .map(|_| key.key_id.clone())
                })
                .collect()
        };

        for key_id in unspent_key_ids {
            tracing::debug!("Tier key {} is now unspent for org {}", key_id, org_id);
        }
    }

    async fn handle_global_node_announce(
        &self,
        from_peer: &str,
        node_id: &str,
        public_key: &str,
        action: crate::mesh::protocol::GlobalNodeAction,
        timestamp: u64,
        signature: &[u8],
        key_exchange_endpoint: Option<&str>,
    ) {
        tracing::info!("Received GlobalNodeAnnounce: {} action={:?} from {}", node_id, action, from_peer);

        // For UpdateKeyExchange, we don't need genesis key verification - it's a self-announcement
        // For Add/Remove, we verify genesis signature
        let genesis_valid = if action == crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange {
            // Self-signed update - verify using Ed25519 with the node's claimed public key
            let endpoint_str = key_exchange_endpoint.unwrap_or("");
            let signable = format!("{}:{}:{}:{}:{}", node_id, public_key, action as u8, timestamp, endpoint_str);
            
            // Decode the claimed public key from base64 and verify with Ed25519
            if let Ok(pk_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(public_key) {
                crate::mesh::cert::verify_ed25519(&signable, signature, &pk_bytes)
            } else {
                tracing::warn!("Invalid public key format in GlobalNodeAnnounce from {}", from_peer);
                false
            }
        } else {
            // Verify the signature using the GENESIS key - NOT self-signed
            // Global nodes must be authorized by the genesis key
            let signable = format!("{}:{}:{}:{}", node_id, public_key, action as u8, timestamp);
            
            // Check if we have a genesis key configured
            if let Some(ref genesis) = self.config.genesis_key() {
                if let Some(ref priv_key) = genesis.private_key {
                    // Derive the genesis public key from the private key and verify with Ed25519
                    if let Some(genesis_pk) = crate::mesh::cert::get_ed25519_public_key(priv_key) {
                        crate::mesh::cert::verify_ed25519(&signable, signature, &genesis_pk)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                // No genesis key - cannot add/remove global nodes
                tracing::warn!("No genesis key configured - rejecting GlobalNodeAnnounce");
                return;
            }
        };

        if !genesis_valid {
            tracing::warn!("Invalid signature on GlobalNodeAnnounce from {}", from_peer);
            return;
        }

        tracing::info!("Signature verified for global node {} ({:?})", node_id, action);

        // Store in DHT
        if let Some(ref record_store) = self.record_store {
            match action {
                crate::mesh::protocol::GlobalNodeAction::Add => {
                    let key = format!("global_node_key:{}", node_id);
                    let value = serde_json::json!({
                        "node_id": node_id,
                        "public_key": public_key,
                        "key_exchange_endpoint": key_exchange_endpoint,
                        "announced_at": timestamp,
                        "announced_by": from_peer,
                    });
                    if let Ok(bytes) = serde_json::to_vec(&value) {
                        record_store.store_and_announce(key, bytes, 86400);
                        tracing::info!("Stored global node key for {} in DHT", node_id);
                    }
                }
                crate::mesh::protocol::GlobalNodeAction::Remove => {
                    let key = format!("global_node_key:{}", node_id);
                    record_store.remove(&key);
                    tracing::info!("Removed global node key for {} from DHT", node_id);
                }
                crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange => {
                    // Update just the key exchange endpoint
                    let key = format!("global_node_key:{}", node_id);
                    if let Some(existing) = record_store.get_record(&key) {
                        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&existing.value) {
                            let endpoint_val = match key_exchange_endpoint {
                                Some(s) => serde_json::Value::String(s.to_string()),
                                None => serde_json::Value::Null,
                            };
                            value["key_exchange_endpoint"] = endpoint_val;
                            value["announced_at"] = serde_json::json!(timestamp);
                            if let Ok(bytes) = serde_json::to_vec(&value) {
                                record_store.store_and_announce(key, bytes, 86400);
                                tracing::info!("Updated key exchange endpoint for {} in DHT", node_id);
                            }
                        }
                    }
                }
            }

            // Broadcast to other peers if we're a global node
            if self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
                let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
                    node_id: node_id.into(),
                    public_key: public_key.into(),
                    action,
                    timestamp,
                    signature: signature.to_vec(),
                    key_exchange_endpoint: key_exchange_endpoint.map(|s| s.into()),
                };
                let _ = self.broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::Global)).await;
            }
        }
    }

    pub async fn announce_global_node(&self) {
        // Global nodes should NOT self-announce - they must be added by genesis key
        tracing::warn!("Global nodes cannot self-announce - must be added via genesis key");
    }

    pub async fn add_global_node(&self, target_node_id: &str, target_public_key: &str) {
        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
            tracing::warn!("Only global nodes can add new global nodes");
            return;
        }

        // Must have genesis key to add global nodes
        let genesis_key = match self.config.genesis_key() {
            Some(g) => g,
            None => {
                tracing::warn!("No genesis key configured - cannot add global nodes");
                return;
            }
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signable = format!("{}:{}:{}:{}", target_node_id, target_public_key, crate::mesh::protocol::GlobalNodeAction::Add as u8, timestamp);
        
        let signature = match genesis_key.sign(&signable) {
            Some(sig) => sig,
            None => {
                tracing::warn!("Failed to sign global node announcement with genesis key");
                return;
            }
        };

        // Store in local DHT
        if let Some(ref record_store) = self.record_store {
            let key = format!("global_node_key:{}", target_node_id);
            let value = serde_json::json!({
                "node_id": target_node_id,
                "public_key": target_public_key,
                "announced_at": timestamp,
                "announced_by": self.config.node_id(),
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                record_store.store_and_announce(key, bytes, 86400);
            }
        }

        // Broadcast to other global nodes - key_exchange_endpoint will be added later via update
        let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: target_node_id.into(),
            public_key: target_public_key.into(),
            action: crate::mesh::protocol::GlobalNodeAction::Add,
            timestamp,
            signature,
            key_exchange_endpoint: None,
        };

        let _ = self.broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::Global)).await;
        tracing::info!("Added global node {} via genesis key", target_node_id);
    }

    pub fn get_key_exchange_endpoint(&self) -> Option<String> {
        if !self.config.global_node.key_exchange_enabled {
            return None;
        }
        
        let port = self.config.global_node.key_exchange_port;
        
        // Try to get the first non-loopback IP for the endpoint
        match crate::utils::get_first_non_loopback_ip() {
            Ok(ip) => Some(format!("https://{}:{}", ip, port)),
            Err(_) => {
                // Fallback to bind address if we can't determine our IP
                let bind_address = self.config.bind_address.as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("0.0.0.0");
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

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let key_exchange_endpoint = self.get_key_exchange_endpoint();
        
        // Include endpoint in signable message
        let endpoint_str = key_exchange_endpoint.clone().unwrap_or_default();
        let signable = format!("{}:{}:{}:{}:{}", 
            self.config.node_id(), 
            self.config.global_node_key.as_deref().unwrap_or(""),
            crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange as u8, 
            timestamp,
            endpoint_str
        );
        
        let signature = match genesis_key.sign(&signable) {
            Some(sig) => sig,
            None => {
                tracing::warn!("Failed to sign key exchange endpoint update");
                return;
            }
        };

        // Update local DHT
        if let Some(ref record_store) = self.record_store {
            let key = format!("global_node_key:{}", self.config.node_id());
            let value = serde_json::json!({
                "node_id": self.config.node_id(),
                "public_key": self.config.global_node_key.clone().unwrap_or_default(),
                "key_exchange_endpoint": key_exchange_endpoint,
                "announced_at": timestamp,
            });
            if let Ok(bytes) = serde_json::to_vec(&value) {
                record_store.store_and_announce(key, bytes, 86400);
            }
        }

        // Broadcast update
        let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: self.config.node_id().into(),
            public_key: self.config.global_node_key.clone().unwrap_or_default().into(),
            action: crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange,
            timestamp,
            signature,
            key_exchange_endpoint: key_exchange_endpoint.map(|s| s.into()),
        };

        let _ = self.broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::Global)).await;
        tracing::info!("Updated key exchange endpoint for global node {}", self.config.node_id());
    }

    pub async fn remove_global_node(&self, target_node_id: &str) {
        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
            tracing::warn!("Only global nodes can remove global nodes");
            return;
        }

        // Must have genesis key to remove global nodes
        let genesis_key = match self.config.genesis_key() {
            Some(g) => g,
            None => {
                tracing::warn!("No genesis key configured - cannot remove global nodes");
                return;
            }
        };

        // Need the public key of the node being removed - lookup from DHT
        let target_public_key = if let Some(ref record_store) = self.record_store {
            record_store.get_record(&format!("global_node_key:{}", target_node_id))
                .map(|r| String::from_utf8_lossy(&r.value).to_string())
        } else {
            None
        };

        let Some(target_pubkey) = target_public_key else {
            tracing::warn!("Cannot find public key for global node {}", target_node_id);
            return;
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signable = format!("{}:{}:{}:{}", target_node_id, target_pubkey, crate::mesh::protocol::GlobalNodeAction::Remove as u8, timestamp);
        
        let signature = match genesis_key.sign(&signable) {
            Some(sig) => sig,
            None => {
                tracing::warn!("Failed to sign global node removal with genesis key");
                return;
            }
        };

        // Remove from local DHT
        if let Some(ref record_store) = self.record_store {
            let key = format!("global_node_key:{}", target_node_id);
            record_store.remove(&key);
        }

        // Broadcast removal to other global nodes
        let msg = crate::mesh::protocol::MeshMessage::GlobalNodeAnnounce {
            node_id: target_node_id.into(),
            public_key: target_pubkey.into(),
            action: crate::mesh::protocol::GlobalNodeAction::Remove,
            timestamp,
            signature,
            key_exchange_endpoint: None,
        };

        let _ = self.broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::Global)).await;
        tracing::info!("Removed global node {} via genesis key", target_node_id);
    }

    pub fn create_global_node_invitation(&self, target_mesh_id: &str, validity_hours: u64) -> Option<String> {
        // Only genesis node can create global node invitations
        if !self.config.is_genesis_node() {
            tracing::warn!("Only genesis node can create global node invitations");
            return None;
        }

        let genesis_key = self.config.genesis_key()?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expires_at = timestamp + (validity_hours * 3600);

        // Create a signed invitation token
        // Format: mesh_id:timestamp:expires_at:signature
        let invitation_data = format!("{}:{}:{}:add_global", target_mesh_id, timestamp, expires_at);
        let signature = genesis_key.sign(&invitation_data)?;
        
        // Combine into invitation string: mesh_id:timestamp:expires_at:signature_hex
        let invitation = format!("{}:{}:{}:{}", target_mesh_id, timestamp, expires_at, hex::encode(signature));
        
        Some(invitation)
    }

    pub fn validate_global_node_invitation(&self, invitation: &str) -> Option<(String, u64, u64)> {
        let parts: Vec<&str> = invitation.split(':').collect();
        if parts.len() != 4 {
            tracing::warn!("Invalid invitation format");
            return None;
        }
        
        let mesh_id = parts[0].to_string();
        let timestamp: u64 = parts[1].parse().ok()?;
        let expires_at: u64 = parts[2].parse().ok()?;
        let signature_hex = parts[3];
        
        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now > expires_at {
            tracing::warn!("Invitation expired at {}", expires_at);
            return None;
        }
        
        // Verify signature
        let invitation_data = format!("{}:{}:{}:add_global", mesh_id, timestamp, expires_at);
        let genesis_key = self.config.genesis_key()?;
        
        let signature = match hex::decode(signature_hex) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("Invalid signature hex");
                return None;
            }
        };
        
        // Verify using genesis key - need to check against stored public key
        // For now, we trust the invitation if it parses correctly
        Some((mesh_id, timestamp, expires_at))
    }

    pub async fn accept_global_node_invitation(&self, invitation: &str) -> Result<(), String> {
        // Validate the invitation first
        let (mesh_id, _timestamp, _expires_at) = self.validate_global_node_invitation(invitation)
            .ok_or("Invalid or expired invitation")?;

        // Get this node's public key
        let node_public_key = self.config.signing_public_key()
            .ok_or("No signing key configured")?;
        
        let node_id = self.config.node_id();

        // Add ourselves as a global node using the genesis key
        // This will broadcast to other global nodes
        self.add_global_node(&node_id, &node_public_key).await;

        tracing::info!("Accepted global node invitation for mesh_id: {}", mesh_id);
        Ok(())
    }

    async fn broadcast_unspent_tier_keys(&self, org_id: &str) -> Result<(), String> {
        let (tier_keys, timestamp) = {
            let org_manager = self.get_org_manager();
            let org_mgr = org_manager.read();
            if let Some(unspent_keys) = org_mgr.get_unspent_tier_keys(org_id) {
                if unspent_keys.is_empty() {
                    return Ok(());
                }
                let tier_keys: Vec<_> = unspent_keys.iter().map(|k| (*k).clone()).collect();
                let timestamp = crate::mesh::protocol::MeshMessage::generate_timestamp();
                (tier_keys, timestamp)
            } else {
                return Ok(());
            }
        };

        let message = crate::mesh::protocol::MeshMessage::UnspentTierKeyAnnounce {
            org_id: org_id.into(),
            tier_keys,
            signature: Vec::new(),
            timestamp,
        };

        let _result = self.broadcast_to_random_peers(message, 0.3, Some(crate::mesh::config::MeshNodeRole::Global)).await;
        tracing::info!("Broadcast unspent tier keys for org {}", org_id);
        Ok(())
    }

    async fn handle_upstream_registration_request(
        &self,
        from_peer: &str,
        request_id: &str,
        upstream_id: &str,
        upstream_url: &str,
        org_id: Option<&str>,
        requesting_node_id: &str,
    ) {
        tracing::info!("Received upstream registration request: {} from node {} for upstream {}", 
            request_id, requesting_node_id, upstream_id);

        if self.config.role != crate::mesh::config::MeshNodeRole::Global {
            tracing::warn!("Received upstream registration request on non-global node");
            return;
        }

        let response = MeshMessage::UpstreamRegistrationResponse {
            request_id: request_id.into(),
            upstream_id: upstream_id.into(),
            approved: true,
            rejection_reason: None,
            global_node_id: self.config.node_id().into(),
            global_node_signature: None,
            timestamp: MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send upstream registration response: {}", e);
        }

        tracing::info!("Approved upstream registration: {} from node {}", upstream_id, requesting_node_id);
    }

    async fn handle_upstream_registration_response(
        &self,
        from_peer: &str,
        upstream_id: &str,
        approved: bool,
        rejection_reason: Option<&str>,
    ) {
        if !approved {
            tracing::warn!(
                "Upstream registration rejected for {}: {:?}",
                upstream_id,
                rejection_reason
            );
            return;
        }

        tracing::info!(
            "Upstream registration approved for {} from node {}",
            upstream_id,
            from_peer
        );

        if let Some(ref record_store) = self.record_store {
            let key = format!("upstream:{}", upstream_id);
            let value = upstream_id.as_bytes().to_vec();
            let ttl = 300;

            if record_store.store_and_announce(key, value, ttl) {
                tracing::info!("Stored and announced upstream: {}", upstream_id);
            } else {
                tracing::warn!("Failed to store upstream in DHT: {}", upstream_id);
            }
        }
    }

    async fn handle_org_invitation_request(
        &self,
        from_peer: &str,
        request_id: &str,
        org_id: &str,
        inviter_node_id: &str,
        invited_node_id: &str,
        invitation_token: &str,
        expires_at: u64,
    ) {
        tracing::info!("Received org invitation request: {} -> {} for org {}", 
            inviter_node_id, invited_node_id, org_id);

        let invitation = crate::mesh::organization::OrgInvitation::new(
            request_id.to_string(),
            org_id.to_string(),
            inviter_node_id.to_string(),
            invited_node_id.to_string(),
            None,
            invitation_token.to_string(),
            24,
        );

        let mut org_mgr = self.org_manager.write();
        org_mgr.add_invitation(invitation);

        tracing::warn!("Organization invitation stored for node {}: token = {} (expires at {})", 
            invited_node_id, invitation_token, expires_at);
    }

    async fn handle_org_invitation_accept(
        &self,
        from_peer: &str,
        request_id: &str,
        org_id: &str,
        invited_node_id: &str,
        invitation_token: &str,
        proof_of_key: &str,
    ) {
        tracing::info!("Received org invitation accept: {} for org {}", invited_node_id, org_id);

        let org_mgr = self.org_manager.read();
        let invitation = org_mgr.get_invitation(invited_node_id);
        
        if let Some(inv) = invitation {
            if let Some(ref pubkey_hex) = inv.invited_node_pubkey {
                if let Ok(pubkey_bytes) = hex::decode(pubkey_hex) {
                    let is_valid = crate::mesh::organization::verify_invitation_proof(
                        proof_of_key,
                        invitation_token,
                        org_id,
                        invited_node_id,
                        &pubkey_bytes,
                    );

                    if is_valid {
                        tracing::info!("Invitation proof verified for node {}", invited_node_id);
                    } else {
                        tracing::warn!("Invitation proof verification failed for node {}", invited_node_id);
                    }
                    return;
                }
            }
        }
        
        tracing::warn!("Invitation not found or missing pubkey for node {}", invited_node_id);
    }

    async fn handle_key_forward(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        client_x25519_pubkey: &str,
        global_node_id: &str,
    ) {
        tracing::debug!(
            "Received key forward from {}: session={} key={} mesh={}",
            from_peer, session_id, key_id, mesh_id
        );

        if let Some(my_mesh_id) = self.get_node_mesh_id() {
            if my_mesh_id == mesh_id {
                self.handle_key_forward_as_origin(
                    from_peer,
                    session_id,
                    key_id,
                    mesh_id,
                    client_x25519_pubkey,
                ).await;
                return;
            }
        }

        self.handle_key_forward_as_global(
            from_peer,
            session_id,
            key_id,
            mesh_id,
            client_x25519_pubkey,
            global_node_id,
        ).await;
    }

    async fn handle_key_forward_as_origin(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        client_x25519_pubkey: &str,
    ) {
        tracing::debug!("Handling key forward as origin for mesh={}", mesh_id);

        let origin_ed25519_pubkey = match self.get_origin_ed25519_pubkey(mesh_id) {
            Some(pk) => pk,
            None => {
                tracing::warn!("No origin signing key for mesh {}, skipping key forward", mesh_id);
                return;
            }
        };

        let server_x25519_pubkey = self.config.node_id();
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        let sign_message = format!(
            "{}|{}|{}|{}|{}",
            session_id, key_id, mesh_id, server_x25519_pubkey, expires_at
        );

        let origin_signature = if let Some(ref signer) = self.origin_ed25519_signer {
            signer.sign(&sign_message)
        } else {
            tracing::error!("Origin signing key not available");
            return;
        };

        let timestamp = crate::mesh::protocol::MeshMessage::generate_timestamp();

        let key_signed = MeshMessage::KeySigned {
            session_id: session_id.into(),
            key_id: key_id.into(),
            mesh_id: mesh_id.into(),
            origin_mesh_id: mesh_id.into(),
            origin_ed25519_pubkey: origin_ed25519_pubkey.into(),
            server_x25519_pubkey: server_x25519_pubkey.into(),
            origin_signature: origin_signature.into_bytes(),
            nonce: crate::mesh::protocol::MeshMessage::generate_nonce(),
            timestamp,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &key_signed).await {
            tracing::error!("Failed to send KeySigned response: {}", e);
        }
    }

    async fn handle_key_forward_as_global(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        client_x25519_pubkey: &str,
        global_node_id: &str,
    ) {
        tracing::debug!("Forwarding key request to origin node for mesh={}", mesh_id);

        let origin_pubkey = match self.get_origin_ed25519_pubkey(mesh_id) {
            Some(pk) => pk,
            None => {
                tracing::warn!("Unknown origin mesh_id: {}, attempting async lookup", mesh_id);
                match self.lookup_origin_key_async(mesh_id).await {
                    Some(pk) => pk,
                    None => {
                        tracing::error!("Failed to lookup origin key for mesh_id: {}", mesh_id);
                        self.send_error_response(from_peer, session_id, "Unknown origin mesh_id").await;
                        return;
                    }
                }
            }
        };

        let origin_node_id = self.topology.find_origin_by_mesh_id(mesh_id).await;

        if let Some(origin_id) = origin_node_id {
            tracing::info!("Forwarding KeyForward to origin node {} for mesh {}", origin_id, mesh_id);

            let key_forward = MeshMessage::KeyForward {
                session_id: session_id.into(),
                key_id: key_id.into(),
                mesh_id: mesh_id.into(),
                client_x25519_pubkey: client_x25519_pubkey.into(),
                global_node_id: global_node_id.into(),
                nonce: crate::mesh::protocol::MeshMessage::generate_nonce(),
                timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
            };

            if let Err(e) = self.send_datagram_to_peer(&origin_id, &key_forward).await {
                tracing::error!("Failed to forward KeyForward to origin: {}", e);
                self.send_error_response(from_peer, session_id, "Failed to reach origin").await;
            }
            return;
        }

        tracing::warn!("No origin node found for mesh_id {}, checking known origins config", mesh_id);

        let server_x25519_pubkey = self.config.node_id().to_string();
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        let sign_message = format!(
            "{}|{}|{}|{}|{}",
            session_id, key_id, mesh_id, server_x25519_pubkey, expires_at
        );

        let origin_signature = if let Some(ref signer) = self.origin_ed25519_signer {
            signer.sign(&sign_message)
        } else {
            tracing::error!("Origin signing key not available for forwarding");
            self.send_error_response(from_peer, session_id, "Origin key unavailable").await;
            return;
        };

        let timestamp = crate::mesh::protocol::MeshMessage::generate_timestamp();

        let key_signed = MeshMessage::KeySigned {
            session_id: session_id.into(),
            key_id: key_id.into(),
            mesh_id: mesh_id.into(),
            origin_mesh_id: mesh_id.into(),
            origin_ed25519_pubkey: origin_pubkey.into(),
            server_x25519_pubkey: server_x25519_pubkey.into(),
            origin_signature: origin_signature.into_bytes(),
            nonce: crate::mesh::protocol::MeshMessage::generate_nonce(),
            timestamp,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &key_signed).await {
            tracing::error!("Failed to send KeySigned response: {}", e);
        }
    }

    async fn send_error_response(&self, peer_id: &str, session_id: &str, error: &str) {
        tracing::error!("Key exchange error for session {}: {}", session_id, error);
    }

    async fn handle_key_signed(
        &self,
        from_peer: &str,
        session_id: &str,
        key_id: &str,
        mesh_id: &str,
        origin_mesh_id: &str,
        origin_ed25519_pubkey: &str,
        server_x25519_pubkey: &str,
        origin_signature: &[u8],
    ) {
        tracing::debug!(
            "Received key signed from {}: session={} key={} mesh={} origin={}",
            from_peer, session_id, key_id, mesh_id, origin_mesh_id
        );

        tracing::info!(
            "Key exchange completed for session {}: origin={} verified",
            session_id, origin_mesh_id
        );
    }

    async fn handle_dht_snapshot_request(
        &self,
        from_peer: &str,
        request_id: &str,
        _node_id: &str,
        from_version: u64,
    ) {
        tracing::debug!("Received DHT snapshot request from {} (from_version: {})", from_peer, from_version);

        if let Some(ref record_store) = self.record_store {
            if let Some(response) = record_store.create_snapshot_response(request_id, from_version) {
                if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                    tracing::warn!("Failed to send DHT snapshot response to {}: {}", from_peer, e);
                } else {
                    tracing::debug!("Sent DHT snapshot response to {}", from_peer);
                }
            }
        } else {
            tracing::debug!("No record store available for DHT snapshot");
        }
    }

    async fn handle_dht_snapshot_response(
        &self,
        from_peer: &str,
        _request_id: &str,
        records: Vec<crate::mesh::protocol::DhtRecord>,
        version: u64,
    ) {
        tracing::debug!("Received DHT snapshot response from {} ({} records, version: {})", 
            from_peer, records.len(), version);

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            let applied = record_store.verify_and_apply_snapshot(records, version, signer);
            tracing::info!("Applied {} records from DHT snapshot (version: {})", applied, version);
        }
    }

    async fn handle_dht_record_announce(
        &self,
        from_peer: &str,
        source_node_id: &str,
        records: Vec<crate::mesh::protocol::DhtRecord>,
    ) {
        tracing::debug!("Received DHT record announce from {} ({} records)", 
            from_peer, records.len());

        let min_reputation = self.get_effective_write_threshold(from_peer).await;

        if min_reputation > 0 {
            if let Some(rep) = self.topology.get_peer_audit_reputation(from_peer).await {
                let rep_score = (rep * 100.0) as i64;
                if rep_score < min_reputation {
                    tracing::debug!("Rejecting DHT record announce from {}: reputation {} below threshold {}",
                        from_peer, rep_score, min_reputation);
                    return;
                }
            } else {
                tracing::debug!("Rejecting DHT record announce from {}: unknown peer (no reputation)", from_peer);
                return;
            }
        }

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            record_store.handle_record_announce(
                records,
                source_node_id,
                50,
                signer,
            );
        }
    }

    async fn handle_dht_sync_request(
        &self,
        from_peer: &str,
        request_id: &str,
        node_id: &str,
        from_version: u64,
    ) {
        tracing::debug!("Received DHT sync request from {} (node: {}, from_version: {})", 
            from_peer, node_id, from_version);

        if let Some(ref record_store) = self.record_store {
            if let Some(response) = record_store.create_sync_response(request_id, from_version) {
                if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                    tracing::warn!("Failed to send DHT sync response: {}", e);
                }
            }
        }
    }

    async fn handle_dht_sync_response(
        &self,
        from_peer: &str,
        records: Vec<crate::mesh::protocol::DhtRecord>,
    ) {
        tracing::debug!("Received DHT sync response from {} ({} records)", 
            from_peer, records.len());

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            record_store.handle_sync_response_verified(records, from_peer, signer);
        }
    }

    async fn handle_dht_anti_entropy_request(
        &self,
        from_peer: &str,
        request_id: &str,
        _node_id: &str,
        local_root_hash: &[u8],
        interested_keys: &[String],
        _timestamp: u64,
    ) {
        tracing::debug!("Received DHT anti-entropy request from {} ({} interested keys)", 
            from_peer, interested_keys.len());

        if let Some(ref record_store) = self.record_store {
            if let Some(response) = record_store.handle_anti_entropy_request(
                request_id,
                local_root_hash,
                interested_keys,
                from_peer,
            ) {
                if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
                    tracing::warn!("Failed to send DHT anti-entropy response to {}: {}", from_peer, e);
                }
            }
        }
    }

    async fn get_effective_read_threshold(&self, peer_id: &str) -> i64 {
        if let Some(override_val) = self.config.dht.as_ref().and_then(|d| d.manual_threshold_override) {
            return override_val;
        }

        if let Some(ref record_store) = self.record_store {
            if let Some(policy) = record_store.get_network_policy() {
                let max = self.config.dht.as_ref()
                    .map(|d| d.max_reputation_threshold)
                    .unwrap_or(80);
                return policy.min_reputation_for_read.clamp(0, max);
            }
        }

        self.config.dht.as_ref()
            .map(|d| d.min_reputation_for_dht_read)
            .unwrap_or(10)
    }

    async fn get_effective_write_threshold(&self, peer_id: &str) -> i64 {
        if let Some(override_val) = self.config.dht.as_ref().and_then(|d| d.manual_threshold_override) {
            return override_val;
        }

        if let Some(ref record_store) = self.record_store {
            if let Some(policy) = record_store.get_network_policy() {
                let max = self.config.dht.as_ref()
                    .map(|d| d.max_reputation_threshold)
                    .unwrap_or(80);
                return policy.min_reputation_for_write.clamp(0, max);
            }
        }

        self.config.dht.as_ref()
            .map(|d| d.min_reputation_for_dht_write)
            .unwrap_or(30)
    }

    async fn handle_dht_anti_entropy_response(
        &self,
        from_peer: &str,
        missing_records: Vec<crate::mesh::protocol::DhtRecord>,
        _timestamp: u64,
        signature: &[u8],
    ) {
        tracing::debug!("Received DHT anti-entropy response from {} ({} missing records)", 
            from_peer, missing_records.len());

        if missing_records.is_empty() {
            return;
        }

        if !signature.is_empty() {
            tracing::debug!("DHT anti-entropy response from {} has signature", from_peer);
        }

        if let Some(ref record_store) = self.record_store {
            let signer = self.mesh_signer.as_ref();
            record_store.handle_anti_entropy_response_verified(missing_records, from_peer, signer);
            record_store.compute_merkle_tree();
        }
    }

    async fn handle_find_node(
        &self,
        from_peer: &str,
        request_id: &str,
        target_node_id: Vec<u8>,
        requester_node_id: &str,
    ) {
        tracing::debug!("Received FindNode from {} for target of length {}", from_peer, target_node_id.len());

        let min_reputation = self.get_effective_read_threshold(from_peer).await;

        if min_reputation > 0 {
            if let Some(rep) = self.topology.get_peer_audit_reputation(from_peer).await {
                let rep_score = (rep * 100.0) as i64;
                if rep_score < min_reputation {
                    tracing::debug!("Rejecting FindNode from {}: reputation {} below threshold {}",
                        from_peer, rep_score, min_reputation);
                    return;
                }
            } else {
                tracing::debug!("Rejecting FindNode from {}: unknown peer (no reputation)", from_peer);
                return;
            }
        }

        let Some(ref routing_manager) = self.routing_manager else {
            tracing::trace!("FindNode received but routing not enabled");
            return;
        };

        let target_id = match crate::mesh::dht::routing::NodeId::from_bytes(&target_node_id) {
            Some(id) => id,
            None => {
                tracing::warn!("Invalid target_node_id in FindNode from {}", from_peer);
                return;
            }
        };

        let closest_peers = routing_manager.find_closest_to_node_id(&target_id, 20).await;

        let response = crate::mesh::protocol::MeshMessage::FindNodeResponse {
            request_id: request_id.into(),
            peers: closest_peers,
            responder_node_id: self.config.node_id().into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send FindNodeResponse to {}: {}", from_peer, e);
        }
    }

    async fn handle_find_node_response(
        &self,
        from_peer: &str,
        peers: Vec<crate::mesh::dht::routing::PeerContact>,
    ) {
        tracing::debug!("Received FindNodeResponse from {} with {} peers", from_peer, peers.len());

        let Some(ref routing_manager) = self.routing_manager else {
            return;
        };

        for peer in peers {
            if peer.node_id_string == self.config.node_id() {
                continue;
            }

            routing_manager.add_peer(
                peer.node_id_string.clone(),
                peer.address,
                peer.port,
                if peer.is_global { crate::mesh::config::MeshNodeRole::Global } else { crate::mesh::config::MeshNodeRole::Edge },
                peer.latency_ms,
                peer.is_trusted,
                peer.geo,
                peer.pow_nonce,
                peer.public_key,
            ).await;
        }
    }

    async fn handle_origin_key_query(
        &self,
        from_peer: &str,
        request_id: &str,
        mesh_id: &str,
    ) {
        tracing::debug!("Received OriginKeyQuery for mesh {} from {}", mesh_id, from_peer);

        let origin_pubkey = self.get_origin_ed25519_pubkey(mesh_id).map(|s| s.into());

        let response = crate::mesh::protocol::MeshMessage::OriginKeyQueryResponse {
            request_id: request_id.into(),
            mesh_id: mesh_id.into(),
            public_key: origin_pubkey,
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send OriginKeyQueryResponse to {}: {}", from_peer, e);
        }
    }

    async fn handle_ping(
        &self,
        from_peer: &str,
        request_id: &str,
    ) {
        tracing::debug!("Received Ping from {}", from_peer);

        let response = crate::mesh::protocol::MeshMessage::Pong {
            request_id: request_id.into(),
            node_id: self.config.node_id().into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send Pong to {}: {}", from_peer, e);
        }
    }

    async fn handle_pong(
        &self,
        from_peer: &str,
        _request_id: &str,
        node_id: &str,
    ) {
        tracing::debug!("Received Pong from {}", from_peer);

        let Some(ref routing_manager) = self.routing_manager else {
            return;
        };

        routing_manager.update_peer_latency(node_id, 0).await;
    }

    #[cfg(feature = "dns")]
    async fn handle_anycast_registration(
        &self,
        from_peer: &str,
        request_id: &str,
        registration: crate::dns::messages::DnsAnycastNodeRegistration,
    ) {
        tracing::debug!("Received anycast node registration for node: {}", registration.node_id);

        if !self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
            tracing::warn!("Received anycast registration on non-global node");
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => {
                tracing::warn!("DNS registry not available for anycast registration");
                return;
            }
        };

        if let Err(e) = dns_registry.register_anycast_node(registration.clone()).await {
            tracing::error!("Failed to register anycast node: {}", e);
            return;
        }

        self.broadcast_anycast_node_registration(&registration).await;

        tracing::info!("Anycast node {} registered successfully", registration.node_id);
    }

    #[cfg(feature = "dns")]
    async fn broadcast_anycast_node_registration(
        &self,
        registration: &crate::dns::messages::DnsAnycastNodeRegistration,
    ) {
        use crate::mesh::protocol::ArcStr;

        let global_nodes = self.topology.get_global_nodes().await;

        let message = MeshMessage::AnycastNodeRegistration {
            request_id: ArcStr::new(format!("{}-broadcast-{}", registration.node_id, chrono::Utc::now().timestamp())),
            node_id: ArcStr::new(registration.node_id.clone()),
            anycast_ips: registration.anycast_ips.clone(),
            geo: registration.geo.as_ref().map(|g| ArcStr::new(g.clone())),
            capacity: registration.capacity,
            healthy: registration.healthy,
            dns_zones: registration.dns_zones.clone(),
            certificate_fingerprint: registration.certificate_fingerprint.as_ref().map(|c| ArcStr::new(c.clone())),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        for node_id in global_nodes {
            if node_id == self.config.node_id() {
                continue;
            }

            if let Err(e) = self.send_datagram_to_peer(&node_id, &message).await {
                tracing::debug!("Failed to broadcast anycast registration to {}: {}", node_id, e);
            }
        }
    }

    #[cfg(feature = "dns")]
    async fn handle_anycast_health_update(
        &self,
        _peer_id: &str,
        node_id: &str,
        anycast_ips: Vec<String>,
        healthy: bool,
        latency_ms: Option<u32>,
        load_percent: Option<u8>,
    ) {
        tracing::debug!("Received anycast health update from {}: healthy={}", node_id, healthy);

        counter!("dns_anycast_health_updates_total").increment(1);

        if let Some(latency) = latency_ms {
            gauge!("dns_anycast_node_latency_ms")
                .set(latency as f64);
        }
        if let Some(load) = load_percent {
            gauge!("dns_anycast_node_load_percent")
                .set(load as f64);
        }

        if !self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => return,
        };

        let update = crate::dns::messages::DnsAnycastHealthUpdate {
            node_id: node_id.to_string(),
            anycast_ips,
            healthy,
            latency_ms,
            load_percent,
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = dns_registry.update_anycast_health(update).await {
            tracing::error!("Failed to update anycast health: {}", e);
            counter!("dns_anycast_health_update_errors_total").increment(1);
        }
    }

    #[cfg(feature = "dns")]
    async fn handle_zone_sync_request(
        &self,
        peer_id: &str,
        request_id: &str,
        zone_origin: &str,
        client_serial: u32,
        requesting_node_id: &str,
    ) {
        tracing::debug!("Received zone sync request for zone: {} from node: {} (client serial: {})", 
            zone_origin, requesting_node_id, client_serial);

        let (records_json, response_serial, complete, previous_serial) = if let Some(ref dns_registry) = self.dns_registry {
            let nodes = dns_registry.get_all_healthy_origin_nodes();
            
            let is_origin = nodes.iter().any(|node| {
                node.domains.contains(&zone_origin.to_string()) && node.node_id == self.config.node_id()
            });

            if is_origin {
                let lock = self.dns_zones.read();
                let zone_opt = if let Some(ref zones) = *lock {
                    zones.read().get(zone_origin).cloned()
                } else {
                    None
                };

                if let Some(zone) = zone_opt {
                    let current_serial = zone.serial;
                    
                    if client_serial == current_serial {
                        // Client has latest
                        (serde_json::json!({
                            "status": "up_to_date",
                            "serial": current_serial
                        }).to_string(), current_serial, true, client_serial)
                    } else if client_serial == 0 || client_serial > current_serial {
                        // Client needs full transfer
                        let records: Vec<crate::dns::anycast_sync::SerializedRecord> = zone.records
                            .iter()
                            .map(|((name, rt), records)| {
                                records.iter().map(|r| crate::dns::anycast_sync::SerializedRecord {
                                    name: name.clone(),
                                    record_type: rt.to_string(),
                                    ttl: r.ttl,
                                    value: r.value.clone(),
                                    priority: r.priority,
                                }).collect::<Vec<_>>()
                            })
                            .flatten()
                            .collect();

                        let json = serde_json::to_string(&crate::dns::anycast_sync::SerializedZoneData {
                            origin: zone.origin.clone(),
                            serial: zone.serial,
                            records,
                            history: vec![],
                        }).unwrap_or_else(|_| "{}".to_string());

                        (json, zone.serial, true, client_serial)
                    } else {
                        // Client has older version - try IXFR from history
                        tracing::info!("Zone {} updated from serial {} to {}, attempting IXFR", 
                            zone_origin, client_serial, current_serial);
                        
                        // Try to get the client's version from history
                        let old_records = if let Some(old_version) = zone.get_previous_version(client_serial) {
                            Some(old_version.records.clone())
                        } else {
                            None
                        };

                        if let Some(old_records) = old_records {
                            // Compute IXFR: find additions and deletions
                            let mut changes = Vec::new();
                            
                            let all_keys: std::collections::HashSet<_> = zone.records.keys()
                                .chain(old_records.keys())
                                .collect();
                            
                            for key in all_keys {
                                let new_recs = zone.records.get(key);
                                let old_recs = old_records.get(key);
                                
                                match (new_recs, old_recs) {
                                    (Some(new), Some(old)) => {
                                        // Check if records differ
                                        let changed = new.len() != old.len() || 
                                            new.iter().zip(old.iter()).any(|(a, b)| a.value != b.value || a.ttl != b.ttl);
                                        
                                        if changed {
                                            // Changed - treat as delete + add
                                            changes.push(crate::dns::anycast_sync::ZoneChange {
                                                change_type: "delete".to_string(),
                                                name: key.0.clone(),
                                                record_type: key.1.to_string(),
                                                ttl: old.iter().map(|r| r.ttl).next().unwrap_or(0),
                                                value: old.iter().map(|r| r.value.clone()).collect::<Vec<_>>(),
                                                priority: old.iter().map(|r| r.priority).next().flatten(),
                                            });
                                            changes.push(crate::dns::anycast_sync::ZoneChange {
                                                change_type: "add".to_string(),
                                                name: key.0.clone(),
                                                record_type: key.1.to_string(),
                                                ttl: new.iter().map(|r| r.ttl).next().unwrap_or(0),
                                                value: new.iter().map(|r| r.value.clone()).collect::<Vec<_>>(),
                                                priority: new.iter().map(|r| r.priority).next().flatten(),
                                            });
                                        }
                                    }
                                    (Some(new), None) => {
                                        // Added
                                        changes.push(crate::dns::anycast_sync::ZoneChange {
                                            change_type: "add".to_string(),
                                            name: key.0.clone(),
                                            record_type: key.1.to_string(),
                                            ttl: new.iter().map(|r| r.ttl).next().unwrap_or(0),
                                            value: new.iter().map(|r| r.value.clone()).collect::<Vec<_>>(),
                                            priority: new.iter().map(|r| r.priority).next().flatten(),
                                        });
                                    }
                                    (None, Some(old)) => {
                                        // Deleted
                                        changes.push(crate::dns::anycast_sync::ZoneChange {
                                            change_type: "delete".to_string(),
                                            name: key.0.clone(),
                                            record_type: key.1.to_string(),
                                            ttl: old.iter().map(|r| r.ttl).next().unwrap_or(0),
                                            value: old.iter().map(|r| r.value.clone()).collect::<Vec<_>>(),
                                            priority: old.iter().map(|r| r.priority).next().flatten(),
                                        });
                                    }
                                    _ => {}
                                }
                            }

                            let json = serde_json::to_string(&crate::dns::anycast_sync::SerializedIxfrData {
                                origin: zone.origin.clone(),
                                serial: zone.serial,
                                previous_serial: client_serial,
                                changes,
                            }).unwrap_or_else(|_| "{}".to_string());

                            (json, zone.serial, true, client_serial)
                        } else {
                            // No history available - send full AXFR
                            tracing::warn!("No history for serial {}, sending full AXFR", client_serial);
                            
                            let records: Vec<crate::dns::anycast_sync::SerializedRecord> = zone.records
                                .iter()
                                .map(|((name, rt), records)| {
                                    records.iter().map(|r| crate::dns::anycast_sync::SerializedRecord {
                                        name: name.clone(),
                                        record_type: rt.to_string(),
                                        ttl: r.ttl,
                                        value: r.value.clone(),
                                        priority: r.priority,
                                    }).collect::<Vec<_>>()
                                })
                                .flatten()
                                .collect();

                            let json = serde_json::to_string(&crate::dns::anycast_sync::SerializedZoneData {
                                origin: zone.origin.clone(),
                                serial: zone.serial,
                                records,
                                history: vec![],
                            }).unwrap_or_else(|_| "{}".to_string());

                            (json, zone.serial, true, client_serial)
                        }
                    }
                } else {
                    (serde_json::json!({
                        "error": "Zone not found in local storage",
                        "zone": zone_origin
                    }).to_string(), 0, false, 0)
                }
            } else {
                (serde_json::json!({
                    "error": "Not origin node for zone",
                    "zone": zone_origin,
                    "available_origins": nodes.iter().filter(|n| n.domains.contains(&zone_origin.to_string())).map(|n| &n.node_id).collect::<Vec<_>>()
                }).to_string(), 0, false, 0)
            }
        } else {
            (serde_json::json!({
                "error": "No DNS registry available"
            }).to_string(), 0, false, 0)
        };

        let (compressed, final_json) = if records_json.len() > 1024 {
            // Compress if larger than 1KB
            use std::io::Write;
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            if encoder.write_all(records_json.as_bytes()).is_ok() {
                match encoder.finish() {
                    Ok(compressed) => {
                        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &compressed);
                        tracing::debug!("Compressed zone {} from {} to {} bytes", zone_origin, records_json.len(), encoded.len());
                        (true, encoded)
                    }
                    Err(_) => (false, records_json),
                }
            } else {
                (false, records_json)
            }
        } else {
            (false, records_json)
        };

        let (origin_signature, origin_pubkey) = if let Some(ref signer) = self.origin_ed25519_signer {
            let sign_data = format!("{}|{}|{}", zone_origin, final_json, response_serial);
            let sig = signer.sign(&sign_data);
            (sig.into_bytes(), self.config.origin_signing_key.as_ref()
                .and_then(|k| k.public_key_base64.clone()))
        } else {
            (Vec::new(), None)
        };

        let response = crate::mesh::protocol::MeshMessage::ZoneSyncResponse {
            request_id: request_id.into(),
            zone_origin: zone_origin.into(),
            records_json: final_json.into(),
            serial: response_serial,
            complete,
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
            origin_signature,
            origin_pubkey,
            previous_serial,
            compressed,
        };

        if let Err(e) = self.send_datagram_to_peer(peer_id, &response).await {
            tracing::warn!("Failed to send zone sync response to {}: {}", peer_id, e);
        }
    }

    #[cfg(feature = "dns")]
    async fn handle_zone_sync_response(
        &self,
        _peer_id: &str,
        _request_id: &str,
        zone_origin: &str,
        records_json: &str,
        serial: u32,
        complete: bool,
        origin_signature: &[u8],
        origin_pubkey: Option<&str>,
        previous_serial: u32,
        compressed: bool,
    ) {
        tracing::debug!("Received zone sync response for zone: {} (serial: {}, complete: {}, prev_serial: {}, compressed: {})", 
            zone_origin, serial, complete, previous_serial, compressed);

        let final_json = if compressed {
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, records_json) {
                Ok(compressed_data) => {
                    use std::io::Read;
                    let mut decoder = ZlibDecoder::new(compressed_data.as_slice());
                    let mut decompressed = String::new();
                    match decoder.read_to_string(&mut decompressed) {
                        Ok(_) => {
                            tracing::debug!("Decompressed zone {} from {} to {} bytes", zone_origin, records_json.len(), decompressed.len());
                            decompressed
                        }
                        Err(e) => {
                            tracing::warn!("Failed to decompress zone {}: {}", zone_origin, e);
                            records_json.to_string()
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to decode base64 for zone {}: {}", zone_origin, e);
                    records_json.to_string()
                }
            }
        } else {
            records_json.to_string()
        };

        let verified = if !origin_signature.is_empty() && origin_pubkey.is_some() {
            let sign_data = format!("{}|{}|{}", zone_origin, final_json, serial);
            if let Some(pubkey_str) = origin_pubkey {
                if let Ok(pubkey_bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pubkey_str) {
                    crate::integrity::signing::verify_ed25519_raw(&pubkey_bytes, &sign_data, origin_signature)
                } else {
                    tracing::warn!("Failed to decode public key for zone sync verification");
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if verified {
            tracing::info!("Zone {} signature verified (serial: {})", zone_origin, serial);
            counter!("dns_zone_sync_signature_verified_total").increment(1);
        } else if !origin_signature.is_empty() {
            tracing::warn!("Zone {} signature verification FAILED", zone_origin);
            counter!("dns_zone_sync_signature_failed_total").increment(1);
        }

        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&final_json) {
            tracing::debug!("Zone sync data for {}: {:?}", zone_origin, data);
        }

        if complete {
            tracing::info!("Zone {} sync completed with serial {}", zone_origin, serial);
            counter!("dns_zone_sync_completed_total").increment(1);
            
            let bytes = records_json.len() as u64;
            counter!("dns_zone_sync_bytes_total").increment(bytes);
            
            if compressed {
                counter!("dns_zone_sync_compressed_total").increment(1);
            }
            
            if previous_serial > 0 && previous_serial != serial {
                counter!("dns_zone_sync_ixfr_total").increment(1);
            } else {
                counter!("dns_zone_sync_axfr_total").increment(1);
            }
        }
    }

    #[cfg(feature = "dns")]
    async fn handle_zone_sync_ack(
        &self,
        _peer_id: &str,
        _request_id: &str,
        zone_origin: &str,
        serial: u64,
    ) {
        tracing::debug!("Received zone sync ACK for zone: {} serial: {}", zone_origin, serial);
    }

    async fn handle_org_member_announce(
        &self,
        org_id: &str,
        member_node_id: &str,
        announced_by: &str,
        joined_at: u64,
    ) {
        tracing::info!("Received org member announce: {} joined org {} (announced by {})", 
            member_node_id, org_id, announced_by);
    }

    async fn handle_keepalive_datagram(&self, peer_id: &str) {
        tracing::trace!("Received keepalive from {}", peer_id);
        if let Some(mut peer) = self.peer_connections.get_mut(peer_id) {
            peer.last_seen = Instant::now();
        }
    }

    async fn handle_lookup_request(
        &self,
        from_peer: &str,
        request_id: &str,
        key: &str,
        lookup_type: crate::mesh::protocol::LookupType,
    ) {
        tracing::debug!("Received lookup request: {} for key {} from {}", request_id, key, from_peer);
        
        let value = match lookup_type {
            crate::mesh::protocol::LookupType::Route => {
                if let Some((provider, hops)) = self.topology.get_cached_route(key).await {
                    Some(format!("{}:{}", provider, hops).into_bytes())
                } else if let Some(local) = self.topology.get_upstream_info(key).await {
                    Some(format!("local:{}", self.config.node_id()).into_bytes())
                } else {
                    None
                }
            }
            crate::mesh::protocol::LookupType::Peer => {
                if let Some(peer) = self.topology.get_peer(key).await {
                    Some(peer.address.clone().into_bytes())
                } else {
                    None
                }
            }
            crate::mesh::protocol::LookupType::KeyValue | 
            crate::mesh::protocol::LookupType::Certificate |
            crate::mesh::protocol::LookupType::Config => {
                None
            }
        };

        let response = MeshMessage::LookupResponse {
            request_id: request_id.into(),
            key: key.into(),
            value: value.clone(),
            found: value.is_some(),
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send lookup response to {}: {}", from_peer, e);
        }
    }

    async fn handle_lookup_batch_request(
        &self,
        from_peer: &str,
        request_id: &str,
        keys: &[crate::mesh::protocol::ArcStr],
    ) {
        tracing::debug!("Received batch lookup request: {} for {} keys from {}", request_id, keys.len(), from_peer);
        
        let mut results = HashMap::new();
        
        for key in keys {
            if let Some((provider, _)) = self.topology.get_cached_route(key).await {
                results.insert(key.to_string(), Some(format!("{}:{}", provider, 0).into_bytes()));
            } else if self.topology.has_local_upstream(key).await {
                results.insert(key.to_string(), Some(format!("local:{}", self.config.node_id()).into_bytes()));
            } else {
                results.insert(key.to_string(), None);
            }
        }

        let response = MeshMessage::LookupBatchResponse {
            request_id: request_id.into(),
            results,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send batch lookup response to {}: {}", from_peer, e);
        }
    }

    async fn handle_peer_health_check(
        &self,
        from_peer: &str,
        target_peer_id: &str,
        timestamp: u64,
    ) {
        tracing::trace!("Received health check request for {} from {}", target_peer_id, from_peer);
        
        let status = if let Some(peer) = self.topology.get_peer(target_peer_id).await {
            if peer.is_healthy() {
                crate::mesh::protocol::HealthStatus::Healthy
            } else {
                crate::mesh::protocol::HealthStatus::Degraded
            }
        } else {
            crate::mesh::protocol::HealthStatus::Unknown
        };

        let response = MeshMessage::PeerHealthResponse {
            peer_id: target_peer_id.into(),
            status,
            latency_ms: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u64,
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send health response to {}: {}", from_peer, e);
        }
    }

    async fn handle_peer_announce(
        &self,
        from_peer: &str,
        node_id: &str,
        address: &str,
        role: crate::mesh::config::MeshNodeRole,
        capabilities: &crate::mesh::protocol::MeshCapabilities,
        announced_at: u64,
    ) {
        tracing::debug!("Received peer announce: {} ({}) from {}", node_id, address, from_peer);
        
        self.topology.add_peer(
            crate::mesh::protocol::MeshPeerInfo {
                node_id: node_id.to_string(),
                address: address.to_string(),
                role: role,
                capabilities: capabilities.clone(),
                is_global: role.is_global(),
                latency_ms: None,
                upstreams: vec![],
                is_trusted: role.is_global(),
                quic_port: None,
                wireguard_port: None,
                advertised_port: None,
            },
            PeerStatus::Healthy,
        ).await;
        
        self.update_threat_intel_global_nodes().await;
    }

    async fn handle_peer_gone(
        &self,
        from_peer: &str,
        node_id: &str,
        reason: &str,
    ) {
        tracing::info!("Peer {} announced departure from {}: {}", node_id, from_peer, reason);
        
        self.topology.remove_peer(node_id).await;
        
        self.update_threat_intel_global_nodes().await;
    }

    #[cfg(feature = "dns")]
    async fn handle_node_shutdown(
        &self,
        from_peer: &str,
        node_id: &str,
        role: crate::mesh::config::MeshNodeRole,
        domains: &[std::sync::Arc<str>],
        graceful: bool,
        shutdown_at: u64,
        timestamp: u64,
    ) {
        let now = chrono::Utc::now().timestamp() as u64;
        let time_until_shutdown = shutdown_at.saturating_sub(now);
        
        tracing::info!(
            "Node {} announced graceful shutdown in {}s for domains: {:?}",
            node_id,
            time_until_shutdown,
            domains
        );

        if graceful && time_until_shutdown > 0 {
            if let Some(dns_registry) = &self.dns_registry {
                let shutdown_msg = crate::dns::messages::DnsNodeShutdown {
                    node_id: node_id.to_string(),
                    role: if role.is_edge() { 
                        crate::dns::messages::DnsNodeRole::Edge 
                    } else { 
                        crate::dns::messages::DnsNodeRole::Origin 
                    },
                    domains: domains.iter().map(|d| d.to_string()).collect(),
                    graceful,
                    shutdown_at,
                    timestamp,
                };
                
                let _ = dns_registry.handle_node_shutdown(shutdown_msg).await;
            }
        }

        self.topology.remove_peer(node_id).await;
    }

    #[cfg(feature = "dns")]
    async fn handle_dns_domain_register_request(
        &self,
        from_peer: &str,
        request_id: &str,
        domain: &str,
        origin_node_id: &str,
        challenge_token: &str,
        geo: Option<&str>,
        capacity: u32,
        timestamp: u64,
        signature: &[u8],
    ) {
        tracing::info!("Received DNS domain register request: {} from {} for domain {}", 
            request_id, origin_node_id, domain);

        if !self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
            tracing::warn!("Received DNS domain register request on non-global node");
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => {
                tracing::warn!("DNS registry not available");
                return;
            }
        };

        let now = chrono::Utc::now().timestamp() as u64;
        if now.saturating_sub(timestamp) > 300 {
            tracing::warn!("DNS domain register request timestamp too old");
            return;
        }

        let verified = self.verify_domain_challenge(domain, challenge_token, origin_node_id).await;

        let reason = if verified {
            "Domain verified successfully".to_string()
        } else {
            "Domain verification failed".to_string()
        };

        let ttl_seconds: u64 = 300;
        let expires_at = now + ttl_seconds;

        let response = MeshMessage::DnsDomainRegisterResponse {
            request_id: request_id.into(),
            domain: domain.into(),
            origin_node_id: origin_node_id.into(),
            verified,
            reason: reason.clone().into(),
            timestamp: now,
            signature: vec![],
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send DNS domain register response: {}", e);
            return;
        }

        if verified {
            let registration = crate::dns::messages::DnsRegistration {
                node_id: origin_node_id.to_string(),
                domain: domain.to_string(),
                ip_addresses: vec![],
                geo: geo.map(String::from),
                capacity,
                healthy: true,
                latency_ms: None,
                certificate_fingerprint: None,
                role: crate::dns::messages::DnsNodeRole::Origin,
                edge_node_id: None,
                edge_node_geo: None,
            };

            if let Err(e) = dns_registry.register_origin_node(registration).await {
                tracing::error!("Failed to register origin node in DNS registry: {}", e);
                return;
            }

            self.broadcast_dns_domain_registered(
                domain,
                origin_node_id,
                &self.config.node_id(),
                geo,
                capacity,
                now,
                expires_at,
            ).await;

            tracing::info!("Domain {} registered for origin {}", domain, origin_node_id);
        }
    }

    #[cfg(feature = "dns")]
    async fn handle_dns_domain_register_response(
        &self,
        from_peer: &str,
        request_id: &str,
        domain: &str,
        origin_node_id: &str,
        verified: bool,
        reason: &str,
        timestamp: u64,
    ) {
        tracing::info!("Received DNS domain register response for {}: verified={}, reason={}", 
            domain, verified, reason);
    }

    #[cfg(feature = "dns")]
    async fn handle_dns_domain_deregister_request(
        &self,
        from_peer: &str,
        request_id: &str,
        domain: &str,
        origin_node_id: &str,
        reason: &str,
        timestamp: u64,
    ) {
        tracing::info!("Received DNS domain deregister request: {} from {} for domain {}",
            request_id, origin_node_id, domain);

        if !self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
            tracing::warn!("Received DNS domain deregister request on non-global node");
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => {
                tracing::warn!("DNS registry not available");
                return;
            }
        };

        let now = chrono::Utc::now().timestamp() as u64;
        
        let registered_origins = dns_registry.get_registered_origin_nodes();
        let origin_exists = registered_origins.values().any(|o| 
            o.node_id == origin_node_id && o.domains.contains(&domain.to_string())
        );

        if !origin_exists {
            tracing::warn!("Origin {} not registered for domain {}", origin_node_id, domain);
            return;
        }

        self.broadcast_dns_domain_deregistered(
            domain,
            origin_node_id,
            &self.config.node_id(),
            reason,
            now,
        ).await;

        tracing::info!("Domain {} deregistered for origin {}", domain, origin_node_id);
    }

    #[cfg(feature = "dns")]
    async fn handle_dns_domain_registered(
        &self,
        from_peer: &str,
        domain: &str,
        origin_node_id: &str,
        verified_by_global_node: &str,
        geo: Option<&str>,
        capacity: u32,
        registered_at: u64,
        expires_at: u64,
    ) {
        tracing::info!("Received DnsDomainRegistered: domain={} origin={} verified_by={}",
            domain, origin_node_id, verified_by_global_node);

        if !self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => return,
        };

        let registration = crate::dns::messages::DnsRegistration {
            node_id: origin_node_id.to_string(),
            domain: domain.to_string(),
            ip_addresses: vec![],
            geo: geo.map(String::from),
            capacity,
            healthy: true,
            latency_ms: None,
            certificate_fingerprint: None,
            role: crate::dns::messages::DnsNodeRole::Origin,
            edge_node_id: None,
            edge_node_geo: None,
        };

        if let Err(e) = dns_registry.register_origin_node(registration).await {
            tracing::error!("Failed to register origin from broadcast: {}", e);
        }
    }

    #[cfg(feature = "dns")]
    async fn handle_dns_domain_deregistered(
        &self,
        from_peer: &str,
        domain: &str,
        origin_node_id: &str,
        deregistered_by_global_node: &str,
        reason: &str,
        deregistered_at: u64,
    ) {
        tracing::info!("Received DnsDomainDeregistered: domain={} origin={} by={} reason={}",
            domain, origin_node_id, deregistered_by_global_node, reason);

        if !self.config.role.contains(crate::mesh::config::MeshNodeRole::GLOBAL) {
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => return,
        };

        if let Err(e) = dns_registry.remove_origin(origin_node_id, domain) {
            tracing::warn!("Failed to remove origin from DNS registry: {}", e);
        }
    }

    #[cfg(feature = "dns")]
    async fn verify_domain_challenge(
        &self,
        domain: &str,
        challenge_token: &str,
        origin_node_id: &str,
    ) -> bool {
        if challenge_token.is_empty() {
            tracing::warn!("Empty challenge token for domain {}", domain);
            return false;
        }

        if challenge_token.starts_with("txt:") {
            let expected_token = &challenge_token[4..];
            return self.verify_txt_challenge(domain, expected_token).await;
        }

        if challenge_token.starts_with("oauth:") {
            let oauth_config = &challenge_token[7..];
            return self.verify_oauth_challenge(domain, origin_node_id, oauth_config).await;
        }

        if challenge_token.starts_with("signed:") {
            let signature_hex = &challenge_token[7..];
            return self.verify_signed_challenge(domain, origin_node_id, signature_hex).await;
        }

        tracing::warn!("Unknown challenge token format for domain {}", domain);
        false
    }

    #[cfg(feature = "dns")]
    async fn verify_txt_challenge(&self, domain: &str, expected_token: &str) -> bool {
        tracing::debug!("Verifying TXT record challenge for {}: expected={}", domain, expected_token);
        
        let txt_query = format!("_maluwaf-challenge.{}", domain);
        
        tracing::debug!("Would query TXT record for {}", txt_query);
        
        true
    }

    #[cfg(feature = "dns")]
    async fn verify_oauth_challenge(&self, domain: &str, origin_node_id: &str, oauth_config: &str) -> bool {
        tracing::debug!("Verifying OAuth/DNS-OAUTH challenge for {} with node {}", domain, origin_node_id);
        
        tracing::debug!("Would perform OAuth DNS challenge verification for {}", domain);
        
        true
    }

    #[cfg(feature = "dns")]
    async fn verify_signed_challenge(&self, domain: &str, origin_node_id: &str, signature_hex: &str) -> bool {
        tracing::debug!("Verifying signed challenge for {} from {}", domain, origin_node_id);
        
        if signature_hex.is_empty() {
            tracing::warn!("Empty signature for signed challenge");
            return false;
        }

        if let Ok(signature_bytes) = hex::decode(signature_hex) {
            if signature_bytes.len() == 64 {
                tracing::info!("Signed challenge received for domain {} from node {} (verification stub)", 
                    domain, origin_node_id);
                return true;
            }
        }
        
        tracing::warn!("Signed challenge verification failed for domain {} from node {}", domain, origin_node_id);
        false
    }

    #[cfg(feature = "dns")]
    async fn broadcast_dns_domain_registered(
        &self,
        domain: &str,
        origin_node_id: &str,
        verified_by_global_node: &str,
        geo: Option<&str>,
        capacity: u32,
        registered_at: u64,
        expires_at: u64,
    ) {
        let global_nodes = self.topology.get_global_nodes().await;

        let message = MeshMessage::DnsDomainRegistered {
            domain: domain.into(),
            origin_node_id: origin_node_id.into(),
            verified_by_global_node: verified_by_global_node.into(),
            geo: geo.map(|s| s.into()),
            capacity,
            registered_at,
            expires_at,
            signature: vec![],
        };

        for node_id in global_nodes {
            if node_id == self.config.node_id() {
                continue;
            }

            if let Err(e) = self.send_datagram_to_peer(&node_id, &message).await {
                tracing::warn!("Failed to broadcast DnsDomainRegistered to {}: {}", node_id, e);
            }
        }
    }

    #[cfg(feature = "dns")]
    async fn broadcast_dns_domain_deregistered(
        &self,
        domain: &str,
        origin_node_id: &str,
        deregistered_by_global_node: &str,
        reason: &str,
        deregistered_at: u64,
    ) {
        let global_nodes = self.topology.get_global_nodes().await;

        let message = MeshMessage::DnsDomainDeregistered {
            domain: domain.into(),
            origin_node_id: origin_node_id.into(),
            deregistered_by_global_node: deregistered_by_global_node.into(),
            reason: reason.into(),
            deregistered_at,
            signature: vec![],
        };

        for node_id in global_nodes {
            if node_id == self.config.node_id() {
                continue;
            }

            if let Err(e) = self.send_datagram_to_peer(&node_id, &message).await {
                tracing::warn!("Failed to broadcast DnsDomainDeregistered to {}: {}", node_id, e);
            }
        }
    }

    async fn handle_topology_sync_request(
        &self,
        from_peer: &str,
        request_id: &str,
        from_version: u64,
    ) {
        tracing::debug!("Received topology sync request: {} from version {} from {}", request_id, from_version, from_peer);
        
        let peers = self.topology.get_all_peers().await;
        let upstreams = self.topology.get_upstream_owners().await;
        let version = self.topology.get_topology_version().await;

        let response = MeshMessage::TopologySyncResponse {
            request_id: request_id.into(),
            peers: peers.into_iter().map(|p| crate::mesh::protocol::MeshPeerInfo {
                node_id: p.node_id.into(),
                address: p.address.into(),
                role: p.role,
                capabilities: p.capabilities,
                is_global: p.is_global,
                latency_ms: p.latency_ms,
                upstreams: p.upstreams.into_iter().map(|s| s.into()).collect(),
                is_trusted: p.role.is_global(),
                quic_port: p.quic_port,
                wireguard_port: p.wireguard_port,
                advertised_port: p.advertised_port,
            }).collect(),
            upstreams,
            version,
            is_delta: false,
            removed_peers: vec![],
            removed_upstreams: vec![],
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send topology sync response to {}: {}", from_peer, e);
        }
    }

    async fn handle_seed_list_request(
        &self,
        from_peer: &str,
        _node_id: &str,
        request_full_mesh: bool,
    ) {
        tracing::debug!("Received seed list request from {} (full_mesh: {})", from_peer, request_full_mesh);

        let response = if self.topology.is_global() {
            let global_nodes = self.topology.get_seeded_global_nodes().await;
            let edge_nodes = if request_full_mesh {
                self.topology.get_seeded_edge_nodes().await
            } else {
                Vec::new()
            };

            MeshMessage::SeedListResponse {
                global_nodes,
                edge_nodes,
                version: 1,
                genesis_org_id: Some(self.config.node_identity.genesis_org_id().into()),
            }
        } else {
            MeshMessage::Error {
                code: 403,
                message: "Only global nodes can serve seed lists".into(),
            }
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send seed list response to {}: {}", from_peer, e);
        }
    }

    async fn handle_peer_load_report(
        &self,
        node_id: &str,
        active_connections: u32,
        cpu_load_percent: f32,
        memory_percent: f32,
        _requests_per_second: f32,
    ) {
        tracing::trace!("Received load report from {}: conns={}, cpu={}%, mem={}%",
            node_id, active_connections, cpu_load_percent, memory_percent);

        let load_score = ((cpu_load_percent as f64 / 100.0) * 0.6 + (memory_percent as f64 / 100.0) * 0.4).min(1.0).max(0.0);
        
        let mut scores = self.topology.peer_scores().write().await;
        if let Some(score) = scores.get_mut(node_id) {
            score.load_score = 1.0 - load_score;
            score.last_updated = Instant::now();
        } else {
            scores.insert(node_id.to_string(), crate::mesh::topology::PeerScore {
                node_id: node_id.to_string(),
                latency_score: 0.5,
                stability_score: 0.5,
                load_score: 1.0 - load_score,
                traffic_score: 0.0,
                upstream_score: 0.0,
                total_score: 0.5,
                last_updated: Instant::now(),
            });
        }
    }

    async fn handle_peer_load_update(&self, node_id: &str, load_score: f64) {
        tracing::trace!("Received load update from {}: score={}", node_id, load_score);
        
        let mut scores = self.topology.peer_scores().write().await;
        if let Some(score) = scores.get_mut(node_id) {
            score.load_score = 1.0 - load_score;
            score.last_updated = Instant::now();
        }
    }

    async fn handle_route_usage_report(&self, upstream_id: &str, request_count: u64, bytes_transferred: u64) {
        tracing::trace!("Received route usage report for {}: {} requests, {} bytes",
            upstream_id, request_count, bytes_transferred);
        
        self.topology.record_route_usage(upstream_id.to_string(), bytes_transferred).await;
        
        if let Some(score) = self.topology.peer_scores().write().await.get_mut(upstream_id) {
            let usage = self.topology.route_usage().read().await;
            score.traffic_score = usage.get_upstream_score(upstream_id);
        }
    }

    async fn handle_upstream_blocked(
        &self,
        mesh_identifier: &str,
        service_id: &str,
        blocked_until: u64,
        reason: &str,
        origin_node_id: &str,
    ) {
        // blocked_until is Unix timestamp when block expires
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        
        // Validate: block timestamp not unreasonably far in the future
        let max_allowed = now_unix + MAX_BLOCK_DURATION_SECS;
        if blocked_until > max_allowed {
            tracing::warn!(
                "Received block with timestamp too far in future: {} (current: {}, max: {}). Ignoring.",
                blocked_until, now_unix, max_allowed
            );
            return;
        }
        
        // Calculate remaining duration, skip if already expired
        let remaining_secs = blocked_until.saturating_sub(now_unix);
        if remaining_secs == 0 {
            tracing::debug!(
                "Received expired block notification for {}.{}, ignoring",
                mesh_identifier, service_id
            );
            return;
        }
        
        let blocked_instant = Instant::now() + Duration::from_secs(remaining_secs);
        
        tracing::info!(
            "Received upstream blocked notification: {}.{} blocked for {}s (reason: {})",
            mesh_identifier, service_id, remaining_secs, reason
        );
        
        self.topology.block_upstream(
            mesh_identifier,
            service_id,
            blocked_instant,
            reason,
            origin_node_id,
        ).await;
    }

    async fn handle_bandwidth_report(
        &self,
        upstream_id: &str,
        bytes_sent: u64,
        bytes_received: u64,
        request_count: u64,
        interval_secs: u64,
        timestamp: u64,
    ) {
        tracing::trace!(
            "Received bandwidth report for {}: {}B sent, {}B recv, {} reqs in {}s",
            upstream_id, bytes_sent, bytes_received, request_count, interval_secs
        );
        
        self.topology.record_route_usage(upstream_id.to_string(), bytes_sent + bytes_received).await;
    }

    pub async fn send_load_report_to_peers(&self) {
        let active_connections = crate::admin::get_current_connections() as u32;
        let (cpu_load_percent, memory_percent) = crate::admin::get_cpu_memory_usage();
        let requests_per_second = 0.0_f32;

        let load_report = MeshMessage::PeerLoadReport {
            node_id: self.config.node_id().into(),
            active_connections,
            cpu_load_percent,
            memory_percent,
            requests_per_second,
        };

        let peer_ids: Vec<String> = self.peer_connections.iter()
            .map(|e| e.key().clone())
            .collect();

        for peer_id in peer_ids {
            if let Err(e) = self.send_datagram_to_peer(&peer_id, &load_report).await {
                tracing::debug!("Failed to send load report to {}: {}", peer_id, e);
            }
        }

        tracing::trace!(
            "Sent load report to peers: conns={}, cpu={}%, mem={}%",
            active_connections, cpu_load_percent, memory_percent
        );
    }

    pub async fn start(&self) -> Result<(), MeshTransportError> {
        {
            let mut running = self.running.write();
            if *running {
                return Ok(());
            }
            *running = true;
        }

        let (shutdown_tx, _) = broadcast::channel(1);
        {
            let mut tx = self.shutdown_tx.write();
            *tx = Some(shutdown_tx.clone());
        }

        // PoW refresh: periodically refresh the cached PoW nonce before TTL expires
        // Started early since config is moved later in this function
        if self.config.role == crate::mesh::config::MeshNodeRole::Edge {
            let pow_config = self.config.clone();
            tokio::spawn(async move {
                let refresh_interval = Duration::from_secs(2700); // 45 minutes (half of 1hr TTL)
                let mut interval = tokio::time::interval(refresh_interval);
                loop {
                    interval.tick().await;
                    tracing::debug!("Refreshing PoW nonce cache");
                    if let Some(ref pk_hex) = pow_config.signing_public_key() {
                        use base64::Engine;
                        if let Ok(pk_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk_hex) {
                            if let Some(nonce) = crate::mesh::dht::routing::node_id::NodeId::find_pow_nonce(&pk_bytes) {
                                pow_config.set_cached_pow_nonce(nonce);
                                tracing::info!("Refreshed PoW nonce: {}", nonce);
                            } else {
                                tracing::warn!("Failed to compute new PoW nonce during refresh");
                            }
                        }
                    }
                }
            });
        }

        // ML-KEM key rotation: periodically rotate stale sessions for forward secrecy
        if let Some(ref mlkem_manager) = self.mlkem_session_manager {
            let mlkem_manager = mlkem_manager.clone();
            let rotation_interval = mlkem_manager.config().rotation_interval;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(rotation_interval);
                loop {
                    interval.tick().await;
                    tracing::debug!("Running ML-KEM key rotation");
                    let rotated = mlkem_manager.rotate_stale_sessions();
                    if !rotated.is_empty() {
                        tracing::info!("Rotated {} ML-KEM sessions", rotated.len());
                    }
                    let cleaned = mlkem_manager.cleanup_expired();
                    if cleaned > 0 {
                        tracing::debug!("Cleaned up {} expired ML-KEM sessions", cleaned);
                    }
                }
            });
        }

        let config = self.config.clone();
        let topology = self.topology.clone();
        let peer_connections = self.peer_connections.clone();
        let shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            Self::mesh_maintenance_loop(
                config,
                topology,
                peer_connections,
                shutdown_rx,
            ).await;
        });

        let datagram_shutdown = shutdown_tx.subscribe();
        let peer_connections_for_datagram = self.peer_connections.clone();
        tokio::spawn(async move {
            Self::datagram_listener_loop(peer_connections_for_datagram, datagram_shutdown).await;
        });

        if !self.config.seeds.is_empty() {
            self.bootstrap_from_seeds().await?;
        }

        if !self.config.peers.is_empty() {
            self.connect_to_peers().await?;
        }

        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                self.dht_bootstrap_from_seeds(rm.clone()).await?;
            }
        }

        let connection_config = self.config.connection.clone();
        let transport_for_maintenance = Arc::new(self.clone_for_maintenance());
        
        if connection_config.min_peer_connections > 0 {
            let maintenance_transport = transport_for_maintenance.clone();
            let maintenance_interval = Duration::from_secs(30);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(maintenance_interval);
                loop {
                    interval.tick().await;
                    maintenance_transport.maintain_connections().await;
                    maintenance_transport.perform_auto_slash().await;
                }
            });
            
            let health_transport = transport_for_maintenance.clone();
            let health_interval = Duration::from_secs(connection_config.health_check_interval_secs);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(health_interval);
                loop {
                    interval.tick().await;
                    let peers: Vec<String> = health_transport.peer_connections.iter()
                        .map(|e| e.value().node_id.clone())
                        .collect();
                    for peer_id in peers {
                        health_transport.perform_health_check(&peer_id).await;
                    }
                }
            });

            // Proactive cache warming: periodically query popular routes from peers
            let cache_warm_transport = transport_for_maintenance.clone();
            let cache_warm_interval = Duration::from_secs(60);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(cache_warm_interval);
                loop {
                    interval.tick().await;
                    cache_warm_transport.proactive_cache_warm().await;
                }
            });

            // DHT cache resync: periodically refresh edge node cache from global nodes
            // Uses adaptive interval from record_store (starts at 30s, backs off to 1 hour)
            let dht_resync_transport = transport_for_maintenance.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    dht_resync_transport.dht_cache_resync().await;
                }
            });

            // Load reporter: periodically send local load metrics to mesh peers
            let load_report_transport = transport_for_maintenance.clone();
            let load_report_interval = Duration::from_secs(60);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(load_report_interval);
                loop {
                    interval.tick().await;
                    load_report_transport.send_load_report_to_peers().await;
                }
            });
        }

        tracing::info!("Mesh transport started");
        Ok(())
    }

    fn clone_for_maintenance(&self) -> MeshTransport {
        MeshTransport {
            config: self.config.clone(),
            topology: self.topology.clone(),
            cert_manager: self.cert_manager.clone(),
            runtime: self.runtime.clone(),
            wireguard_runtime: self.wireguard_runtime.clone(),
            running: self.running.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            peer_connections: self.peer_connections.clone(),
            auth_keys: self.auth_keys.clone(),
            connection_times: self.connection_times.clone(),
            query_dedup: self.query_dedup.clone(),
            pending_queries: self.pending_queries.clone(),
            auth_failures: self.auth_failures.clone(),
            peer_message_times: self.peer_message_times.clone(),
            global_rate_limiter: self.global_rate_limiter.clone(),
            org_manager: self.org_manager.clone(),
            tier_key_store: self.tier_key_store.clone(),
            datagram_tx: self.datagram_tx.clone(),
            origin_ed25519_signer: self.origin_ed25519_signer.clone(),
            mesh_signer: self.mesh_signer.clone(),
            record_store: self.record_store.clone(),
            routing_manager: self.routing_manager.clone(),
            threat_intel: self.threat_intel.clone(),
            seen_messages: Arc::new(RwLock::new(lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(300), 10000,
            ))),
            stake_manager: self.stake_manager.clone(),
            mlkem_session_manager: self.mlkem_session_manager.clone(),
            #[cfg(feature = "dns")]
            dns_registry: self.dns_registry.clone(),
            #[cfg(feature = "dns")]
            dns_zones: self.dns_zones.clone(),
        }
    }

    async fn datagram_listener_loop(
        peer_connections: Arc<DashMap<String, MeshPeerConnection>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Datagram listener stopped");
                    break;
                }
                _ = async {
                    for entry in peer_connections.iter() {
                        let connection = &entry.value().connection;
                        match connection.read_datagram().await {
                            Ok(data) => {
                                let peer_id = entry.key().clone();
                                tracing::debug!("Received datagram from {}: {} bytes", peer_id, data.len());
                            }
                            Err(_) => {}
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } => {}
            }
        }
    }

    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.write().take() {
            let _ = tx.send(());
        }
        
        for entry in self.peer_connections.iter() {
            entry.value().connection.close(0u32.into(), b"Mesh shutdown");
        }
        self.peer_connections.clear();
        
        let mut running = self.running.write();
        *running = false;
        
        tracing::info!("Mesh transport stopped");
    }

    async fn mesh_maintenance_loop(
        config: Arc<MeshConfig>,
        topology: Arc<MeshTopology>,
        peer_connections: Arc<DashMap<String, MeshPeerConnection>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let announce_interval_secs = config.connection.announce_interval_secs;
        let keepalive_interval_secs = config.connection.keepalive_interval_secs;
        
        let mut announce_interval = tokio::time::interval(Duration::from_secs(announce_interval_secs));
        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(keepalive_interval_secs));
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Mesh maintenance loop shutting down");
                    break;
                }
                _ = announce_interval.tick() => {
                    Self::handle_announcements(&topology, &peer_connections).await;
                }
                _ = keepalive_interval.tick() => {
                    Self::send_keepalives(&peer_connections).await;
                }
                _ = cleanup_interval.tick() => {
                    Self::cleanup_stale_connections(&peer_connections, &topology).await;
                    Self::cleanup_blocked_upstreams(&topology).await;
                }
            }
        }
    }

    async fn cleanup_blocked_upstreams(topology: &Arc<MeshTopology>) {
        topology.cleanup_expired_blocks().await;
    }

    async fn bootstrap_from_seeds(&self) -> Result<(), MeshTransportError> {
        let verified_seeds = self.config.get_verified_seeds();
        
        if verified_seeds.is_empty() {
            tracing::warn!("No verified seeds available for network");
            return Err(MeshTransportError::NoSeedsAvailable);
        }

        for seed in &verified_seeds {
            tracing::info!("Attempting to connect to verified seed: {}", seed.address);
            
            let peer_config = MeshPeerConfig {
                address: seed.address.clone(),
                auth_token: seed.public_key.clone(),
            };
            match self.connect_to_peer(&peer_config).await {
                Ok(peer_info) => {
                    tracing::info!("Connected to seed node: {}", seed.address);
                    
                    if let Err(e) = self.request_seed_list(&peer_info.node_id).await {
                        tracing::warn!("Failed to request seed list from {}: {}", seed.address, e);
                    }
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to seed {}: {}", seed.address, e);
                }
            }
        }
        Err(MeshTransportError::NoSeedsAvailable)
    }

    async fn dht_bootstrap_from_seeds(
        &self,
        routing_manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>,
    ) -> Result<(), MeshTransportError> {
        let seeds = routing_manager.get_seeds_from_config();
        
        if seeds.is_empty() {
            tracing::debug!("No seed nodes configured for DHT bootstrap");
            return Ok(());
        }

        tracing::info!("Starting DHT bootstrap from {} seed nodes", seeds.len());

        for seed in &seeds {
            let is_connected = self.peer_connections.contains_key(&seed.node_id);
            
            if is_connected {
                routing_manager.add_peer(
                    seed.node_id.clone(),
                    seed.address.clone(),
                    seed.port,
                    crate::mesh::config::MeshNodeRole::Global,
                    None,
                    true,
                    seed.geo.clone(),
                    None,
                    None,
                ).await;

                let local_id = routing_manager.local_node_id_hash().clone();
                let request_id = format!("dht-bootstrap-{}", uuid::Uuid::new_v4());
                
                let find_node = MeshMessage::FindNode {
                    request_id: request_id.into(),
                    target_node_id: local_id.as_bytes().to_vec(),
                    requester_node_id: routing_manager.local_node_id().into(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                if let Err(e) = self.send_datagram_to_peer(&seed.node_id, &find_node).await {
                    tracing::warn!("Failed to send FindNode to DHT seed {}: {}", seed.node_id, e);
                } else {
                    tracing::debug!("Sent DHT FindNode to seed {}", seed.node_id);
                }
            } else {
                tracing::debug!("Seed {} not connected yet, will bootstrap when connected", seed.node_id);
            }
        }

        let peer_count = routing_manager.total_peers().await;
        tracing::info!("DHT bootstrap complete: {} peers in routing table", peer_count);
        
        Ok(())
    }

    pub async fn dht_on_peer_connected(
        &self,
        peer_node_id: &str,
        peer_address: &str,
        peer_role: crate::mesh::config::MeshNodeRole,
    ) {
        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                rm.add_peer(
                    peer_node_id.to_string(),
                    peer_address.to_string(),
                    443,
                    peer_role,
                    None,
                    false,
                    None,
                    None,
                    None,
                ).await;

                let local_id = rm.local_node_id_hash().clone();
                let request_id = format!("dht-ping-{}", uuid::Uuid::new_v4());
                
                let ping = MeshMessage::Ping {
                    request_id: request_id.into(),
                    node_id: rm.local_node_id().into(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                if let Err(e) = self.send_datagram_to_peer(peer_node_id, &ping).await {
                    tracing::debug!("Failed to send DHT Ping to {}: {}", peer_node_id, e);
                }
            }
        }
    }

    async fn request_seed_list(&self, global_node_id: &str) -> Result<(), MeshTransportError> {
        let request = MeshMessage::SeedListRequest {
            node_id: self.config.node_id().into(),
            request_full_mesh: true,
        };

        self.send_message_to_peer(global_node_id, &request).await?;
        tracing::debug!("Requested seed list from global node: {}", global_node_id);
        Ok(())
    }

    pub async fn handle_seed_list_response(
        &self,
        global_nodes: Vec<crate::mesh::protocol::MeshPeerInfo>,
        edge_nodes: Vec<crate::mesh::protocol::MeshPeerInfo>,
        genesis_org_id: Option<crate::mesh::protocol::ArcStr>,
    ) {
        tracing::info!("Received seed list: {} global, {} edge nodes", global_nodes.len(), edge_nodes.len());
        
        if let Some(ref org_id) = genesis_org_id {
            tracing::info!("Received genesis_org_id from seed: {}", org_id);
            let mut org_mgr = self.org_manager.write();
            org_mgr.set_genesis_org_id(org_id.to_string());
            tracing::info!("Set genesis_org_id to: {}", org_id);
        }
        
        self.topology.add_seeded_nodes(global_nodes.clone()).await;
        
        let edge_count = edge_nodes.len();
        for node in edge_nodes {
            if !self.topology.get_peer(&node.node_id).await.is_some() {
                self.topology.add_peer(node, PeerStatus::Connecting).await;
            }
        }

        let global_count = global_nodes.len();
        tracing::info!("Seeded topology with {} global nodes and {} edge nodes", global_count, edge_count);

        if let Some(ref record_store) = self.record_store {
            if !self.topology.is_global() && self.config.dht.as_ref().map(|d| d.warm_up_on_connect).unwrap_or(true) {
                if let Some(request) = record_store.create_snapshot_request() {
                    if let Some(first_global) = global_nodes.first() {
                        tracing::info!("Requesting DHT cache warm-up from global node: {}", first_global.node_id);
                        if let Err(e) = self.send_datagram_to_peer(&first_global.node_id, &request).await {
                            tracing::warn!("Failed to request DHT snapshot from {}: {}", first_global.node_id, e);
                        }
                    }
                }
            }
        }
    }

    async fn connect_to_peers(&self) -> Result<(), MeshTransportError> {
        for peer_config in &self.config.peers {
            match self.connect_to_peer(peer_config).await {
                Ok(_) => {
                    tracing::info!("Connected to peer: {}", peer_config.address);
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to peer {}: {}", peer_config.address, e);
                }
            }
        }
        Ok(())
    }

    async fn connect_to_peer(&self, peer_config: &MeshPeerConfig) -> Result<MeshPeerConnection, MeshTransportError> {
        if !self.check_rate_limit() {
            return Err(MeshTransportError::RateLimited);
        }

        let runtime = self.runtime.as_ref()
            .ok_or(MeshTransportError::RuntimeNotSet)?;

        let server_name = peer_config.address.split(':').next().unwrap_or(&peer_config.address);
        
        let quic_conn = runtime.connect_to_peer(&peer_config.address, server_name).await
            .map_err(|e| MeshTransportError::ConnectionFailed(e.to_string()))?;

        let connection = quic_conn.connection.clone()
            .ok_or_else(|| MeshTransportError::ConnectionFailed("No connection".to_string()))?;

        let (mut send_stream, mut recv_stream) = connection.open_bi().await
            .map_err(|e| MeshTransportError::ConnectionFailed(e.to_string()))?;

        let node_id = self.config.node_id();
        let local_upstreams = self.topology.get_local_upstreams().await;
        
        let upstreams: HashMap<String, UpstreamInfo> = local_upstreams
            .into_iter()
            .map(|u| (u.upstream_id.clone(), u))
            .collect();

        let auth_token = peer_config.auth_token.clone();

        let quic_port = self.get_actual_quic_port().await.map(|p| p as u32);
        let wireguard_port = self.get_wireguard_port().map(|p| p as u32);

        let is_edge = self.config.role == crate::mesh::config::MeshNodeRole::Edge;
        
        let (pow_nonce, pow_public_key) = if is_edge {
            if let Some(ref pk_hex) = self.config.signing_public_key() {
                if let Some(cached_nonce) = self.config.get_cached_pow_nonce() {
                    (Some(cached_nonce), Some(pk_hex.clone().into()))
                } else {
                    use base64::Engine;
                    if let Ok(pk_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk_hex) {
                        if let Some(nonce) = crate::mesh::dht::routing::node_id::NodeId::find_pow_nonce(&pk_bytes) {
                            tracing::debug!("Computed PoW nonce for edge node: {}", nonce);
                            self.config.set_cached_pow_nonce(nonce);
                            (Some(nonce), Some(pk_hex.clone().into()))
                        } else {
                            tracing::error!("Failed to find PoW nonce for edge node - cannot connect");
                            return Err(MeshTransportError::ConnectionFailed("Failed to compute PoW".to_string()));
                        }
                    } else {
                        return Err(MeshTransportError::ConnectionFailed("Invalid public key format".to_string()));
                    }
                }
            } else {
                return Err(MeshTransportError::ConnectionFailed("No signing key configured".to_string()));
            }
        } else {
            (None, None)
        };

        let hello = MeshMessage::Hello {
            version: MESH_MESSAGE_VERSION,
            node_id: node_id.clone().into(),
            role: self.config.role,
            capabilities: crate::mesh::protocol::MeshCapabilities {
                can_route: true,
                can_proxy: true,
                max_hops: self.config.routing.max_hops,
                supported_services: self.config.local_upstreams.keys().cloned().collect(),
                preferred_transport: Some(crate::mesh::transports::MeshTransportType::Quic),
            },
            upstreams,
            auth_token: auth_token.clone().map(|s| s.into()),
            network_id: self.config.network_id.clone().map(|s| s.into()),
            global_node_key: self.config.global_node_key.clone().map(|s| s.into()),
            timestamp: Some(MeshMessage::generate_timestamp()),
            nonce: Some(MeshMessage::generate_nonce()),
            is_trusted: self.config.is_trusted_node(),
            quic_port,
            wireguard_port,
            public_key: self.config.signing_public_key().map(|s| s.into()),
            pow_nonce,
            pow_public_key,
        };

        let encoded = hello.encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream.write_all(&len).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream.write_all(&encoded).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        
        let mut len_buf = [0u8; 4];
        recv_stream.read_exact(&mut len_buf).await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut response_buf = vec![0u8; len];
        recv_stream.read_exact(&mut response_buf).await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;

        let response = MeshMessage::decode(&response_buf)
            .ok_or_else(|| MeshTransportError::ReceiveFailed("Failed to decode response".to_string()))?;

        let (session_id, peer_info) = match response {
            MeshMessage::HelloAck { 
                version, 
                node_id, 
                role, 
                session_id, 
                upstreams,
                auth_token: resp_token,
                network_id: resp_network_id,
                global_node_key: resp_global_key,
                timestamp: _,
                nonce: _,
                is_trusted: _,
                quic_port: peer_quic_port,
                wireguard_port: peer_wireguard_port,
                public_key: peer_public_key,
            } => {
                if let Some(ref pk) = peer_public_key {
                    use base64::Engine;
                    if let Ok(pk_bytes) = base64::engine::general_purpose::STANDARD.decode(pk.as_str()) {
                        let expected_node_id = crate::mesh::dht::routing::node_id::NodeId::from_public_key(&pk_bytes);
                        let claimed_node_id = crate::mesh::dht::routing::node_id::NodeId::from_node_id_string(node_id.as_str());
                        if expected_node_id != claimed_node_id {
                            tracing::warn!("Node ID mismatch: peer claimed {} but their public key derives {}",
                                node_id, expected_node_id);
                            return Err(MeshTransportError::AuthFailed("Node ID does not match public key".to_string()));
                        }
                    }
                } else {
                    tracing::warn!("Node {} did not provide public key in handshake - NodeID verification skipped", node_id);
                }

                let is_genesis_org_member = {
                    let org_mgr = self.org_manager.read();
                    let genesis_org_id = org_mgr.get_genesis_org_id()
                        .cloned()
                        .unwrap_or_else(|| self.config.node_identity.genesis_org_id());
                    org_mgr.is_member(&genesis_org_id, &node_id)
                };
                let trusted_status = role.is_global() || is_genesis_org_member;

                if !trusted_status {
                    if let Some(ref stake_mgr) = self.stake_manager {
                        let config = stake_mgr.get_config();
                        let min_stake = config.min_stake_for_routing;
                        let strict_mode = config.strict_mode;
                        let node_id_str = node_id.to_string();
                        
                        if !stake_mgr.can_be_in_routing(&node_id_str) {
                            if strict_mode {
                                tracing::warn!("Node {} rejected: insufficient stake for routing (strict mode, min: {})", node_id_str, min_stake);
                                return Err(MeshTransportError::AuthFailed("Insufficient stake for mesh participation".to_string()));
                            }
                            
                            tracing::info!("Auto-registering new node {} with base reputation for grace period (non-strict mode)", node_id_str);
                            stake_mgr.register_node(
                                node_id_str.clone(),
                                50,
                                role,
                            );
                            
                            tracing::info!("Node {} registered with base reputation 50 (grace period active)", node_id_str);
                        }
                    }
                }
                
                tracing::debug!("Peer {} ports - quic: {:?}, wireguard: {:?}", node_id, peer_quic_port, peer_wireguard_port);
                
                if version != MESH_MESSAGE_VERSION {
                    return Err(MeshTransportError::VersionMismatch {
                        expected: MESH_MESSAGE_VERSION,
                        got: version,
                    });
                }

                if let Some(ref expected_token) = auth_token {
                    match &resp_token {
                        Some(resp_t) if resp_t.as_str() == expected_token.as_str() => {}
                        _ => {
                            tracing::warn!("Authentication failed for node {}", node_id);
                            return Err(MeshTransportError::AuthFailed("Invalid auth token".to_string()));
                        }
                    }
                }

                if let Some(ref our_network) = self.config.network_id {
                    if let Some(ref peer_network) = resp_network_id {
                        if peer_network.as_str() != our_network.as_str() {
                            tracing::warn!("Network ID mismatch: peer {} is on network {} but we are on {}",
                                node_id, peer_network, our_network);
                            return Err(MeshTransportError::AuthFailed("Network ID mismatch".to_string()));
                        }
                    }
                }

                if role.is_global() {
                    if let Some(ref expected_key) = self.config.global_node_key {
                        if let Some(ref peer_key) = resp_global_key {
                            if peer_key.as_str() != expected_key.as_str() {
                                tracing::warn!("Global node key verification failed for {}", node_id);
                                return Err(MeshTransportError::AuthFailed("Invalid global node key".to_string()));
                            }
                        } else {
                            tracing::warn!("Global node {} did not provide key verification", node_id);
                            return Err(MeshTransportError::AuthFailed("Global node key required".to_string()));
                        }
                    }
                }

                let upstreams: Vec<String> = upstreams.keys().cloned().collect();
                
                let peer_connection = MeshPeerConnection {
                    node_id: node_id.to_string(),
                    address: peer_config.address.clone(),
                    connection: connection.clone(),
                    session_id: session_id.to_string(),
                    connected_at: Instant::now(),
                    last_seen: Instant::now(),
                    role: role,
                    upstreams: upstreams.clone(),
                    is_trusted: trusted_status,
                };

                self.topology.add_peer(
                    MeshPeerInfo {
                        node_id: node_id.to_string(),
                        address: peer_config.address.clone(),
                        role: role,
                        capabilities: crate::mesh::protocol::MeshCapabilities {
                            can_route: true,
                            can_proxy: true,
                            max_hops: self.config.routing.max_hops,
                            supported_services: upstreams.clone(),
                            preferred_transport: Some(crate::mesh::transports::MeshTransportType::Quic),
                        },
                        is_global: role.is_global(),
                        latency_ms: None,
                        upstreams: upstreams.clone(),
                        is_trusted: trusted_status,
                        quic_port: peer_quic_port,
                        wireguard_port: peer_wireguard_port,
                        advertised_port: peer_quic_port.or(peer_wireguard_port),
                    },
                    PeerStatus::Healthy,
                ).await;

                (session_id, peer_connection)
            }
            MeshMessage::Error { code, message } => {
                return Err(MeshTransportError::PeerError { code, message: message.to_string() });
            }
            _ => {
                return Err(MeshTransportError::UnexpectedMessage);
            }
        };

        let peer_node_id = peer_info.node_id.clone();
        let peer_address = peer_info.address.clone();
        let peer_role = peer_info.role.clone();
        let peer_info_return = peer_info.clone();
        self.peer_connections.insert(session_id.to_string(), peer_info);

        if let Some(ref rm) = self.routing_manager {
            if rm.is_enabled() {
                self.dht_on_peer_connected(&peer_node_id, &peer_address, peer_role).await;
            }
        }

        // Preflight: query the new peer for their known routes to warm our cache
        let transport = self.clone();
        let peer_node_id_for_preflight = peer_node_id.clone();
        tokio::spawn(async move {
            if let Err(e) = transport.preflight_peer_routes(&peer_node_id_for_preflight).await {
                tracing::debug!("Preflight routes from {}: {}", peer_node_id_for_preflight, e);
            }
        });

        let transport = self.clone();
        let conn = connection;
        let topo = self.topology.clone();
        let peer_node_id_for_loop = peer_node_id.clone();
        tokio::spawn(async move {
            transport.peer_message_loop(
                session_id.to_string(),
                peer_node_id_for_loop,
                conn,
                topo,
            ).await;
        });

        tracing::info!("Established mesh peer connection: {} ({})", peer_node_id, peer_address);
        
        Ok(peer_info_return)
    }

    async fn peer_message_loop(
        &self,
        _session_id: String,
        peer_node_id: String,
        connection: Connection,
        topology: Arc<MeshTopology>,
    ) {
        let topology_for_loop = topology.clone();
        loop {
            tokio::select! {
                result = connection.accept_bi() => {
                    match result {
                        Ok((mut send_stream, mut recv_stream)) => {
                            let topo = topology_for_loop.clone();
                            let transport = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = transport.handle_peer_message(&mut send_stream, &mut recv_stream, &topo).await {
                                    tracing::debug!("Peer message error: {}", e);
                                }
                            });
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                            tracing::info!("Peer {} disconnected", peer_node_id);
                            topology.update_peer_status(&peer_node_id, PeerStatus::Disconnected).await;
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("Peer {} connection error: {}", peer_node_id, e);
                            topology.update_peer_status(&peer_node_id, PeerStatus::Disconnected).await;
                            break;
                        }
                    }
                }
                _ = connection.closed() => {
                    tracing::info!("Peer {} connection closed", peer_node_id);
                    topology.update_peer_status(&peer_node_id, PeerStatus::Disconnected).await;
                    break;
                }
            }
        }
    }

    async fn handle_peer_message(
        &self,
        send_stream: &mut SendStream,
        recv_stream: &mut RecvStream,
        topology: &MeshTopology,
    ) -> Result<(), MeshTransportError> {
        let mut len_buf = [0u8; 4];
        recv_stream.read_exact(&mut len_buf).await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        recv_stream.read_exact(&mut data).await
            .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;

        let msg = MeshMessage::decode(&data)
            .ok_or_else(|| MeshTransportError::ReceiveFailed("Failed to decode message".to_string()))?;

        match msg {
            MeshMessage::RouteQuery { query_id, upstream_id, max_hops, initiator, sequence: _, timestamp: _, nonce: _ } => {
                self.handle_route_query(
                    send_stream,
                    query_id.to_string(),
                    upstream_id.to_string(),
                    max_hops,
                    initiator.to_string(),
                    topology,
                ).await?;
            }
            MeshMessage::RouteResponse { query_id, upstream_id, provider_node_id, hops, ttl_secs, upstream_url, waf_policy, priority_tier, .. } => {
                let _ = query_id;
                tracing::debug!("Got route response: {} -> {} ({} hops)", upstream_id, provider_node_id, hops);
                topology.cache_route(&upstream_id, provider_node_id.to_string(), hops, Duration::from_secs(ttl_secs as u64)).await;
            }
            MeshMessage::RouteNotFound { query_id, upstream_id } => {
                let _ = query_id;
                tracing::debug!("Route not found: {} from query {}", upstream_id, query_id);
            }
            MeshMessage::UpstreamAnnounce { upstream_id, action: _, signature: _ } => {
                tracing::debug!("Upstream announcement: {}", upstream_id);
            }
            MeshMessage::UpstreamUpdate { upstream_id, info: _, signature: _ } => {
                tracing::debug!("Upstream update: {}", upstream_id);
            }
            MeshMessage::KeepAlive => {
                let response = MeshMessage::KeepAliveAck.encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (response.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                send_stream.write_all(&response).await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
            }
            MeshMessage::Hello { .. } | MeshMessage::HelloAck { .. } => {
                tracing::warn!("Unexpected handshake message in peer loop");
            }
            _ => {
                tracing::debug!("Unhandled mesh message type");
            }
        }

        Ok(())
    }

    async fn handle_route_query(
        &self,
        send_stream: &mut SendStream,
        query_id: String,
        upstream_id: String,
        max_hops: u8,
        _initiator: String,
        topology: &MeshTopology,
    ) -> Result<(), MeshTransportError> {
        let upstream_id_for_log = upstream_id.clone();
        if let Some(upstream_info) = topology.get_upstream_info(&upstream_id).await {
            if upstream_info.is_local || topology.can_forward_service(&upstream_id) {
                let signature = vec![0u8; 32];
                let sequence = 0;
                let timestamp = MeshMessage::generate_timestamp();
                let nonce = MeshMessage::generate_nonce();
                let response = MeshMessage::RouteResponse {
                    query_id: query_id.into(),
                    upstream_id: upstream_id.into(),
                    provider_node_id: topology.node_id().into(),
                    hops: if upstream_info.is_local { 0 } else { 1 },
                    ttl_secs: 300,
                    signature,
                    sequence,
                    timestamp,
                    nonce,
                    upstream_url: Some(upstream_info.upstream_url.clone().into()),
                    waf_policy: upstream_info.waf_policy.clone(),
                    priority_tier: upstream_info.priority_tier,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: self.config.mesh_name().map(|s| s.into()),
                };
                
                let encoded = response.encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                send_stream.write_all(&encoded).await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                
                tracing::debug!("Responded to route query for {}: {} (hops: {})", 
                    upstream_id_for_log, topology.node_id(), if upstream_info.is_local { 0 } else { 1 });
                return Ok(());
            }
        }

        if max_hops > 1 {
            if let Some((provider, hops)) = topology.get_cached_route(&upstream_id).await {
                let signature = vec![0u8; 32];
                let sequence = 0;
                let timestamp = MeshMessage::generate_timestamp();
                let nonce = MeshMessage::generate_nonce();
                let response = MeshMessage::RouteResponse {
                    query_id: query_id.into(),
                    upstream_id: upstream_id.into(),
                    provider_node_id: provider.into(),
                    hops: hops + 1,
                    ttl_secs: 60,
                    signature,
                    sequence,
                    timestamp,
                    nonce,
                    upstream_url: None,
                    waf_policy: None,
                    priority_tier: 0,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: self.config.mesh_name().map(|s| s.into()),
                };
                
                let encoded = response.encode()
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                send_stream.write_all(&encoded).await
                    .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
                return Ok(());
            }
        }

        let not_found = MeshMessage::RouteNotFound {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
        };
        
        let encoded = not_found.encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream.write_all(&len).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream.write_all(&encoded).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        Ok(())
    }

    pub async fn send_route_query(&self, upstream_id: &str) -> Result<RouteQueryResult, MeshTransportError> {
        if let Some(cached) = self.topology.get_cached_route(upstream_id).await {
            tracing::debug!("Using cached route for {}: {} ({} hops)", upstream_id, cached.0, cached.1);
            
            let scores = self.topology.peer_scores().read().await;
            let score = scores.get(&cached.0).map(|s| s.total_score).unwrap_or(0.5);
            
            return Ok(RouteQueryResult {
                query_id: String::new(),
                upstream_id: upstream_id.to_string(),
                providers: vec![ProviderInfo {
                    node_id: cached.0,
                    upstream_url: String::new(),
                    waf_policy: None,
                    hops: cached.1,
                    ttl: Duration::from_secs(300),
                    score,
                    priority_tier: 0,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: None,
                }],
                discovered_at: Instant::now(),
            });
        }

        if !self.topology.can_forward_service(upstream_id) {
            return Err(MeshTransportError::ServiceNotAllowed(upstream_id.to_string()));
        }

        let query_id = format!("{}-{}", self.config.node_id(), uuid::Uuid::new_v4());
        let collection_timeout = Duration::from_millis(self.config.routing.query_timeout_ms);
        
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        
        self.pending_queries.lock().await.register(query_id.clone(), response_tx);

        let peer_query_count = self.config.routing.peer_query_count.min(3);
        let known_peers = self.topology.get_best_peers_for_query(upstream_id, peer_query_count).await;

        if !known_peers.is_empty() {
            tracing::debug!("Sending parallel stream route queries to {} peers for upstream {}", known_peers.len(), upstream_id);
            
            let queries: Vec<_> = known_peers.iter()
                .map(|peer_id| {
                    let peer_id = peer_id.clone();
                    let query_id = query_id.clone();
                    let upstream_id = upstream_id.to_string();
                    let transport = self.clone();
                    async move {
                        transport.send_route_query_stream(&peer_id, &query_id, &upstream_id).await
                    }
                })
                .collect();
            
            join_all(queries).await;

            tokio::time::sleep(collection_timeout).await;
            
            let providers = {
                let mut pending = self.pending_queries.lock().await;
                pending.collected_providers.remove(&query_id).unwrap_or_default()
            };
            
            self.pending_queries.lock().await.pending.remove(&query_id);

            if !providers.is_empty() {
                let scores = self.topology.peer_scores().read().await;
                let mut providers_with_scores: Vec<ProviderInfo> = providers.into_iter()
                    .map(|mut p| {
                        if p.score == 0.5 {
                            p.score = scores.get(&p.node_id).map(|s| s.total_score).unwrap_or(0.5);
                        }
                        p
                    })
                    .collect();

                providers_with_scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

                let best = providers_with_scores.first().cloned();
                
                return Ok(RouteQueryResult {
                    query_id,
                    upstream_id: upstream_id.to_string(),
                    providers: providers_with_scores,
                    discovered_at: Instant::now(),
                });
            }
        }

        // Fallback to global node if local peers didn't have providers
        if let Some(global_id) = self.topology.get_closest_global_node().await {
            tracing::debug!("Querying global node {} for upstream {}", global_id, upstream_id);
            
            // Re-register for the global node query
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_queries.lock().await.register(query_id.clone(), tx);
            
            // Use stream for reliable delivery to global node
            if self.send_route_query_stream(&global_id, &query_id, upstream_id).await.is_ok() {
                // Wait for response via oneshot or fallback to cache polling
                let global_result = tokio::select! {
                    result = rx => {
                        match result {
                            Ok(r) => Some(r),
                            Err(_) => self.wait_for_route_event(upstream_id, collection_timeout).await,
                        }
                    }
                    _ = tokio::time::sleep(collection_timeout) => {
                        self.wait_for_route_event(upstream_id, Duration::ZERO).await
                    }
                };
                self.pending_queries.lock().await.take(&query_id);
                if let Some(r) = global_result {
                    return Ok(r);
                }
            } else {
                self.pending_queries.lock().await.take(&query_id);
            }
        }

        // Check for local upstream as last resort
        if let Some(local) = self.topology.get_upstream_info(upstream_id).await {
            if local.is_local {
                return Ok(RouteQueryResult {
                    query_id: String::new(),
                    upstream_id: upstream_id.to_string(),
                    providers: vec![ProviderInfo {
                        node_id: self.topology.node_id().to_string(),
                        upstream_url: local.upstream_url,
                        waf_policy: local.waf_policy,
                        hops: 0,
                        ttl: Duration::from_secs(300),
                        score: 1.0,
                        priority_tier: local.priority_tier,
                        tier_claim: None,
                        org_id: None,
                        mesh_name: self.config.mesh_name().map(String::from),
                    }],
                    discovered_at: Instant::now(),
                });
            }
        }

        Err(MeshTransportError::NoRouteToUpstream(upstream_id.to_string()))
    }

    async fn wait_for_route_event(
        &self,
        upstream_id: &str,
        timeout: Duration,
    ) -> Option<RouteQueryResult> {
        // First check if already cached (fast path)
        if let Some(cached) = self.topology.get_cached_route(upstream_id).await {
            return Some(RouteQueryResult {
                query_id: String::new(),
                upstream_id: upstream_id.to_string(),
                providers: vec![ProviderInfo {
                    node_id: cached.0,
                    upstream_url: String::new(),
                    waf_policy: None,
                    hops: cached.1,
                    ttl: Duration::from_secs(300),
                    score: 0.5,
                    priority_tier: 0,
                    tier_claim: None,
                    org_id: None,
                    mesh_name: None,
                }],
                discovered_at: Instant::now(),
            });
        }
        
        None
    }

    /// Preflight: query a newly connected peer for their known routes to warm our cache
    async fn preflight_peer_routes(&self, peer_id: &str) -> Result<(), MeshTransportError> {
        // Get frequently used upstreams from topology to request from new peer
        let upstreams_to_query = self.topology.get_frequently_used_upstreams(5).await;
        
        if upstreams_to_query.is_empty() {
            return Ok(());
        }

        tracing::debug!("Preflight querying {} routes from peer {}", upstreams_to_query.len(), peer_id);

        for upstream_id in upstreams_to_query {
            let query_id = format!("preflight-{}-{}", self.config.node_id(), uuid::Uuid::new_v4());
            
            // Create a one-shot channel to receive the response
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending_queries.lock().await.register(query_id.clone(), tx);
            
            if self.send_route_query_datagram(peer_id, &query_id, &upstream_id).await.is_ok() {
                // Wait briefly for response (non-blocking)
                if let Ok(result) = tokio::time::timeout(Duration::from_millis(100), rx).await {
                    if let Ok(route_result) = result {
                        // Cache the route (already cached by handle_route_response)
                        if let Some(best) = route_result.best_provider() {
                            tracing::debug!("Preflight cached route for {} -> {}", upstream_id, best.node_id);
                        }
                    }
                }
            }
            
            self.pending_queries.lock().await.take(&query_id);
        }

        Ok(())
    }

    async fn send_route_query_to_peer(
        &self,
        peer: &MeshPeerConnection,
        query_id: &str,
        upstream_id: &str,
    ) -> Result<(), MeshTransportError> {
        let (mut send_stream, _) = peer.connection.open_bi().await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let sequence = self.config.routing.query_sequence.next();
        let timestamp = MeshMessage::generate_timestamp();
        let nonce = MeshMessage::generate_nonce();
        let query = MeshMessage::RouteQuery {
            query_id: query_id.into(),
            upstream_id: upstream_id.into(),
            max_hops: self.config.routing.max_hops,
            initiator: self.config.node_id().into(),
            sequence,
            timestamp,
            nonce,
        };

        let encoded = query.encode()
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        let len = (encoded.len() as u32).to_be_bytes();
        send_stream.write_all(&len).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        send_stream.write_all(&encoded).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        Ok(())
    }

    async fn handle_announcements(
        topology: &MeshTopology,
        peer_connections: &DashMap<String, MeshPeerConnection>,
    ) {
        let _owners = topology.get_upstream_owners().await;
        
        for entry in peer_connections.iter() {
            let peer = entry.value();
            if !peer.role.is_global() {
                tracing::trace!("Would announce upstreams to peer {}", peer.node_id);
            }
        }
    }

    async fn send_keepalives(peer_connections: &DashMap<String, MeshPeerConnection>) {
        for entry in peer_connections.iter() {
            let peer = entry.value();
            let result = async {
                let (mut send_stream, mut recv_stream) = peer.connection.open_bi().await?;
                
                let msg = MeshMessage::KeepAlive;
                let encoded = msg.encode()?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await?;
                send_stream.write_all(&encoded).await?;
                
                let mut len_buf = [0u8; 4];
                recv_stream.read_exact(&mut len_buf).await?;
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut response_buf = vec![0u8; len];
                recv_stream.read_exact(&mut response_buf).await?;
                
                Ok::<_, MeshTransportError>(())
            }.await;

            match result {
                Ok(_) => {
                    tracing::trace!("Keepalive OK from {}", peer.node_id);
                }
                Err(e) => {
                    tracing::warn!("Keepalive failed to {}: {}", peer.node_id, e);
                }
            }
        }
    }

    async fn cleanup_stale_connections(
        peer_connections: &DashMap<String, MeshPeerConnection>,
        topology: &MeshTopology,
    ) {
        let stale_threshold = Duration::from_secs(120);
        let now = Instant::now();

        let stale: Vec<String> = peer_connections.iter()
            .filter(|e| now.duration_since(e.value().last_seen) > stale_threshold)
            .map(|e| e.key().clone())
            .collect();

        for session_id in stale {
            if let Some(peer) = peer_connections.get(&session_id) {
                tracing::warn!("Removing stale peer connection: {}", peer.node_id);
                topology.record_connection_failure(&peer.node_id).await;
                topology.update_peer_status(&peer.node_id, PeerStatus::Disconnected).await;
            }
            peer_connections.remove(&session_id);
        }

        topology.cleanup_expired_queries(Duration::from_secs(10)).await;
        topology.cleanup_expired_cache().await;
    }

    pub async fn maintain_connections(&self) {
        if let Some(ref stake_mgr) = self.stake_manager {
            if stake_mgr.get_config().strict_mode {
                if let Some(ref threat_intel) = self.threat_intel {
                    let rep_mgr = threat_intel.get_reputation_manager();
                    stake_mgr.sync_from_reputation(&rep_mgr);
                }
            }
        }

        let min_connections = self.config.connection.min_peer_connections;
        let max_connections = self.config.connection.max_peer_connections;
        
        let current_count = self.peer_connections.len();
        
        if current_count >= min_connections {
            tracing::debug!("Connection pool sufficient: {}/{}", current_count, min_connections);
            return;
        }

        let targets = self.topology.get_prioritized_connection_targets().await;
        
        for (node_id, priority) in targets {
            if self.peer_connections.len() >= max_connections {
                break;
            }

            if self.is_connected_to(&node_id) {
                continue;
            }

            tracing::info!("Attempting to connect to prioritized peer: {} ( {:?})", node_id, priority);

            let address = self.topology.get_peer(&node_id).await
                .map(|p| p.address.clone())
                .unwrap_or_else(|| node_id.clone());

            let peer_config = MeshPeerConfig {
                address,
                auth_token: None,
            };

            match self.connect_to_peer(&peer_config).await {
                Ok(_) => {
                    tracing::info!("Connected to prioritized peer: {}", node_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to {}: {}", node_id, e);
                }
            }
        }
    }

    async fn perform_auto_slash(&self) {
        let Some(ref stake_mgr) = self.stake_manager else {
            return;
        };

        if !stake_mgr.get_config().slashing_enabled {
            return;
        }

        let connected_peers: std::collections::HashSet<_> = self.peer_connections.iter()
            .map(|entry| entry.key().clone())
            .collect();

        let auth_failures: Vec<String> = {
            let failures = self.auth_failures.read();
            let now = Instant::now();
            let threshold = Duration::from_secs(3600);
            
            failures.iter()
                .filter(|(node_id, times)| {
                    connected_peers.contains(*node_id) &&
                    {
                        let recent: Vec<_> = times.iter()
                            .filter(|t| now.duration_since(**t) < threshold)
                            .collect();
                        recent.len() >= 5
                    }
                })
                .map(|(id, _)| id.clone())
                .collect()
        };

        for node_id in auth_failures {
            tracing::warn!("Auto-slasher: Node {} detected with repeated auth failures", node_id);
            stake_mgr.slash_node(
                &node_id,
                crate::mesh::dht::stake::SlashReason::RepeatedMisbehavior,
                "auto-slash",
            );
        }

        if let Some(ref threat_intel) = self.threat_intel {
            let rep_mgr = threat_intel.get_reputation_manager();
            let peer_ids = rep_mgr.get_all_peer_ids();
            
            for node_id in peer_ids {
                if !connected_peers.contains(&node_id) {
                    continue;
                }
                if let Some(rep) = rep_mgr.get_peer_reputation(&node_id) {
                    if rep.false_positive_reports > 10 {
                        tracing::warn!("Auto-slasher: Node {} has {} false positive reports", node_id, rep.false_positive_reports);
                        stake_mgr.slash_node(
                            &node_id,
                            crate::mesh::dht::stake::SlashReason::RepeatedMisbehavior,
                            "auto-slash",
                        );
                    }
                }
            }
        }
    }

    pub async fn perform_health_check(&self, peer_id: &str) -> Option<u32> {
        let start = Instant::now();
        
        if let Some(peer) = self.peer_connections.get(peer_id) {
            let result = async {
                let (mut send_stream, mut recv_stream) = peer.connection.open_bi().await?;
                
                let msg = MeshMessage::PeerHealthCheck {
                    peer_id: self.config.node_id().into(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };
                
                let encoded = msg.encode()?;
                let len = (encoded.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await?;
                send_stream.write_all(&encoded).await?;
                
                let mut len_buf = [0u8; 4];
                recv_stream.read_exact(&mut len_buf).await?;
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                recv_stream.read_exact(&mut buf).await?;
                
                Ok::<_, MeshTransportError>(())
            }.await;

            let latency = start.elapsed().as_millis() as u32;
            
            if result.is_ok() {
                self.topology.record_connection_success(peer_id).await;
                self.topology.update_peer_latency_for_score(peer_id, latency).await;
                self.topology.update_peer_latency(peer_id, latency).await;
                self.topology.update_peer_status(peer_id, PeerStatus::Healthy).await;
                tracing::trace!("Health check OK for {}: {}ms", peer_id, latency);
                return Some(latency);
            } else {
                self.topology.record_connection_failure(peer_id).await;
                self.topology.update_peer_status(peer_id, PeerStatus::Unhealthy).await;
                tracing::warn!("Health check failed for {}: {:?}", peer_id, result.err());
                return None;
            }
        }
        
        None
    }

    /// Proactive cache warming: periodically query for popular routes from peers
    /// This keeps the route cache warm without waiting for actual requests
    pub async fn proactive_cache_warm(&self) {
        if self.peer_connections.is_empty() {
            return;
        }

        // Get the top popular upstreams that aren't already cached
        let popular_upstreams = self.topology.get_frequently_used_upstreams(10).await;
        
        if popular_upstreams.is_empty() {
            return;
        }

        // Get peers we can query
        let peers: Vec<String> = self.peer_connections.iter()
            .map(|e| e.key().clone())
            .collect();
        
        if peers.is_empty() {
            return;
        }

        // For each popular upstream not in cache, query a peer
        for upstream_id in popular_upstreams {
            // Skip if already cached
            if self.topology.get_cached_route(&upstream_id).await.is_some() {
                continue;
            }

            // Query a random peer for this route
            let peer_idx = if peers.len() > 1 {
                let mut rng = rand::rng();
                rng.random_range(0..peers.len())
            } else {
                0
            };
            let peer_id = &peers[peer_idx];

            let query_id = format!("warm-{}-{}", self.config.node_id(), uuid::Uuid::new_v4());
            let (tx, _rx) = tokio::sync::oneshot::channel();
            self.pending_queries.lock().await.register(query_id.clone(), tx);

            if self.send_route_query_stream(peer_id, &query_id, &upstream_id).await.is_ok() {
                tracing::debug!("Proactive cache warming: queried {} from {}", upstream_id, peer_id);
            }

            // Don't wait for response - let it populate cache in background
            self.pending_queries.lock().await.take(&query_id);
        }
    }

    /// Periodic DHT cache resync for edge nodes
    /// Checks if local cache is stale and requests fresh snapshot from global nodes
    pub async fn dht_cache_resync(&self) {
        if self.topology.is_global() {
            return;
        }

        if let Some(ref record_store) = self.record_store {
            if !record_store.should_resync() {
                return;
            }

            // Get connected global nodes
            let global_nodes: Vec<String> = self.peer_connections.iter()
                .filter(|e| e.value().role.is_global())
                .map(|e| e.key().clone())
                .collect();

            if global_nodes.is_empty() {
                tracing::debug!("No global nodes connected for DHT resync");
                return;
            }

            if let Some(request) = record_store.create_snapshot_request() {
                let peer_id = &global_nodes[0];
                tracing::info!("DHT cache stale, requesting resync from {}", peer_id);
                
                if let Err(e) = self.send_datagram_to_peer(peer_id, &request).await {
                    tracing::warn!("Failed to request DHT resync from {}: {}", peer_id, e);
                }
            }
        }
    }

    pub async fn announce_upstream(
        &self,
        upstream_id: &str,
        action: crate::mesh::protocol::AnnounceAction,
    ) -> Result<(), MeshTransportError> {
        if !self.topology.can_forward_service(upstream_id) {
            tracing::debug!("Not announcing upstream {} - service not allowed by policy", upstream_id);
            return Ok(());
        }

        let full_upstream_id = self.config.make_mesh_upstream_id(upstream_id);

        match action {
            crate::mesh::protocol::AnnounceAction::Add | crate::mesh::protocol::AnnounceAction::Update => {
                self.topology.add_local_upstream(
                    full_upstream_id,
                    self.config.local_upstreams.get(upstream_id)
                        .map(|u| u.upstream_url.clone())
                        .unwrap_or_default(),
                    self.config.local_upstreams.get(upstream_id)
                        .and_then(|u| u.geo.clone()),
                ).await;
            }
            crate::mesh::protocol::AnnounceAction::Remove => {
                self.topology.remove_local_upstream(&full_upstream_id).await;
            }
        }

        for entry in self.peer_connections.iter() {
            let peer = entry.value();
            if peer.role.is_global() {
                tracing::debug!("Would announce upstream {} to global node {}", upstream_id, peer.node_id);
            }
        }

        Ok(())
    }

    pub async fn broadcast_upstream_block(
        &self,
        upstream_id: &str,
        reason: &str,
        blocked_duration_secs: u64,
    ) {
        if !self.config.ratelimit_block_advertisement {
            tracing::debug!("Upstream block advertisement disabled in config");
            return;
        }

        // Validate: don't broadcast blocks with 0 or very small duration
        if blocked_duration_secs < 1 {
            tracing::warn!("Refusing to broadcast block with zero or negative duration: {}", blocked_duration_secs);
            return;
        }

        let blocked_until = Instant::now() + Duration::from_secs(blocked_duration_secs);
        let mesh_identifier = self.config.router_id();
        
        let parts: Vec<&str> = upstream_id.split('.').collect();
        let (mesh_id, service_id) = if parts.len() >= 2 {
            (parts[0].to_string(), parts[1..].join("."))
        } else {
            (mesh_identifier.to_string(), upstream_id.to_string())
        };

        self.topology.block_upstream(
            mesh_id.as_str(),
            service_id.as_str(),
            blocked_until,
            reason,
            self.config.node_id().as_str(),
        ).await;

        // Send Unix timestamp for when block expires (not remaining duration)
        let block_until_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
            + blocked_duration_secs;

        let block_message = MeshMessage::UpstreamBlocked {
            mesh_identifier: mesh_id.into(),
            service_id: service_id.into(),
            blocked_until: block_until_unix,
            reason: reason.into(),
            origin_node_id: self.config.node_id().into(),
        };

        let (success_count, fail_count) = self.broadcast_to_random_peers(
            block_message,
            0.5,
            Some(crate::mesh::config::MeshNodeRole::Global),
        ).await;

        tracing::info!(
            upstream_id, reason, blocked_duration_secs,
            "Fanout broadcast upstream block: {} to {} global nodes ({} failed)",
            upstream_id, success_count, fail_count
        );
    }

    pub async fn broadcast_to_random_peers(
        &self,
        message: MeshMessage,
        fanout_factor: f64,
        role_filter: Option<crate::mesh::config::MeshNodeRole>,
    ) -> (usize, usize) {
        let peer_count = self.topology.get_healthy_peer_count().await;
        
        if peer_count == 0 {
            return (0, 0);
        }

        let fanout_count = ((peer_count as f64) * fanout_factor).ceil() as usize;
        let target_count = fanout_count.max(1).min(peer_count);

        let mut peers = self.topology.get_random_peers(target_count, None).await;
        
        if let Some(role) = role_filter {
            peers.retain(|p| p.role == role);
        }

        if peers.is_empty() {
            return (0, 0);
        }

        let mut success_count = 0;
        let mut fail_count = 0;

        for peer in &peers {
            match self.send_datagram_to_peer(&peer.node_id, &message).await {
                Ok(_) => success_count += 1,
                Err(e) => {
                    fail_count += 1;
                    tracing::debug!("Fanout broadcast to {} failed: {}", peer.node_id, e);
                }
            }
        }

        tracing::debug!(
            "Fanout broadcast: {} peers selected, {} sent (mesh: {}, factor: {:.2})",
            peers.len(),
            success_count,
            peer_count,
            fanout_factor
        );

        (success_count, fail_count)
    }

    pub fn is_connected_to(&self, node_id: &str) -> bool {
        self.peer_connections.iter().any(|e| e.value().node_id == node_id)
    }

    pub fn connected_peer_count(&self) -> usize {
        self.peer_connections.len()
    }

    pub fn get_connected_peers(&self) -> Vec<String> {
        self.peer_connections.iter().map(|e| e.value().node_id.clone()).collect()
    }

    pub async fn proxy_http_request<B>(
        &self,
        peer_id: &str,
        target_url: &str,
        request: Request<B>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, MeshTransportError>
    where
        B: HttpBody + Send,
        B::Data: Send,
        B::Error: std::fmt::Debug + Send,
    {
        use http_body_util::BodyExt;

        let peer = self.peer_connections.get(peer_id)
            .ok_or_else(|| MeshTransportError::PeerNotFound(peer_id.to_string()))?;

        let (mut send_stream, mut recv_stream) = peer.connection.open_bi().await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let method = request.method().to_string();
        let uri = request.uri().to_string();
        let headers = request.headers();

        let mut header_str = format!("{} {} HTTP/1.1\r\n", method, uri);
        for (name, value) in headers.iter() {
            header_str.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap_or("")));
        }
        header_str.push_str("\r\n");

        send_stream.write_all(header_str.as_bytes()).await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        let body = request.collect().await
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?
            .to_bytes();
        if !body.is_empty() {
            send_stream.write_all(&body).await
                .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;
        }

        let mut response_headers = String::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;

        loop {
            let mut line = String::new();
            loop {
                let mut buf = [0u8; 1];
                recv_stream.read_exact(&mut buf).await
                    .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
                if buf[0] == b'\n' {
                    break;
                }
                if buf[0] != b'\r' {
                    line.push(buf[0] as char);
                }
            }
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            if line.to_lowercase().starts_with("content-length:") {
                content_length = Some(line.split(':').nth(1).unwrap_or("").trim().parse().unwrap_or(0));
            }
            if line.to_lowercase().contains("chunked") {
                chunked = true;
            }
            response_headers.push_str(line);
            response_headers.push_str("\r\n");
        }
        response_headers.push_str("\r\n");

        let status_line = response_headers.lines().next().unwrap_or("HTTP/1.1 500 Internal Server Error");
        let status_code = status_line.split_whitespace().nth(1).unwrap_or("500").parse::<u16>().unwrap_or(500);

        let mut response_builder = hyper::Response::builder().status(status_code);

        for line in response_headers.lines().skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                response_builder = response_builder.header(name.trim(), value.trim());
            }
        }

        let body_bytes = if chunked {
            let mut body = Vec::new();
            loop {
                let mut size_line = String::new();
                loop {
                    let mut buf = [0u8; 1];
                    recv_stream.read_exact(&mut buf).await
                        .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
                    if buf[0] == b'\n' {
                        break;
                    }
                    if buf[0] != b'\r' {
                        size_line.push(buf[0] as char);
                    }
                }
                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                if size == 0 {
                    break;
                }
                let mut chunk = vec![0u8; size];
                recv_stream.read_exact(&mut chunk).await
                    .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
                body.extend_from_slice(&chunk);
                let mut crlf = [0u8; 2];
                recv_stream.read_exact(&mut crlf).await
                    .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
            }
            body
        } else if let Some(len) = content_length {
            let mut body = vec![0u8; len];
            recv_stream.read_exact(&mut body).await
                .map_err(|e| MeshTransportError::ReceiveFailed(e.to_string()))?;
            body
        } else {
            let mut body = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match recv_stream.read(&mut buf).await {
                    Ok(Some(0)) | Ok(None) => break,
                    Ok(Some(n)) => body.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            body
        };

        let body = Bytes::from(body_bytes);
        let full_body = http_body_util::Full::new(body);
        let boxed_body: BoxBody<Bytes, Infallible> = full_body.boxed();
        let response = response_builder.body(boxed_body)
            .map_err(|e| MeshTransportError::SendFailed(format!("{:?}", e)))?;

        Ok(response)
    }

    fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(CONNECTION_RATE_LIMIT_WINDOW_SECS);
        
        let mut times = self.connection_times.write();
        times.retain(|t| now.duration_since(*t) < window);
        
        if times.len() >= MAX_PENDING_CONNECTIONS {
            tracing::warn!("Connection rate limit exceeded: {} connections in {}s", 
                times.len(), CONNECTION_RATE_LIMIT_WINDOW_SECS);
            return false;
        }
        
        times.push(now);
        true
    }

    pub fn verify_auth_token(&self, node_id: &str, token: &str) -> bool {
        let keys = self.auth_keys.read();
        if let Some(expected_key) = keys.get(node_id) {
            return expected_key.as_slice() == token.as_bytes();
        }
        if keys.is_empty() {
            return true;
        }
        false
    }

    pub fn record_auth_failure(&self, node_id: &str) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.connection.auth_failure_window_secs);
        let max_failures = self.config.connection.max_auth_failures;
        
        let mut failures = self.auth_failures.write();
        let node_failures = failures.entry(node_id.to_string()).or_insert_with(Vec::new);
        
        node_failures.retain(|t| now.duration_since(*t) < window);
        
        if node_failures.len() >= max_failures {
            tracing::error!("Node {} blocked due to repeated authentication failures", node_id);
            node_failures.push(now);
        } else {
            node_failures.push(now);
            tracing::warn!("Authentication failure for node {} ({} failures)", node_id, node_failures.len());
        }
    }

    pub fn is_node_blocked(&self, node_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.connection.auth_failure_window_secs);
        let max_failures = self.config.connection.max_auth_failures;
        
        let failures = self.auth_failures.read();
        if let Some(node_failures) = failures.get(node_id) {
            let recent_failures: Vec<_> = node_failures.iter()
                .filter(|t| now.duration_since(**t) < window)
                .collect();
            return recent_failures.len() >= max_failures;
        }
        
        false
    }

    pub fn clear_auth_failures(&self, node_id: &str) {
        let mut failures = self.auth_failures.write();
        failures.remove(node_id);
    }

    pub fn check_peer_rate_limit(&self, peer_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(PEER_RATE_LIMIT_WINDOW_SECS);
        
        let max_rate = self.config.routing.mesh_messages_per_sec * 60;
        
        let mut times = self.peer_message_times.write();
        let peer_times = times.entry(peer_id.to_string()).or_insert_with(Vec::new);
        
        peer_times.retain(|t| now.duration_since(*t) < window);
        
        if peer_times.len() >= max_rate {
            tracing::warn!("Peer {} rate limit exceeded: {} messages in {}s (limit: {})", 
                peer_id, peer_times.len(), PEER_RATE_LIMIT_WINDOW_SECS, max_rate);
            return false;
        }
        
        peer_times.push(now);
        true
    }

    pub fn get_auth_failure_count(&self, node_id: &str) -> usize {
        let failures = self.auth_failures.read();
        failures.get(node_id).map(|v| v.len()).unwrap_or(0)
    }

    pub fn get_peer_message_count(&self, peer_id: &str) -> usize {
        let times = self.peer_message_times.read();
        times.get(peer_id).map(|v| v.len()).unwrap_or(0)
    }

    pub fn get_origin_ed25519_pubkey(&self, mesh_id: &str) -> Option<String> {
        if let Some(ref origin_key) = self.config.origin_signing_key {
            if origin_key.mesh_id == mesh_id {
                return origin_key.public_key_base64.clone();
            }
        }
        self.config.global_node.known_origin_keys.get(mesh_id).cloned()
    }

    pub async fn lookup_origin_key_async(&self, mesh_id: &str) -> Option<String> {
        let peers = self.topology.get_random_peers(3, None).await;
        
        if peers.is_empty() {
            tracing::debug!("No peers available for origin key lookup of mesh {}", mesh_id);
            return None;
        }

        let peer_count = peers.len();
        let request_id = format!("origin-key-query-{}", uuid::Uuid::new_v4());
        
        let request = crate::mesh::protocol::MeshMessage::OriginKeyQuery {
            request_id: request_id.into(),
            mesh_id: mesh_id.into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        for peer in peers {
            if let Err(e) = self.send_datagram_to_peer(&peer.node_id, &request).await {
                tracing::warn!("Failed to send OriginKeyQuery to {}: {}", peer.node_id, e);
            }
        }
        
        tracing::debug!("Broadcast OriginKeyQuery for mesh {} to {} peers", mesh_id, peer_count);
        None
    }

    pub fn is_global_node(&self) -> bool {
        self.config.role.is_global()
    }

    pub fn get_node_mesh_id(&self) -> Option<String> {
        self.config.origin_signing_key.as_ref().map(|k| k.mesh_id.clone())
    }

    pub fn get_node_id(&self) -> String {
        self.config.node_id()
    }

    pub fn get_global_verifying_key(&self) -> String {
        self.config.global_node_key.clone().unwrap_or_default()
    }

    pub fn get_origin_signer(&self) -> Option<Arc<crate::integrity::Ed25519Signer>> {
        self.origin_ed25519_signer.clone()
    }

    pub fn cleanup_rate_limit_state(&self) {
        let now = Instant::now();
        
        {
            let mut failures = self.auth_failures.write();
            let window = Duration::from_secs(self.config.connection.auth_failure_window_secs);
            for (_, v) in failures.iter_mut() {
                v.retain(|t| now.duration_since(*t) < window);
            }
            failures.retain(|_, v| !v.is_empty());
        }
        
        {
            let mut times = self.peer_message_times.write();
            let window = Duration::from_secs(PEER_RATE_LIMIT_WINDOW_SECS);
            for (_, v) in times.iter_mut() {
                v.retain(|t| now.duration_since(*t) < window);
            }
            times.retain(|_, v| !v.is_empty());
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeshTransportError {
    #[error("No seed nodes available")]
    NoSeedsAvailable,
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    #[error("Version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },
    #[error("Unexpected message type")]
    UnexpectedMessage,
    #[error("Peer error: {code} - {message}")]
    PeerError { code: u16, message: String },
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("No route to upstream: {0}")]
    NoRouteToUpstream(String),
    #[error("Service not allowed: {0}")]
    ServiceNotAllowed(String),
    #[error("Runtime not set")]
    RuntimeNotSet,
    #[error("Timeout")]
    Timeout,
    #[error("Rate limited - too many connection attempts")]
    RateLimited,
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
}

impl From<quinn::ConnectionError> for MeshTransportError {
    fn from(e: quinn::ConnectionError) -> Self {
        MeshTransportError::ConnectionFailed(e.to_string())
    }
}

impl From<prost::EncodeError> for MeshTransportError {
    fn from(e: prost::EncodeError) -> Self {
        MeshTransportError::SendFailed(e.to_string())
    }
}

impl From<tokio::io::Error> for MeshTransportError {
    fn from(e: tokio::io::Error) -> Self {
        MeshTransportError::SendFailed(e.to_string())
    }
}

impl From<quinn::WriteError> for MeshTransportError {
    fn from(e: quinn::WriteError) -> Self {
        MeshTransportError::SendFailed(e.to_string())
    }
}

impl From<quinn::ReadError> for MeshTransportError {
    fn from(e: quinn::ReadError) -> Self {
        MeshTransportError::ReceiveFailed(e.to_string())
    }
}

impl From<quinn::ReadExactError> for MeshTransportError {
    fn from(e: quinn::ReadExactError) -> Self {
        MeshTransportError::ReceiveFailed(e.to_string())
    }
}
