#![allow(unused_variables)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use linked_hash_map::LinkedHashMap;
use metrics::counter;
use parking_lot::RwLock;
use tokio::sync::mpsc;

use crate::mesh::config::MeshNodeRole;
use crate::mesh::dht::keys::DhtKey;
use crate::mesh::dht::merkle::MerkleTree;
use crate::mesh::dht::{validate_message_timestamp, DhtAccessControl};
use crate::mesh::protocol::{DhtRecord, MeshMessage};

const DEFAULT_SYNC_INTERVAL_SECS: u64 = 300;
const DEFAULT_REPLICATION_FACTOR: usize = 20;
const DEFAULT_WRITE_QUORUM: u32 = 11;
const DEFAULT_READ_QUORUM: u32 = 11;
const DEFAULT_RECORD_TTL: u64 = 3600;
const DEFAULT_EDGE_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_EDGE_CACHE_MAX_ENTRIES: usize = 1000;
const DEFAULT_CONVERGENCE_THRESHOLD: usize = 3;

#[derive(Debug, Clone)]
pub struct RecordStoreConfig {
    pub enabled: bool,
    pub sync_interval_secs: u64,
    pub replication_factor: usize,
    pub write_quorum: u32,
    pub read_quorum: u32,
    pub record_ttl: Duration,
    pub edge_cache_enabled: bool,
    pub edge_cache_max_entries: usize,
    pub edge_cache_ttl_secs: u64,
    pub edge_write_enabled: bool,
    pub health_ttl_secs: u64,
    pub load_ttl_secs: u64,
    pub initial_sync_interval_secs: u64,
    pub max_sync_interval_secs: u64,
    pub fanout_factor: f64,
    pub convergence_threshold: usize,
}

impl Default for RecordStoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_interval_secs: DEFAULT_SYNC_INTERVAL_SECS,
            replication_factor: DEFAULT_REPLICATION_FACTOR,
            write_quorum: DEFAULT_WRITE_QUORUM,
            read_quorum: DEFAULT_READ_QUORUM,
            record_ttl: Duration::from_secs(DEFAULT_RECORD_TTL),
            edge_cache_enabled: true,
            edge_cache_max_entries: DEFAULT_EDGE_CACHE_MAX_ENTRIES,
            edge_cache_ttl_secs: DEFAULT_EDGE_CACHE_TTL_SECS,
            edge_write_enabled: false,
            health_ttl_secs: 60,
            load_ttl_secs: 60,
            initial_sync_interval_secs: 30,
            max_sync_interval_secs: 3600,
            fanout_factor: 0.5,
            convergence_threshold: DEFAULT_CONVERGENCE_THRESHOLD,
        }
    }
}

pub struct RecordStoreManager {
    config: Arc<RecordStoreConfig>,
    node_id: String,
    node_role: MeshNodeRole,
    mesh_signer: RwLock<Option<crate::mesh::protocol::MeshMessageSigner>>,
    record_signer: RwLock<Option<crate::mesh::dht::RecordSigner>>,
    access_control: Arc<DhtAccessControl>,
    local_version: RwLock<u64>,
    records: RwLock<LinkedHashMap<String, DhtRecordEntry>>,
    mesh_sender: Arc<RwLock<Option<mpsc::Sender<MeshMessage>>>>,
    transport: Arc<RwLock<Option<Arc<crate::mesh::transport::MeshTransport>>>>,
    routing_manager: RwLock<Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>>,
    stake_manager: RwLock<Option<Arc<crate::mesh::dht::StakeManager>>>,
    last_sync: RwLock<Instant>,
    pending_announces: RwLock<Vec<DhtRecord>>,
    cache_hits: RwLock<u64>,
    cache_misses: RwLock<u64>,
    last_snapshot_version: RwLock<u64>,
    initial_sync_completed: RwLock<bool>,
    current_sync_interval: RwLock<u64>,
    recent_changes: RwLock<Vec<Instant>>,
    merkle_tree: RwLock<Option<MerkleTree>>,
    propagation_states: RwLock<HashMap<String, PropagationState>>,
    convergence_threshold: usize,
    rate_limiter: RwLock<Option<crate::mesh::dht::DhtRateLimiter>>,
    network_policy: RwLock<Option<crate::mesh::dht::NetworkPolicy>>,
    blocklist: RwLock<Option<crate::mesh::dht::GlobalNodeBlocklist>>,
}

#[derive(Debug, Clone)]
pub struct PropagationState {
    pub key: String,
    pub ack_count: usize,
    pub attempted_peers: Vec<String>,
    pub completed: bool,
    pub last_update: Instant,
}

#[derive(Debug, Clone)]
pub struct DhtRecordEntry {
    pub record: DhtRecord,
    pub local_origin: bool,
    pub version: u64,
}

impl RecordStoreManager {
    pub fn new(
        config: RecordStoreConfig,
        node_id: String,
        node_role: MeshNodeRole,
        mesh_signer: Option<crate::mesh::protocol::MeshMessageSigner>,
        access_control: DhtAccessControl,
    ) -> Self {
        let initial_interval = config.initial_sync_interval_secs;
        let convergence_threshold = config.convergence_threshold;
        let fanout_factor = config.fanout_factor;
        let replication_factor = config.replication_factor;
        Self {
            config: Arc::new(config),
            node_id,
            node_role,
            mesh_signer: RwLock::new(mesh_signer),
            record_signer: RwLock::new(None),
            access_control: Arc::new(access_control),
            local_version: RwLock::new(1),
            records: RwLock::new(LinkedHashMap::new()),
            mesh_sender: Arc::new(RwLock::new(None)),
            transport: Arc::new(RwLock::new(None)),
            routing_manager: RwLock::new(None),
            stake_manager: RwLock::new(None),
            last_sync: RwLock::new(Instant::now()),
            pending_announces: RwLock::new(Vec::new()),
            cache_hits: RwLock::new(0),
            cache_misses: RwLock::new(0),
            last_snapshot_version: RwLock::new(0),
            initial_sync_completed: RwLock::new(false),
            current_sync_interval: RwLock::new(initial_interval),
            recent_changes: RwLock::new(Vec::new()),
            merkle_tree: RwLock::new(None),
            propagation_states: RwLock::new(HashMap::new()),
            convergence_threshold,
            rate_limiter: RwLock::new(None),
            network_policy: RwLock::new(None),
            blocklist: RwLock::new(None),
        }
    }

    pub fn set_record_signer(&self, signing_key: Option<[u8; 32]>) {
        let mut signer = self.record_signer.write();
        *signer = Some(crate::mesh::dht::RecordSigner::new(signing_key));
    }

    pub fn enable_rate_limiting(&self, max_requests: u32, window_secs: u64) {
        let mut limiter = self.rate_limiter.write();
        *limiter = Some(crate::mesh::dht::DhtRateLimiter::new(max_requests, window_secs));
    }

    pub fn is_rate_limited(&self, peer_id: &str) -> bool {
        let limiter = self.rate_limiter.read();
        match limiter.as_ref() {
            Some(l) => !l.is_allowed(peer_id),
            None => false,
        }
    }

    pub fn set_mesh_sender(&self, sender: mpsc::Sender<MeshMessage>) {
        let mut sender_guard = self.mesh_sender.write();
        *sender_guard = Some(sender);
    }

    pub fn set_transport(&self, transport: Arc<crate::mesh::transport::MeshTransport>) {
        let mut t = self.transport.write();
        *t = Some(transport);
    }

    pub fn set_routing_manager(&self, manager: Arc<crate::mesh::dht::routing::DhtRoutingManager>) {
        let mut rm = self.routing_manager.write();
        *rm = Some(manager);
    }

    pub fn set_stake_manager(&self, manager: Arc<crate::mesh::dht::StakeManager>) {
        let mut sm = self.stake_manager.write();
        *sm = Some(manager);
    }

    pub fn is_routing_enabled(&self) -> bool {
        let rm = self.routing_manager.read();
        rm.as_ref().map(|m| m.is_enabled()).unwrap_or(false)
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn is_global_node(&self) -> bool {
        self.node_role == MeshNodeRole::Global
    }

    pub fn get_network_policy(&self) -> Option<crate::mesh::dht::NetworkPolicy> {
        self.network_policy.read().clone()
    }

    pub fn set_network_policy(&self, policy: crate::mesh::dht::NetworkPolicy) {
        *self.network_policy.write() = Some(policy);
    }

    pub fn get_blocklist(&self) -> Option<crate::mesh::dht::GlobalNodeBlocklist> {
        self.blocklist.read().clone()
    }

    pub fn set_blocklist(&self, blocklist: crate::mesh::dht::GlobalNodeBlocklist) {
        *self.blocklist.write() = Some(blocklist);
    }

    pub fn is_node_blocked(&self, node_id: &str, ip: Option<&str>) -> bool {
        let blocklist = self.blocklist.read();
        if let Some(ref bl) = *blocklist {
            bl.is_blocked(node_id, ip)
        } else {
            false
        }
    }

    fn can_cache_on_edge(&self, key: &str) -> bool {
        if !self.config.edge_cache_enabled {
            return false;
        }
        let dht_key = DhtKey::from_str(key);
        dht_key.is_public()
    }

    pub fn store_record(&self, record: DhtRecord, source_reputation: i64) -> bool {
        if !self.config.enabled {
            return false;
        }

        let is_global = self.is_global_node();

        if !is_global && record.signature.is_empty() {
            tracing::warn!(
                "Record store: edge node record for key {} must be signed",
                record.key
            );
            return false;
        }

        if !record.signature.is_empty() {
            if let Some(ref signer_pk) = record.signer_public_key {
                if let Ok(pk_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signer_pk) {
                    let signable = format!(
                        "{}:{}:{}:{}",
                        record.key,
                        record.source_node_id,
                        record.timestamp,
                        serde_json::to_string(&record.value).unwrap_or_default()
                    );
                    if !crate::mesh::cert::verify_ed25519(&signable, &record.signature, &pk_bytes) {
                        tracing::warn!(
                            "Record store: invalid signature for key {} from node {}",
                            record.key,
                            record.source_node_id
                        );
                        return false;
                    }
                } else {
                    tracing::warn!(
                        "Record store: invalid public key format for key {}",
                        record.key
                    );
                    return false;
                }
            } else if !is_global {
                tracing::warn!(
                    "Record store: missing signer public key for key {} from node {}",
                    record.key,
                    record.source_node_id
                );
                return false;
            }
        }

        if let Some(ref stake_mgr) = *self.stake_manager.read() {
            if !stake_mgr.can_write_dht(&record.source_node_id) {
                tracing::warn!(
                    "Record store: node {} has insufficient stake to write DHT record",
                    record.source_node_id
                );
                return false;
            }
        }

        if self.is_global_node() {
            return self.store_record_global(record);
        }

        let dht_key = DhtKey::from_str(&record.key);
        let is_self_record = dht_key.is_self_record(&self.node_id);

        if !self.config.edge_write_enabled {
            if self.can_cache_on_edge(&record.key) && is_self_record {
                return self.store_record_edge_cache(record);
            }
            tracing::warn!(
                "Record store: edge write disabled, cannot store: {}",
                record.key
            );
            return false;
        }

        if !self.access_control.can_store(&record.key, false, is_self_record, source_reputation) {
            tracing::warn!(
                "Record store: access denied for key {} (reputation: {} < {})",
                record.key,
                source_reputation,
                self.access_control.min_reputation_for_write()
            );
            return false;
        }

        if self.access_control.requires_global_signature(&record.key) {
            tracing::warn!(
                "Record store: key {} requires global signature, edge node cannot store",
                record.key
            );
            return false;
        }

        if self.access_control.is_self_only(&record.key) && !is_self_record {
            tracing::warn!(
                "Record store: key {} can only be stored by the owning node",
                record.key
            );
            return false;
        }

        if self.can_cache_on_edge(&record.key) {
            return self.store_record_edge_cache(record);
        }

        tracing::warn!(
            "Record store: edge node cannot cache privileged record: {}",
            record.key
        );
        false
    }

    fn store_record_global(&self, mut record: DhtRecord) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expires_at = record.timestamp + record.ttl_seconds;
        if now > expires_at {
            tracing::warn!("Received expired record: {}", record.key);
            return false;
        }

        let is_local_record = record.source_node_id == self.node_id;
        
        if !is_local_record && !record.signature.is_empty() {
            if let Some(ref signer_pk) = record.signer_public_key {
                if !signer_pk.is_empty() {
                    let record_signer = self.record_signer.read();
                    if let Some(ref verifier) = *record_signer {
                        let signed_record = crate::mesh::dht::SignedDhtRecord {
                            key: record.key.clone(),
                            value: record.value.clone(),
                            publisher_id: record.source_node_id.clone(),
                            signature: record.signature.clone(),
                            created_at: record.timestamp,
                            expires_at: Some(expires_at),
                            record_type: crate::mesh::dht::SignedRecordType::NodeInfo,
                            sequence_number: 0,
                            source_node_id: record.source_node_id.clone(),
                            ttl_seconds: record.ttl_seconds,
                            signer_public_key: record.signer_public_key.clone(),
                        };
                        
                        if !verifier.verify(&signed_record) {
                            tracing::warn!("Rejected record with invalid Ed25519 signature: {}", record.key);
                            return false;
                        }
                        tracing::debug!("Verified Ed25519 signature on record: {}", record.key);
                    }
                }
            }
        }
        
        if is_local_record {
            let record_signer = self.record_signer.read();
            if let Some(ref signer) = *record_signer {
                let signed_record = crate::mesh::dht::SignedDhtRecord::new(
                    record.key.clone(),
                    record.value.clone(),
                    record.source_node_id.clone(),
                    crate::mesh::dht::SignedRecordType::NodeInfo,
                );
                
                if let Some(signature) = signer.sign(&signed_record) {
                    record.signature = signature;
                    record.signer_public_key = signer.get_verifying_key();
                    tracing::debug!("Signed local record with Ed25519: {}", record.key);
                }
            }
        }

        let mut records = self.records.write();
        records.insert(
            record.key.clone(),
            DhtRecordEntry {
                record: record.clone(),
                local_origin: is_local_record,
                version: *self.local_version.read(),
            },
        );

        *self.local_version.write() += 1;

        tracing::debug!("Stored global record: {}", record.key);

        drop(records);

        self.maybe_queue_for_announce(&record);

        if self.is_global_node() {
            self.record_change();
        }

        self.compute_merkle_tree();

        true
    }

    fn maybe_queue_for_announce(&self, record: &DhtRecord) {
        let dht_key = DhtKey::from_str(&record.key);

        if dht_key.is_public() && !dht_key.requires_confirmation() {
            self.queue_for_announce(record.clone());
            tracing::debug!("Auto-queued public record for announce: {}", record.key);
        }
    }

    fn store_record_edge_cache(&self, record: DhtRecord) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expires_at = record.timestamp + record.ttl_seconds;
        if now > expires_at {
            tracing::debug!("Ignoring expired record in edge cache: {}", record.key);
            return false;
        }

        let effective_ttl = self.config.edge_cache_ttl_secs.min(record.ttl_seconds);
        let record_key = record.key.clone();

        let cache_ttl_record = DhtRecord {
            key: record_key.clone(),
            value: record.value.clone(),
            timestamp: record.timestamp,
            ttl_seconds: effective_ttl,
            source_node_id: record.source_node_id.clone(),
            signature: record.signature.clone(),
            signer_public_key: record.signer_public_key.clone(),
        };

        let mut records = self.records.write();

        while records.len() >= self.config.edge_cache_max_entries {
            if let Some(oldest_key) = records.front().map(|(k, _)| k.clone()) {
                records.remove(&oldest_key);
                tracing::debug!("Edge cache full, evicted LRU: {}", oldest_key);
            } else {
                break;
            }
        }

        records.insert(
            record_key,
            DhtRecordEntry {
                record: cache_ttl_record,
                local_origin: false,
                version: *self.local_version.read(),
            },
        );

        *self.local_version.write() += 1;

        tracing::debug!("Cached edge record: {}", record.key);
        
        if self.is_global_node() {
            drop(records);
            self.compute_merkle_tree();
        }
        
        true
    }

    pub fn get_record(&self, key: &str) -> Option<DhtRecord> {
        if !self.config.enabled {
            return None;
        }

        let (record, is_expired) = {
            let records = self.records.read();
            match records.get(key) {
                Some(entry) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                    (Some(entry.record.clone()), now >= expires_at)
                }
                None => (None, false),
            }
        };

        if let Some(record) = record {
            if !is_expired {
                if !self.is_global_node() {
                    *self.cache_hits.write() += 1;
                    let mut records = self.records.write();
                    if let Some(entry) = records.remove(key) {
                        records.insert(key.to_string(), entry);
                    }
                }
                return Some(record);
            } else {
                let mut records = self.records.write();
                records.remove(key);
            }
        }

        if !self.is_global_node() {
            *self.cache_misses.write() += 1;
        }
        None
    }

    pub fn get_record_cached(&self, key: &str) -> Option<DhtRecord> {
        if !self.config.enabled || self.is_global_node() {
            return None;
        }

        let dht_key = DhtKey::from_str(key);
        if !dht_key.is_public() {
            return None;
        }

        self.get_record(key)
    }

    pub fn should_query_global(&self, key: &str) -> bool {
        if !self.config.enabled || self.is_global_node() {
            return false;
        }

        let dht_key = DhtKey::from_str(key);
        if !dht_key.is_public() {
            return true;
        }

        self.get_record(key).is_none()
    }

    pub fn get_all_records(&self) -> Vec<DhtRecord> {
        let records = self.records.read();
        records
            .values()
            .filter(|entry| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at
            })
            .map(|e| e.record.clone())
            .collect()
    }

    pub fn get_version(&self) -> u64 {
        *self.local_version.read()
    }

    pub fn should_sync(&self) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let interval = self.get_adaptive_sync_interval();
        let last = *self.last_sync.read();
        last.elapsed() > Duration::from_secs(interval)
    }

    pub fn get_adaptive_sync_interval(&self) -> u64 {
        let base_interval = self.config.sync_interval_secs;
        
        let mut recent = self.recent_changes.write();
        let now = Instant::now();
        recent.retain(|t| now.duration_since(*t).as_secs() < 300);
        
        let change_count = recent.len();
        
        let interval = if change_count > 10 {
            (base_interval / 4).max(60)
        } else if change_count > 5 {
            (base_interval / 2).max(120)
        } else if change_count == 0 {
            (base_interval * 2).min(self.config.max_sync_interval_secs)
        } else {
            base_interval
        };

        interval
    }

    pub fn record_change(&self) {
        let mut recent = self.recent_changes.write();
        recent.push(Instant::now());
    }

    pub fn record_sync(&self) {
        *self.last_sync.write() = Instant::now();
    }

    pub fn get_records_for_sync(&self, from_version: u64) -> Vec<DhtRecord> {
        let records = self.records.read();

        records
            .values()
            .filter(|entry| entry.version > from_version)
            .filter(|entry| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at
            })
            .map(|entry| entry.record.clone())
            .collect()
    }

    pub fn apply_sync(&self, records: Vec<DhtRecord>) {
        let mut records_map = self.records.write();
        let mut changed = false;

        for record in records {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let expires_at = record.timestamp + record.ttl_seconds;
            if now > expires_at {
                continue;
            }

            let existing = records_map.get(&record.key);
            if existing.is_none() || existing.map(|e| e.record.timestamp < record.timestamp).unwrap_or(true) {
                changed = true;
                records_map.insert(
                    record.key.clone(),
                    DhtRecordEntry {
                        record,
                        local_origin: false,
                        version: *self.local_version.read() + 1,
                    },
                );
            }
        }

        if changed {
            *self.local_version.write() += 1;
            drop(records_map);
            self.compute_merkle_tree();
        }
    }

    pub fn queue_for_announce(&self, record: DhtRecord) {
        let mut queue = self.pending_announces.write();
        queue.push(record);
    }

    pub fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let count_before = self.records.read().len();
        
        let mut records = self.records.write();
        let keys_to_remove: Vec<String> = records
            .iter()
            .filter(|(_, entry)| {
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now >= expires_at
            })
            .map(|(k, _)| k.clone())
            .collect();
        
        for key in keys_to_remove {
            records.remove(&key);
        }

        let count_after = records.len();
        if count_before != count_after {
            tracing::debug!("Cleaned up {} expired DHT records", count_before - count_after);
        }
    }

    pub fn get_record_count(&self) -> usize {
        self.records.read().len()
    }

    pub fn create_record_announce(&self) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let queue = self.pending_announces.read();
        if queue.is_empty() {
            return None;
        }

        let records: Vec<DhtRecord> = queue.iter().cloned().collect();

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{}",
                self.node_id,
                records.len(),
                self.node_role.bits(),
                timestamp
            );
            signature = signer.sign(&content);
            signer_public_key = signer.get_public_key();
        }

        let request_id = uuid::Uuid::new_v4().to_string();

        let message = MeshMessage::DhtRecordAnnounce {
            request_id: request_id.into(),
            records,
            write_quorum: self.config.write_quorum,
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature,
            signer_public_key,
        };

        drop(queue);

        let mut pending = self.pending_announces.write();
        pending.clear();

        Some(message)
    }

    pub fn publish_global_node_public_key(&self, public_key: &str) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let key = format!("global_node_key:{}", self.node_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let value = serde_json::json!({
            "public_key": public_key,
            "timestamp": now,
        });
        let value = match serde_json::to_vec(&value) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize global node public key: {}", e);
                return false;
            }
        };

        let record = DhtRecord {
            key,
            value,
            timestamp: now,
            ttl_seconds: 86400,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
        };

        let stored = self.store_record(record.clone(), 100);
        if stored {
            self.queue_for_announce(record);
            tracing::info!("Published global node public key for node {}", self.node_id);
        }
        stored
    }

    pub fn store_and_announce(&self, key: String, value: Vec<u8>, ttl_seconds: u64) -> bool {
        if !self.config.enabled {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = DhtRecord {
            key: key.clone(),
            value,
            timestamp: now,
            ttl_seconds,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
        };

        let stored = self.store_record(record.clone(), 100);
        if stored {
            self.queue_for_announce(record);
            tracing::debug!("Stored and queued record for announce: {}", key);
        }
        stored
    }

    pub fn remove(&self, key: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let mut records = self.records.write();
        if records.remove(key).is_some() {
            tracing::debug!("Removed record from DHT: {}", key);
            self.record_change();
            return true;
        }
        false
    }

    pub fn create_sync_request(&self) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        Some(MeshMessage::DhtSyncRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            from_version: *self.local_version.read(),
        })
    }

    pub fn create_sync_response(&self, request_id: &str, from_version: u64) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let records = self.get_records_for_sync(from_version);

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{}",
                request_id,
                *self.local_version.read(),
                records.len(),
                timestamp
            );
            signature = signer.sign(&content);
            signer_public_key = signer.get_public_key();
        }

        Some(MeshMessage::DhtSyncResponse {
            request_id: request_id.into(),
            records,
            version: *self.local_version.read(),
            timestamp: MeshMessage::generate_timestamp(),
            signature,
            signer_public_key,
        })
    }

    pub fn create_snapshot_request(&self) -> Option<MeshMessage> {
        if !self.config.enabled || self.is_global_node() {
            return None;
        }

        Some(MeshMessage::DhtSnapshotRequest {
            request_id: uuid::Uuid::new_v4().to_string().into(),
            node_id: self.node_id.clone().into(),
            from_version: *self.local_version.read(),
        })
    }

    pub fn create_snapshot_response(&self, request_id: &str, from_version: u64) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let records: Vec<DhtRecord> = self.get_all_records()
            .into_iter()
            .filter(|r| {
                let dht_key = DhtKey::from_str(&r.key);
                dht_key.is_public()
            })
            .collect();

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{}",
                request_id,
                *self.local_version.read(),
                records.len(),
                timestamp
            );
            signature = signer.sign(&content);
            signer_public_key = signer.get_public_key();
        }

        Some(MeshMessage::DhtSnapshotResponse {
            request_id: request_id.into(),
            records,
            version: *self.local_version.read(),
            timestamp: MeshMessage::generate_timestamp(),
            signature,
            signer_public_key,
        })
    }

    pub fn apply_snapshot(&self, records: Vec<DhtRecord>, version: u64, is_verified: bool) -> usize {
        if !self.config.enabled || self.is_global_node() {
            return 0;
        }

        let reputation = if is_verified { 100 } else { 0 };
        let mut applied = 0;
        for record in records {
            if self.store_record(record, reputation) {
                applied += 1;
            }
        }

        *self.last_snapshot_version.write() = version;
        self.record_successful_sync();
        
        self.compute_merkle_tree();

        tracing::info!("Applied DHT snapshot: {} records cached (version: {})", applied, version);
        applied
    }

    pub fn verify_and_apply_snapshot(
        &self,
        records: Vec<DhtRecord>,
        version: u64,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> usize {
        if !self.config.enabled || self.is_global_node() {
            return 0;
        }

        let record_signer = self.record_signer.read();
        let Some(ref verifier) = *record_signer else {
            tracing::warn!("No record signer configured, rejecting unsigned records");
            return 0;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        let mut applied = 0;
        
        for record in records {
            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type: crate::mesh::dht::signed::SignedRecordType::Organization,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };
            
            let verified = if signer_public_key.as_ref().map(|pk| !pk.is_empty()).unwrap_or(false) {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer.as_ref()
                        .map(|s| s.verify(signed_record.get_signable_content().as_str(), &signed_record.signature, &pk_bytes))
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };
            
            if verified {
                if self.store_record(record, 100) {
                    applied += 1;
                }
            } else {
                let record_key = record.key.clone();
                tracing::warn!("Failed to verify record {} in snapshot", record_key);
            }
        }

        *self.last_snapshot_version.write() = version;
        self.record_successful_sync();
        
        self.compute_merkle_tree();

        tracing::info!("Verified and applied DHT snapshot: {} records (version: {})", applied, version);
        applied
    }

    pub fn should_resync(&self) -> bool {
        if !self.config.enabled || self.is_global_node() {
            return false;
        }

        let now = Instant::now();
        let last_sync = *self.last_sync.read();
        let current_interval = *self.current_sync_interval.read();
        now.duration_since(last_sync) > Duration::from_secs(current_interval)
    }

    pub fn record_successful_sync(&self) {
        if !self.config.enabled || self.is_global_node() {
            return;
        }

        *self.last_sync.write() = Instant::now();
        *self.initial_sync_completed.write() = true;

        let current = *self.current_sync_interval.read();
        let max_interval = self.config.max_sync_interval_secs;
        
        if current < max_interval {
            let new_interval = (current * 2).min(max_interval);
            *self.current_sync_interval.write() = new_interval;
            tracing::info!("DHT sync interval increased to {}s (max: {}s)", new_interval, max_interval);
        }
    }

    pub fn reset_sync_interval(&self) {
        if !self.config.enabled || self.is_global_node() {
            return;
        }

        let initial = self.config.initial_sync_interval_secs;
        *self.current_sync_interval.write() = initial;
        tracing::debug!("DHT sync interval reset to {}s", initial);
    }

    pub fn get_current_sync_interval(&self) -> u64 {
        *self.current_sync_interval.read()
    }

    pub fn get_last_snapshot_version(&self) -> u64 {
        *self.last_snapshot_version.read()
    }

    pub fn handle_record_announce(
        &self,
        records: Vec<DhtRecord>,
        from_node: &str,
        source_reputation: i64,
        _signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) {
        if !self.config.enabled {
            return;
        }

        let mut stored_count = 0;
        let mut skipped_count = 0;
        
        for record in records {
            if self.is_global_node() {
                if self.store_record(record, source_reputation) {
                    stored_count += 1;
                }
            } else {
                if self.can_cache_on_edge(&record.key) {
                    if self.store_record(record, source_reputation) {
                        stored_count += 1;
                    }
                } else {
                    skipped_count += 1;
                }
            }
        }

        tracing::debug!(
            "Applied DHT record announce from {}: {} stored, {} skipped (edge node)",
            from_node,
            stored_count,
            skipped_count
        );
    }

    pub fn handle_record_query(
        &self,
        request_id: &str,
        key: &str,
        from_node: &str,
    ) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        if let Some(ref stake_mgr) = *self.stake_manager.read() {
            if !stake_mgr.can_read_dht(from_node) {
                tracing::debug!(
                    "DHT query rejected: node {} has insufficient stake to read",
                    from_node
                );
                return None;
            }
        }

        let record = self.get_record(key);

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            if let Some(ref rec) = record {
                let timestamp = MeshMessage::generate_timestamp();
                let content = format!(
                    "{},{},{},{},{}",
                    request_id,
                    key,
                    rec.timestamp,
                    self.node_id,
                    timestamp
                );
                signature = signer.sign(&content);
                signer_public_key = signer.get_public_key();
            }
        }

        Some(MeshMessage::DhtRecordResponse {
            request_id: request_id.into(),
            key: key.into(),
            value: record.as_ref().map(|r| r.value.clone()).unwrap_or_default(),
            found: record.is_some(),
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature,
            signer_public_key,
        })
    }

    pub fn handle_sync_request(
        &self,
        request_id: &str,
        _from_node: &str,
        from_version: u64,
    ) -> Option<MeshMessage> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        self.create_sync_response(request_id, from_version)
    }

    pub fn handle_sync_response(
        &self,
        records: Vec<DhtRecord>,
        _from_node: &str,
    ) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        self.apply_sync(records);
    }

    pub fn handle_sync_response_verified(
        &self,
        records: Vec<DhtRecord>,
        _from_node: &str,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        let record_signer = self.record_signer.read();
        let Some(ref verifier) = *record_signer else {
            tracing::warn!("No record signer configured, rejecting sync response");
            return;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        let mut verified_records = Vec::new();
        
        for record in records {
            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type: crate::mesh::dht::signed::SignedRecordType::Organization,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };
            
            let verified = if signer_public_key.as_ref().map(|pk| !pk.is_empty()).unwrap_or(false) {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer.as_ref()
                        .map(|s| s.verify(signed_record.get_signable_content().as_str(), &signed_record.signature, &pk_bytes))
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };
            
            if verified {
                verified_records.push(record);
            } else {
                tracing::warn!("Failed to verify record {} in sync response", record.key);
            }
        }

        self.apply_sync(verified_records);
    }

    pub fn handle_anti_entropy_response_verified(
        &self,
        records: Vec<DhtRecord>,
        from_node: &str,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        let record_signer = self.record_signer.read();
        let Some(ref verifier) = *record_signer else {
            tracing::warn!("No record signer configured, rejecting anti-entropy response");
            return;
        };

        let signer_public_key = signer.map(|s| s.get_public_key());
        
        let mut accepted_count = 0;
        let mut rejected_count = 0;
        
        for record in records {
            if record.signature.is_empty() {
                tracing::debug!("Rejecting record {} from {}: no signature", record.key, from_node);
                rejected_count += 1;
                continue;
            }

            let signed_record = crate::mesh::dht::signed::SignedDhtRecord {
                key: record.key.clone(),
                value: record.value.clone(),
                publisher_id: record.source_node_id.clone(),
                signature: record.signature.clone(),
                created_at: record.timestamp,
                expires_at: Some(record.timestamp + record.ttl_seconds),
                record_type: crate::mesh::dht::signed::SignedRecordType::Organization,
                sequence_number: 0,
                source_node_id: record.source_node_id.clone(),
                ttl_seconds: record.ttl_seconds,
                signer_public_key: record.signer_public_key.clone(),
            };
            
            let verified = if signer_public_key.as_ref().map(|pk| !pk.is_empty()).unwrap_or(false) {
                if let Some(ref pk) = signer_public_key {
                    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_default();
                    signer.as_ref()
                        .map(|s| s.verify(signed_record.get_signable_content().as_str(), &signed_record.signature, &pk_bytes))
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                verifier.verify(&signed_record)
            };
            
            if !verified {
                tracing::debug!("Rejecting record {} from {}: invalid signature", record.key, from_node);
                rejected_count += 1;
                
                if let Some(ref stake_mgr) = *self.stake_manager.read() {
                    stake_mgr.submit_global_slash_vote(
                        record.source_node_id.clone(),
                        crate::mesh::dht::stake::SlashReason::InvalidRecordSignature,
                    );
                }
                continue;
            }
            
            let record_key = record.key.clone();
            
            if self.store_record(record, 100) {
                tracing::debug!("Stored record {} from {} (verified)", record_key, from_node);
                accepted_count += 1;
            }
        }
        
        if rejected_count > 0 {
            tracing::info!("Anti-entropy from {}: {} accepted, {} rejected", from_node, accepted_count, rejected_count);
        }

        self.compute_merkle_tree();
    }

    pub async fn broadcast_pending_records(&self) {
        if !self.config.enabled || !self.is_global_node() {
            return;
        }

        self.announce_records_via_kademlia().await;
    }

    async fn announce_records_via_kademlia(&self) {
        let Some(message) = self.create_record_announce() else {
            return;
        };

        let routing_manager = self.routing_manager.read().clone();
        let Some(rm) = routing_manager else {
            tracing::warn!("No routing manager available for Kademlia announce");
            return;
        };

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            return;
        };

        let replication_factor = self.config.replication_factor;
        
        // Use None for target_geo - we're announcing from our location,
        // so we'll get our regional hubs first via the hybrid lookup
        let target_geo = None;
        
        let peers = rm.find_closest_peers_hybrid(&self.node_id, target_geo, replication_factor).await;
        
        if peers.is_empty() {
            tracing::debug!("No peers found for record announce");
            return;
        }

        let mut success_count = 0;
        let mut fail_count = 0;

        for peer in peers {
            if peer.node_id_string == self.node_id {
                continue;
            }

            if let Err(e) = transport.send_datagram_to_peer(&peer.node_id_string, &message).await {
                fail_count += 1;
                tracing::debug!("Failed to announce to peer {}: {}", peer.node_id_string, e);
            } else {
                success_count += 1;
            }
        }

        tracing::debug!("Kademlia DHT record announce: {} sent, {} failed", success_count, fail_count);
    }

    async fn broadcast_pending_records_legacy(&self) {
        let Some(message) = self.create_record_announce() else {
            return;
        };

        let transport_opt = self.transport.read().clone();
        let fanout_factor = self.config.fanout_factor;
        if let Some(transport) = transport_opt {
            let (success, fail) = transport.broadcast_to_random_peers(
                message,
                fanout_factor,
                Some(crate::mesh::config::MeshNodeRole::Global),
            ).await;
            tracing::debug!("Fanout DHT record announce (deprecated): {} sent, {} failed", success, fail);
        } else { match self.mesh_sender.read().clone() { Some(sender) => {
            if let Err(e) = sender.send(message).await {
                tracing::warn!("Failed to broadcast DHT record announce: {}", e);
            } else {
                tracing::debug!("Broadcast DHT record announce to mesh");
            }
        } _ => {}}}
    }

    pub async fn query_record_iterative(&self, key: &str) -> Option<DhtRecord> {
        if !self.config.enabled {
            return None;
        }

        let local_record = self.get_record(key);
        if local_record.is_some() {
            return local_record;
        }

        let routing_manager = self.routing_manager.read().clone();
        let Some(rm) = routing_manager else {
            return None;
        };

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            return None;
        };

        let dht_key = crate::mesh::dht::keys::DhtKey::from_str(key);
        
        if dht_key.is_privileged() && !rm.can_respond_to_privileged() {
            tracing::debug!("Query for privileged key {} requires global node", key);
            return None;
        }

        let target_geo = None;
        let closest_peers = rm.find_closest_peers_hybrid(key, target_geo, 8).await;
        
        if closest_peers.is_empty() {
            return None;
        }

        let mut queried_peers: Vec<String> = Vec::new();
        
        for peer in closest_peers {
            if peer.node_id_string == self.node_id {
                continue;
            }

            if queried_peers.contains(&peer.node_id_string) {
                continue;
            }
            queried_peers.push(peer.node_id_string.clone());

            let request_id = format!("query-{}-{}", key, uuid::Uuid::new_v4());
            let query = MeshMessage::DhtRecordQuery {
                request_id: request_id.into(),
                key: key.into(),
                timestamp: MeshMessage::generate_timestamp(),
                source_node_id: self.node_id.clone().into(),
            };

            if transport.send_datagram_to_peer(&peer.node_id_string, &query).await.is_ok() {
                tracing::debug!("Sent DHT record query for {} to peer {}", key, peer.node_id_string);
            }
        }

        None
    }

    pub async fn announce_record_to_closest(&self, record: &DhtRecord, replication_factor: usize) -> usize {
        if !self.config.enabled || !self.is_global_node() {
            return 0;
        }

        let routing_manager = self.routing_manager.read().clone();
        let Some(rm) = routing_manager else {
            return 0;
        };

        let transport_opt = self.transport.read().clone();
        let Some(transport) = transport_opt else {
            return 0;
        };

        let target_geo = None;
        let closest_peers = rm.find_closest_peers_hybrid(&record.key, target_geo, replication_factor).await;
        
        if closest_peers.is_empty() {
            return 0;
        }

        let request_id = format!("announce-{}-{}", record.key, uuid::Uuid::new_v4());
        
        let signer_public_key = {
            let mesh_signer = self.mesh_signer.read();
            mesh_signer.as_ref().map(|s| s.get_public_key()).unwrap_or_default()
        };
        
        let announce = MeshMessage::DhtRecordAnnounce {
            request_id: request_id.into(),
            records: vec![record.clone()],
            write_quorum: self.config.write_quorum,
            timestamp: MeshMessage::generate_timestamp(),
            source_node_id: self.node_id.clone().into(),
            signature: Vec::new(),
            signer_public_key,
        };

        let mut success_count = 0;
        
        for peer in closest_peers {
            if peer.node_id_string == self.node_id {
                continue;
            }

            if transport.send_datagram_to_peer(&peer.node_id_string, &announce).await.is_ok() {
                success_count += 1;
            }
        }

        let write_quorum = self.config.write_quorum as usize;
        if success_count >= write_quorum {
            counter!("maluwaf.dht.quorum.achieved", "type" => "write").increment(1);
            tracing::debug!("DHT write quorum achieved for {}: {}/{} peers", record.key, success_count, write_quorum);
        } else {
            counter!("maluwaf.dht.quorum.failed", "type" => "write").increment(1);
            tracing::debug!("DHT write quorum NOT achieved for {}: {}/{} peers", record.key, success_count, write_quorum);
        }
        
        tracing::debug!("Announced record {} to {} peers", record.key, success_count);
        success_count
    }

    pub fn init_propagation_state(&self, key: &str) {
        let mut states = self.propagation_states.write();
        if !states.contains_key(key) {
            states.insert(key.to_string(), PropagationState {
                key: key.to_string(),
                ack_count: 0,
                attempted_peers: Vec::new(),
                completed: false,
                last_update: Instant::now(),
            });
        }
    }

    pub fn record_propagation_attempt(&self, key: &str, peer_id: &str) {
        let mut states = self.propagation_states.write();
        if let Some(state) = states.get_mut(key) {
            if !state.attempted_peers.contains(&peer_id.to_string()) {
                state.attempted_peers.push(peer_id.to_string());
                state.last_update = Instant::now();
            }
        }
    }

    pub fn record_propagation_ack(&self, key: &str) -> bool {
        let mut states = self.propagation_states.write();
        if let Some(state) = states.get_mut(key) {
            state.ack_count += 1;
            state.last_update = Instant::now();
            
            if state.ack_count >= self.convergence_threshold {
                state.completed = true;
                tracing::debug!("DHT propagation converged for key {} after {} acks", key, state.ack_count);
                return true;
            }
        }
        false
    }

    pub fn is_propagation_complete(&self, key: &str) -> bool {
        let states = self.propagation_states.read();
        states.get(key).map(|s| s.completed).unwrap_or(false)
    }

    pub fn get_propagation_state(&self, key: &str) -> Option<PropagationState> {
        let states = self.propagation_states.read();
        states.get(key).cloned()
    }

    pub fn cleanup_stale_propagation_states(&self, max_age_secs: u64) {
        let mut states = self.propagation_states.write();
        let now = Instant::now();
        states.retain(|_, state| {
            now.duration_since(state.last_update).as_secs() < max_age_secs
        });
    }

    pub fn get_pending_propagations(&self) -> Vec<String> {
        let states = self.propagation_states.read();
        states
            .values()
            .filter(|s| !s.completed)
            .map(|s| s.key.clone())
            .collect()
    }

    fn get_sender_reputation(&self, from_node: &str, signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>) -> i64 {
        if signer.is_some() {
            return 75;
        }
        0
    }

    pub fn handle_mesh_message(
        &self,
        message: &MeshMessage,
        from_node: &str,
        signer: Option<&Arc<crate::mesh::protocol::MeshMessageSigner>>,
    ) -> Option<MeshMessage> {
        let timestamp = match message {
            MeshMessage::DhtRecordAnnounce { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordQuery { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordResponse { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtSyncResponse { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtAntiEntropyRequest { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtAntiEntropyResponse { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordPush { timestamp, .. } => Some(*timestamp),
            MeshMessage::DhtRecordPushAck { timestamp, .. } => Some(*timestamp),
            _ => None,
        };

        if let Some(ts) = timestamp {
            if !validate_message_timestamp(ts) {
                tracing::warn!("DHT message rejected: timestamp {} outside acceptable window", ts);
                return None;
            }
        }

        if self.is_rate_limited(from_node) {
            tracing::warn!("DHT message rejected: rate limited peer {}", from_node);
            return None;
        }

        match message {
            MeshMessage::DhtRecordAnnounce {
                request_id: _,
                records,
                write_quorum: _,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => {
                tracing::debug!(
                    "Received DhtRecordAnnounce from {} with {} records",
                    from_node,
                    records.len()
                );

                if let Some(signer) = signer {
                    if !signature.is_empty() {
                        let content = format!(
                            "{},{},{},{}",
                            source_node_id,
                            records.len(),
                            self.node_role.bits(),
                            timestamp
                        );
                        let pk_bytes = if signer_public_key.is_empty() {
                            Vec::new()
                        } else {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(&signer_public_key)
                                .unwrap_or_default()
                        };
                        if !signer.verify(&content, signature, &pk_bytes) {
                            tracing::warn!(
                                "DhtRecordAnnounce signature verification failed from {}",
                                from_node
                            );
                            return None;
                        }
                    }
                }

                let reputation = self.get_sender_reputation(from_node, signer);
                self.handle_record_announce(records.clone(), from_node, reputation, signer);
                None
            }
            MeshMessage::DhtRecordQuery {
                request_id,
                key,
                timestamp: _,
                source_node_id: _,
            } => {
                tracing::debug!("Received DhtRecordQuery from {} for key: {}", from_node, key);
                self.handle_record_query(request_id, key, from_node)
            }
            MeshMessage::DhtRecordResponse {
                request_id: _,
                key: _,
                value: _,
                found: _,
                timestamp: _,
                source_node_id: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::debug!("Received DhtRecordResponse from {}", from_node);
                None
            }
            MeshMessage::DhtSyncRequest {
                request_id,
                node_id: _,
                from_version,
            } => {
                tracing::debug!(
                    "Received DhtSyncRequest from {} (version: {})",
                    from_node,
                    from_version
                );
                self.handle_sync_request(request_id, from_node, *from_version)
            }
            MeshMessage::DhtSyncResponse {
                request_id: _,
                records,
                version: _,
                timestamp: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::debug!(
                    "Received DhtSyncResponse from {} with {} records",
                    from_node,
                    records.len()
                );
                self.handle_sync_response(records.clone(), from_node);
                None
            }
            MeshMessage::DhtAntiEntropyRequest {
                request_id,
                node_id,
                local_root_hash,
                interested_keys,
                timestamp: _,
                ..
            } => {
                tracing::debug!(
                    "Received DhtAntiEntropyRequest from {} for {} keys",
                    from_node,
                    interested_keys.len()
                );
                self.handle_anti_entropy_request(
                    request_id,
                    local_root_hash,
                    interested_keys,
                    from_node,
                )
            }
            MeshMessage::DhtAntiEntropyResponse {
                request_id: _,
                root_hash: _,
                proof_keys: _,
                proof_hashes: _,
                missing_records,
                timestamp: _,
                signature: _,
                signer_public_key: _,
            } => {
                tracing::debug!(
                    "Received DhtAntiEntropyResponse from {} with {} records",
                    from_node,
                    missing_records.len()
                );
                self.handle_anti_entropy_response(message, from_node);
                None
            }
            MeshMessage::DhtRecordPush {
                request_id,
                records,
                hop_count,
                seen_node_ids,
                timestamp: _,
                signer_public_key: _,
            } => {
                tracing::debug!(
                    "Received DhtRecordPush from {} with {} records, hop {}",
                    from_node,
                    records.len(),
                    hop_count
                );
                
                if seen_node_ids.contains(&self.node_id) {
                    tracing::debug!("DhtRecordPush already seen, skipping");
                    return None;
                }

                let reputation = self.get_sender_reputation(from_node, signer);
                for record in records {
                    self.store_record(record.clone(), reputation);
                    self.init_propagation_state(&record.key);
                }
                self.compute_merkle_tree();

                if *hop_count < 5 {
                    let new_seen_ids: Vec<String> = seen_node_ids.iter()
                        .chain(std::iter::once(&self.node_id))
                        .cloned()
                        .collect();
                    
                    let ack = MeshMessage::DhtRecordPushAck {
                        request_id: format!("{}-ack", request_id).into(),
                        original_request_id: request_id.clone(),
                        node_id: self.node_id.clone().into(),
                        accepted: true,
                        missing_keys: Vec::new(),
                        timestamp: MeshMessage::generate_timestamp(),
                    };
                    
                    Some(ack)
                } else {
                    None
                }
            }
            MeshMessage::DhtRecordPushAck {
                request_id: _,
                original_request_id,
                node_id,
                accepted,
                missing_keys: _,
                timestamp: _,
            } => {
                tracing::debug!(
                    "Received DhtRecordPushAck from {} for {}: accepted={}",
                    node_id,
                    original_request_id,
                    accepted
                );
                
                if *accepted {
                    self.record_propagation_ack(original_request_id);
                }
                None
            }
            _ => None,
        }
    }

    pub fn compute_merkle_tree(&self) {
        let records = self.records.read();
        let mut record_map = HashMap::new();
        
        for (key, entry) in records.iter() {
            record_map.insert(key.clone(), entry.record.value.clone());
        }
        
        let tree = MerkleTree::from_records(&record_map);
        
        let mut merkle = self.merkle_tree.write();
        *merkle = Some(tree);
    }

    pub fn get_merkle_root_hash(&self) -> Option<Vec<u8>> {
        let merkle = self.merkle_tree.read();
        merkle.as_ref().and_then(|t| t.root_hash())
    }

    pub fn generate_merkle_proof(&self, keys: &[String]) -> Option<crate::mesh::dht::merkle::MerkleProof> {
        let merkle = self.merkle_tree.read();
        merkle.as_ref().and_then(|t| t.generate_proof(keys))
    }

    pub fn get_records_for_keys(&self, keys: &[String]) -> Vec<DhtRecord> {
        let records = self.records.read();
        keys.iter()
            .filter_map(|k| records.get(k).map(|e| e.record.clone()))
            .collect()
    }

    pub fn handle_anti_entropy_request(
        &self,
        request_id: &str,
        local_root_hash: &[u8],
        interested_keys: &[String],
        from_node: &str,
    ) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        let my_root_hash = self.get_merkle_root_hash();
        
        if my_root_hash.as_ref().map(|h| h.as_slice()) == Some(local_root_hash) {
            tracing::debug!("DHT anti-entropy: {} has same root hash as {}", from_node, self.node_id);
            return Some(MeshMessage::DhtAntiEntropyResponse {
                request_id: request_id.into(),
                root_hash: local_root_hash.to_vec(),
                proof_keys: interested_keys.to_vec(),
                proof_hashes: Vec::new(),
                missing_records: Vec::new(),
                timestamp: MeshMessage::generate_timestamp(),
                signature: Vec::new(),
                signer_public_key: String::new(),
            });
        }

        let records = self.get_records_for_keys(interested_keys);
        
        let proof = self.generate_merkle_proof(interested_keys);
        let proof_keys: Vec<String> = proof.as_ref().map(|p| p.queried_keys.clone()).unwrap_or_default();
        let proof_hashes: Vec<Vec<u8>> = proof.as_ref().map(|p| {
            p.proof_nodes.iter().map(|n| n.hash.clone()).collect()
        }).unwrap_or_default();

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();
        
        let mesh_signer = self.mesh_signer.read();
        if let Some(ref signer) = *mesh_signer {
            let timestamp = MeshMessage::generate_timestamp();
            let content = format!(
                "{},{},{},{},{}",
                request_id,
                proof_keys.len(),
                records.len(),
                self.node_role.bits(),
                timestamp
            );
            signature = signer.sign(&content);
            signer_public_key = signer.get_public_key();
        }

        tracing::debug!(
            "DHT anti-entropy: responding to {} with {} records (hash mismatch)",
            from_node,
            records.len()
        );

        Some(MeshMessage::DhtAntiEntropyResponse {
            request_id: request_id.into(),
            root_hash: my_root_hash.unwrap_or_default(),
            proof_keys,
            proof_hashes,
            missing_records: records,
            timestamp: MeshMessage::generate_timestamp(),
            signature,
            signer_public_key,
        })
    }

    pub fn handle_anti_entropy_response(
        &self,
        response: &MeshMessage,
        from_node: &str,
    ) {
        if !self.config.enabled {
            return;
        }

        let MeshMessage::DhtAntiEntropyResponse {
            request_id: _,
            root_hash: _,
            proof_keys: _,
            proof_hashes: _,
            missing_records,
            timestamp: _,
            signature: _,
            signer_public_key: _,
        } = response else {
            return;
        };

        if missing_records.is_empty() {
            tracing::debug!("DHT anti-entropy: no missing records from {}", from_node);
            return;
        }

        let mut stored_count = 0;
        let reputation = self.get_sender_reputation(from_node, None);
        
        for record in missing_records {
            if self.store_record(record.clone(), reputation) {
                stored_count += 1;
            }
        }

        self.compute_merkle_tree();
        
        tracing::info!(
            "DHT anti-entropy: stored {} records from {}",
            stored_count,
            from_node
        );
    }

    pub fn start_background_tasks(&self) {
        let config = self.config.clone();
        let node_id = self.node_id.clone();
        let node_role = self.node_role;
        let initial_interval = self.config.initial_sync_interval_secs;
        let replication_factor = self.config.replication_factor;
        let self_arc = Arc::new(self.clone());
        let merkle_self = Arc::downgrade(&self_arc);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            let mut last_sync = Instant::now();

            loop {
                interval.tick().await;

                if !config.enabled || node_role != MeshNodeRole::Global {
                    continue;
                }

                if last_sync.elapsed().as_secs() > initial_interval {
                    tracing::debug!("DHT sync interval reached");
                    last_sync = Instant::now();

                    if let Some(record_store) = merkle_self.upgrade() {
                        if record_store.is_routing_enabled() {
                            tracing::debug!("Skipping anti-entropy: Kademlia routing is enabled");
                            continue;
                        }
                        let _ = Self::run_anti_entropy_cycle(&record_store, replication_factor).await;
                    }
                }
            }
        });
    }

    async fn run_anti_entropy_cycle(
        record_store: &Arc<RecordStoreManager>,
        replication_factor: usize,
    ) {
        let transport = match record_store.transport.read().clone() {
            Some(t) => t,
            None => return,
        };

        let topology = transport.get_topology();
        let peers = topology.get_global_nodes_as_peer_info().await;
        
        if peers.is_empty() {
            return;
        }

        let my_root_hash = match record_store.get_merkle_root_hash() {
            Some(h) => h,
            None => return,
        };

        let node_id = record_store.node_id.clone();

        let peer_count = peers.len().min(replication_factor);
        let selected_peers: Vec<_> = peers.into_iter().take(peer_count).collect();

        let signer_public_key = {
            let mesh_signer = record_store.mesh_signer.read();
            mesh_signer.as_ref().map(|s| s.get_public_key()).unwrap_or_default()
        };

        let transport_clone = transport.clone();
        
        let anti_entropy_futures: Vec<_> = selected_peers.iter().map(|peer| {
            let request_id = MeshMessage::generate_nonce().to_string();
            
            let interested_keys: Vec<String> = {
                let records = record_store.records.read();
                let mut entries: Vec<_> = records.iter()
                    .map(|(k, v)| (k.clone(), v.version))
                    .collect();
                entries.sort_by(|a, b| b.1.cmp(&a.1));
                entries.into_iter()
                    .take(100)
                    .map(|(k, _)| k)
                    .collect()
            };

            let request = MeshMessage::DhtAntiEntropyRequest {
                request_id: request_id.into(),
                node_id: node_id.clone().into(),
                local_root_hash: my_root_hash.clone(),
                interested_keys,
                timestamp: MeshMessage::generate_timestamp(),
                signer_public_key: signer_public_key.clone(),
            };

            let transport = transport_clone.clone();
            async move {
                if let Err(e) = transport.send_datagram_to_peer(&peer.node_id, &request).await {
                    tracing::debug!("DHT anti-entropy request to {} failed: {}", peer.node_id, e);
                } else {
                    tracing::debug!("DHT anti-entropy request sent to {}", peer.node_id);
                }
            }
        }).collect();

        futures::future::join_all(anti_entropy_futures).await;
    }

    pub fn store_dns_domain_registration(
        &self,
        domain: String,
        origin_node_id: String,
        ip_addresses: Vec<String>,
        ttl_seconds: u64,
    ) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            tracing::warn!("DNS domain registration rejected: not a global node or DHT disabled");
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let value = serde_json::json!({
            "domain": domain,
            "origin_node_id": origin_node_id,
            "ip_addresses": ip_addresses,
            "registered_at": now,
        });

        let value = match serde_json::to_vec(&value) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize DNS domain registration: {}", e);
                return false;
            }
        };

        let dht_key = DhtKey::dns_domain_registration(&domain);
        let key = dht_key.as_str();

        let record = DhtRecord {
            key,
            value,
            timestamp: now,
            ttl_seconds,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
        };

        let stored = self.store_record_global(record);
        if stored {
            tracing::info!("Stored DNS domain registration for {} in DHT", domain);
        }
        stored
    }

    pub fn get_dns_domain_registration(&self, domain: &str) -> Option<serde_json::Value> {
        if !self.config.enabled || !self.is_global_node() {
            return None;
        }

        let key = DhtKey::dns_domain_registration(domain).as_str();
        let record = self.get_record(&key)?;

        serde_json::from_slice(&record.value).ok()
    }

    pub fn get_all_dns_domain_registrations(&self) -> Vec<(String, String, Vec<String>)> {
        if !self.config.enabled || !self.is_global_node() {
            return Vec::new();
        }

        let records = self.records.read();
        let mut registrations = Vec::new();

        for (key, entry) in records.iter() {
            if key.starts_with("dns_domain_reg:") {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.record.value) {
                    let domain = value.get("domain").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let origin_id = value.get("origin_node_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let ips: Vec<String> = value.get("ip_addresses")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    registrations.push((domain, origin_id, ips));
                }
            }
        }

        registrations
    }

    pub fn remove_dns_domain_registration(&self, domain: &str) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let key = DhtKey::dns_domain_registration(domain).as_str();
        self.remove(&key)
    }

    #[cfg(feature = "dns")]
    pub fn store_anycast_node(
        &self,
        node_id: String,
        anycast_ips: Vec<String>,
        geo: Option<String>,
        capacity: u32,
        healthy: bool,
        dns_zones: Vec<String>,
    ) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            tracing::warn!("Anycast node storage rejected: not a global node or DHT disabled");
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let value = serde_json::json!({
            "node_id": node_id,
            "anycast_ips": anycast_ips,
            "geo": geo,
            "capacity": capacity,
            "healthy": healthy,
            "dns_zones": dns_zones,
            "registered_at": now,
        });

        let value = match serde_json::to_vec(&value) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize anycast node: {}", e);
                return false;
            }
        };

        let dht_key = DhtKey::anycast_node(&node_id);
        let key = dht_key.as_str();

        let record = DhtRecord {
            key,
            value,
            timestamp: now,
            ttl_seconds: 600,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
        };

        let stored = self.store_record_global(record);
        if stored {
            tracing::info!("Stored anycast node {} in DHT", node_id);
        }
        stored
    }

    #[cfg(feature = "dns")]
    pub fn get_anycast_node(&self, node_id: &str) -> Option<serde_json::Value> {
        if !self.config.enabled {
            return None;
        }

        let key = DhtKey::anycast_node(node_id).as_str();
        let record = self.get_record(&key)?;

        serde_json::from_slice(&record.value).ok()
    }

    #[cfg(feature = "dns")]
    pub fn get_anycast_nodes_for_zone(&self, zone: &str) -> Vec<serde_json::Value> {
        if !self.config.enabled {
            return Vec::new();
        }

        let records = self.records.read();
        let mut nodes = Vec::new();

        for (key, entry) in records.iter() {
            if key.starts_with("anycast_node:") {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.record.value) {
                    let zones: Vec<String> = value.get("dns_zones")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    
                    if zones.contains(&zone.to_string()) {
                        nodes.push(value.clone());
                    }
                }
            }
        }

        nodes
    }

    #[cfg(feature = "dns")]
    pub fn get_all_anycast_nodes(&self) -> Vec<serde_json::Value> {
        if !self.config.enabled {
            return Vec::new();
        }

        let records = self.records.read();
        let mut nodes = Vec::new();

        for (key, entry) in records.iter() {
            if key.starts_with("anycast_node:") {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.record.value) {
                    nodes.push(value.clone());
                }
            }
        }

        nodes
    }

    #[cfg(feature = "dns")]
    pub fn remove_anycast_node(&self, node_id: &str) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let key = DhtKey::anycast_node(node_id).as_str();
        self.remove(&key)
    }
}

impl Clone for RecordStoreManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            mesh_signer: RwLock::new(self.mesh_signer.read().clone()),
            record_signer: RwLock::new(self.record_signer.read().clone()),
            access_control: self.access_control.clone(),
            local_version: RwLock::new(*self.local_version.read()),
            records: RwLock::new(self.records.read().clone()),
            mesh_sender: self.mesh_sender.clone(),
            transport: self.transport.clone(),
            routing_manager: RwLock::new(self.routing_manager.read().clone()),
            stake_manager: RwLock::new(self.stake_manager.read().clone()),
            last_sync: RwLock::new(*self.last_sync.read()),
            pending_announces: RwLock::new(self.pending_announces.read().clone()),
            cache_hits: RwLock::new(*self.cache_hits.read()),
            cache_misses: RwLock::new(*self.cache_misses.read()),
            last_snapshot_version: RwLock::new(*self.last_snapshot_version.read()),
            initial_sync_completed: RwLock::new(*self.initial_sync_completed.read()),
            current_sync_interval: RwLock::new(*self.current_sync_interval.read()),
            recent_changes: RwLock::new(self.recent_changes.read().clone()),
            merkle_tree: RwLock::new(self.merkle_tree.read().clone()),
            propagation_states: RwLock::new(self.propagation_states.read().clone()),
            convergence_threshold: self.convergence_threshold,
            rate_limiter: RwLock::new(self.rate_limiter.read().clone()),
            network_policy: RwLock::new(self.network_policy.read().clone()),
            blocklist: RwLock::new(self.blocklist.read().clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordStoreStats {
    pub node_id: String,
    pub node_role: MeshNodeRole,
    pub version: u64,
    pub record_count: usize,
    pub pending_announce_count: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub is_global: bool,
    pub last_snapshot_version: u64,
}

impl RecordStoreManager {
    pub fn get_stats(&self) -> RecordStoreStats {
        RecordStoreStats {
            node_id: self.node_id.clone(),
            node_role: self.node_role,
            version: *self.local_version.read(),
            record_count: self.records.read().len(),
            pending_announce_count: self.pending_announces.read().len(),
            cache_hits: *self.cache_hits.read(),
            cache_misses: *self.cache_misses.read(),
            is_global: self.is_global_node(),
            last_snapshot_version: *self.last_snapshot_version.read(),
        }
    }
}
