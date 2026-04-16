use super::*;

impl RecordStoreManager {
    pub(crate) fn can_cache_on_edge(&self, key: &str) -> bool {
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
                if let Ok(pk_bytes) =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signer_pk)
                {
                    let value_json = serde_json::to_string(&record.value).unwrap_or_default();
                    let signable = serde_json::to_string(&serde_json::json!({
                        "key": record.key,
                        "source_node_id": record.source_node_id,
                        "timestamp": record.timestamp,
                        "value": record.value,
                    }))
                    .unwrap_or_default();
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

        if let Some(ref stake_mgr) = self.routing_state.read().stake_manager {
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

        if dht_key.is_privileged() {
            if let Err(e) = self.access_control.require_global_node() {
                tracing::warn!(
                    "Record store: {} cannot store privileged record",
                    record.source_node_id
                );
                return false;
            }
        }

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

        if !self
            .access_control
            .can_store(&record.key, false, is_self_record, source_reputation)
        {
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

    pub(crate) fn store_record_global(&self, mut record: DhtRecord) -> bool {
        let now = crate::mesh::safe_unix_timestamp();

        let expires_at = record.timestamp + record.ttl_seconds;
        if now > expires_at {
            tracing::warn!("Received expired record: {}", record.key);
            crate::metrics::record_dht_store_operation(false);
            return false;
        }

        let is_local_record = record.source_node_id == self.node_id;

        if !is_local_record && !record.signature.is_empty() {
            if let Some(ref signer_pk) = record.signer_public_key {
                if !signer_pk.is_empty() {
                    let rs = self.record_state.read();
                    if let Some(ref verifier) = rs.record_signer {
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
                            tracing::warn!(
                                "Rejected record with invalid Ed25519 signature: {}",
                                record.key
                            );
                            return false;
                        }
                        tracing::debug!("Verified Ed25519 signature on record: {}", record.key);
                    }
                }
            }
        }

        let key_requires_quorum = self.access_control.requires_quorum(&record.key);

        if key_requires_quorum && is_local_record {
            let record_store = self.clone();
            let key = record.key.clone();
            let value = record.value.clone();
            let ttl = record.ttl_seconds;

            tokio::spawn(async move {
                if let Some(request_id) = record_store
                    .start_quorum_request(key.clone(), value, ttl)
                    .await
                {
                    tracing::debug!("Started quorum request {} for key: {}", request_id, key);
                    let mut attempts = 0;
                    let max_attempts = 50;

                    while attempts < max_attempts {
                        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

                        if let Some(result) =
                            record_store.check_quorum_completion(&request_id).await
                        {
                            match result {
                                crate::mesh::dht::quorum::QuorumResult::Approved(_) => {
                                    tracing::info!(
                                        "Quorum approved for key: {}, storing record",
                                        key
                                    );
                                    if record_store.store_record_after_quorum(&record).await {
                                        tracing::info!(
                                            "Record stored after quorum for key: {}",
                                            key
                                        );
                                    }
                                    break;
                                }
                                crate::mesh::dht::quorum::QuorumResult::Rejected { .. } => {
                                    tracing::warn!("Quorum rejected for key: {}", key);
                                    break;
                                }
                                crate::mesh::dht::quorum::QuorumResult::Timeout { .. } => {
                                    tracing::warn!("Quorum timeout for key: {}", key);
                                    break;
                                }
                            }
                        }
                        attempts += 1;
                    }
                }
            });

            return true;
        }

        if is_local_record {
            let rs = self.record_state.read();
            if let Some(ref signer) = rs.record_signer {
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

        let mut rs = self.record_state.write();

        let should_replace = match rs.records.get(&record.key) {
            None => true,
            Some(existing_entry) => {
                let existing_key = (
                    existing_entry.record.timestamp,
                    existing_entry.record.sequence_number,
                    existing_entry.record.source_node_id.clone(),
                );
                let new_key = (
                    record.timestamp,
                    record.sequence_number,
                    record.source_node_id.clone(),
                );
                new_key > existing_key
            }
        };

        if !should_replace {
            tracing::debug!(
                "Rejected older record for key {} (existing timestamp: {}, new timestamp: {})",
                record.key,
                rs.records
                    .get(&record.key)
                    .map(|e| e.record.timestamp)
                    .unwrap_or(0),
                record.timestamp
            );
            crate::metrics::record_dht_store_operation(false);
            return false;
        }

        let version = rs.local_version;
        rs.records.insert(
            record.key.clone(),
            DhtRecordEntry {
                record: record.clone(),
                local_origin: is_local_record,
                version,
            },
        );

        rs.local_version += 1;

        tracing::debug!("Stored global record: {}", record.key);

        drop(rs);

        self.maybe_queue_for_announce(&record);

        if self.is_global_node() {
            self.record_change();
        }

        self.compute_merkle_tree();

        let record_type = crate::mesh::dht::keys::DhtKey::from_str(&record.key).key_type();
        crate::metrics::increment_dht_records_by_type(record_type);
        crate::metrics::record_dht_store_operation(true);
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
        let now = crate::mesh::safe_unix_timestamp();

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
            sequence_number: 0,
            ttl_seconds: effective_ttl,
            source_node_id: record.source_node_id.clone(),
            signature: record.signature.clone(),
            signer_public_key: record.signer_public_key.clone(),
            content_hash: record.content_hash.clone(),
        };

        let mut rs = self.record_state.write();

        while rs.records.len() >= self.config.edge_cache_max_entries {
            if let Some(oldest_key) = rs.records.front().map(|(k, _)| k.clone()) {
                rs.records.remove(&oldest_key);
                tracing::debug!("Edge cache full, evicted LRU: {}", oldest_key);
            } else {
                break;
            }
        }

        let version = rs.local_version;
        rs.records.insert(
            record_key,
            DhtRecordEntry {
                record: cache_ttl_record,
                local_origin: false,
                version,
            },
        );

        rs.local_version += 1;

        tracing::debug!("Cached edge record: {}", record.key);

        if self.is_global_node() {
            drop(rs);
            self.compute_merkle_tree();
        }

        crate::metrics::record_dht_store_operation(true);
        true
    }

    pub fn get_record(&self, key: &str) -> Option<DhtRecord> {
        if !self.config.enabled {
            return None;
        }

        let (record, is_expired) = {
            let rs = self.record_state.read();
            match rs.records.get(key) {
                Some(entry) => {
                    let now = crate::mesh::safe_unix_timestamp();
                    let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                    (Some(entry.record.clone()), now >= expires_at)
                }
                None => (None, false),
            }
        };

        if let Some(record) = record {
            if !is_expired {
                if !self.is_global_node() {
                    self.metrics_state.write().cache_hits += 1;
                    let rs = self.record_state.write();
                    if let Some(entry) = rs.records.remove(key) {
                        rs.records.insert(key.to_string(), entry);
                    }
                }
                crate::metrics::record_dht_get_operation(true);
                return Some(record);
            } else {
                let rs = self.record_state.write();
                rs.records.remove(key);
            }
        }

        if !self.is_global_node() {
            self.metrics_state.write().cache_misses += 1;
        }
        crate::metrics::record_dht_get_operation(false);
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
        let rs = self.record_state.read();
        rs.records
            .values()
            .into_iter()
            .filter(|entry| {
                let now = crate::mesh::safe_unix_timestamp();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at
            })
            .map(|e| e.record.clone())
            .collect()
    }

    pub fn get_by_prefix(&self, prefix: &str) -> Vec<DhtRecord> {
        let rs = self.record_state.read();
        rs.records
            .get_by_prefix(prefix)
            .into_iter()
            .filter(|(_, entry)| {
                let now = crate::mesh::safe_unix_timestamp();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at
            })
            .map(|(_, e)| e.record.clone())
            .collect()
    }

    pub fn get_version(&self) -> u64 {
        self.record_state.read().local_version
    }

    pub fn should_sync(&self) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let interval = self.get_adaptive_sync_interval();
        let last = self.metrics_state.read().last_sync;
        last.elapsed() > Duration::from_secs(interval)
    }

    pub fn get_adaptive_sync_interval(&self) -> u64 {
        let base_interval = self.config.sync_interval_secs;

        let mut ms = self.metrics_state.write();
        let now = Instant::now();
        ms.recent_changes
            .retain(|t| now.duration_since(*t).as_secs() < 300);

        let change_count = ms.recent_changes.len();

        if change_count > 10 {
            (base_interval / 4).max(60)
        } else if change_count > 5 {
            (base_interval / 2).max(120)
        } else if change_count == 0 {
            (base_interval * 2).min(self.config.max_sync_interval_secs)
        } else {
            base_interval
        }
    }

    pub fn record_change(&self) {
        let mut ms = self.metrics_state.write();
        ms.recent_changes.push(Instant::now());
    }

    pub fn record_sync(&self) {
        self.metrics_state.write().last_sync = Instant::now();
    }

    pub fn get_records_for_sync(&self, from_version: u64) -> Vec<DhtRecord> {
        let rs = self.record_state.read();

        rs.records
            .values()
            .into_iter()
            .filter(|entry| entry.version > from_version)
            .filter(|entry| {
                let now = crate::mesh::safe_unix_timestamp();
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now < expires_at
            })
            .map(|entry| entry.record.clone())
            .collect()
    }

    pub fn apply_sync(&self, records: Vec<DhtRecord>) {
        let mut rs = self.record_state.write();
        let mut changed = false;

        for record in records {
            let now = crate::mesh::safe_unix_timestamp();

            let expires_at = record.timestamp + record.ttl_seconds;
            if now > expires_at {
                continue;
            }

            let existing = rs.records.get(&record.key);
            let should_replace = match existing {
                None => true,
                Some(existing_entry) => {
                    let existing_key = (
                        existing_entry.record.timestamp,
                        existing_entry.record.sequence_number,
                        existing_entry.record.source_node_id.clone(),
                    );
                    let new_key = (
                        record.timestamp,
                        record.sequence_number,
                        record.source_node_id.clone(),
                    );
                    new_key > existing_key
                }
            };

            if should_replace {
                changed = true;
                let version = rs.local_version + 1;
                rs.records.insert(
                    record.key.clone(),
                    DhtRecordEntry {
                        record,
                        local_origin: false,
                        version,
                    },
                );
            }
        }

        if changed {
            rs.local_version += 1;
            drop(rs);
            self.compute_merkle_tree();
        }
    }

    pub fn queue_for_announce(&self, record: DhtRecord) {
        let mut rs = self.record_state.write();
        if rs.pending_announces.len() >= MAX_PENDING_ANNOUNCES {
            rs.pending_announces.pop_front();
        }
        rs.pending_announces.push_back(record);
        crate::metrics::record_dht_announce_queue_depth(rs.pending_announces.len());
    }

    pub fn cleanup_expired(&self) {
        let now = crate::mesh::safe_unix_timestamp();

        let count_before = self.record_state.read().records.len();

        let rs = self.record_state.write();
        let keys_to_remove: Vec<String> = rs
            .records
            .iter()
            .into_iter()
            .filter(|(_, entry)| {
                let expires_at = entry.record.timestamp + entry.record.ttl_seconds;
                now >= expires_at
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_remove {
            rs.records.remove(&key);
        }

        let count_after = rs.records.len();
        if count_before != count_after {
            tracing::debug!(
                "Cleaned up {} expired DHT records",
                count_before - count_after
            );
        }
    }

    pub fn get_record_count(&self) -> usize {
        self.record_state.read().records.len()
    }

    pub fn create_record_announce(&self) -> Option<MeshMessage> {
        if !self.config.enabled {
            return None;
        }

        let mut rs = self.record_state.write();
        if rs.pending_announces.is_empty() {
            return None;
        }

        let records: Vec<DhtRecord> = rs.pending_announces.iter().cloned().collect();

        let mut signature = Vec::new();
        let mut signer_public_key = String::new();

        if let Some(ref signer) = rs.mesh_signer {
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

        rs.pending_announces.clear();
        crate::metrics::record_dht_announce_queue_depth(0);
        Some(message)
    }

    pub fn publish_global_node_public_key(&self, public_key: &str) -> bool {
        if !self.config.enabled || !self.is_global_node() {
            return false;
        }

        let key = format!("global_node_key:{}", self.node_id);
        let now = crate::mesh::safe_unix_timestamp();

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
            value: value.clone(),
            timestamp: now,
            sequence_number: 0,
            ttl_seconds: 86400,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&value);
                hasher.finalize().to_vec()
            },
        };

        let stored = self.store_record(record.clone(), 100);
        if stored {
            self.queue_for_announce(record);
            tracing::info!("Published global node public key for node {}", self.node_id);
        }
        stored
    }

    pub fn store_and_announce(&self, key: String, value: Vec<u8>, ttl_seconds: u64) -> bool {
        self.store_and_announce_with_broadcast(key, value, ttl_seconds, false, 0)
    }

    pub fn store_and_announce_critical(
        &self,
        key: String,
        value: Vec<u8>,
        ttl_seconds: u64,
        replication_factor: usize,
    ) -> bool {
        self.store_and_announce_with_broadcast(key, value, ttl_seconds, true, replication_factor)
    }

    fn store_and_announce_with_broadcast(
        &self,
        key: String,
        value: Vec<u8>,
        ttl_seconds: u64,
        immediate_broadcast: bool,
        replication_factor: usize,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }

        let now = crate::mesh::safe_unix_timestamp();

        let record = DhtRecord {
            key: key.clone(),
            value: value.clone(),
            timestamp: now,
            sequence_number: 0,
            ttl_seconds,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&value);
                hasher.finalize().to_vec()
            },
        };

        let stored = self.store_record(record.clone(), 100);
        if stored {
            self.queue_for_announce(record.clone());
            tracing::debug!("Stored and queued record for announce: {}", key);

            if immediate_broadcast && self.is_global_node() && replication_factor > 0 {
                let record_store = self.clone();
                tokio::spawn(async move {
                    record_store
                        .announce_record_to_closest(&record, replication_factor)
                        .await;
                });
            }
        }
        stored
    }

    pub fn remove(&self, key: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let rs = self.record_state.write();
        if rs.records.remove(key).is_some() {
            tracing::debug!("Removed record from DHT: {}", key);
            drop(rs);
            self.record_change();
            return true;
        }
        false
    }

    pub fn get(&self, key: &str) -> Option<crate::mesh::protocol::DhtRecord> {
        let rs = self.record_state.read();
        rs.records.get(key).map(|entry| entry.record.clone())
    }
}
