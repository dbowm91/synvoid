use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

use crate::mesh::dht::record_store::{DhtRecordEntry, RecordStoreManager};
use crate::mesh::protocol::DhtRecord;

const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedNeighborhood {
    version: u32,
    node_id: String,
    mesh_id: String,
    persisted_at: u64,
    records: Vec<PersistedRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRecord {
    key: String,
    value: Vec<u8>,
    timestamp: u64,
    sequence_number: u64,
    ttl_seconds: u64,
    source_node_id: String,
    content_hash: Vec<u8>,
}

impl RecordStoreManager {
    pub fn start_recovery_worker(&self) {
        let self_arc = Arc::new(self.clone());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            tracing::info!("RecoveryWorker: scanning for PendingQuorum records");
            let pending_records = {
                let rs = self_arc.record_state.read();
                if let Some(ref disk_store) = rs.disk_store {
                    disk_store.get_pending_quorum_records()
                } else {
                    Vec::new()
                }
            };

            if pending_records.is_empty() {
                tracing::info!("RecoveryWorker: no PendingQuorum records found");
                return;
            }

            tracing::warn!("RecoveryWorker: found {} PendingQuorum records, re-initializing quorum requests", pending_records.len());

            for (key, entry) in pending_records {
                let now = crate::mesh::safe_unix_timestamp();
                let record_age = now.saturating_sub(entry.record.timestamp);
                let ttl = entry.record.ttl_seconds;

                if entry.record.timestamp + entry.record.ttl_seconds < now {
                    tracing::warn!("RecoveryWorker: record {} is expired (age {}s, ttl {}s), removing", key, record_age, ttl);
                    let mut rs = self_arc.record_state.write();
                    rs.records.remove(&key);
                    if let Some(ref disk_store) = rs.disk_store {
                        let _ = disk_store.remove(&key);
                    }
                    continue;
                }

                tracing::info!("RecoveryWorker: re-initializing quorum request for key: {}", key);
                let key_clone = key.clone();
                let value_clone = entry.record.value.clone();
                let ttl_clone = entry.record.ttl_seconds;

                let self_clone = self_arc.clone();
                tokio::spawn(async move {
                    if let Some(request_id) = self_clone.start_quorum_request(key_clone.clone(), value_clone.clone(), ttl_clone).await {
                        tracing::info!("RecoveryWorker: restarted quorum request {} for key: {}", request_id, key_clone);
                    } else {
                        tracing::warn!("RecoveryWorker: failed to restart quorum request for key: {}", key_clone);
                    }
                });
            }
        });

        tracing::info!("RecoveryWorker started");
    }

    pub fn persist_neighborhood(&self, storage_path: &Path) -> Result<(), String> {
        let records = self.get_neighborhood_records();
        if records.is_empty() {
            return Ok(());
        }

        let mesh_id = self.node_id.clone();
        let persisted_at = crate::mesh::safe_unix_timestamp();

        let neighborhood = PersistedNeighborhood {
            version: CURRENT_SCHEMA_VERSION,
            node_id: self.node_id.clone(),
            mesh_id,
            persisted_at,
            records: records
                .into_iter()
                .map(|entry| PersistedRecord {
                    key: entry.record.key,
                    value: entry.record.value,
                    timestamp: entry.record.timestamp,
                    sequence_number: entry.record.sequence_number,
                    ttl_seconds: entry.record.ttl_seconds,
                    source_node_id: entry.record.source_node_id,
                    content_hash: entry.record.content_hash,
                })
                .collect(),
        };

        let content = serde_json::to_string_pretty(&neighborhood)
            .map_err(|e| format!("Failed to serialize neighborhood: {}", e))?;

        let temp_path = storage_path.with_extension("tmp");
        std::fs::write(&temp_path, &content)
            .map_err(|e| format!("Failed to write temp file: {}", e))?;

        std::fs::rename(&temp_path, storage_path)
            .map_err(|e| format!("Failed to rename temp file: {}", e))?;

        tracing::debug!(
            "Persisted {} neighborhood records to {:?}",
            neighborhood.records.len(),
            storage_path
        );
        Ok(())
    }

    pub fn load_neighborhood(&self, storage_path: &Path) -> Result<usize, String> {
        if !storage_path.exists() {
            return Ok(0);
        }

        let content = std::fs::read_to_string(storage_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        let neighborhood: PersistedNeighborhood =
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        if neighborhood.version != CURRENT_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported schema version: {}",
                neighborhood.version
            ));
        }

        let mut loaded = 0;
        let now = crate::mesh::safe_unix_timestamp();
        let max_age = self.config.persist_max_age_secs;

        for persisted in neighborhood.records {
            if persisted.timestamp + persisted.ttl_seconds + max_age < now {
                continue;
            }

            let record = DhtRecord {
                key: persisted.key.clone(),
                value: persisted.value,
                timestamp: persisted.timestamp,
                sequence_number: persisted.sequence_number,
                ttl_seconds: persisted.ttl_seconds,
                source_node_id: persisted.source_node_id,
                signature: Vec::new(),
                signer_public_key: None,
                content_hash: persisted.content_hash,
            quorum_proof: Vec::new(),
            };

            let entry = DhtRecordEntry {
                record,
                local_origin: false,
                version: persisted.timestamp,
                status: Default::default(),
            };

            self.record_state
                .read()
                .records
                .insert(persisted.key, entry);
            loaded += 1;
        }

        tracing::info!(
            "Loaded {} DHT records from neighborhood persistence",
            loaded
        );
        Ok(loaded)
    }

    fn get_neighborhood_records(&self) -> Vec<DhtRecordEntry> {
        let records = self.record_state.read().records.values();
        let node_id = self.node_id.clone();
        let max_cache_size = self.config.neighborhood_cache_size;

        let mut with_distance: Vec<_> = records
            .into_iter()
            .map(|r| {
                let distance = key_distance(&r.record.key, &node_id);
                (distance, r)
            })
            .collect();

        with_distance.sort_by_key(|(d, _)| *d);

        with_distance
            .into_iter()
            .take(max_cache_size)
            .map(|(_, r)| r)
            .filter(|r| self.should_persist_record(r))
            .collect()
    }

    fn should_persist_record(&self, record: &DhtRecordEntry) -> bool {
        if record.local_origin {
            return false;
        }

        let now = crate::mesh::safe_unix_timestamp();
        let max_age = self.config.persist_max_age_secs;

        record.record.timestamp + record.record.ttl_seconds + max_age > now
    }

    pub fn start_pruning_task(&self, interval_secs: u64) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                this.prune_expired_persisted_records().await;
            }
        });
    }

    async fn prune_expired_persisted_records(&self) {
        let now = crate::mesh::safe_unix_timestamp();
        let keys_to_remove: Vec<String> = self
            .record_state
            .read()
            .records
            .iter()
            .into_iter()
            .filter(|(_, entry)| entry.record.timestamp + entry.record.ttl_seconds < now)
            .map(|(k, _): (String, DhtRecordEntry)| k.clone())
            .collect();

        for key in keys_to_remove {
            self.record_state.read().records.remove(&key);
        }
    }
}

fn key_distance(key: &str, node_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(node_id.as_bytes());
    let result = hasher.finalize();
    u64::from_le_bytes(result[..8].try_into().unwrap())
}

impl DhtRecordEntry {
    pub fn compute_distance(&self, node_id: &str) -> u64 {
        key_distance(&self.record.key, node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_distance() {
        let d1 = key_distance("test_key", "node_123");
        let d2 = key_distance("test_key", "node_456");
        assert_ne!(d1, d2);

        let d3 = key_distance("same_key", "node_123");
        let d4 = key_distance("same_key", "node_123");
        assert_eq!(d3, d4);
    }

    #[test]
    fn test_persisted_neighborhood_serialization() {
        let neighborhood = PersistedNeighborhood {
            version: CURRENT_SCHEMA_VERSION,
            node_id: "test_node".to_string(),
            mesh_id: "mesh_1".to_string(),
            persisted_at: 1000,
            records: vec![PersistedRecord {
                key: "key1".to_string(),
                value: vec![1, 2, 3],
                timestamp: 1000,
                sequence_number: 1,
                ttl_seconds: 3600,
                source_node_id: "source_1".to_string(),
                content_hash: vec![],
            }],
        };

        let json = serde_json::to_string_pretty(&neighborhood).unwrap();
        let parsed: PersistedNeighborhood = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, CURRENT_SCHEMA_VERSION);
        assert_eq!(parsed.records.len(), 1);
    }
}
