use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct RecordMetadata {
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u64,
    pub publisher: Option<String>,
}

impl RecordMetadata {
    pub fn new(publisher: Option<String>) -> Self {
        let now = synvoid_utils::safe_unix_timestamp();

        Self {
            created_at: now,
            updated_at: now,
            version: 1,
            publisher,
        }
    }

    pub fn increment_version(&mut self) {
        self.version += 1;
        self.updated_at = synvoid_utils::safe_unix_timestamp();
    }
}

#[derive(Debug, Clone)]
pub struct DhtRecord {
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: RecordMetadata,
}

impl DhtRecord {
    pub fn new(key: String, value: Vec<u8>, publisher: Option<String>) -> Self {
        Self {
            key,
            value,
            metadata: RecordMetadata::new(publisher),
        }
    }
}

pub struct DhtRecordStore {
    records: Arc<RwLock<HashMap<String, DhtRecord>>>,
    max_records: usize,
}

impl DhtRecordStore {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            max_records: 10000,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::with_capacity(capacity))),
            max_records: capacity,
        }
    }

    pub fn get(&self, key: &str) -> Option<DhtRecord> {
        self.records.read().get(key).cloned()
    }

    pub fn put(&self, record: DhtRecord) {
        let mut records = self.records.write();

        if records.len() >= self.max_records && !records.contains_key(&record.key) {
            tracing::warn!("DHT record store is full, rejecting new record");
            return;
        }

        let key = record.key.clone();
        records.insert(key, record);
    }

    pub fn remove(&self, key: &str) -> Option<DhtRecord> {
        self.records.write().remove(key)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.records.read().contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.records.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.read().is_empty()
    }

    pub fn keys(&self) -> Vec<String> {
        self.records.read().keys().cloned().collect()
    }

    pub fn values(&self) -> Vec<DhtRecord> {
        self.records.read().values().cloned().collect()
    }

    pub fn clear(&self) {
        self.records.write().clear();
    }

    pub fn get_by_prefix(&self, prefix: &str) -> Vec<DhtRecord> {
        self.records
            .read()
            .values()
            .filter(|r| r.key.starts_with(prefix))
            .cloned()
            .collect()
    }
}

impl Default for DhtRecordStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_storage() {
        let store = DhtRecordStore::new();

        let key = "test_key".to_string();
        let value = b"test_value".to_vec();

        let record = DhtRecord::new(key.clone(), value.clone(), None);
        store.put(record);

        let retrieved = store.get(&key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, value);

        let removed = store.remove(&key);
        assert!(removed.is_some());

        let retrieved = store.get(&key);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_prefix_search() {
        let store = DhtRecordStore::new();

        store.put(DhtRecord::new(
            "org:test".to_string(),
            b"value1".to_vec(),
            None,
        ));

        store.put(DhtRecord::new(
            "upstream:test".to_string(),
            b"value2".to_vec(),
            None,
        ));

        store.put(DhtRecord::new(
            "org:other".to_string(),
            b"value3".to_vec(),
            None,
        ));

        let org_records = store.get_by_prefix("org:");
        assert_eq!(org_records.len(), 2);

        let upstream_records = store.get_by_prefix("upstream:");
        assert_eq!(upstream_records.len(), 1);
    }
}
