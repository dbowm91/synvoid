use parking_lot::Mutex;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Arc;

use crate::mesh::protocol::{DhtRecord, DhtRecordStatus};

use crate::mesh::dht::record_store::DhtRecordEntry;

pub struct DiskRecordStore {
    conn: Arc<Mutex<Connection>>,
}

impl DiskRecordStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let conn = Connection::open(&path).map_err(|e| format!("Failed to open DB: {}", e))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = 10000;
             PRAGMA temp_store = MEMORY;
             CREATE TABLE IF NOT EXISTS dht_records (
                 key TEXT PRIMARY KEY,
                 value BLOB NOT NULL,
                 timestamp INTEGER NOT NULL,
                 sequence_number INTEGER NOT NULL,
                 ttl_seconds INTEGER NOT NULL,
                 source_node_id TEXT NOT NULL,
                 content_hash BLOB NOT NULL,
                 signature BLOB,
                 signer_public_key TEXT,
                 quorum_proof BLOB,
                 request_id TEXT,
                 local_origin INTEGER NOT NULL,
                 version INTEGER NOT NULL,
                 status INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_timestamp ON dht_records(timestamp);
             CREATE INDEX IF NOT EXISTS idx_source ON dht_records(source_node_id);",
        )
        .map_err(|e| format!("Failed to initialize DB schema: {}", e))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn get(&self, key: &str) -> Option<DhtRecordEntry> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT key, value, timestamp, sequence_number, ttl_seconds, source_node_id, content_hash, signature, signer_public_key, quorum_proof, request_id, local_origin, version, status FROM dht_records WHERE key = ?")
            .ok()?;
        stmt.query_row(params![key], |row| {
            let quorum_proof_bytes: Option<Vec<u8>> = row.get(9)?;
            let quorum_proof = quorum_proof_bytes
                .map(|b| crate::serialization::deserialize(&b).unwrap_or_default())
                .unwrap_or_default();
            Ok(DhtRecordEntry {
                record: DhtRecord {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    timestamp: row.get(2)?,
                    sequence_number: row.get(3)?,
                    ttl_seconds: row.get(4)?,
                    source_node_id: row.get(5)?,
                    signature: row.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
                    signer_public_key: row.get(8)?,
                    content_hash: row.get(6)?,
                    quorum_proof,
                    request_id: row.get(10)?,
                },
                local_origin: row.get::<_, i32>(11)? != 0,
                version: row.get::<_, i64>(12)? as u64,
                status: DhtRecordStatus::from_u8(row.get::<_, i32>(13)? as u8),
            })
        })
        .ok()
    }

    pub fn insert(&self, key: String, value: DhtRecordEntry) -> Option<DhtRecordEntry> {
        let conn = self.conn.lock();
        let old = self.get_internal(&conn, &key);

        conn.execute(
            "INSERT OR REPLACE INTO dht_records (key, value, timestamp, sequence_number, ttl_seconds, source_node_id, content_hash, signature, signer_public_key, quorum_proof, request_id, local_origin, version, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                key,
                value.record.value,
                value.record.timestamp as i64,
                value.record.sequence_number as i64,
                value.record.ttl_seconds as i64,
                value.record.source_node_id,
                value.record.content_hash,
                value.record.signature,
                value.record.signer_public_key,
                crate::serialization::serialize(&value.record.quorum_proof).ok(),
                value.record.request_id,
                if value.local_origin { 1 } else { 0 },
                value.version as i64,
                value.status.to_u8() as i32,
            ],
        )
        .ok()?;

        old
    }

    pub fn remove(&self, key: &str) -> Option<DhtRecordEntry> {
        let conn = self.conn.lock();
        let old = self.get_internal(&conn, key)?;
        conn.execute("DELETE FROM dht_records WHERE key = ?", params![key])
            .ok()?;
        Some(old)
    }

    pub fn len(&self) -> usize {
        let conn = self.conn.lock();
        conn.query_row("SELECT COUNT(*) FROM dht_records", [], |row| row.get(0))
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> Vec<(String, DhtRecordEntry)> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT key, value, timestamp, sequence_number, ttl_seconds, source_node_id, content_hash, signature, signer_public_key, quorum_proof, request_id, local_origin, version, status FROM dht_records")
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                let quorum_proof_bytes: Option<Vec<u8>> = row.get(9)?;
                let quorum_proof = quorum_proof_bytes
                    .map(|b| crate::serialization::deserialize(&b).unwrap_or_default())
                    .unwrap_or_default();
                Ok(DhtRecordEntry {
                    record: DhtRecord {
                        key: row.get(0)?,
                        value: row.get(1)?,
                        timestamp: row.get(2)?,
                        sequence_number: row.get(3)?,
                        ttl_seconds: row.get(4)?,
                        source_node_id: row.get(5)?,
                        signature: row.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
                        signer_public_key: row.get(8)?,
                        content_hash: row.get(6)?,
                        quorum_proof,
                        request_id: row.get(10)?,
                    },
                    local_origin: row.get::<_, i32>(11)? != 0,
                    version: row.get::<_, i64>(12)? as u64,
                    status: DhtRecordStatus::from_u8(row.get::<_, i32>(13)? as u8),
                })
            })
            .unwrap();

        let mut result = Vec::new();
        for row in rows.flatten() {
            result.push((row.record.key.clone(), row));
        }
        result
    }

    pub fn get_by_prefix(&self, prefix: &str, limit: usize) -> Vec<(String, DhtRecordEntry)> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT key, value, timestamp, sequence_number, ttl_seconds, source_node_id, content_hash, signature, signer_public_key, quorum_proof, request_id, local_origin, version, status FROM dht_records WHERE key >= ? AND key < ? ORDER BY key")
            .unwrap();

        let next_prefix = increment_string_prefix(prefix);
        let rows = stmt
            .query_map(params![prefix, next_prefix], |row| {
                let quorum_proof_bytes: Option<Vec<u8>> = row.get(9)?;
                let quorum_proof = quorum_proof_bytes
                    .map(|b| crate::serialization::deserialize(&b).unwrap_or_default())
                    .unwrap_or_default();
                Ok(DhtRecordEntry {
                    record: DhtRecord {
                        key: row.get(0)?,
                        value: row.get(1)?,
                        timestamp: row.get(2)?,
                        sequence_number: row.get(3)?,
                        ttl_seconds: row.get(4)?,
                        source_node_id: row.get(5)?,
                        signature: row.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
                        signer_public_key: row.get(8)?,
                        content_hash: row.get(6)?,
                        quorum_proof,
                        request_id: row.get(10)?,
                    },
                    local_origin: row.get::<_, i32>(11)? != 0,
                    version: row.get::<_, i64>(12)? as u64,
                    status: DhtRecordStatus::from_u8(row.get::<_, i32>(13)? as u8),
                })
            })
            .unwrap();

        let mut result = Vec::new();
        for row in rows.flatten() {
            if result.len() >= limit {
                break;
            }
            if row.record.key.starts_with(prefix) {
                result.push((row.record.key.clone(), row));
            }
        }
        result
    }

    fn get_internal(&self, conn: &Connection, key: &str) -> Option<DhtRecordEntry> {
        let mut stmt = conn
            .prepare("SELECT key, value, timestamp, sequence_number, ttl_seconds, source_node_id, content_hash, signature, signer_public_key, quorum_proof, request_id, local_origin, version, status FROM dht_records WHERE key = ?")
            .ok()?;
        stmt.query_row(params![key], |row| {
            let quorum_proof_bytes: Option<Vec<u8>> = row.get(9)?;
            let quorum_proof = quorum_proof_bytes
                .map(|b| crate::serialization::deserialize(&b).unwrap_or_default())
                .unwrap_or_default();
            Ok(DhtRecordEntry {
                record: DhtRecord {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    timestamp: row.get(2)?,
                    sequence_number: row.get(3)?,
                    ttl_seconds: row.get(4)?,
                    source_node_id: row.get(5)?,
                    signature: row.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
                    signer_public_key: row.get(8)?,
                    content_hash: row.get(6)?,
                    quorum_proof,
                    request_id: row.get(10)?,
                },
                local_origin: row.get::<_, i32>(11)? != 0,
                version: row.get::<_, i64>(12)? as u64,
                status: DhtRecordStatus::from_u8(row.get::<_, i32>(13)? as u8),
            })
        })
        .ok()
    }

    pub fn checkpoint(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .map_err(|e| format!("Checkpoint failed: {}", e))?;
        Ok(())
    }

    pub fn vacuum(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute_batch("VACUUM")
            .map_err(|e| format!("Vacuum failed: {}", e))?;
        Ok(())
    }
}

fn increment_string_prefix(prefix: &str) -> String {
    let bytes = prefix.as_bytes();
    let mut result = bytes.to_vec();

    let mut i = result.len();
    while i > 0 {
        i -= 1;
        if result[i] < 0xFF {
            result[i] += 1;
            return String::from_utf8(result).unwrap_or_else(|_| {
                let mut r = bytes.to_vec();
                r.push(0);
                String::from_utf8(r).unwrap_or_default()
            });
        }
        result[i] = 0;
    }

    result.push(0);
    String::from_utf8(result).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn cleanup_db(db_path: &std::path::Path) {
        let _ = fs::remove_file(db_path);
        let _ = fs::remove_file(db_path.with_extension("db-wal"));
        let _ = fs::remove_file(db_path.with_extension("db-shm"));
    }

    #[test]
    fn test_disk_store_basic_ops() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_dht_store.db");
        cleanup_db(&db_path);

        let store = DiskRecordStore::new(&db_path).unwrap();

        let entry = DhtRecordEntry {
            record: DhtRecord {
                key: "test_key".to_string(),
                value: vec![1, 2, 3],
                timestamp: 1000,
                sequence_number: 1,
                ttl_seconds: 3600,
                source_node_id: "node_1".to_string(),
                signature: Vec::new(),
                signer_public_key: None,
                content_hash: vec![],
                quorum_proof: Vec::new(),
                request_id: None,
            },
            local_origin: true,
            version: 1,
            status: DhtRecordStatus::Live,
        };

        let old = store.insert("test_key".to_string(), entry.clone());
        assert!(old.is_none());

        let retrieved = store.get("test_key").unwrap();
        assert_eq!(retrieved.record.key, "test_key");
        assert_eq!(retrieved.record.value, vec![1, 2, 3]);

        let old = store.remove("test_key").unwrap();
        assert_eq!(old.record.key, "test_key");

        assert!(store.get("test_key").is_none());
        assert!(store.is_empty());

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_disk_store_replace() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_dht_store_replace.db");
        cleanup_db(&db_path);

        let store = DiskRecordStore::new(&db_path).unwrap();

        let entry1 = DhtRecordEntry {
            record: DhtRecord {
                key: "test_key".to_string(),
                value: vec![1],
                timestamp: 1000,
                sequence_number: 1,
                ttl_seconds: 3600,
                source_node_id: "node_1".to_string(),
                signature: Vec::new(),
                signer_public_key: None,
                content_hash: vec![],
                quorum_proof: Vec::new(),
                request_id: None,
            },
            local_origin: true,
            version: 1,
            status: DhtRecordStatus::Live,
        };

        let entry2 = DhtRecordEntry {
            record: DhtRecord {
                key: "test_key".to_string(),
                value: vec![2],
                timestamp: 2000,
                sequence_number: 2,
                ttl_seconds: 3600,
                source_node_id: "node_1".to_string(),
                signature: Vec::new(),
                signer_public_key: None,
                content_hash: vec![],
                quorum_proof: Vec::new(),
                request_id: None,
            },
            local_origin: true,
            version: 2,
            status: DhtRecordStatus::Live,
        };

        store.insert("test_key".to_string(), entry1.clone());
        let old = store
            .insert("test_key".to_string(), entry2.clone())
            .unwrap();
        assert_eq!(old.record.value, vec![1]);

        let retrieved = store.get("test_key").unwrap();
        assert_eq!(retrieved.record.value, vec![2]);
        assert_eq!(retrieved.version, 2);

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_prefix_query() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_dht_prefix.db");
        cleanup_db(&db_path);

        let store = DiskRecordStore::new(&db_path).unwrap();

        for i in 0..5 {
            let entry = DhtRecordEntry {
                record: DhtRecord {
                    key: format!("key{:03}", i),
                    value: vec![i as u8],
                    timestamp: 1000 + i as u64,
                    sequence_number: i as u64,
                    ttl_seconds: 3600,
                    source_node_id: "node_1".to_string(),
                    signature: Vec::new(),
                    signer_public_key: None,
                    content_hash: vec![],
                    quorum_proof: Vec::new(),
                    request_id: None,
                },
                local_origin: false,
                version: i as u64,
                status: DhtRecordStatus::Live,
            };
            store.insert(format!("key{:03}", i), entry);
        }

        let results = store.get_by_prefix("key", 10);
        assert_eq!(results.len(), 5);

        let results = store.get_by_prefix("key000", 10);
        assert_eq!(results.len(), 1);

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_checkpoint() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_dht_checkpoint.db");
        cleanup_db(&db_path);

        let store = DiskRecordStore::new(&db_path).unwrap();

        let entry = DhtRecordEntry {
            record: DhtRecord {
                key: "test_key".to_string(),
                value: vec![1, 2, 3],
                timestamp: 1000,
                sequence_number: 1,
                ttl_seconds: 3600,
                source_node_id: "node_1".to_string(),
                signature: Vec::new(),
                signer_public_key: None,
                content_hash: vec![],
                quorum_proof: Vec::new(),
                request_id: None,
            },
            local_origin: true,
            version: 1,
            status: DhtRecordStatus::Live,
        };

        store.insert("test_key".to_string(), entry);
        store.checkpoint().unwrap();

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_regression_disk_persistence_drops_security_metadata() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_dht_security_metadata.db");
        cleanup_db(&db_path);

        let store = DiskRecordStore::new(&db_path).unwrap();

        let signature = vec![0xDEu8; 64];
        let signer_pk = "fake_public_key_base64".to_string();
        let quorum_proof = vec![
            crate::mesh::protocol::QuorumSignatureProto {
                node_id: "global1".to_string(),
                signature: vec![1u8; 64],
                timestamp: 1000,
                signer_public_key: None,
            },
            crate::mesh::protocol::QuorumSignatureProto {
                node_id: "global2".to_string(),
                signature: vec![2u8; 64],
                timestamp: 1001,
                signer_public_key: None,
            },
        ];
        let content_hash = vec![0xABu8; 32];

        let entry = DhtRecordEntry {
            record: DhtRecord {
                key: "verified_upstream:test.com".to_string(),
                value: b"test_value".to_vec(),
                timestamp: 1000,
                sequence_number: 1,
                ttl_seconds: 3600,
                source_node_id: "node_1".to_string(),
                signature: signature.clone(),
                signer_public_key: Some(signer_pk.clone()),
                content_hash: content_hash.clone(),
                quorum_proof: quorum_proof.clone(),
                request_id: None,
            },
            local_origin: false,
            version: 1,
            status: DhtRecordStatus::Live,
        };

        store.insert("verified_upstream:test.com".to_string(), entry);

        let retrieved = store.get("verified_upstream:test.com").unwrap();

        assert_eq!(
            retrieved.record.signature, signature,
            "Signature should be persisted and retrieved correctly"
        );
        assert_eq!(
            retrieved.record.signer_public_key,
            Some(signer_pk),
            "signer_public_key should be persisted and retrieved correctly"
        );
        assert_eq!(
            retrieved.record.quorum_proof, quorum_proof,
            "quorum_proof should be persisted and retrieved correctly"
        );
        assert_eq!(
            retrieved.record.content_hash, content_hash,
            "Content hash is persisted correctly"
        );

        let _ = fs::remove_file(db_path);
    }
}
